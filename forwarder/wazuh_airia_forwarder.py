#!/usr/bin/env python3
"""Forward Wazuh file-integrity alerts to Airia and expose analyses to Grafana."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from flask import Flask, jsonify, request
from waitress import serve

AIRIA_API_URL = os.environ["AIRIA_API_URL"]
AIRIA_API_KEY = os.environ["AIRIA_API_KEY"]
LOCAL_API_KEY = os.environ["LOCAL_API_KEY"]
LOCAL_API_HEADER = os.getenv("LOCAL_API_HEADER", "X-API-Key")

WAZUH_ALERTS_FILE = Path(
    os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
)
ANALYSES_FILE = Path(
    os.getenv(
        "ANALYSES_FILE",
        "/var/lib/wazuh-airia-forwarder/analyses.jsonl",
    )
)
STATE_FILE = Path(
    os.getenv(
        "STATE_FILE",
        "/var/lib/wazuh-airia-forwarder/state.json",
    )
)

BIND_HOST = os.getenv("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.getenv("BIND_PORT", "8010"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "120"))
FORWARD_EXISTING_ON_FIRST_START = (
    os.getenv("FORWARD_EXISTING_ON_FIRST_START", "false").lower() == "true"
)
INCLUDE_FILE_DIFF = os.getenv("INCLUDE_FILE_DIFF", "false").lower() == "true"
MAX_DIFF_CHARS = int(os.getenv("MAX_DIFF_CHARS", "4000"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOG = logging.getLogger("wazuh-airia-forwarder")

FILE_LOCK = threading.RLock()
STOP_EVENT = threading.Event()
app = Flask(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def file_event(alert: dict[str, Any]) -> tuple[str, str] | None:
    """Return (event, path) only for an actual FIM file change."""
    rule = alert.get("rule") or {}
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]

    syscheck = alert.get("syscheck") or {}
    event = str(syscheck.get("event") or "").lower()
    path = str(syscheck.get("path") or "").strip()

    if "syscheck" not in groups or event not in {"added", "modified", "deleted"}:
        return None
    if not path:
        return None
    return event, path


def make_event_id(alert: dict[str, Any], event: str, path: str) -> str:
    source = "|".join(
        [
            str(alert.get("id") or ""),
            str(alert.get("timestamp") or ""),
            str((alert.get("agent") or {}).get("id") or ""),
            event,
            path,
        ]
    )
    return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:24]


def build_airia_input(alert: dict[str, Any], event: str, path: str) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    syscheck = alert.get("syscheck") or {}

    payload: dict[str, Any] = {
        "schema": "wazuh_fim_alert_v1",
        "event_id": make_event_id(alert, event, path),
        "timestamp": alert.get("timestamp"),
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip"),
        },
        "rule": {
            "id": rule.get("id"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "groups": rule.get("groups"),
        },
        "file_integrity": {
            "event": event,
            "path": path,
            "size_before": syscheck.get("size_before"),
            "size_after": syscheck.get("size_after"),
            "md5_before": syscheck.get("md5_before"),
            "md5_after": syscheck.get("md5_after"),
            "sha1_before": syscheck.get("sha1_before"),
            "sha1_after": syscheck.get("sha1_after"),
            "sha256_before": syscheck.get("sha256_before"),
            "sha256_after": syscheck.get("sha256_after"),
            "changed_attributes": syscheck.get("changed_attributes"),
        },
        "analyst_request": (
            "Assess this Wazuh file-integrity event. Return the strict JSON schema "
            "defined by the agent playbook."
        ),
    }
    if INCLUDE_FILE_DIFF and syscheck.get("diff"):
        payload["file_integrity"]["diff"] = str(syscheck["diff"])[:MAX_DIFF_CHARS]
    return payload


def find_candidate_output(value: Any) -> Any:
    """Find a likely analysis object or text inside tenant-specific Airia wrappers."""
    if isinstance(value, dict):
        if {"risk_score", "summary"}.issubset(value.keys()):
            return value
        for key in ("output", "result", "response", "answer", "content", "text", "message"):
            if key in value:
                found = find_candidate_output(value[key])
                if found not in (None, "", [], {}):
                    return found
        for child in value.values():
            found = find_candidate_output(child)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_candidate_output(child)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(value, str) and value.strip():
        return value.strip()
    return None


def parse_json_text(text: str) -> dict[str, Any] | None:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I | re.S)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(cleaned[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def normalize_analysis(
    airia_response: Any,
    alert: dict[str, Any],
    event: str,
    path: str,
) -> dict[str, Any]:
    candidate = find_candidate_output(airia_response)
    analysis: dict[str, Any] = {}
    raw_text = ""

    if isinstance(candidate, dict):
        analysis = candidate
    elif isinstance(candidate, str):
        raw_text = candidate
        analysis = parse_json_text(candidate) or {}

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}

    fallback_score = min(100, max(0, safe_int(rule.get("level"), 0) * 7))
    score = min(100, max(0, safe_int(analysis.get("risk_score"), fallback_score)))

    recommendations = analysis.get("recommended_actions") or []
    if isinstance(recommendations, str):
        recommendations = [recommendations]

    evidence = analysis.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]

    summary = str(analysis.get("summary") or raw_text or rule.get("description") or "")

    return {
        "analysis_timestamp": utc_now(),
        "alert_timestamp": alert.get("timestamp"),
        "event_id": make_event_id(alert, event, path),
        "alert_name": str(
            analysis.get("alert_name")
            or rule.get("description")
            or f"File {event}"
        ),
        "risk_score": score,
        "severity": str(analysis.get("severity") or severity_from_score(score)),
        "confidence": str(analysis.get("confidence") or "Not stated"),
        "summary": summary[:4000],
        "evidence": evidence[:10],
        "evidence_text": " | ".join(str(item) for item in evidence[:10]),
        "recommended_actions": recommendations[:10],
        "recommended_actions_text": " | ".join(
            str(item) for item in recommendations[:10]
        ),
        "file_event": event,
        "file_path": path,
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
    }


def send_to_airia(payload: dict[str, Any]) -> Any:
    response = requests.post(
        AIRIA_API_URL,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": AIRIA_API_KEY,
        },
        json={
            "userInput": json.dumps(payload, separators=(",", ":")),
            "asyncOutput": False,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return {"output": response.text}


def append_analysis(record: dict[str, Any]) -> None:
    ANALYSES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with FILE_LOCK, ANALYSES_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_state() -> dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def write_state(inode: int, offset: int) -> None:
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(
        json.dumps({"inode": inode, "offset": offset, "updated_at": utc_now()}),
        encoding="utf-8",
    )
    os.replace(temp, STATE_FILE)


def process_alert(alert: dict[str, Any]) -> None:
    matched = file_event(alert)
    if not matched:
        return
    event, path = matched
    payload = build_airia_input(alert, event, path)
    LOG.info("Forwarding FIM event=%s path=%s", event, path)
    airia_response = send_to_airia(payload)
    record = normalize_analysis(airia_response, alert, event, path)
    append_analysis(record)
    LOG.info(
        "Stored Airia analysis event_id=%s risk_score=%s",
        record["event_id"],
        record["risk_score"],
    )


def tail_alerts() -> None:
    state = read_state()
    first_open = True

    while not STOP_EVENT.is_set():
        try:
            stat = WAZUH_ALERTS_FILE.stat()
            inode = int(stat.st_ino)

            if first_open:
                if state.get("inode") == inode:
                    offset = min(safe_int(state.get("offset"), 0), stat.st_size)
                elif FORWARD_EXISTING_ON_FIRST_START:
                    offset = 0
                else:
                    offset = stat.st_size
                write_state(inode, offset)
                state = {"inode": inode, "offset": offset}
                first_open = False
            elif state.get("inode") != inode or safe_int(state.get("offset"), 0) > stat.st_size:
                offset = 0
            else:
                offset = safe_int(state.get("offset"), 0)

            with WAZUH_ALERTS_FILE.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                while not STOP_EVENT.is_set():
                    line_start = handle.tell()
                    line = handle.readline()
                    if not line:
                        break
                    try:
                        alert = json.loads(line)
                        process_alert(alert)
                    except json.JSONDecodeError:
                        LOG.warning("Skipped malformed JSON at byte %s", line_start)
                    except requests.RequestException as exc:
                        LOG.error("Airia request failed; retrying this alert: %s", exc)
                        handle.seek(line_start)
                        time.sleep(10)
                        continue
                    offset = handle.tell()
                    write_state(inode, offset)
                    state = {"inode": inode, "offset": offset}

        except FileNotFoundError:
            LOG.error("Wazuh alerts file not found: %s", WAZUH_ALERTS_FILE)
        except PermissionError:
            LOG.exception("Permission denied reading or writing a service file")
        except Exception:
            LOG.exception("Unexpected forwarder error")

        STOP_EVENT.wait(2)


def load_analyses(limit: int) -> list[dict[str, Any]]:
    if not ANALYSES_FILE.exists():
        return []
    records: deque[dict[str, Any]] = deque(maxlen=max(1, min(limit, 1000)))
    with FILE_LOCK, ANALYSES_FILE.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(records)


@app.before_request
def protect_analysis_api():
    if not request.path.startswith("/api/"):
        return None
    supplied = request.headers.get(LOCAL_API_HEADER, "")
    if not hmac.compare_digest(supplied, LOCAL_API_KEY):
        return jsonify({"error": "unauthorized"}), 401
    return None


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "bind_host": BIND_HOST,
            "alerts_readable": os.access(WAZUH_ALERTS_FILE, os.R_OK),
            "analyses_writable": os.access(ANALYSES_FILE.parent, os.W_OK),
        }
    )


@app.get("/api/latest")
def latest_analysis():
    records = load_analyses(1)
    if records:
        return jsonify(records[-1])
    return jsonify(
        {
            "analysis_timestamp": None,
            "alert_timestamp": None,
            "alert_name": "No Airia analysis received yet",
            "risk_score": 0,
            "severity": "None",
            "confidence": "None",
            "summary": "Generate a Wazuh file-integrity event to populate this panel.",
            "recommended_actions_text": "",
            "file_event": "none",
            "file_path": "",
            "agent_name": "",
            "rule_id": "",
            "rule_level": 0,
        }
    )


@app.get("/api/analyses")
def analysis_history():
    limit = safe_int(request.args.get("limit"), 100)
    return jsonify({"analyses": load_analyses(limit)})


def main() -> None:
    missing = [name for name, value in {
        "AIRIA_API_URL": AIRIA_API_URL,
        "AIRIA_API_KEY": AIRIA_API_KEY,
        "LOCAL_API_KEY": LOCAL_API_KEY,
    }.items() if not value]
    if missing:
        raise RuntimeError(f"Missing required settings: {', '.join(missing)}")

    worker = threading.Thread(target=tail_alerts, name="wazuh-alert-tailer", daemon=True)
    worker.start()

    LOG.info("Serving Grafana API on http://%s:%s", BIND_HOST, BIND_PORT)
    serve(app, host=BIND_HOST, port=BIND_PORT, threads=4)


if __name__ == "__main__":
    main()
