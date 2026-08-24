# Architecture & build notes

Full reference for how this lab is wired together, why each security control exists,
and how to troubleshoot the common failure points. See the top-level `README.md` for
the high-level overview.

## Topology

Two hosts on the same lab network:

| Host | Role |
|---|---|
| Windows endpoint | Runs the Wazuh agent (security + FIM telemetry source) and Grafana (dashboard) |
| Ubuntu VM | Runs Wazuh Manager + Indexer, NetAlertX (Docker), and the Airia forwarder (systemd) |

Replace `<LAB_HOST_IP>` / `<WINDOWS_HOST_IP>` placeholders throughout this repo with
your actual lab addresses. Every port below is scoped to traffic between just these
two hosts via UFW — not open to the wider subnet.

| Purpose | Port | Direction |
|---|---|---|
| Wazuh agent traffic | TCP 1514 | Windows → Ubuntu |
| Wazuh agent enrollment | TCP 1515 | Windows → Ubuntu |
| Wazuh Indexer (OpenSearch) | TCP 9200 | Windows (Grafana) → Ubuntu |
| NetAlertX web UI | TCP 20211 | Windows → Ubuntu |
| NetAlertX API | TCP 20212 | Windows (Grafana) → Ubuntu |
| Airia helper API | TCP 8010 | Windows (Grafana) → Ubuntu |

## Data flow, step by step

1. A file changes inside the Wazuh agent's monitored directory on the Windows endpoint.
2. The agent reports the change to the Wazuh Manager over TCP 1514.
3. The Manager writes a `syscheck` alert to `alerts.json` on the Ubuntu VM.
4. The forwarder service (`forwarder/wazuh_airia_forwarder.py`) tails that file, filters
   for `added` / `modified` / `deleted` events with a non-empty path, and builds a
   structured JSON payload.
5. The payload is POSTed to the Airia agent's execution API with an `X-API-Key` header.
6. Airia's LLM step (see `airia/system_prompt.md`) returns a structured risk
   assessment: score, severity, summary, evidence, recommended actions.
7. The forwarder normalizes the response and appends it to a local JSONL log.
8. Grafana polls the forwarder's small internal API (`/api/latest`, `/api/analyses`)
   via the Infinity data source and renders the result alongside Wazuh and NetAlertX
   panels.

The forwarder never blocks on Grafana — it's a pure producer that batches nothing and
retries failed Airia calls without losing the alert offset.

## Security design decisions

**Separate credential per trust boundary.** Grafana's connection to the Wazuh Indexer
uses a read-only OpenSearch role scoped to `wazuh-alerts-*` indices — never the Wazuh
admin account. The NetAlertX API, the helper API, and the Airia API key are all
independently generated and independently rotatable. A compromise of one integration
doesn't hand over access to the others.

**Prompt-injection-aware LLM boundary.** Every field forwarded to Airia originates from
attacker-reachable data (a file path or rule description on a monitored endpoint is
something an attacker who already has some foothold could influence). The system
prompt treats all of it as untrusted evidence and explicitly refuses to follow
instructions embedded in alert content — the same threat model as sanitizing
user input before it reaches an LLM in any other application.

**Least data exposure.** `INCLUDE_FILE_DIFF` defaults to `false`, so raw file contents
never leave the lab network unless that's a deliberate, reviewed choice. Only
metadata — path, hashes, rule level — is sent to the LLM by default.

**Hardened systemd unit.** The forwarder runs under a dedicated unprivileged service
account (`wazuh-airia`) with `ProtectSystem=strict`, `NoNewPrivileges=true`,
`PrivateTmp=true`, and explicit `ReadOnlyPaths` / `ReadWritePaths` — it can read the
Wazuh alert log and write to its own state directory, and nothing else.

**Fail-safe, not fail-open, log handling.** If the Airia API call throws an exception,
the forwarder does not advance its file offset, so the event is retried on the next
loop rather than silently dropped. Malformed JSON lines are logged and skipped rather
than crashing the tailer thread.

## Build order

1. Confirm network reachability between the two hosts (`ip route`, firewall rules).
2. Install and configure the Wazuh Manager + Indexer on the Ubuntu VM.
3. Bind the Indexer to the VM's bridged address and verify the TLS certificate's SAN
   includes that address — Grafana's OpenSearch connection will fail strict TLS
   validation otherwise.
4. Create the read-only `grafana_reader` OpenSearch role and user.
5. Install the Wazuh agent on the Windows endpoint and confirm enrollment.
6. Configure FIM (`<syscheck>` directories block) on the Windows agent and validate
   with a manual add/modify/delete test, checking `alerts.json` on Ubuntu.
7. Deploy NetAlertX via Docker Compose and generate its API token.
8. Build the Airia agent (Input → AI Model → Output), paste in the system prompt from
   `airia/system_prompt.md`, and test it against a sample FIM payload.
9. Deploy the forwarder service: create the `wazuh-airia` system user, install the
   Python venv, set ownership/permissions on the state directory, install the
   systemd unit, and start it.
10. Configure the three Grafana data sources (OpenSearch, NetAlertX Infinity, helper
    Infinity) and build the dashboard panels.
11. Run an end-to-end test: create/modify/delete a test file on Windows and confirm
    the event flows through to a rendered Grafana panel within one refresh interval.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Infinity JSON parse error, response starts with `<` | Endpoint returned HTML (login page, wrong URL) | Curl the exact URL directly, confirm `200` + `application/json`, fix auth/endpoint |
| Infinity JSON parse error, response starts with `N` (e.g. "Not authorized") | Missing/incorrect Bearer or API-key header | Recheck the header name and value in the Infinity data source config |
| JQ parser rejects a leading dot (`.devices[]`) | JSONata parser selected instead of JQ | Switch the Infinity parser to Backend → JQ, or drop the leading dot for JSONata |
| OpenSearch panel shows "missing metrics and aggregations" | Stat/Gauge/time-series query has no metric or date histogram | Set Metric = Count and Group by = Date histogram; use Raw Data for plain event tables |
| Lucene query fails to parse a Windows path | Unescaped backslashes | Double-escape backslashes in the quoted path; test with a wildcard first |
| Helper API (`:8010`) connection refused | Service not running, wrong bind address, or firewall blocking it | Check `systemctl status`, confirm `BIND_HOST`, check UFW rule |
| Certificate identity mismatch on `:9200` | Indexer cert's SAN doesn't include the VM's bridged IP | Regenerate the cert with the correct IP in its SAN and restart dependent services |
| `Permission denied` writing `analyses.jsonl` | Service user doesn't own the state directory | Re-apply `chown`/`chmod` on `/var/lib/wazuh-airia-forwarder` and restart |
| Helper can't read `alerts.json` | Service account not in the `wazuh` group | Add `wazuh-airia` to the `wazuh` group, restart the service |
| NetAlertX devices stuck on "New" | Discovery hasn't completed a cycle yet | Wait for a scan cycle; inspect a single `/device/<mac>` for computed status |
| Event visible in Wazuh but not Grafana | Wrong time range, index pattern, or query type | Set range to Last 24h, confirm `wazuh-alerts-*` index pattern and `rule.groups:syscheck` query |
| Event visible in Grafana but no Airia analysis | Forwarder started after the file offset moved past the event, or the Airia call failed | Trigger a fresh test event; check the forwarder's service logs for request errors |

## Operations

- **Log rotation:** `analyses.jsonl` grows without bound; rotate it with `logrotate`
  (daily, 30-day retention, `copytruncate` so the running service doesn't need a
  restart signal).
- **Backups:** Wazuh Indexer config + certs, the Windows agent's `ossec.conf`,
  the NetAlertX Compose file + data volume, this repo's config directory (with
  secrets excluded), and exported Grafana dashboard JSON (secrets stripped).
- **Credential rotation cadence:** review Wazuh Indexer roles, the Airia API key
  scope, and Grafana admin accounts on a monthly cadence at minimum, and immediately
  after any suspected exposure.

## Known limitations

- The helper API currently serves plain HTTP — fine for an isolated lab segment,
  not appropriate to expose more broadly without adding TLS.
- No rate limiting in front of the helper; acceptable for a single Grafana
  consumer, would need a reverse proxy for more.
- Airia's risk assessment is analyst assistance, not an authoritative verdict —
  every High/Critical result should still be manually reviewed.
