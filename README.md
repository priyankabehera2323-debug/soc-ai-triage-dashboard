# AI-Assisted File Integrity Monitoring & Network Security Dashboard

A home-lab SOC pipeline built to practise the whole path from a raw endpoint event to an analyst-ready result. **Wazuh** watches a Windows laptop for file changes, a small **Python service** scores every change with fixed rules, and a **local LLM (Ollama)** can add a plain-English summary. **Grafana** and **NetAlertX** (network inventory) are the next pieces.

> **Status: work in progress.** The path from the Windows agent through Wazuh to the scoring API works end to end and has been tested on real alerts. The Grafana dashboard and NetAlertX are not built yet; see [Build progress](#build-progress).

---

## Why this project

Most junior SOC portfolios stop at "I installed Wazuh and made a dashboard". This one asks a harder question: what happens when an AI model is asked to judge an alert whose contents an attacker controls? A filename is enough.

I tested it. A small local model (qwen3:0.6b), told to treat the event as untrusted data, still returned a risk score of 99 for a file whose name contained an injected instruction, and it scored a routine file edit 70. (Informal test, one run each; details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).) So the final design never lets the model score anything: **fixed rules compute the risk score, and the model only writes the summary wording.**

---

## Architecture

```
┌────────────────────────────────┐                          ┌───────────────────────────────────┐
│ Windows laptop                 │                          │ Ubuntu VM (Wazuh server)          │
│                                │                          │                                   │
│ - Wazuh agent                  │ ── TCP 1514 (events) ──▶ │ - Wazuh Manager -> alerts.json    │
│   (FIM on C:\SOC-Lab\fim-test) │                          │ - Filebeat -> Wazuh Indexer       │
│                                │                          │ - Wazuh Dashboard                 │
│ - Browser: Wazuh Dashboard     │ ◀── HTTPS 443 ─────────  │ - Forwarder service (systemd)     │
│                                │                          │     tails alerts.json             │
│ - Grafana (planned)            │                          │     scores with fixed rules       │
│                                │                          │     read-only API (:8010)         │
│                                │                          │ - Ollama + qwen3:0.6b (local,     │
│                                │                          │     off by default): summary text │
│                                │                          │ - NetAlertX (planned)             │
└────────────────────────────────┘                          └───────────────────────────────────┘
```

**Data flow**

1. A file changes in the monitored folder on the Windows laptop.
2. The Wazuh agent reports it to the Wazuh Manager (TCP 1514).
3. The Manager writes a `syscheck` alert to `alerts.json`; Filebeat ships it to the Indexer, and it appears in the Wazuh Dashboard.
4. The forwarder service tails `alerts.json` and keeps only `added`, `modified` and `deleted` file-integrity events.
5. It scores each event with fixed rules (event type, Wazuh rule level, sensitive-path patterns, executable file types) and stores the result immediately with a template summary.
6. If the local model is enabled and the VM has enough free memory, it rewrites the summary in plain English. The score is never touched.
7. A read-only HTTP API (API-key protected) serves the latest result and the history. Grafana will read it.

| Component | Role | Host | Status |
|---|---|---|---|
| Wazuh agent | File integrity monitoring and endpoint telemetry | Windows laptop | Running |
| Wazuh Manager, Indexer, Dashboard, Filebeat | Analysis, storage, web UI | Ubuntu VM | Running |
| Forwarder service | Scoring, optional LLM summaries, read-only API | Ubuntu VM (systemd) | Running |
| Ollama (qwen3:0.6b) | Summary wording only | Ubuntu VM | Working, off by default |
| Grafana | Dashboard | Windows laptop | Planned |
| NetAlertX | Network inventory | Ubuntu VM (Docker) | Planned |

---

## Key design decisions

**The model never scores.** Risk score and severity come from code, using fields an attacker cannot easily choose (event type, Wazuh rule level, a fixed list of sensitive paths and file types). Filename text has no effect on the score, and every score comes with the list of reasons behind it. The worst an injected filename can do is change the wording of a summary, and each record labels whether its summary came from the model or from a template.

**Untrusted data is handled as untrusted.** Control characters are stripped and lengths capped before anything reaches the model. The model sees only the agent name, rule ID and level, event type, the path and the computed score; no file contents, hashes or diffs. Only the `summary` and `recommended_actions` fields are read from its reply; anything else it returns, including a score, is ignored.

**Everything stays local.** Inference runs on the VM through Ollama, so alert data never leaves the lab network.

**Built for a small VM.** The VM has 4 GB of RAM. The model is unloaded after each answer, runs at most three times a minute, and is skipped when less than 900 MB is free, so a scan that produces hundreds of events can't flood the CPU. Skipped events keep their template summary.

**Least privilege.** Grafana is meant to read Wazuh data through a read-only OpenSearch role, never the admin account. The forwarder runs as its own unprivileged user under a hardened systemd unit (no new privileges, read-only access to the alert log, write access only to its own state folder), and its API is bound to loopback and requires an API key.

**Fail-safe tailing.** The service remembers its position in `alerts.json`, copes with log rotation, and never consumes a half-written line. If the model is slow, down or returns garbage, the event is still scored and stored.

---

## Try it

Replay recent real alerts through the scoring rules, without running the service or the model:

```bash
sudo python3 forwarder/wazuh_ollama_forwarder.py --replay 2000 --match fim-test
```

Each line shows the event, its score and severity, and why.

---

## Build progress

- [x] Ubuntu Server VM in VirtualBox (Host-Only and NAT adapters)
- [x] Wazuh Manager, Indexer, Dashboard and Filebeat installed and running
- [x] Indexer TLS certificate regenerated so its SAN matches the address the Indexer is bound to
- [x] Read-only OpenSearch role and user for Grafana created and tested (to be re-tested after the address change below)
- [x] Windows agent connected over the Host-Only network
- [x] FIM on a dedicated folder verified end to end: add, modify and delete events (rules 554, 550, 553) reach the Wazuh Dashboard
- [x] Forwarder service: rule-based scoring, API-key auth, hardened systemd unit, running
- [x] Local LLM summaries working (qwen3:0.6b); off by default because of memory pressure
- [ ] Move the Indexer, Dashboard and Filebeat to the Host-Only address and re-issue the certificate
- [ ] Install Grafana, add data sources, build the dashboard
- [ ] Deploy NetAlertX
- [ ] Tighten the VM firewall (current rules are broader than intended)
- [ ] Put the forwarder API behind HTTPS before exposing it beyond the VM
- [ ] Add the forwarder's tests to the repo
- [ ] Record a short demo of an event flowing through to the dashboard

---

## Known limitations

- The scoring rules are hand-written heuristics, not tuned on real attacks. A new DLL in System32, for example, scores 68 (Medium), just under High.
- Files in the configured test folder are capped at Low so lab demos don't look alarming.
- A 0.6B model writes fluent but sometimes vague or wrong summaries; in testing, one summary stated a detail that wasn't in the event. That is why it cannot influence the score.
- Lab-grade security: self-signed certificates, and the API is plain HTTP on loopback for now.
- The Wazuh Manager in this lab also has a VirusTotal integration enabled. It sends file hashes to an external service, so it would need turning off to keep the "nothing leaves the lab" claim fully true.

---

## Repo structure

```
.
├── forwarder/
│   └── wazuh_ollama_forwarder.py           # scoring, optional LLM summaries, read-only API
├── config/
│   ├── wazuh-ollama-forwarder.service      # hardened systemd unit
│   ├── wazuh-ollama-forwarder.env.example  # settings template (no secrets)
│   └── netalertx-compose.yml               # planned, not deployed yet
├── grafana/
│   └── README.md                           # how to export the dashboard JSON
└── docs/
    └── ARCHITECTURE.md                     # design, scoring rules, tests, troubleshooting
```

## Stack

`Wazuh 4.14` · `OpenSearch` · `Filebeat` · `Python 3 / Flask / waitress` · `Ollama (qwen3:0.6b)` · `systemd` · `UFW` · `VirtualBox` · planned: `Grafana`, `NetAlertX`

---

*Built as a personal SOC lab project to practise detection engineering, secure service design and careful use of AI in alert triage. Not intended for production use without additional hardening (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).*
