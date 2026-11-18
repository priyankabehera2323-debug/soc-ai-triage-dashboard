# AI-Assisted File Integrity Monitoring & Network Security Dashboard

A home-lab SOC pipeline built to practise the whole path from a raw endpoint event to an analyst-ready result. **Wazuh** watches a Windows laptop for file changes, a small **Python service** scores every change with fixed rules, and a **local LLM (Ollama)** can add a plain-English summary. **Grafana** provides SOC monitoring and security alert visualization, with **NetAlertX** planned for network inventory.

> **Status: Work in progress.** The Windows agent-to-Wazuh-to-Python scoring pipeline works end to end and has been tested with real alerts. Grafana is now connected to Wazuh OpenSearch, and a SOC monitoring dashboard with 13 panels has been built and saved. NetAlertX deployment and further project improvements remain in progress. See [Build progress](#build-progress).

---

## Why this project

Most junior SOC portfolios stop at "I installed Wazuh and made a dashboard". This one asks a harder question: what happens when an AI model is asked to judge an alert whose contents an attacker controls? A filename is enough.

I tested it. A small local model (qwen3:0.6b), told to treat the event as untrusted data, still returned a risk score of 99 for a file whose name contained an injected instruction, and it scored a routine file edit 70. (Informal test, one run each; details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).) So the final design never lets the model score anything: **fixed rules compute the risk score, and the model only writes the summary wording.**

---

## Architecture

```text
┌────────────────────────────────┐
│ Windows laptop                 │
│                                │
│ - Wazuh agent                  │
│   (FIM on C:\SOC-Lab\fim-test) │
│ - Wazuh Dashboard (browser)    │
│ - Grafana 13                   │
│   - OpenSearch data source     │
│   - 13 SOC monitoring panels  │
└───────────────┬────────────────┘
                │
                │ Wazuh events
                │ TCP 1514
                ▼
┌────────────────────────────────────┐
│ Ubuntu VM (Wazuh server)           │
│                                    │
│ - Wazuh Manager -> alerts.json     │
│ - Filebeat -> Wazuh Indexer        │
│ - Wazuh Dashboard                  │
│ - OpenSearch Indexer               │
│ - Forwarder service (systemd)      │
│     tails alerts.json              │
│     scores with fixed rules        │
│     read-only API (:8010)          │
│ - Ollama + qwen3:0.6b              │
│     optional summary text          │
│ - NetAlertX (planned)              │
└────────────────────────────────────┘
```

**Data flow**

1. A file changes in the monitored folder on the Windows laptop.
2. The Wazuh agent reports it to the Wazuh Manager (TCP 1514).
3. The Manager writes a `syscheck` alert to `alerts.json`; Filebeat ships it to the Indexer, and it appears in the Wazuh Dashboard.
4. The forwarder service tails `alerts.json` and keeps only `added`, `modified` and `deleted` file-integrity events.
5. It scores each event with fixed rules (event type, Wazuh rule level, sensitive-path patterns, executable file types) and stores the result immediately with a template summary.
6. If the local model is enabled and the VM has enough free memory, it rewrites the summary in plain English. The score is never touched.
7. A read-only HTTP API (API-key protected) serves the latest result and history.
8. Grafana connects to Wazuh OpenSearch through a read-only account and visualizes security alerts in the SOC dashboard.

| Component | Role | Host | Status |
|---|---|---|---|
| Wazuh agent | File integrity monitoring and endpoint telemetry | Windows laptop | Running |
| Wazuh Manager, Indexer, Dashboard, Filebeat | Analysis, storage, web UI | Ubuntu VM | Running |
| Forwarder service | Scoring, optional LLM summaries, read-only API | Ubuntu VM (systemd) | Running |
| Ollama (qwen3:0.6b) | Summary wording only | Ubuntu VM | Working, off by default |
| Grafana 13 | SOC monitoring and security alert visualization | Windows laptop | Connected — 13 panels saved |
| NetAlertX | Network inventory | Ubuntu VM (Docker) | Planned |

---

## Grafana SOC Monitoring Dashboard

Grafana is connected to Wazuh OpenSearch using a dedicated read-only account.

The dashboard currently contains 13 saved panels:

1. Total Security Alerts
2. Higher-Severity Alerts (Levels 7–10)
3. Security Alerts Over Time
4. Top 10 Alert Rules
5. Top 10 Alert-Generating Agents
6. Recent Security Events
7. Alert Severity Distribution
8. Failed Login Attempts
9. SSH Brute-Force Attempts
10. Successful Login Activity
11. Alerts by Severity
12. Top Source IPs – Failed Authentication
13. Top 10 Triggered Wazuh Rules

The dashboard provides visibility into alert volume, severity, authentication activity, SSH brute-force-related events, source IP addresses and frequently triggered Wazuh rules.

**Note:** Alert counts represent matching Wazuh alert events, not necessarily unique attacks or incidents. For example, `127.0.0.1` appeared as a source IP during local SSH authentication testing.

---

## Key design decisions

**The model never scores.** Risk score and severity come from code, using fields an attacker cannot easily choose (event type, Wazuh rule level, a fixed list of sensitive paths and file types). Filename text has no effect on the score, and every score comes with the list of reasons behind it. The worst an injected filename can do is change the wording of a summary, and each record labels whether its summary came from the model or from a template.

**Untrusted data is handled as untrusted.** Control characters are stripped and lengths capped before anything reaches the model. The model sees only the agent name, rule ID and level, event type, the path and the computed score; no file contents, hashes or diffs. Only the `summary` and `recommended_actions` fields are read from its reply; anything else it returns, including a score, is ignored.

**Local inference.** Inference runs on the VM through Ollama, so the model's processing stays within the lab network. Note that the Wazuh VirusTotal integration can send file hashes to an external service.

**Built for a small VM.** The VM has 4 GB of RAM. The model is unloaded after each answer, runs at most three times a minute, and is skipped when less than 900 MB is free, so a scan that produces hundreds of events can't flood the CPU. Skipped events keep their template summary.

**Least privilege.** Grafana reads Wazuh data through a dedicated read-only OpenSearch role, never the admin account. The forwarder runs as its own unprivileged user under a hardened systemd unit (no new privileges, read-only access to the alert log, write access only to its own state folder), and its API is bound to loopback and requires an API key.

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
- [x] Read-only OpenSearch role and user for Grafana created and tested
- [x] Windows agent connected over the Host-Only network
- [x] FIM on a dedicated folder verified end to end: add, modify and delete events (rules 554, 550, 553) reach the Wazuh Dashboard
- [x] Forwarder service: rule-based scoring, API-key auth, hardened systemd unit, running
- [x] Local LLM summaries working (qwen3:0.6b); off by default because of memory pressure
- [x] Grafana 13 installed on Windows
- [x] Grafana OpenSearch data source configured and connection tested
- [x] Grafana SOC monitoring dashboard created with 13 panels
- [x] Failed and successful authentication monitoring configured
- [x] SSH brute-force alert monitoring configured using Wazuh rule 2502
- [x] Source IP and top triggered Wazuh rule monitoring configured
- [ ] Export and commit Grafana dashboard JSON
- [ ] Add dashboard screenshots and project demonstration
- [ ] Deploy NetAlertX
- [ ] Tighten the VM firewall
- [ ] Put the forwarder API behind HTTPS before exposing it beyond the VM
- [ ] Add the forwarder's tests to the repo
- [ ] Record a short demo of an event flowing through to the dashboard

---

## Known limitations

- The scoring rules are hand-written heuristics, not tuned on real attacks. A new DLL in System32, for example, scores 68 (Medium), just under High.
- Files in the configured test folder are capped at Low so lab demos don't look alarming.
- A 0.6B model writes fluent but sometimes vague or wrong summaries; in testing, one summary stated a detail that wasn't in the event. That is why it cannot influence the score.
- Lab-grade security: self-signed certificates, and the API is plain HTTP on loopback for now.
- The Wazuh Manager in this lab also has a VirusTotal integration enabled. It sends file hashes to an external service, so the "nothing leaves the lab" claim does not apply to that integration.

---

## Repo structure

```text

soc-ai-triage-dashboard/
│
├── config/
│   ├── netalertx-compose.yml
│   ├── wazuh-ollama-forwarder.env.example
│   └── wazuh-ollama-forwarder.service
│
├── docs/
│   ├── ARCHITECTURE.md
│   └── GRAFANA_DASHBOARD.md       
│
├── forwarder/
│   └── wazuh_ollama_forwarder.py
│
├── grafana/
│   └── README.md
└── README.md

```

## Stack

`Wazuh 4.14` · `OpenSearch` · `Filebeat` · `Grafana 13` · `Python 3 / Flask / waitress` · `Ollama (qwen3:0.6b)` · `systemd` · `UFW` · `VirtualBox`

Planned: `NetAlertX`

---

*Built as a personal SOC lab project to practise detection engineering, secure service design and careful use of AI in alert triage. Not intended for production use without additional hardening (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).*
