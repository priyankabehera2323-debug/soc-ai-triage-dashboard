# Architecture & build notes

Full reference for how this lab is wired together, why each security control exists,
and how to troubleshoot the common failure points. See the top-level `README.md` for
the high-level overview and current build progress.

## Topology

Two hosts on the same lab network:

| Host | Role |
|---|---|
| Windows endpoint | Runs the Wazuh agent (security + FIM telemetry source) and Grafana (dashboard) |
| Ubuntu VM | Runs Wazuh Manager + Indexer, NetAlertX (Docker), and the Airia forwarder (systemd) |

This lab uses VirtualBox with a **dual-adapter** setup: a Host-Only adapter for
Windows↔VM communication, and a NAT adapter for the VM's internet access (needed to
install packages). Replace `<LAB_HOST_IP>` placeholders throughout this repo with
your actual Host-Only network addresses. Every port below is scoped via UFW to
traffic between just these two hosts — not open to the wider subnet.

| Purpose | Port | Direction |
|---|---|---|
| Wazuh agent traffic | TCP 1514 | Windows → Ubuntu |
| Wazuh agent enrollment | TCP 1515 | Windows → Ubuntu |
| Wazuh Indexer (OpenSearch) | TCP 9200 | Windows (Grafana) → Ubuntu |
| Wazuh Dashboard | TCP 443 | Windows → Ubuntu |
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
uses a read-only OpenSearch role (`grafana_wazuh_read`) scoped to `wazuh-alerts-*`
indices — never the Wazuh admin account. The NetAlertX API, the helper API, and the
Airia API key are all independently generated and independently rotatable. A
compromise of one integration doesn't hand over access to the others.

**Prompt-injection-aware LLM boundary.** Every field forwarded to Airia originates from
attacker-reachable data (a file path or rule description on a monitored endpoint is
something an attacker who already has some foothold could influence). The system
prompt treats all of it as untrusted evidence and explicitly refuses to follow
instructions embedded in alert content.

**Least data exposure.** `INCLUDE_FILE_DIFF` defaults to `false`, so raw file contents
never leave the lab network unless that's a deliberate, reviewed choice.

**Hardened systemd unit.** The forwarder runs under a dedicated unprivileged service
account (`wazuh-airia`) with `ProtectSystem=strict`, `NoNewPrivileges=true`,
`PrivateTmp=true`, and explicit `ReadOnlyPaths` / `ReadWritePaths`.

**Fail-safe, not fail-open, log handling.** If the Airia API call throws an exception,
the forwarder does not advance its file offset, so the event is retried on the next
loop rather than silently dropped.

## Build order (progress tracked in root README.md)

1. [x] Confirm network reachability between the two hosts.
2. [x] Install and configure the Wazuh Manager + Indexer on the Ubuntu VM.
3. [x] Bind the Indexer to the VM's network address and verify the TLS certificate's
   SAN includes that address.
4. [x] Create the read-only `grafana_reader` OpenSearch role and user.
5. [x] Install the Wazuh agent on the Windows endpoint and confirm enrollment.
6. [ ] Configure FIM on a dedicated test directory and validate add/modify/delete
   events end-to-end.
7. [ ] Deploy NetAlertX via Docker Compose and generate its API token.
8. [ ] Build the Airia agent and test it against a sample FIM payload.
9. [ ] Deploy the forwarder service.
10. [ ] Configure the three Grafana data sources and build the dashboard panels.
11. [ ] Run an end-to-end test.

## Troubleshooting

### Issues hit during this build (with fixes)

| Symptom | Root cause | Fix |
|---|---|---|
| `wazuh-install.sh` fails partway with `dpkg` errors, `No space left on device` | Ubuntu's guided LVM install only allocated ~24GB of a 50GB disk to `/`, leaving the rest unused | `sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv` then `sudo resize2fs /dev/ubuntu-vg/ubuntu-lv` |
| `apt remove --purge wazuh-manager` fails with exit code 127 | A disk-full crash left the package's `prerm`/`postrm` maintainer scripts referencing files that no longer existed | Overwrite the broken script with a no-op (`echo 'exit 0' > /var/lib/dpkg/info/<pkg>.prerm`), `chmod +x`, then retry the purge |
| Re-running the installer fails: "Port 1515/55000 is being used by another process" | Old Wazuh processes and the `wazuh` system user survived a purge because they were already running | `sudo pkill -9 -f wazuh`, confirm with `ps aux \| grep wazuh`, then `sudo userdel -r wazuh` before reinstalling |
| SSH session drops mid-install (`client_loop: send disconnect: Connection reset`) | Host-Only VirtualBox network isn't rock-solid under load; a dropped SSH session normally kills whatever was running in it | Run long installs inside `screen -S <name>`; if disconnected, reconnect and run `screen -r <name>` to resume exactly where it left off |
| Wazuh Indexer login works locally but Grafana/curl from another host can't reach `:9200` | Indexer's `network.host` defaulted to `127.0.0.1` | Edit `/etc/wazuh-indexer/opensearch.yml`, set `network.host` to the VM's real IP, restart the service |
| TLS certificate error / identity mismatch when connecting to the Indexer over HTTPS | Default cert's SAN only includes `127.0.0.1`, not the VM's actual IP | Regenerate just the Indexer cert with `wazuh-certs-tool.sh -wi <root-ca.pem> <root-ca.key>` (both extracted from the installer's own `wazuh-install-files.tar` backup), then replace `/etc/wazuh-indexer/certs/wazuh-indexer.pem` and `-key.pem`, fix ownership (`wazuh-indexer:wazuh-indexer`), restart |
| `curl --cacert .../root-ca.pem` fails with "error setting certificate file" even though the file exists and is readable | Root cause was actually a **parent directory** permission (`/etc/wazuh-indexer` itself was `750`, blocking traversal for non-owner users) — not the file's own permissions | Check the whole path with `ls -ld` at every level, not just the target file; `chmod o+x` on parent directories that need to be traversed (never loosen the private key's own permissions) |
| OpenSearch rejects a new user with `{"status":"error","reason":"Weak password"}` | Default password policy requires a mix of upper/lowercase, digits, and symbols, plus a minimum length — an 8-9 character password without enough variety still fails | Use a longer password (12+) mixing all four character classes |
| Ubuntu's text-mode installer or GRUB recovery mode won't respond to mouse clicks or Enter | It's a keyboard-only TUI; focus must be moved with Tab, not the mouse | Click inside the VM window first, then Tab repeatedly until the target button is visibly highlighted before pressing Enter |
| Forgot the Ubuntu login password | — | Reboot, interrupt GRUB (tap Shift repeatedly at boot), Advanced options → recovery mode → root shell, `mount -o remount,rw /`, `passwd <username>`, `reboot` |
| Copy-paste doesn't work in the raw VirtualBox console window | Clipboard sharing requires Guest Additions installed *inside* the guest OS, not just the VirtualBox clipboard setting | Either install Guest Additions properly, or (simpler) do all work over SSH from a host terminal instead, where normal copy-paste works |

### General troubleshooting (anticipated, not yet hit)

| Symptom | Likely cause | Fix |
|---|---|---|
| Infinity JSON parse error, response starts with `<` | Endpoint returned HTML (login page, wrong URL) | Curl the exact URL directly, confirm `200` + `application/json` |
| JQ parser rejects a leading dot (`.devices[]`) | JSONata parser selected instead of JQ | Switch the Infinity parser to Backend → JQ |
| OpenSearch panel shows "missing metrics and aggregations" | Stat/Gauge/time-series query has no metric or date histogram | Set Metric = Count and Group by = Date histogram |
| Lucene query fails to parse a Windows path | Unescaped backslashes | Double-escape backslashes in the quoted path |
| NetAlertX devices stuck on "New" | Discovery hasn't completed a cycle yet | Wait for a scan cycle |
| Event visible in Grafana but no Airia analysis | Forwarder started after the file offset moved past the event, or the Airia call failed | Trigger a fresh test event; check the forwarder's service logs |

## Operations

- **Log rotation:** rotate `analyses.jsonl` with `logrotate` once the forwarder is deployed.
- **Backups:** Wazuh Indexer config + certs (including the extracted `root-ca.key`/`root-ca.pem`
  from `wazuh-install-files.tar` — keep this safe, it's needed for any future cert regeneration),
  the Windows agent's `ossec.conf`, and exported Grafana dashboard JSON.
- **Credential rotation cadence:** review OpenSearch roles, the Airia API key scope, and
  Grafana admin accounts monthly at minimum.

## Known limitations

- The helper API currently serves plain HTTP — not yet built.
- Airia's risk assessment will be analyst assistance, not an authoritative verdict.
- This lab uses a self-signed CA; browsers will show a certificate warning when
  accessing the Wazuh Dashboard directly, which is expected and fine for a lab.
