# Grafana dashboard export

`dashboard.json` isn't included yet — it should be your own exported dashboard, not a
fabricated one, since it needs to reflect the panels, queries, and data source UIDs
you actually configured.

## How to export it

1. Open the dashboard in Grafana.
2. Dashboard settings (gear icon) → **JSON Model**.
3. Copy the JSON and save it here as `dashboard.json`.

## Before committing

Check the exported JSON for anything sensitive before pushing:

- Data source **UIDs** are fine to keep (they're internal references, not secrets).
- Confirm no panel has a hardcoded API key, token, or password baked into a query
  string, URL, or annotation — Infinity panels sometimes inline auth in the URL if
  you didn't use the secure header/token fields.
- Strip any hardcoded internal IP addresses if you don't want your lab topology
  public; replace with a placeholder like `<LAB_HOST_IP>`.

## Recommended panel layout

See `README.md` at the repo root and `docs/ARCHITECTURE.md` for the full panel list
(FIM event table, NetAlertX inventory, Airia risk gauge, analysis history, etc.) —
recreate these in your own Grafana instance, then export and drop the JSON here.
