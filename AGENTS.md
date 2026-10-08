# AGENTS.md

## What this is
Single-file CLI tool `recon-odoo.py` — Python 3 Odoo reconnaissance scanner (v0.3). No package, no build, no tests, no tests directory. License: GPLv3 (`LICENSE`).

## Run
```bash
python3 recon-odoo.py -t https://example.com
python3 recon-odoo.py --targets sites.txt --brute --json
```
- Only dependency: `requests` (`pip install requests`). Exits with an error at import if missing.
- Python 3.10+ recommended (uses `X | None` annotations; `from __future__ import annotations` covers 3.8+ but runtime behavior targets modern 3.x).

## Conventions that differ from defaults
- Single file by design — do not split into modules or add a package layout unless asked.
- No test framework exists; verify changes by running the tool against a live/local Odoo instance or `python3 -m py_compile recon-odoo.py`.
- Color output auto-disables when `NO_COLOR` is set or stdout is not a TTY; `--json` also sets `QUIET=True` — do not print to stdout in `--json` mode except the JSON payload. `-o/--output` may print a confirmation line when not in quiet mode.

## Behavior contracts (do not break)
- Exit codes: `0` all targets reachable, `1` one or more unreachable (partial scan), `2` usage error (missing target / bad args / missing `--targets` file / no valid targets).
- Either `-t/--target` or `--targets` is required; bare hosts default to `https://`; `--port`/`--scheme` override the URL.
- `--targets` file: one URL per line, blank lines and `#` comments ignored.
- Dorking is capped at 10 unique hosts (`_DORK_HOST_CAP`) with a 1.0s delay between queries — intentional rate limiting; don't remove without reason.
- Per-target scan errors are caught and recorded in results (with an `error` key); the loop always continues with remaining targets.
- All checks against a running DB must stay non-destructive / read-only: the master-password check infers state from page markup (GET only) and never creates, drops, or changes passwords; `--dblist` probes `db.status` only.
- GET responses are cached per path in `_get_cache` (with a separate `|no-redirect` key) and XML-RPC calls in `_xmlrpc_cache`; keep both direct (no-redirect) and redirect-followed probes for endpoints — the redirect-hidden state (302 → `/`) is a distinct, reportable finding.

## Pipeline (v0.3, in `run_all`)
connectivity → headers → Odoo detection (stops here if not Odoo) → version detection → `db.list()` → `--dblist` → database endpoints (redirect-aware state: open / redirect_hidden / disabled / forbidden / …) → **master password check (new: infers not_set / present / disabled / unknown from DB-manager + restore pages)** → **database posture (new: composes RPC `db.list()` state with manager-UI state into `results["database_posture"]`)** → modules → extra endpoints → info leaks (user enumeration, phone numbers, tracebacks) → auth endpoints (`--brute` / `--user`/`--password`) → reporting endpoints → longpolling/WebSocket → edition detection → risk summary.

Version/edition detection are skipped when `--no-version-checks` is set.

## Version detection
Multi-method: XML-RPC (`common.version`, `db.server_version`), JSON-RPC `web/webclient.version_info`, GET `/web/webclient/version`, GET `/web/version`, asset-path fingerprint (≤14 vs ≥15 layout), login-page HTML fingerprint, static paths. Ordered A–I in `_version_detection`; sources are recorded in `results["version"]["sources"]`, all raw candidates in `results["version"]["candidates"]`; `detected` is the highest `major.minor` found.

## Output
`-j/--json` prints the full bundle to stdout (and sets `QUIET`). `-o FILE` additionally writes the bundle to a file. `_exit_meta` contains `unreachable`, `total`, `scanned_at`, and `tool` (`recon-odoo.py v0.3`).
