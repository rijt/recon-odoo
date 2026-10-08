# recon-odoo

The Odoo Reconnaissance Tool — v0.3 by Jan van de Rijt (c)2026

A single-file, dependency-light Python 3 CLI that performs passive and active reconnaissance against one or more Odoo instances. It checks connectivity and security headers, fingerprints Odoo, runs multi-vector version detection, enumerates the database list via XML-RPC, infers the database-manager master-password state **non-destructively**, composes a high-level **database-posture** assessment, discovers installed modules, probes information leaks (tracebacks, user enumeration, phone numbers), tests auth/reporting/longpolling endpoints, and can run Google-dork searches.

- **Single file** — no package layout, no build step
- **One hard dependency** — `requests` (plus optional `googlesearch-python` for dorking)
- **Non-destructive / read-only** — GETs and read-only RPCs only; it never creates, drops, changes, or sets passwords
- **Redirect-aware** — a 302 → `/` "hidden behind login" endpoint state is reported distinctly, not masked as the landing page's 200
- **JSON-first** — full results bundle for scripting, piping, and report export

---

## Install

Requirements: Python 3.8+ (3.10+ recommended).

```
pip install requests
```

That is the only required external dependency. Everything else is stdlib.

Optional (for `--dorks`):

```
pip install googlesearch-python
```

Without it, dorking is skipped with a warning (`'googlesearch' module not installed (pip install googlesearch-python) - dorking skipped.`). Without `requests`, the tool exits at import time with:

```
[ERROR] 'requests' is required.  pip install requests
```

## Quick start

```
# Scan a single target
python3 recon-odoo.py -t https://odoo.example.com

# Scan a batch of targets from a file
python3 recon-odoo.py --targets sites.txt

# Check common default credentials
python3 recon-odoo.py -t https://odoo.example.com --brute

# JSON output (for scripting / piping)
python3 recon-odoo.py -t https://odoo.example.com --json

# Export the full results bundle to a file
python3 recon-odoo.py --targets sites.txt -o results.json --json

# Bare host defaults to https://; force http on a custom port
python3 recon-odoo.py -t 192.168.1.10 -P 8069 --scheme http --insecure
```

## Targets

A target is a URL or a bare hostname:

| Form | Resolved as |
|---|---|
| `https://odoo.example.com` | as given |
| `odoo.example.com` | `https://odoo.example.com` (bare hosts default to `https`) |
| `odoo.example.com:8069` | `https://odoo.example.com:8069` |
| with `-P 8069` / `--port 8069` | port overrides the URL's port |
| with `--scheme http` | scheme overrides the URL's scheme |

Either `-t/--target` or `--targets` is required; passing neither (or ending up with zero valid targets) is a usage error → exit code `2`.

### Sites-file format

One target per line; blank lines and `#` comments ignored. Malformed lines are skipped with a warning.

```
# production
https://odoo.mycorp.com
odoo-legacy.mycorp.com:8069

# staging (note: no scheme → defaults to https://)
staging.odoo.mycorp.com
```

## CLI reference

| Flag | Description |
|---|---|
| `-t`, `--target` | Single target (URL or bare hostname; bare hosts default to `https://`) |
| `--targets` | Path to a file with one target per line; blank lines and `#` comments ignored |
| `-P`, `--port` | Override the port in the target URL |
| `--scheme` | Force `http` or `https` (overrides the URL's scheme) |
| `-k`, `--insecure` | Skip TLS certificate verification |
| `--timeout` | Per-request timeout in seconds (default: 10) |
| `-A`, `--user-agent` | Custom `User-Agent` header (default: a Chrome 125 user agent) |
| `--brute` | Probe with known default credential pairs: `--user/--password` first (if given), then `admin/admin` and `admin/odoo` via `/web/session/authenticate` |
| `--user` | Username used in two places: first pair of the `--brute` check, and the "known login" side of the user-enumeration probe |
| `--password` | Password for authenticated probes (used with `--user`) |
| `--dorks` | Run Google dork searches for the unique target hostnames (capped at 10 hosts; requires optional `googlesearch-python` package) |
| `--dorks-delay` | Delay between dork queries in seconds (default: 1.0) |
| `-j`, `--json` | Emit results as a JSON bundle to stdout and suppress all human-readable output |
| `-o`, `--output FILE` | Write the full JSON results bundle to FILE (in addition to `--json` on stdout; the "written to FILE" confirmation line is suppressed in `--json` mode). Parent directories are created automatically |
| `--no-version-checks` | Skip version-detection probes (step 4) and edition detection (step 16); `results["version"]["skipped"]` is set to `true` |
| `--dblist NAME [NAME …]` | Space-separated DB-name wordlist to probe against `db.status` (read-only) |
| `-v`, `--verbose` | Print per-request trace (method, URL, status, latency, body preview / RPC responses) — implies no human-facing noise, only probe chatter |
| `-h`, `--help` | Show full help with examples and exit-code legend |

Run `python3 recon-odoo.py -h` for the built-in summary.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All targets reachable, scan complete |
| `1` | One or more targets unreachable (partial scan) |
| `2` | Usage error — missing `-t`/`--targets`, bad args, target file not found, or no valid targets |

> `--json` returns the same codes; check `$?` in scripts.

## Scan pipeline (in order)

Per target, `run_all()` executes these steps in order. If Odoo is not confirmed, the scan stops after step 3.

| # | Step | What it does | Output key(s) |
|---|---|---|---|
| 1 | Connectivity | Reaches `/`, records resolved IP, HTTP status, `Server` header | `connectivity` |
| 2 | Headers & security | HSTS, `X-Frame-Options`, `X-Content-Type-Options`, CSP, cookie audit | `headers` |
| 3 | Odoo detection | Login-page fingerprint, `X-Odoo-*` headers, endpoint content checks | `detection`, `is_odoo` |
| 4 | Version detection | Multi-vector A–I (below); skipped with `--no-version-checks` | `version` |
| 5 | Database list | XML-RPC `db.list()` — open list = data-exposure risk | `database_list` |
| 6 | DB wordlist | `db.status` per name from `--dblist` (only with `--dblist`) | `dblist` |
| 7 | Database endpoints | Manager/selector/restore/info probed **with and without** redirect-following; state + severity per endpoint | `endpoints` |
| 8 | Master password | Non-destructive (GET only) inference: `not_set` / `present` / `disabled` / `unknown` | `master_password` |
| 9 | Database posture | Composes `db.list()` state with manager-UI state into one assessment | `database_posture` |
| 10 | Module detection | `/app/<module>` and OCA `github.com/<org>/<repo>` links from `/website/info` | `modules` |
| 11 | Extra endpoints | `/my`, `/web/google_sso`, `/auth_oauth/gateway`, `/web/geoip/json` | `endpoints` |
| 12 | Info leaks | RPC endpoints, traceback leaks, user enumeration, phone numbers, `/debug/` | `leaks`, `user_enum`, `phone_numbers`, `debug_page` |
| 13 | Auth endpoints | Login/auth/settings routes; with `--brute`: default credentials | (printed/risks) |
| 14 | Reporting endpoints | `/web/report*`, `/web/content` (incl. `?id=1` auth-bypass probe) | (printed/risks) |
| 15 | Longpolling/WebSocket | `/bus/longpolling/immediate`, `/websocket`, `/bus/longpolling/pop` (active = 202/3xx) | (printed/risks) |
| 16 | Edition detection | `server_serie` / `protocol_version` from `common.version`; skipped with `--no-version-checks` | `edition` |
| 17 | Risk summary | Aggregated findings | `risks`, `summary` |

Per-target scan errors are caught and recorded in the target's result object under an `error` key; the batch loop always continues with remaining targets.

---

## How each stage works

### 1. Connectivity

GETs `/`. On failure the target is marked `UNREACHABLE` and recorded in `_exit_meta.unreachable` (drives exit code 1). Records the resolved IP via `socket.gethostbyname` (or the literal IP if the target is one).

### 2. Headers & security

Collects the security-relevant response headers (`Server`, `X-Powered-By`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`) and all cookies (names + values). Required headers (HSTS, `X-Frame-Options`, `X-Content-Type-Options`) missing → `MISSING`; CSP absent → `ABSENT` (informational).

### 3. Odoo detection

Confirmed if **any** indicator matches:
- login page (`/web/login`) contains `odoo`, `data-odoo-*` / `data-oe-*` attributes, `/web/assets/` / `/web/static/` asset paths, or `web/client`
- any `X-Odoo-*` response header
- `/website/info` or `/web/dataset/call_kw` content contains `odoo` (fallback)

All matched indicators are stored in `detection.indicators`. If nothing matches, the scan stops here (result still contains `connectivity`, `headers`, `detection`, `risks`).

### 4. Version detection (multi-vector, A → I)

Each vector is tried in order; every hit is recorded in `results["version"]["sources"]` and all raw candidates are kept in `results["version"]["candidates"]`. The final `detected` value is the **highest version** found — candidates are parsed for `MAJOR.MINOR` and ordered by major (e.g. if A returns `14.0.20230101` and G returns `16.0`, `detected` is `16.0`). If no vector yields anything, `VERSION UNKNOWN` is added to risks.

| Vector | Method | What it checks |
|--------|--------|----------------|
| A | XML-RPC | `common.version()` → `server_version` + `protocol_version` fields |
| B | XML-RPC | `db.server_version()` |
| C | JSON-RPC | `POST /web/webclient/version_info` (Odoo 14+ webclient) |
| D | HTTP GET | `/web/webclient/version` (JSON) |
| E | HTTP GET | `/web/version` (JSON, newer Odoo) |
| F | HTTP GET | Asset layout — `/web/content/1-web.assets_common.min.css` (≤14 layout) vs `/web/assets/0/web.assets_common.min.css` (≥15 layout) |
| G | HTTP GET | Login page — `module_version`, `data-odoo-key`, `data-odoo-version`, `<title>` hints |
| H | HTTP GET | `/web/session/authenticate` (response-shape fingerprint) |
| I | HTTP GET | `/web/static/demo`, `/web/static/test` — inline `Odoo X.Y` strings |

### 5. Database list

XML-RPC `db.list()`:
- **non-empty list** → `open_with_databases` (data exposure; each DB name recorded)
- **empty list** → `open_no_databases` (manager open, no DB created yet)
- **denied/error** → `open: false` with the raw error under `error`

### 6. DB wordlist (`--dblist`)

For each supplied name, calls `db.status(<name>)`; `True` = the database exists (recorded as a risk). Read-only. Results in `dblist: {probed: N, found: [...]}`.

### 7. Database management endpoints

`/web/database/manager`, `/web/database/selector`, `/web/database/restore`, `/website/info` — each probed **twice**: once following redirects and once direct (`no_redirect`), so a `302 → /` "hidden behind login" state is not masked as the landing page's 200. Classified state:

| State | Meaning | Severity |
|---|---|---|
| `open` | 200 and enabled — manager UI served with full access, no auth required | `high` (manager) / `medium` (others) |
| `redirect_hidden` | direct 3xx → final page; UI hidden behind login. Note: `db.list()` over XML-RPC may still be open | `medium` / `low` |
| `disabled` | 200 but "disabled by the administrator" text present | `low` |
| `forbidden` | 403 (protected) | `low` |
| `not_found` | 404 (disabled/removed) | `low` |
| `error` | ≥500 (endpoint present) | `low` |
| `unreachable` | no response at all | `unreachable` |

Each entry also carries `direct_status`, `redirects`, `disabled_by_admin`, `hints`, and `note`.

### 8. Master password (v0.3, non-destructive)

Infers the master-password state from the manager + restore page markup using **GET only** — it never submits a form, and never creates, drops, or changes a password.

| State | How it's inferred | Meaning |
|---|---|---|
| `not_set` | page says "database manager is not protected" / "please set a master password" / "we have generated the following master password" (English + French phrasings), **or** manager is open & client-rendered with no password field | create/duplicate/remove/backup/restore work without a password — recorded as a risk |
| `present` | "enter master password" / "master password to confirm" / "current master password", or a password field/button is exposed | a master password is set (or settable) |
| `disabled` | "disabled by the administrator" | DB manager disabled; master password not applicable |
| `unknown` | manager unreachable, or UI redirect-hidden behind login, or markup inconclusive | state not observable; check `db.list()` |

Raw evidence is kept in `master_password.details` (phrase matches found, whether the password field/confirm field exists, client-rendered flag, redirect flag, disabled flag).

### 9. Database posture (v0.3, composite)

Cross-checks the RPC `db.list()` state against the manager/selector UI state and produces one high-level assessment in `results["database_posture"]`:

| Posture | When | Assessment |
|---|---|---|
| `OPEN_AND_ACCESSIBLE` | RPC open with DBs **and** manager UI open | worst case — anyone can create/duplicate/remove/backup/restore |
| `UI_HIDDEN_RPC_OPEN` | RPC open with DBs, manager UI redirect-hidden | DB names still exposed over `db.list()` — hidden ≠ protected |
| `RPC_OPEN_UI_DISABLED` | RPC open with DBs, UI "disabled" | UI-disable does **not** block RPC enumeration |
| `UI_DISABLED_RPC_DENIED` | UI disabled **and** RPC denied | well protected (both gates) |
| `UI_HIDDEN_RPC_HIDDEN` | UI redirect-hidden **and** RPC denied | likely well protected; `--dblist` can still brute names |
| `UI_MAYBE_OPEN_RPC_CLOSED` | RPC denied, UI open/unknown | auth-gated or admin-only; still worth probing |
| `UNKNOWN` | no evidence either side | inconclusive |

The entry includes `rpc_open`, `rpc_databases`, `manager_ui_state`, `selector_ui_state`, and a plain-English `risk` sentence.

### 10. Module detection

`/website/info` (installed-modules page): 200 → extract `/app/<module>` slugs and OCA module names from `github.com/<org>/<repo>/<module>` links (with a 2-part `github.com/<org>/<repo>` fallback, de-duplicated). Result states: `open` / `hidden-behind-login` (3xx) / `not-open` / `unreachable`.

### 11. Extra endpoints

`/my` (employee portal), `/web/google_sso`, `/auth_oauth/gateway`, `/web/geoip/json`. A 200 on any of these without auth is recorded as a risk; `/web/geoip/json` additionally captures and stores the geoip payload (location disclosure).

### 12. Info leaks

- **RPC endpoint presence**: `/web/dataset/call_kw`, `/web/session/authenticate`, `/bus/longpolling/immediate`, `/websocket`
- **Traceback leaks**: any error body (≥400) containing `traceback` is flagged
- **User enumeration**: POSTs two JSON-RPC `web/session` authenticate calls with an obviously fake login and a known login (`--user` if given, else `admin`); if the two responses differ (status or message), user enumeration is flagged as a risk. Result in `user_enum` with both raw probes
- **Phone numbers**: pattern-matches `/phone/index` for phone-like strings (8–15 digits, any separator style / intl prefixes) → `phone_numbers`
- **Debug page**: unauthenticated `/debug/` access is flagged (may leak assets and internal paths) → `debug_page`

### 13. Auth & login endpoints

Probes `/web/login`, `/web/auth/`, `/web/session/destroy`, `/auth_oauth/`, `/auth_signup/`, `/web/settings` and reports which are open. With `--brute`, tries credential pairs in this order:

1. `--user` / `--password` (if `--user` was given)
2. `admin` / `admin`
3. `admin` / `odoo`

A successful login (non-zero `uid`) is recorded as a risk with the returned UID and user name.

### 14. Reporting endpoints

`/web/report`, `/web/report/html`, `/web/report/pdf`, `/web/report/csv`, `/web/content` — reports HTTP status, `Content-Type`, `Content-Disposition`, size. Then probes `/web/content?&id=1`: a 200 means arbitrary content is accessible without auth (potential auth-bypass / IDOR class).

### 15. Longpolling / WebSocket

`/bus/longpolling/immediate`, `/websocket`, `/bus/longpolling/pop`. 202 or 3xx = active/alive (positive finding); 502 = possible longpolling proxy behind a load balancer.

### 16. Edition detection

Reads `server_serie` and `protocol_version` from XML-RPC `common.version()` → `edition`. (Skipped with `--no-version-checks`.)

### 17. Risk summary

Aggregates the detected version, all risk strings, and the `is_odoo` flag into `summary` (and `risks`). In human-readable mode this is the final per-target section.

## Endpoint inventory

Every network call the tool makes (all read-only):

| Method | Path | Used by |
|---|---|---|
| GET | `/` | connectivity, headers |
| GET | `/web/login` | detection, version (G) |
| GET | `/website/info` | detection fallback, endpoints, modules |
| GET | `/web/dataset/call_kw` | detection fallback, leaks |
| XML-RPC | `/xmlrpc/2/common` → `version` | version (A), edition |
| XML-RPC | `/xmlrpc/2/db` → `server_version` | version (B) |
| XML-RPC | `/xmlrpc/2/db` → `list` | database list |
| XML-RPC | `/xmlrpc/2/db` → `status <name>` | `--dblist` |
| POST (JSON-RPC) | `/web/webclient/version_info` | version (C) |
| GET | `/web/webclient/version` | version (D) |
| GET | `/web/version` | version (E) |
| GET | `/web/content/1-web.assets_common.min.css` | version (F, ≤14 layout) |
| GET | `/web/assets/0/web.assets_common.min.css` | version (F, ≥15 layout) |
| GET | `/web/static/demo`, `/web/static/test` | version (I) |
| GET | `/web/database/manager` (± direct) | endpoints, master password |
| GET | `/web/database/selector` | endpoints |
| GET | `/web/database/restore` (± direct) | endpoints, master password |
| GET | `/my` | extra endpoints |
| GET | `/web/google_sso` | extra endpoints |
| GET | `/auth_oauth/gateway` | extra endpoints |
| GET | `/web/geoip/json` | extra endpoints |
| GET | `/phone/index` | phone numbers |
| GET | `/debug/` | debug page |
| GET | `/websocket` | leaks, longpolling |
| GET | `/bus/longpolling/immediate` | leaks, longpolling |
| GET | `/bus/longpolling/pop` | longpolling |
| GET | `/web/login`, `/web/auth/`, `/web/session/destroy`, `/auth_oauth/`, `/auth_signup/`, `/web/settings` | auth endpoints |
| GET | `/web/report`, `/web/report/html`, `/web/report/pdf`, `/web/report/csv`, `/web/content`, `/web/content?&id=1` | reporting |
| POST (JSON-RPC) | `/web/session/authenticate` | user enumeration, `--brute` |
| GET | `/web/session/authenticate` | version (H), leaks |

## Google dorks (`--dorks`)

Runs **after** all targets are scanned, one dork block per unique hostname (capped at `_DORK_HOST_CAP = 10` hosts to avoid exploding a large sites file). Five fixed queries per host:

```
site:<host> "odoo"
site:<host> "/web/database/selector"
site:<host> "/web/database/manager"
site:<host> "/website/info" odoo
site:<host> inurl:("/my" "/web/login")
```

Behavior details:
- requires `pip install googlesearch-python`; without it, each dork block is skipped with a warning
- up to 10 results per dork query
- `--dorks-delay` (default 1.0s) is the sleep between queries; the per-request pause inside the search library is clamped to `[0.5, 2.0]` seconds
- dork results are **printed to the console only** — they are not part of the JSON bundle
- every individual query failure is caught and reported; dorking never aborts the scan

## Output

### Human-readable mode

Colorized console output (`[+] ok`, `[!] warning`, `[*] info`, `[-] error`) with per-step section banners. Colors are **automatically disabled** when stdout is not a TTY or when `NO_COLOR` is set. `-v/--verbose` additionally prints every request/response line (URL, status, latency, body preview, RPC payload/response).

### JSON mode

`-j/--json` prints the full results bundle to stdout (and sets quiet mode — nothing else goes to stdout). `-o FILE` writes the same bundle to a file (parent directories created). The bundle shape:

```
{
  "<target-url>": { target, is_odoo, version, risks, connectivity, headers, detection,
                     database_list, dblist, endpoints, master_password, database_posture,
                     modules, leaks, user_enum, phone_numbers, debug_page, edition, summary,
                     [error] },
  ...
  "_exit_meta": { "unreachable": [...], "total": N, "scanned_at": "...", "tool": "recon-odoo.py v0.3" }
}
```

Key reference (present when the corresponding step ran):

| Key | Notes |
|---|---|
| `target` | normalised URL |
| `is_odoo` | detection verdict |
| `version` | `detected`, `candidates[]`, `sources{}` (vector → raw value), `skipped` |
| `risks` | aggregated risk strings |
| `connectivity` | `reachable`, `status`, `server`, `ip` |
| `headers` | security headers + cookies (or `null`) |
| `detection` | `is_odoo`, `indicators[]` |
| `database_list` | `open`, `count`, `databases[]`, `state`, `management` (or `error`) |
| `dblist` | only with `--dblist`: `probed`, `found[]` |
| `endpoints` | both DB-endpoint and extra-endpoint entries (`endpoint`, `status`, `direct_status`, `redirects`, `state`, `severity`, `hints[]`) |
| `master_password` | `state`, `note`, `details{}` (raw phrase/field evidence) |
| `database_posture` | `posture`, `rpc_open`, `rpc_databases[]`, `manager_ui_state`, `selector_ui_state`, `risk` |
| `modules` | `open`, `endpoint_status`, `state`, `modules[]`, `oca_modules[]` |
| `leaks` | per-endpoint `status`, `flag`, `traceback_leak` |
| `user_enum` | `status`, `fake{}`, `known{}`, `enum`, `note` |
| `phone_numbers` | `[]` of matched phone strings |
| `debug_page` | `status`, `open` |
| `edition` | only when RPC `common.version` answered: `server_serie`, `protocol_version` |
| `summary` | `version`, `risks[]`, `is_odoo` |
| `error` | only when the per-target scan raised: `repr` of the exception |

Minimal example (abbreviated):

```json
{
  "https://odoo.example.com": {
    "target": "https://odoo.example.com",
    "is_odoo": true,
    "version": { "detected": "16.0", "candidates": ["16.0.20240101"], "sources": { "XML-RPC common.version": "16.0.20240101" }, "skipped": false },
    "connectivity": { "reachable": true, "status": 200, "server": "gunicorn", "ip": "203.0.113.5" },
    "database_list": { "open": true, "count": 1, "databases": ["demo"], "state": "open_with_databases" },
    "master_password": { "state": "not_set", "note": "manager page states NOT PROTECTED (…)", "details": { "…": "…" } },
    "database_posture": { "posture": "OPEN_AND_ACCESSIBLE", "rpc_open": true, "rpc_databases": ["demo"], "manager_ui_state": "open", "risk": "DB manager UI + RPC are both open; …" },
    "summary": { "version": "16.0", "risks": ["…"], "is_odoo": true }
  },
  "_exit_meta": { "unreachable": [], "total": 1, "scanned_at": "2026-10-08T12:00:00+0200", "tool": "recon-odoo.py v0.3" }
}
```

Pipe to `jq` for scripting: `python3 recon-odoo.py -t … --json | jq '.[].risks'` (shape depends on number of targets; the bundle is keyed by target URL plus `_exit_meta`).

## More examples

```
# Full scan, verbose, no version probes
python3 recon-odoo.py -t odoo.example.com -P 8069 -v --no-version-checks

# Insecure TLS, default-credential brute, JSON to stdout, keep a file copy
python3 recon-odoo.py -t https://192.168.1.10:8069 -k --brute --json > result.json

# Batch scan + dorks + DB wordlist + report export
python3 recon-odoo.py --targets sites.txt --dorks --dblist myapp prod staging -o report.json --json

# Authenticated probes with your own credentials (also feeds user-enumeration and --brute order)
python3 recon-odoo.py -t https://odoo.example.com --user partner@example.com --password S3cret --brute

# Force http, raise the timeout
python3 recon-odoo.py -t legacy.local --scheme http --port 80 --timeout 20
```

## Notes & behavior contracts

- **Non-destructive by design** — the master-password check and all DB probes are read-only (GET / `db.status` / `db.list()`); the tool never creates, drops, changes, or sets passwords, and all checks infer state from responses.
- **Response caching** — GETs are cached per path (with a separate `no-redirect` cache entry) and XML-RPC calls per (endpoint, method, args) within a target's scan, so the same probe is never repeated and traffic stays minimal.
- **Redirect-aware probing** — a 302 → `/` on the manager UI is reported as `redirect_hidden`, not masked as the landing page's 200.
- **Per-target isolation** — errors on one target never abort the batch; the failure is stored in that target's `error` key.
- **Dorking rate limits** — 10-host cap and 1.0s default delay are intentional; `--dorks-delay` tunes the inter-query delay.
- **`--json` semantics** — suppresses all human-readable stdout (colors never emitted), so it is safe for `jq`. `-o` is independent of `--json`.
- **Exit codes are stable** — `0` / `1` / `2` as documented; use them in CI scripts.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `[ERROR] 'requests' is required` at startup | `pip install requests` |
| Every target `UNREACHABLE`, exit 1 | wrong scheme/port; try `--scheme http`, `-P`, `--insecure`, or a larger `--timeout` |
| `Targets file … does NOT exist`, exit 2 | fix the `--targets` path |
| `No valid targets found`, exit 2 | sites file only had blanks/comments, or lines were all malformed |
| Dorking skipped | `pip install googlesearch-python` |
| TLS warnings | expected with `-k/--insecure` (warnings are suppressed automatically when urllib3 is importable) |
| Version empty but `is_odoo: true` | all version vectors failed (versioned endpoints disabled); check `version.candidates` manually, or rerun with `-v` |
| Master password `unknown` | manager UI hidden behind login, or markup inconclusive — look at `master_password.details` and `database_posture` instead |
| JSON looks "quiet" | `--json` intentionally disables human output; progress/interactivity requires dropping the flag |

## Development notes

- Single file by design — no modules, no build step, no test framework. Verify changes with `python3 -m py_compile recon-odoo.py` and by running the tool against a live or local Odoo instance.
- Python 3.8+ (annotations use `from __future__ import annotations`); Python 3.10+ recommended.
- Companion viewer: `recon-viewer.html` — a standalone HTML file to browse a results bundle.

## License

GNU General Public License v3 or later — see [`LICENSE`](LICENSE).
