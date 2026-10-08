#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon-odoo.py - The Odoo Reconnaissance Tool v0.3 by Jan van de Rijt

A single-file, reliable Python 3 Odoo reconnaissance tool that enumerates the
Odoo version and provides rich passive/active recon. Works against single hosts
or multi-target files (e.g. sites.txt).

Dependencies: requests (stdlib: xmlrpc.client, json, urllib.parse only)

Copyright (C)2026  Jan van de Rijt
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.  See ./LICENSE.
"""
from __future__ import annotations

import sys
import os
import re
import json
import time
import socket
import argparse
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, urljoin

# ---------------------------------------------------------------------------
# Guard imports
# ---------------------------------------------------------------------------
try:
    import requests
except ImportError:
    sys.exit("[ERROR] 'requests' is required.  pip install requests")

try:
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    # urllib3 is a transitive dependency of requests, but if it isn't importable
    # directly we simply proceed without suppressing warnings.
    pass

try:
    from xmlrpc.client import ServerProxy
except ImportError:
    ServerProxy = None

_MISSING = object()


# ---------------------------------------------------------------------------
# ANSI colour helpers (auto-disable for non-TTY / NO_COLOR)
# ---------------------------------------------------------------------------
_DISABLE_COLOUR = os.environ.get("NO_COLOR") or not sys.stdout.isatty()
QUIET = False
DORKS_DELAY = 1.0

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "grey": "\033[90m",
}


def _c(label: str, text: str) -> str:
    if _DISABLE_COLOUR or label not in _C:
        return text
    return f"{_C[label]}{text}{_C['reset']}"


def ok(text) -> None:
    if not QUIET:
        print(_c("green",  f"  [+] {text}"))

def warn(text) -> None:
    if not QUIET:
        print(_c("yellow", f"  [!] {text}"))

def info(text) -> None:
    if not QUIET:
        print(_c("cyan",   f"  [*] {text}"))

def err(text) -> None:
    if not QUIET:
        print(_c("red",    f"  [-] {text}"))

def title(t) -> None:
    if not QUIET:
        print(_c("bold",   f"\n{'='*60}\n  {t}\n{'='*60}"))


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------
class SessionBuilder:
    """Build a requests.Session with TLS/timeout/UA knobs."""

    _DEFAULT_UA = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )

    def __init__(self, timeout=10, ssl_verify=True, user_agent=None):
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self.user_agent = user_agent or self._DEFAULT_UA

    def build(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": self.user_agent, "Accept-Language": "en-US,en;q=0.9"})
        if not self.ssl_verify:
            s.verify = False
        s.timeout = self.timeout
        return s


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------
class OdooRecon:

    def __init__(self, target_url: str, session_builder: SessionBuilder, brute: bool = False, no_version_checks: bool = False, verbose: bool = False, user: str | None = None, password: str | None = None, dblist: list[str] | None = None):
        self.url = self._normalise(target_url)
        parsed = urlparse(self.url)
        self.base = parsed.scheme + "://" + parsed.netloc
        self.session = session_builder.build()
        self.brute: bool = brute
        self.no_version_checks: bool = no_version_checks
        self.verbose: bool = verbose
        self.user: str = user or ""
        self.password: str = password or ""
        self.dblist: list[str] = list(dblist or [])
        self.results: dict = {
            "target": self.url,
            "is_odoo": False,
            "version": {"detected": "", "candidates": [], "sources": {}, "skipped": self.no_version_checks},
            "risks": [],
        }
        self.risks: list[str] = []
        self.version_detected: str = ""
        self.is_odoo: bool = False
        self._get_cache: dict[str, requests.Response | None] = {}
        self._xmlrpc_cache: dict[str, object] = {}
        self._xmlrpc_proxies: dict[str, ServerProxy] = {} if ServerProxy is not None else {}
        self._json_id: int = 0

    def _next_json_id(self) -> str:
        self._json_id += 1
        return str(self._json_id)

    # -- plumbing ----------------------------------------------------------
    @staticmethod
    def _normalise(raw: str) -> str:
        raw = raw.strip()
        if not re.match(r"https?://", raw):
            raw = "https://" + raw
        return raw.rstrip("/")

    def _vlog(self, line: str):
        if self.verbose and not QUIET:
            print(_c("grey", f"    {line}"))

    def _vim(self, line: str):
        """info() that only prints when -v/--verbose is set (probe chatter)."""
        if self.verbose:
            info(line)

    def get(self, path: str, no_redirect: bool = False, **kw) -> requests.Response | None:
        cache_key = path if not no_redirect else path + "|no-redirect"
        if cache_key in self._get_cache:
            self._vlog(f"GET {path} (no_redirect={no_redirect}) -> cache hit")
            return self._get_cache[cache_key]
        url = urljoin(self.base, path)
        t0 = time.time()
        self._vlog(f"GET {url}")
        try:
            r = self.session.get(
                url,
                timeout=self.session.timeout,
                verify=self.session.verify is not False,
                allow_redirects=not no_redirect,
            )
            self._vlog(f"<- GET {path} HTTP {r.status_code} ({(time.time() - t0) * 1000:.1f}ms, {len(r.content)}b)")
            body = r.text
            if len(body) > 800:
                body = body[:800] + "..."
            self._vlog(f"    body: {body.strip()}")
            self._get_cache[cache_key] = r
            return r
        except Exception as e:
            self._vlog(f"<- GET {path} FAILED after {(time.time() - t0) * 1000:.1f}ms: {e}")
            self._get_cache[cache_key] = None
            return None

    def post_jsonrpc(self, path: str, method_call: dict) -> dict | None:
        t0 = time.time()
        self._vlog(f"POST {path} body={json.dumps(method_call)}")
        try:
            payload = json.dumps(method_call).encode()
            resp = self.session.post(
                urljoin(self.base, path),
                data=payload,
                timeout=self.session.timeout,
                verify=self.session.verify is not False,
                headers={"Content-Type": "application/json"},
            )
            out = resp.json() if resp.content else None
            self._vlog(f"<- POST {path} HTTP {resp.status_code} ({(time.time() - t0) * 1000:.1f}ms) resp={out}")
            return out
        except Exception as e:
            self._vlog(f"<- POST {path} FAILED after {(time.time() - t0) * 1000:.1f}ms: {e}")
            return None

    def xmlrpc_call(self, ep: str, method: str, *args) -> tuple | dict | list | str | None:
        if ServerProxy is None:
            return None
        cache_key = (ep, method, tuple(args))
        if cache_key in self._xmlrpc_cache:
            self._vlog(f"XMLRPC {ep} -> {method}({args}) -> cache hit")
            return None if self._xmlrpc_cache[cache_key] is _MISSING else self._xmlrpc_cache[cache_key]
        t0 = time.time()
        self._vlog(f"XMLRPC {ep} -> {method}({args})")
        try:
            proxy = self._xmlrpc_proxies.get(ep)
            if proxy is None:
                proxy = ServerProxy(urljoin(self.base, ep), allow_none=True)
                self._xmlrpc_proxies[ep] = proxy
            out = getattr(proxy, method)(*args)
            self._vlog(f"<- XMLRPC {ep}.{method} ({(time.time() - t0) * 1000:.1f}ms) => {out}")
            self._xmlrpc_cache[cache_key] = out
            return out
        except Exception as e:
            self._vlog(f"<- XMLRPC {ep}.{method} FAILED after {(time.time() - t0) * 1000:.1f}ms: {e}")
            self._xmlrpc_cache[cache_key] = _MISSING
            return None

    @staticmethod
    def _status_ok(resp: requests.Response | None) -> bool:
        if resp is None:
            return False
        return 200 <= resp.status_code < 400

    @staticmethod
    def _status_3xx(resp: requests.Response | None) -> bool:
        if resp is None:
            return False
        return 300 <= resp.status_code < 400

    # -- orchestrator ------------------------------------------------------
    def run_all(self):
        self._connectivity()
        self._headers_fingerprint()
        self._odoo_detection()
        self.results["is_odoo"] = self.is_odoo
        if not self.is_odoo:
            info("Target does NOT appear to be Odoo.")
            self.results["risks"] = list(self.risks)
            return
        if not self.no_version_checks:
            self._version_detection()
        self._db_list()
        self._dblist()
        self._database_endpoints()
        self._master_password_check()
        self._database_posture()
        self._module_detection()
        self._extra_endpoints()
        self._info_leaks()
        self._auth_endpoints()
        self._reporting_endpoints()
        self._longpolling_websocket()
        if not self.no_version_checks:
            self._edition_detection()
        self._risk_summary()

    # -----------------------------------------------------------------------
    # 1. Connectivity
    # -----------------------------------------------------------------------
    def _connectivity(self):
        title("CONNECTIVITY CHECK")
        entry = {"reachable": False, "status": None, "server": None, "ip": None}
        self.results["connectivity"] = entry
        r = self.get("/")
        if r is None:
            err(f"Cannot reach {self.base}")
            self.risks.append("UNREACHABLE")
            return
        entry["reachable"] = True
        entry["status"] = r.status_code
        entry["server"] = r.headers.get("Server")
        info(f"HTTP {r.status_code} - server header: {r.headers.get('Server') or 'N/A'}")
        parsed = urlparse(self.url)
        netloc = parsed.netloc.split(":")[0]
        try:
            ipaddress.ip_address(netloc)
            entry["ip"] = netloc
            hint = f"[IP address: {netloc}]"
        except ValueError:
            resolved = None
            try:
                resolved = socket.gethostbyname(netloc)
            except Exception:
                pass
            if resolved:
                entry["ip"] = resolved
                hint = f"[Resolved IP: {resolved}]"
            else:
                hint = "[Could not resolve host]"
        info(hint)

    # -----------------------------------------------------------------------
    # 2. HTTP headers & security checks
    # -----------------------------------------------------------------------
    _SECURITY_CHECKS = [
        ("Strict-Transport-Security", "HSTS enabled", True),
        ("X-Frame-Options", "Clickjacking protection", True),
        ("X-Content-Type-Options", "MIME sniffing protection", True),
        ("Content-Security-Policy", "CSP present", False),
    ]

    def _headers_fingerprint(self):
        title("HTTP HEADERS & SECURITY CHECKS")
        r = self.get("/")
        if not r:
            self.results["headers"] = None
            return
        headers = dict(r.headers)
        hdr_list = []
        selected = {}
        for k in ("Server", "X-Powered-By", "X-Frame-Options", "X-Content-Type-Options",
                   "Strict-Transport-Security", "Content-Security-Policy",
                   "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"):
            if k in headers:
                hdr_list.append(f"  {k}: {headers[k]}")
                selected[k] = headers[k]
        cookies = r.cookies
        if cookies:
            cookie_strs = [f"{c.name}={c.value[:20]}{'...' if len(c.value) > 20 else ''}" for c in cookies]
            hdr_list.append(f"  Cookies: {', '.join(cookie_strs)}")
            selected["cookies"] = [f"{c.name}={c.value}" for c in cookies]
        self.results["headers"] = selected or None
        for line in hdr_list:
            info(line)
        for header, desc, required in self._SECURITY_CHECKS:
            val = r.headers.get(header)
            if val:
                info(f"  {_c('green', 'OK')} {desc}: {header}={val[:80]}")
            else:
                color = "red" if required else "yellow"
                label = "MISSING" if required else "ABSENT"
                info(f"  {_c(color, label)} {desc} ({header})")

    # -----------------------------------------------------------------------
    # 3. Odoo detection
    # -----------------------------------------------------------------------
    def _odoo_detection(self):
        title("ODOO DETECTION")
        self.results["detection"] = {"is_odoo": False, "indicators": []}
        p = self.get("/web/login")
        if p and p.status_code < 400:
            body_str = ""
            try:
                body_str = p.text.lower()
            except Exception:
                pass
            indicators = []
            if "odoo" in body_str:
                indicators.append("word 'odoo' in login page")
            if "data-odoo-" in body_str or "data-oe-" in body_str:
                indicators.append("data-odoo-* / data-oe-* attributes")
            if "/web/assets/" in body_str or "/web/static/" in body_str:
                indicators.append("asset path pattern (Odoo)")
            if "web/client" in body_str:
                indicators.append("web/client reference")
            if indicators:
                self.is_odoo = True
                self.results["detection"]["is_odoo"] = True
                self.results["detection"]["indicators"].extend(indicators)
                info(f"ODOO DETECTED - indicators: {'; '.join(indicators)}")

        r = self.get("/")
        if r:
            for h in ("X-Odoo-",):
                if h in r.headers:
                    info(f"  Response header '{h}' present (Odoo indicator)")
                    self.is_odoo = True
                    self.results["detection"]["is_odoo"] = True
                    self.results["detection"]["indicators"].append(f"response header '{h}'")

        if not self.is_odoo:
            endpoints_test = ["/website/info", "/web/dataset/call_kw"]
            for ep in endpoints_test:
                r2 = self.get(ep)
                if r2 and "odoo" in r2.text.lower():
                    info(f"  '{ep}' contains 'odoo' - Odoo indicator")
                    self.is_odoo = True
                    self.results["detection"]["is_odoo"] = True
                    self.results["detection"]["indicators"].append(f"'{ep}' contains 'odoo'")

        self.results["detection"]["is_odoo"] = self.is_odoo
        if not self.is_odoo:
            warn("Odoo NOT confirmed by standard probes.")

    # -----------------------------------------------------------------------
    # 4. Version detection (multi-vector)
    # -----------------------------------------------------------------------
    def _version_detection(self):
        title("VERSION DETECTION - Multi-Vector Fingerprinting")
        versions_found: set[str] = set()
        sources: dict[str, str] = {}

        # Method A: XML-RPC /xmlrpc/2/common version()
        self._vim("  [A] XML-RPC /xmlrpc/2/common version() ...")
        data = self.xmlrpc_call("/xmlrpc/2/common", "version")
        if isinstance(data, dict):
            sv = data.get("server_version", "") or ""
            ps = data.get("protocol_version", "") or ""
            self._vim(f"  Response: {json.dumps(data)}")
            versions_found.add(sv)
            sources["XML-RPC common.version"] = sv

        # Method B: XML-RPC /xmlrpc/2/db server_version()
        self._vim("  [B] XML-RPC /xmlrpc/2/db server_version() ...")
        data = self.xmlrpc_call("/xmlrpc/2/db", "server_version")
        if isinstance(data, str) and data:
            versions_found.add(data)
            sources["XML-RPC db.server_version"] = data

        # Method C: JSON-RPC /web/webclient/version_info
        self._vim("  [C] JSON-RPC /web/webclient/version_info ...")
        jp = self.post_jsonrpc("/web/webclient/version_info", {
            "jsonrpc": "2.0", "method": "call",
            "service": "web/webclient", "args": [["version_info"]],
            "id": self._next_json_id(),
        })
        if isinstance(jp, dict):
            v = jp.get("result", "")
            self._vim(f"  Response: {json.dumps(jp)}")
            versions_found.add(str(v))
            sources["JSON-RPC version_info"] = str(v)

        # Method D: GET /web/webclient/version
        self._vim("  [D] GET /web/webclient/version ...")
        r = self.get("/web/webclient/version")
        if self._status_ok(r):
            try:
                jr = r.json()
                self._vim(f"  Response: {json.dumps(jr)}")
                v = str(jr)
                versions_found.add(v)
                sources["GET /web/webclient/version"] = v
            except Exception:
                pass

        # Method E: GET /web/version (newer Odoo)
        self._vim("  [E] GET /web/version ...")
        r = self.get("/web/version")
        if self._status_ok(r):
            try:
                jr = r.json()
                self._vim(f"  Response: {json.dumps(jr)}")
                v = str(jr)
                versions_found.add(v)
                sources["GET /web/version"] = v
            except Exception:
                pass

        # Method F: Asset-style fingerprinting (reliable fallback per do-it.md)
        self._vim("  [F] Asset-style path fingerprinting ...")
        r14 = self.get("/web/content/1-web.assets_common.min.css")
        r15 = self.get("/web/assets/0/web.assets_common.min.css")

        asset_hint = ""
        if self._status_ok(r14) or self._status_3xx(r14):
            asset_hint += "Odoo <= 14 pattern (/web/content/<id>-hash/) "
        if self._status_ok(r15) or self._status_3xx(r15):
            asset_hint += "Odoo >= 15 pattern (/web/assets/0-)"
        if asset_hint:
            info(f"  Asset hint: {asset_hint}")
        else:
            warn("  Neither asset pattern matched")

        # Method G: Login page HTML fingerprint for data-odoo-version etc.
        self._vim("  [G] Login page HTML fingerprint ...")
        lp = self.get("/web/login")
        g_info = []
        if self._status_ok(lp):
            try:
                body_text = lp.text
                mv = re.search(r'"module_version"[^>]*>\s*(\S+)', body_text)
                if mv:
                    g_info.append(f"module_version={mv.group(1)}")
                    versions_found.add(mv.group(1))
                dk = re.search(r'data-odoo-key="([^"]+)"', body_text)
                if dk:
                    g_info.append(f"data-odoo-key={dk.group(1)}")
                ov = re.search(r'data-odoo-version="([^"]+)"', body_text)
                if ov:
                    g_info.append(f"data-odoo-version={ov.group(1)}")
                    versions_found.add(ov.group(1))
                st = re.search(r'<title>([^<]*(?:Odoo|ODOO)\S*)', body_text, re.I)
                if st:
                    g_info.append(f"title hint: {st.group(1)}")
            except Exception:
                pass
        if g_info:
            info(f"  Login page hints: {'; '.join(g_info)}")

        # Method H: /web/session/authenticate probe
        self._vim("  [H] Probe /web/session/authenticate ...")
        r = self.get("/web/session/authenticate")
        if self._status_ok(r):
            try:
                jr = r.json()
                self._vim(f"  Response keys: {list(jr.keys()) if isinstance(jr, dict) else json.dumps(jr)}")
            except Exception:
                pass

        # Method I: Static file version path inspection
        self._vim("  [I] Checking /web/static/ for versions ...")
        for vf in ["/web/static/demo", "/web/static/test"]:
            r = self.get(vf)
            if r and r.status_code < 400:
                self._vim(f"  {vf} -> HTTP {r.status_code}")
                for match in re.finditer(r'Odoo[/\\s](\d+\.?\d*)', r.text, re.I):
                    versions_found.add(match.group(1))

        # --- Report -------------------------------------------------------
        self.version_detected = ""
        if versions_found:
            parsed_versions = []
            for v_str in versions_found:
                m = re.search(r'(\d+\.\d+)', str(v_str))
                if m:
                    parsed_versions.append(m.group(1))
            unique_parsed = sorted(set(parsed_versions), key=lambda x: float(x.split('.')[0] or 0))

            if unique_parsed:
                self.version_detected = unique_parsed[-1]
                if not QUIET:
                    print()
                ok("VERSION DETECTED")
                if not QUIET:
                    sys.stdout.write(f"    \033[92m{self.version_detected}\033[0m\n")
                info(f"  All version candidates found: {unique_parsed}")
            else:
                warn("  Could not parse any valid Odoo version from found strings.")
        else:
            warn("  Version could NOT be determined from any method.")
            self.risks.append("VERSION UNKNOWN")

        self.results["version"] = {
            "detected": self.version_detected,
            "candidates": sorted(versions_found, key=str),
            "sources": sources,
            "skipped": self.no_version_checks,
        }

    # -----------------------------------------------------------------------
    # 5. DB list
    # -----------------------------------------------------------------------
    def _db_list(self):
        title("DATABASE LIST (XML-RPC)")
        data = self.xmlrpc_call("/xmlrpc/2/db", "list")
        MANAGEMENT = "create,duplicate,remove,backup,restore,reset-password"
        if isinstance(data, list):
            if data:
                info(f"  db.list() returned {len(data)} databases!")
                for db in data:
                    info(f"    - {db}")
                self.risks.append(
                    "Database list is OPEN (data exposure: "
                    f"{len(data)} DB(s) {data} - manager allows {MANAGEMENT})"
                )
                self.results["database_list"] = {
                    "open": True, "count": len(data), "databases": list(data),
                    "state": "open_with_databases", "management": MANAGEMENT,
                }
            else:
                warn("  db.list() returned an EMPTY list - database manager is OPEN but NO database has been created yet.")
                self.risks.append(
                    "Database manager is OPEN but EMPTY (no databases created yet) - "
                    f"manager allows {MANAGEMENT}"
                )
                self.results["database_list"] = {
                    "open": True, "count": 0, "databases": [],
                    "state": "open_no_databases", "management": MANAGEMENT,
                }
        else:
            err(f"  db.list() unresponsive or denied: {data}")
            self.results["database_list"] = {"open": False, "databases": [], "error": repr(data)}

    def _dblist(self):
        """Probe a DB-name wordlist against db.status (read-only) when --dblist given."""
        if not self.dblist:
            return
        title("DATABASE WORDLIST (db.status)")
        found: list[str] = []
        probed: int = 0
        for db in self.dblist:
            probed += 1
            ok_db = self.xmlrpc_call("/xmlrpc/2/db", "status", db)
            if ok_db is True:
                found.append(db)
                info(f"  {_c('green', 'EXISTS')} {db} -> db.status True")
                self.risks.append(f"Database '{db}' exists (found via wordlist)")
            else:
                if self.verbose:
                    self._vlog(f"  {db} -> db.status {ok_db!r}")
        info(f"  Probed {probed} name(s), {len(found)} confirmed database(s).")
        self.results["dblist"] = {"probed": probed, "found": found}

    # -----------------------------------------------------------------------
    # 7. Database manager / selector endpoints
    # -----------------------------------------------------------------------
    def _database_endpoints(self):
        title("DATABASE MANAGEMENT ENDPOINTS")
        if "endpoints" not in self.results:
            self.results["endpoints"] = []
        eps = [
            ("/web/database/manager", "DB Manager (drop/create/reset)"),
            ("/web/database/selector", "DB Selector (select DB)"),
            ("/web/database/restore", "DB Restore endpoint"),
            ("/website/info", "Installed modules page"),
        ]
        for ep, desc in eps:
            # Probe WITH redirect-following so a final 200 page is still inspectable,
            # but ALSO probe the DIRECT response (no-redirect) to catch 302 -> /
            # "hidden behind login" redirects that would otherwise be masked as the
            # landing page's 200 (see quividet.nl).
            r = self.get(ep)
            direct = self.get(ep, no_redirect=True)
            if r is None and direct is None:
                warn(f"  {desc} ({ep}) -> unreachable")
                self.results["endpoints"].append({"endpoint": ep, "description": desc, "status": None, "severity": "unreachable", "hints": ["unreachable"]})
                continue

            direct_sc = direct.status_code if direct is not None else None
            final_sc = r.status_code if r is not None else None
            redirects = direct_sc is not None and direct_sc in (301, 302, 303, 307, 308)

            try:
                body_text = (r.text or "").lower() if r is not None else ""
            except Exception:
                body_text = ""
            disabled_by_admin = (
                "disabled by the administrator" in body_text
                or "has been disabled" in body_text
                or "a \xc3\xa9t\xc3\xa9 d\xc3\xa9sactiv\xc3\xa9" in body_text
            )
            hints: list[str] = []
            if direct_sc is not None and final_sc is not None and redirects:
                state = "redirect_hidden"
                if final_sc == 200 and not disabled_by_admin:
                    target = (direct.headers.get("Location") or "").strip()
                    hints = [f"REDIRECT ({direct_sc}) -> {target or '/'} : UI hidden behind login/redirect"]
                    severity = "medium"
                else:
                    hints = [f"REDIRECT ({direct_sc}) - hidden"]
                    severity = "low"
                note = ("manager UI is REDIRECTED (hidden behind login), "
                        "beware: db.list() over XML-RPC may STILL be open - check DATABASE LIST above")
            elif final_sc == 200:
                if disabled_by_admin:
                    state = "disabled"
                    hints.append("DISABLED BY ADMINISTRATOR (page served, manager features disabled)")
                    severity = "low"
                    note = "manager page served but DB manager disabled by administrator"
                else:
                    state = "open"
                    if "manager" in ep:
                        hints.append("FULL ACCESS (create/duplicate/remove/backup/restore/reset-password)")
                    else:
                        hints.append("FULL ACCESS")
                    severity = "high" if "manager" in ep else "medium"
                    note = "manager UI served with FULL ACCESS (no auth required)"
            elif final_sc == 403:
                state = "forbidden"
                hints.append("FORBIDDEN (protected)")
                severity = "low"
                note = "endpoint protected (403)"
            elif final_sc == 404:
                state = "not_found"
                hints.append("NOT FOUND (disabled)")
                severity = "low"
                note = "endpoint not found (404 / disabled)"
            elif final_sc is not None and final_sc >= 500:
                state = "error"
                hints.append(f"HTTP {final_sc} (server error - endpoint present)")
                severity = "low"
                note = f"endpoint present but returned HTTP {final_sc}"
            else:
                state = "other"
                hints.append(f"HTTP {final_sc}")
                severity = "low"
                note = f"endpoint returned HTTP {final_sc}"

            display_sc = (direct_sc if (redirects and direct_sc is not None) else final_sc) or "n/a"
            marker = "HIGH" if severity == "high" else "INFO" if severity == "medium" else ""
            info(f"  {marker} {desc}: {ep} -> {display_sc} {'; '.join(hints)}")
            self.results["endpoints"].append({
                "endpoint": ep, "description": desc, "status": final_sc,
                "direct_status": direct_sc, "redirects": redirects,
                "state": state, "disabled_by_admin": disabled_by_admin,
                "severity": severity, "hints": hints, "note": note,
            })

    def _master_password_check(self):
        """Non-destructive (GET only) inference of the master-password state from
        the DB manager / restore pages. Never creates, drops or changes passwords."""
        title("MASTER PASSWORD (non-destructive, read-only)")
        manager_direct = self.get("/web/database/manager", no_redirect=True)
        manager = self.get("/web/database/manager")
        restore = self.get("/web/database/restore")

        def _body(resp) -> str:
            try:
                return (resp.text or "").lower() if resp is not None else ""
            except Exception:
                return ""

        m_body = _body(manager)
        r_body = _body(restore)
        combined = m_body + " " + r_body

        pw_ui = (
            "master password" in combined
            or 'name="password"' in m_body
            or 'name="master_password"' in m_body
            or 'name="password_confirm"' in m_body
            or "set master password" in combined
        )
        # "not_set" phrasing from the actual Odoo templates (v14+):
        #   "Warning, your Odoo database manager is not protected. To secure it,
        #    we have generated the following master password for it: <b>...
        #   "The DB manager is not protected. Please set a master password to secure it."
        not_protected_phrases = [
            "database manager is not protected",
            "please set a master password",
            "we have generated the following master password",
            "please define a master password",
            "votre manager de base de données n'est pas protégé",
            "s'il vous plaît définissez un mot de passe maître",
        ]
        not_protected_any = any(p in combined for p in not_protected_phrases)
        # "present" phrasing: password prompt without 'not protected' warning
        present_phrases = [
            "enter master password",
            "master password to confirm",
            "current master password",
        ]
        present_any = any(p in combined for p in present_phrases)
        client_rendered = "action: 'database_manager'" in m_body
        disabled_by_admin = "disabled by the administrator" in m_body or "has been disabled" in m_body
        manager_redirects = (
            manager_direct is not None
            and manager_direct.status_code in (301, 302, 303, 307, 308)
        )

        details = {
            "master_password_phrase": "master password" in combined,
            "set_master_password_button": "set master password" in combined,
            "password_field_in_form": 'name="password"' in m_body or 'name="master_password"' in m_body,
            "password_confirm_field": 'name="password_confirm"' in m_body,
            "not_protected_phrases_found": [p for p in not_protected_phrases if p in combined],
            "present_phrases_found": [p for p in present_phrases if p in combined],
            "client_rendered_manager": client_rendered,
            "manager_disabled_by_admin": disabled_by_admin,
            "manager_redirects": manager_redirects,
        }

        if manager is None and manager_direct is None:
            state, note = "unknown", "manager page unreachable - cannot infer master-password state"
        elif manager_redirects:
            state, note = "unknown", (
                "manager UI is REDIRECTED (hidden behind login) - master-password state not observable "
                "from the manager page; check DATABASE LIST (XML-RPC) for whether db.list() is still open"
            )
        elif disabled_by_admin:
            state, note = "disabled", "DB manager disabled by administrator (master password not applicable)"
        elif not_protected_any:
            # Strong evidence: the page itself says the manager is NOT protected.
            state = "not_set"
            note = (
                "manager page explicitly states the database manager is "
                "NOT PROTECTED ('Please set a master password to secure it') "
                "-> NO master password is set (create/duplicate/remove/backup/restore work without a password)"
            )
            self.risks.append(
                "DB manager is NOT PROTECTED (no master password set - create/duplicate/remove/backup/restore work without a password)"
            )
        elif client_rendered and not pw_ui:
            state, note = "not_set", (
                "manager is OPEN and client-rendered with NO master-password field exposed "
                "-> likely NO master password set (create/duplicate/remove/backup/restore without password)"
            )
            self.risks.append("DB manager OPEN with NO master password set (create/duplicate/remove/backup/restore without password)")
        elif present_any:
            state, note = "present", "master-password prompt present - password IS set (must be known to confirm ops)"
        elif pw_ui:
            state, note = "present", "master-password UI present (field/button exposed - password is set or settable)"
        else:
            state, note = "unknown", "could not confirm master-password state from page markup"

        self.results["master_password"] = {"state": state, "note": note, "details": details}
        colour = {
            "not_set": "red", "present": "cyan",
            "disabled": "green", "unknown": "yellow",
        }.get(state, "yellow")
        info(f"  {_c(colour, state.upper())}: {note}")

    def _database_posture(self):
        """Cross-check the XML-RPC db.list() state against the manager UI state and
        produce a single high-level 'database posture' + risk for reporting."""
        dl = self.results.get("database_list") or {}
        dl_open = bool(dl.get("open"))
        dl_dbs = list(dl.get("databases") or [])

        endpoints = self.results.get("endpoints") or []
        def _ep_state(ep):
            for e in endpoints:
                if e.get("endpoint") == ep:
                    return e.get("state", ""), e.get("severity", ""), bool(e.get("redirects"))
            return "unknown", "", False
        mgr_state, mgr_sev, mgr_redirect = _ep_state("/web/database/manager")
        sel_state, sel_sev, sel_redirect = _ep_state("/web/database/selector")

        if not dl and mgr_state == "unknown" and sel_state == "unknown":
            return
        title("DATABASE POSTURE (composite)")

        if dl_open and dl_dbs and mgr_state == "open":
            posture = "OPEN_AND_ACCESSIBLE"
            risk = (f"DB manager UI + RPC are both open; {len(dl_dbs)} database(s) exposed: "
                    f"{', '.join(dl_dbs)} - anyone can create/duplicate/remove/backup/restore")
            self.risks.append(risk)
        elif dl_open and dl_dbs and mgr_state == "redirect_hidden":
            posture = "UI_HIDDEN_RPC_OPEN"
            risk = (f"DATABASE LIST is OPEN ({', '.join(dl_dbs)}) even though the manager UI is "
                    "hidden by a redirect - db.list() over XML-RPC exposes all database names "
                    "to anyone who probes it (hidden != protected)")
            self.risks.append(risk)
        elif dl_open and dl_dbs and mgr_state in ("disabled",):
            posture = "RPC_OPEN_UI_DISABLED"
            risk = (f"db.list() returns {len(dl_dbs)} DB(s) ({', '.join(dl_dbs)}) even though the UI says disabled - "
                    "master-password / UI-disable does NOT block RPC enumeration")
            self.risks.append(risk)
        elif not dl_open and mgr_state == "disabled":
            posture = "UI_DISABLED_RPC_DENIED"
            risk = ("manager UI shows 'disabled by administrator' AND db.list() RPC is denied - "
                    "well-protected (both UI and RPC gate). --dblist wordlist can still probe individual DB names")
        elif not dl_open and mgr_state == "redirect_hidden":
            posture = "UI_HIDDEN_RPC_HIDDEN"
            risk = "both UI (redirect) and RPC db.list() hidden - likely well protected; " \
                   "wordlist --dblist can still brute db names"
        elif not dl_open and (mgr_state == "open" or mgr_state == "unknown"):
            posture = "UI_MAYBE_OPEN_RPC_CLOSED"
            risk = "db.list() denied but manager/selector UI may still be reachable - " \
                   "auth-gated or admin-only; still worth probing"
        else:
            posture = "UNKNOWN"
            risk = ""

        self.results["database_posture"] = {
            "posture": posture,
            "rpc_open": dl_open,
            "rpc_databases": dl_dbs,
            "manager_ui_state": mgr_state,
            "selector_ui_state": sel_state,
            "risk": risk,
        }
        info(f"  Posture: {posture}")
        if risk:
            info(f"  {risk}")

    # -----------------------------------------------------------------------
    # 8. Module detection via /website/info
    # -----------------------------------------------------------------------
    def _module_detection(self):
        title("MODULE DETECTION")
        r = self.get("/website/info")
        if r is None:
            warn("  /website/info unreachable.")
            self.results["modules"] = {"open": False, "endpoint_status": None, "state": "unreachable", "modules": [], "oca_modules": []}
            return
        sc = r.status_code
        if sc == 302 or sc == 303 or (300 <= sc < 400):
            info(f"  /website/info -> HTTP {sc} (REDIRECT - hidden behind login)")
            self.results["modules"] = {"open": False, "endpoint_status": sc, "state": "hidden-behind-login", "modules": [], "oca_modules": []}
            return
        if sc != 200:
            warn(f"  /website/info not open (HTTP {sc}) or unreachable.")
            self.results["modules"] = {"open": False, "endpoint_status": sc, "state": "not-open", "modules": [], "oca_modules": []}
            return
        info(f"  /website/info -> HTTP {sc} (OPEN)")

        modules_found = []
        oca_modules: list[str] = []
        try:
            mods = re.findall(r'/app/([\w-]+)', r.text)
            # OCA modules linked on github.com (do-it.md).
            # 3-part form github.com/<org>/<repo>/<module> -> the module (3rd segment).
            oca_3part_repos = set()
            for _org, _repo, _mod in re.findall(r'github\.com/([\w-]+)/([\w-]+)/([\w-]+)', r.text):
                if _mod not in ("org", "repo", "module"):
                    oca_modules.append(_mod)
                oca_3part_repos.add(_repo)
            # 2-part fallback for bare github.com/<org>/<repo> links (skip repos already
            # covered by a 3-part match, which would otherwise be double-counted).
            for _org, _repo in re.findall(r'github\.com/([\w-]+)/([\w-]+)', r.text):
                if _repo in oca_3part_repos or _repo in ("org", "repo", "module"):
                    continue
                if _repo not in oca_modules:
                    oca_modules.append(_repo)
            modules_found = sorted(set(mods) | set(oca_modules))
        except Exception:
            pass

        self.results["modules"] = {"open": True, "endpoint_status": sc, "state": "open", "modules": modules_found, "oca_modules": sorted(set(oca_modules))}

        if modules_found:
            info(f"  Modules detected ({len(modules_found)}):")
            for mod in modules_found:
                info(f"    - {mod}")
            if oca_modules:
                info(f"  OCA modules (github.com/<org>/<module>) detected: {', '.join(sorted(set(oca_modules)))}")
        else:
            warn("  No modules extracted from /website/info.")

    # -----------------------------------------------------------------------
    # 7b. Extra endpoints from do-it.md
    # -----------------------------------------------------------------------
    def _extra_endpoints(self):
        title("EXTRA ENDPOINT PROBES")
        if "endpoints" not in self.results:
            self.results["endpoints"] = []
        eps = [
            ("/my", "My page (employee portal)"),
            ("/web/google_sso", "Google SSO route"),
            ("/auth_oauth/gateway", "OAuth gateway"),
            ("/web/geoip/json", "GeoIP JSON (location disclosure)"),
        ]
        for ep, desc in eps:
            r = self.get(ep)
            entry = {"endpoint": ep, "description": desc, "status": None, "severity": "low", "hints": []}
            if r is None:
                warn(f"  {desc} ({ep}) -> unreachable")
                entry["severity"] = "unreachable"
                entry["hints"].append("unreachable")
                self.results["endpoints"].append(entry)
                continue
            sc = r.status_code
            entry["status"] = sc
            hints = []
            severity = "low"
            if sc == 200:
                hints.append("OPEN")
                if "geoip" in ep:
                    try:
                        jr = r.json()
                        hints.append(f"geoip={json.dumps(jr)}")
                        entry["geoip"] = jr
                    except Exception:
                        pass
                    severity = "medium"
                    self.risks.append("GeoIP data exposed without auth (/web/geoip/json)")
                else:
                    severity = "medium"
                    self.risks.append(f"{ep} accessible without auth (HTTP 200)")
            elif sc in (302, 303):
                hints.append("REDIRECT - hidden behind login")
            elif sc == 403:
                hints.append("FORBIDDEN (protected)")
            elif sc == 404:
                hints.append("NOT FOUND (disabled)")
            else:
                hints.append(f"HTTP {sc}")
            marker = "INFO" if severity == "medium" else ""
            info(f"  {marker} {desc}: {ep} -> {sc} {'; '.join(hints)}")
            entry["severity"] = severity
            entry["hints"] = hints
            self.results["endpoints"].append(entry)

    # -----------------------------------------------------------------------
    # 9. Info leaks
    # -----------------------------------------------------------------------
    def _info_leaks(self):
        title("INFO LEAK PROBES")
        self.results["leaks"] = []
        leaks = [
            ("/web/dataset/call_kw", "call_kw endpoint (RPC endpoint)"),
            ("/web/session/authenticate", "/web/session/authenticate"),
            ("/bus/longpolling/immediate", "bus/longpolling (message queue)"),
            ("/websocket", "WebSocket endpoint"),
        ]
        for ep, desc in leaks:
            r = self.get(ep)
            entry = {"endpoint": ep, "description": desc, "status": None, "flag": "", "traceback_leak": False}
            if r is None:
                warn(f"  {desc} ({ep}) - unreachable")
                self.results["leaks"].append(entry)
                continue
            sc = r.status_code
            entry["status"] = sc
            if sc == 200 and "longpolling" in desc.lower():
                info(f"  {_c('green', 'HIGH')} {desc}: HTTP {sc}")
                entry["flag"] = "longpolling-200"

            content_type = r.headers.get("Content-Type", "")
            if "html" in content_type:
                try:
                    ver_match = re.search(
                        r'<body[^>]*class="odoo"(?:\s+data-odoo-version="([^"]+)")?',
                        r.text, re.I | re.S
                    )
                    if ver_match:
                        info(f"    Version from body: {ver_match.group(1) or 'unknown'}")
                except Exception:
                    pass

            if sc >= 400 and "traceback" in r.text.lower():
                warn(f"  Traceback leak in {desc} (HTTP {sc})")
                entry["traceback_leak"] = True
                entry["flag"] = "traceback"
            self.results["leaks"].append(entry)

        # User enumeration probe at /web/session/authenticate
        info("  Attempting user enumeration compare at /web/session/authenticate ...")
        user_enum = {"status": None, "fake": None, "known": None, "enum": None, "note": ""}
        self.results["user_enum"] = user_enum

        def _auth_probe(login: str) -> dict:
            """Return (status, snippet) for a single fake/known login probe."""
            out = {"status": None, "snippet": ""}
            try:
                post_payload = json.dumps({
                    "jsonrpc": "2.0",
                    "method": "call",
                    "service": "web/session",
                    "params": {"db": "", "login": login, "password": "wrongpass-wrong"},
                    "id": self._next_json_id(),
                }).encode()
                resp = self.session.post(
                    urljoin(self.base, "/web/session/authenticate"),
                    data=post_payload,
                    timeout=self.session.timeout,
                    verify=self.session.verify is not False,
                    headers={"Content-Type": "application/json"},
                )
                out["status"] = resp.status_code
                try:
                    jr = resp.json()
                except Exception:
                    jr = None
                if isinstance(jr, dict):
                    result = jr.get("result")
                    if isinstance(result, dict):
                        out["snippet"] = str(result.get("redirect_url") or "result")
                    elif result is not None:
                        out["snippet"] = str(result)
                    err_body = jr.get("error")
                    if not out["snippet"] and isinstance(err_body, dict):
                        data = err_body.get("data")
                        if isinstance(data, dict):
                            out["snippet"] = str(data.get("message") or "")
                        out["snippet"] = out["snippet"] or str(err_body.get("message") or "")
            except Exception:
                out["status"] = None
            return out

        fake_login = "nouserxxxxyz123fake@example.com"
        known_login = self.user or "admin"  # use --user if provided, else default
        fake = _auth_probe(fake_login)
        known = _auth_probe(known_login)

        user_enum["status"] = fake["status"]
        user_enum["fake"] = fake
        user_enum["known"] = known

        if fake["status"] is None and known["status"] is None:
            user_enum["note"] = "both probes failed (network) - enumeration inconclusive"
        else:
            differs = (fake["status"] != known["status"]) or (fake["snippet"] != known["snippet"])
            if differs:
                user_enum["enum"] = "POSSIBLE USER ENUMERATION (different responses)"
                self.risks.append("Possible user enumeration (login/known respond differently)")
                info(f"  {_c('green', 'ENUM')} fake[{fake['status']}]{fake['snippet']!r} vs known[{known['status']}]{known['snippet']!r}")
            else:
                user_enum["enum"] = "no distinguishable difference (login likely uniform)"
                info(f"  fake and known login return identical responses [{fake['status']}]{fake['snippet']!r} -> weak enumeration signal")
        self.results["user_enum"] = user_enum

        # /phone/index for phone numbers (multi-country: intl +<cc> or domestic 0; any separator style)
        phones = []
        r_phone = self.get("/phone/index")
        if r_phone and r_phone.status_code < 400:
            candidates = re.findall(r'[\+]?\d[\d\s\-()]{6,}\d', r_phone.text)
            cleaned = []
            for cand in candidates:
                digits = re.sub(r'\D', '', cand)
                if 8 <= len(digits) <= 15:
                    cand = cand.strip()
                    if cand and cand not in cleaned:
                        cleaned.append(cand)
            phones.extend(cleaned)
            if cleaned:
                info(f"  Phone numbers found: {', '.join(cleaned)}")
        self.results["phone_numbers"] = phones

        # debug endpoint
        r_debug = self.get("/debug/")
        debug_open = self._status_ok(r_debug)
        if debug_open:
            info("  /debug/ page accessible (unauthenticated)")
            warn("  /debug/ page may leak assets and internal paths - risk!")
            self.risks.append("/debug/ accessible without auth")
        self.results["debug_page"] = {"status": (r_debug.status_code if r_debug else None), "open": debug_open}

    # -----------------------------------------------------------------------
    # 10. Auth endpoints
    # -----------------------------------------------------------------------
    def _auth_endpoints(self):
        title("AUTH & LOGIN ENDPOINTS")
        eps = [
            "/web/login", "/web/auth/", "/web/session/destroy",
            "/auth_oauth/", "/auth_signup/", "/web/settings",
        ]
        for ep in eps:
            r = self.get(ep)
            if r is None:
                warn(f"  {ep} - unreachable")
                continue
            sc = r.status_code
            if sc == 200:
                info(f"  {_c('green', 'OPEN')} {ep} -> HTTP {sc}")
            elif sc < 400:
                info(f"  {ep} -> HTTP {sc}")

        if self.brute:
            self._default_creds()
        else:
            info("  Default-credential probing skipped (pass --brute to enable).")

    def _default_creds(self):
        cred_pairs = [("admin", "admin"), ("admin", "odoo")]
        if self.user:
            cred_pairs.insert(0, (self.user, self.password or ""))
        for login, pw in cred_pairs:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": "call",
                "service": "web/session",
                "params": {"db": "", "login": login, "password": pw},
                "id": "default-creds",
            }).encode()
            try:
                r = self.session.post(
                    urljoin(self.base, "/web/session/authenticate"),
                    data=payload,
                    timeout=self.session.timeout,
                    verify=self.session.verify is not False,
                    headers={"Content-Type": "application/json"},
                )
                jr = r.json() if r.content else {}
                result = jr.get("result", {})
                uid = 0
                name = ""

                if isinstance(result, dict):
                    uid = result.get("uid") or result.get("userid", 0)
                    name = result.get("name", "")

                if uid:
                    info(f"  {_c('green', 'SUCCESS!')} Default creds: {login}/{'*' * len(pw)} -> UID={uid}, name='{name}'")
                    self.risks.append(f"Default admin/odoo credentials still valid -> UID={uid}")
                else:
                    msg = jr.get("error", {}).get("message", "") if isinstance(jr, dict) else ""
                    info(f"  {login}/{'*' * len(pw)} -> {msg[:80] or 'not accepted'}")
            except Exception as e:
                warn(f"  Default creds check for {login} failed: {e}")

    # -----------------------------------------------------------------------
    # 11. Reporting endpoints
    # -----------------------------------------------------------------------
    def _reporting_endpoints(self):
        title("REPORTING ENDPOINT CHECKS")
        rps = [
            "/web/report", "/web/report/html", "/web/report/pdf",
            "/web/content", "/web/report/csv",
        ]
        for rp in rps:
            r = self.get(rp)
            if r is None:
                warn(f"  {rp} - unreachable")
                continue
            sc = r.status_code
            ct = r.headers.get("Content-Type", "")
            cd = r.headers.get("Content-Disposition", "")

            try:
                cl = int(r.headers["Content-Length"])
                info(f"  {rp} -> HTTP {sc}, CT={ct[:60] or 'N/A'}, CD={cd[:60] or 'N/A'} ({cl}b)")
            except (ValueError, KeyError):
                if "Content-Disposition" in r.headers or ct:
                    info(f"  {rp} -> HTTP {sc}, CT={ct[:80] or 'N/A'}, CD={cd[:60] or 'N/A'}")
                else:
                    info(f"  {rp} -> HTTP {sc}")

        # Test /web/content ID leak
        info("  Testing /web/content with arbitrary ID (potential CVE)...")
        try:
            r = self.get("/web/content?&id=1")
            if r and r.status_code == 200:
                warn("  /web/content?id=1 -> HTTP 200 (content accessible without auth)")
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # 12. Longpolling / WebSocket
    # -----------------------------------------------------------------------
    def _longpolling_websocket(self):
        title("LONGPOLLING / WEBSOCKET CHECKS")
        lps = ["/bus/longpolling/immediate", "/websocket", "/bus/longpolling/pop"]
        for ep in lps:
            r = self.get(ep)
            if r is None:
                warn(f"  {ep} - unreachable")
                continue
            sc = r.status_code
            if sc == 202 or (300 <= sc < 400):
                info(f"  {_c('green', 'LONGPOLLING ACTIVE')} {ep}: HTTP {sc}")
            elif sc == 502:
                warn(f"  {ep} -> HTTP {sc} (possible longpolling proxy)")

    # -----------------------------------------------------------------------
    # 13. Edition detection via XML-RPC extras
    # -----------------------------------------------------------------------
    def _edition_detection(self):
        title("EDITION DETECTION")
        data = self.xmlrpc_call("/xmlrpc/2/common", "version")
        if isinstance(data, dict):
            serie = data.get("server_serie") or ""
            pv = data.get("protocol_version") or ""

            info(f"  server_serie: {serie}")
            info(f"  protocol_version: {pv}")
            self.results["edition"] = {"server_serie": serie, "protocol_version": pv}

    # -----------------------------------------------------------------------
    # 14. Risk summary / print-out
    # -----------------------------------------------------------------------
    def _risk_summary(self):
        title("RISK SUMMARY")

        risk_items = []
        if self.version_detected:
            info(f"  ODOO VERSION: {_c('green', self.version_detected)}")

        for r in self.risks:
            m = re.search(r'Odoo (\d+\.\d+)', r)
            if not m:
                risk_items.append(r)

        if self.risks:
            info(f"  Findings ({len(risk_items)})")
            for ri in risk_items:
                color = "yellow" if "EOL" in ri else "cyan"
                info(f"    {_c(color, '*')} {ri}")
        else:
            info("  No significant risks found.")

        self.results["is_odoo"] = self.is_odoo
        self.results["version"]["detected"] = self.version_detected
        self.results["risks"] = list(self.risks)
        self.results["summary"] = {
            "version": self.version_detected,
            "risks": risk_items,
            "is_odoo": self.is_odoo,
        }


# ===========================================================================
# Google dork helper (optional)
# ===========================================================================
def run_dorks(target_host: str, limit: int = 10, delay: float = DORKS_DELAY):
    """Run basic Google dorks for a given domain / target host."""
    title(f"GOOGLE DORKS - {target_host}")
    dorks = [
        f'site:{target_host} "odoo"',
        f'site:{target_host} "/web/database/selector"',
        f'site:{target_host} "/web/database/manager"',
        f'site:{target_host} "/website/info" odoo',
        f'site:{target_host} inurl:("/my" "/web/login")',
    ]

    try:
        from googlesearch import search as _google_search  # type: ignore
    except ImportError:
        warn("'googlesearch' module not installed (pip install googlesearch-python) - dorking skipped.")
        return []

    found_urls: list[str] = []
    for dork in dorks:
        info(f"  Dork: {dork}")
        try:
            results = list(_google_search(dork, num_results=limit, sleep_interval=max(0.5, min(delay, 2.0))))
            for u in results:
                info(f"    -> {u}")
                found_urls.append(u)
        except Exception as e:
            warn(f"  Dork query failed: {e}")
        if delay > 0:
            time.sleep(delay)

    title(f"DORK RESULTS - Found {len(found_urls)} URLs")
    for url in found_urls:
        info(url)

    return found_urls


# Default cap on how many unique hosts we dork (avoids exploding a large sites.txt)
_DORK_HOST_CAP = 10


def run_dorks_hosts(hosts: list[str], limit: int = 10, delay: float = DORKS_DELAY) -> dict[str, list[str]]:
    """Dork each unique hostname (capped at _DORK_HOST_CAP) and return {host: urls}."""
    seen: list[str] = []
    for h in hosts:
        h = (h or "").strip()
        if h and h not in seen:
            seen.append(h)
    if not seen:
        return {}
    if len(seen) > _DORK_HOST_CAP:
        info(f"  Capping dork hosts at {_DORK_HOST_CAP} (got {len(seen)})")
        seen = seen[:_DORK_HOST_CAP]
    out: dict[str, list[str]] = {}
    for host in seen:
        out[host] = run_dorks(host, limit=limit, delay=delay)
    return out


# ===========================================================================
# Argparse CLI + orchestrator
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon-odoo.py",
        description="The Odoo Reconnaissance Tool - v0.3",
        epilog=(
            "Examples:\n"
            "  %(prog)s -t https://example.com\n"
            "  %(prog)s --targets ./sites.txt --brute --json\n"
            "  %(prog)s -t https://odoo.example.com -p 8069 --dorks\n"
            "\n"
            "Exit codes:\n"
            "  0 = all targets reachable\n"
            "  1 = one or more targets unreachable / partial scan\n"
            "  2 = usage error (bad args, missing targets file, no valid targets)\n"
            "\n"
            "Credits:\n"
            "  Author:  Jan van de Rijt (c)2026\n"
            "  License: GNU GPL v3 or later (see ./LICENSE)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = p.add_argument_group("target")
    group.add_argument("-t", "--target", help="Single target URL or host")
    group.add_argument("--targets", help="File with targets (one per line)")

    group2 = p.add_argument_group("networking")
    group2.add_argument("--port", "-P", type=int, default=None, help="Custom port")
    group2.add_argument("--scheme", choices=["http", "https"], help="Force scheme (overrides URL)")
    group2.add_argument("-k", "--insecure", action="store_true", help="Skip TLS certificate verification")
    group2.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    group2.add_argument("--user-agent", "-A", help="Custom User-Agent string")

    group3 = p.add_argument_group("features")
    group3.add_argument("--brute", action="store_true", help="Check default credentials (admin/admin, admin/odoo)")
    group3.add_argument("--user", help="Username for authenticated probes (user enumeration known-login, --brute pair)")
    group3.add_argument("--password", help="Password for authenticated probes (used with --user)")
    group3.add_argument("--dorks", action="store_true", help="Run Google dork search for the target domain")
    group3.add_argument("--dorks-delay", type=float, metavar="SECS", default=1.0, help="Delay between dork queries in seconds (default: 1.0)")
    group3.add_argument("-j", "--json", action="store_true", dest="json_out", help="Output results as JSON to stdout")
    group3.add_argument("-o", "--output", metavar="FILE", help="Write JSON results to FILE (implies JSON output; progress still prints to stderr). "
        "The full results bundle is written at the end - use this for report export.")
    group3.add_argument("--no-version-checks", action="store_true", help="Skip version detection probes")
    group3.add_argument("--dblist", nargs="+", metavar="NAME", help="DB-name wordlist (space-separated) to probe against db.status (read-only)")

    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    return p


def _resolve_target(raw: str, port_override: int | None = None, scheme_override: str | None = None) -> str:
    """Normalise a single target string (URL or bare host) into a valid URL,
    applying optional port/scheme overrides."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target")

    # Ensure a scheme for parsing; remember the default we added
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw

    parsed = urlparse(raw)
    host = parsed.hostname or parsed.netloc
    if not host:
        raise ValueError(f"No host in target {raw!r}")

    scheme = (scheme_override or parsed.scheme or "https").lower()
    port = port_override if port_override is not None else parsed.port
    netloc = f"{host}:{port}" if port is not None else host
    return f"{scheme}://{netloc}"


def main(argv: list[str] | None = None) -> int:
    global QUIET, DORKS_DELAY
    parser = build_parser()
    args = parser.parse_args(argv)
    DORKS_DELAY = args.dorks_delay

    if not args.target and not args.targets:
        parser.error("Either -t/--target or --targets is required")

    if args.json_out:
        QUIET = True

    sb = SessionBuilder(
        timeout=args.timeout,
        ssl_verify=not args.insecure,
        user_agent=args.user_agent,
    )

    results_bundle: dict = {}
    raw_targets: list[str] = []

    if args.target:
        raw_targets.append(args.target)
    elif args.targets:
        tp = Path(args.targets)
        if not tp.exists():
            err(f"Targets file {args.targets} does NOT exist.")
            return 2
        raw_targets = [l.strip() for l in tp.read_text().splitlines() if l.strip() and not l.startswith("#")]

    if not raw_targets:
        err("No valid targets found.")
        return 2

    targets: list[str] = []
    for raw in raw_targets:
        try:
            targets.append(_resolve_target(raw, port_override=args.port, scheme_override=args.scheme))
        except ValueError as e:
            err(f"Skipping target {raw!r}: {e}")

    if not targets:
        err("No valid targets found.")
        return 2

    title("RECON-ODOO - The Odoo Reconnaissance Tool")
    info(f"Targets: {len(targets)} | Brute: {bool(args.brute)} | Dorks: {bool(args.dorks)} | JSON: {args.json_out}")

    unreachable: list[str] = []
    for target in targets:
        title(f"SCANNING: {target}")
        try:
            scanner = OdooRecon(target, sb, brute=args.brute, no_version_checks=args.no_version_checks, verbose=args.verbose, user=args.user, password=args.password, dblist=args.dblist)
            scanner.run_all()
            results_bundle[target] = scanner.results
        except KeyboardInterrupt:
            raise
        except Exception as e:
            err(f"  Scan of {target} raised: {e!r}")
            warn(f"  Continuing with remaining targets...")
            results_bundle[target] = {
                "target": target,
                "is_odoo": False,
                "version": {"detected": "", "candidates": [], "sources": {}, "skipped": args.no_version_checks},
                "connectivity": {"reachable": False, "status": None, "server": None, "ip": None},
                "risks": [f"scan raised: {e!r}"],
                "error": repr(e),
            }
        conn = results_bundle[target].get("connectivity") or {}
        if not conn.get("reachable"):
            unreachable.append(target)

    if args.dorks and targets:
        hosts = []
        for t in targets:
            host = urlparse(t).hostname or t
            if host and host not in hosts:
                hosts.append(host)
        run_dorks_hosts(hosts, delay=args.dorks_delay)

    results_bundle["_exit_meta"] = {
        "unreachable": unreachable, "total": len(targets),
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "recon-odoo.py v0.3",
    }

    # Export the full results bundle to a JSON file when -o/--output is given.
    if args.output:
        try:
            out_path = Path(args.output).expanduser().resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("w", encoding="utf-8") as fh:
                json.dump(results_bundle, fh, indent=2, default=str)
            if not QUIET:
                print(_c("green", f"  [+] JSON results written to {out_path}"))
        except Exception as e:
            err(f"  Failed to write JSON to {args.output!r}: {e!r}")

    if args.json_out:
        json.dump(results_bundle, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")

    if not args.json_out:
        title("DONE - All targets scanned.")
        if unreachable:
            err(f"{len(unreachable)}/{len(targets)} target(s) unreachable - exit 1")
    return 1 if unreachable else 0


if __name__ == "__main__":
    sys.exit(main())
