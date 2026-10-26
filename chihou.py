#!/usr/bin/env python3
"""
chihou.py  —  斥候 (Chìhòu), "the scout"
========================================
Red-team counterpart to 烽火 (fenghuo.py). Where 烽火 watches the KEV feed for
bugs exploited in the wild against your stack, 斥候 walks out to your own wall
and reports what an attacker SEES when they look at it: the HTTP-layer exposure
and misconfiguration surface the existing eyes (DNS, TCP banners, certs) don't
cover.

It is a POSTURE AUDITOR, not a weapon. Every request is a plain GET / HEAD /
OPTIONS. It fingerprints, it reads, it ranks — it does not fuzz, inject, brute,
or exploit. There is no payload in this file and there never will be. Validate
exposures here, then drive the fix; run actual exploitation through established
tooling you operate (Metasploit, Burp, nuclei), not through this.

Pythonista / iOS friendly: standard library only (http.client, ssl, socket).

HOW TO RUN
  • Just tap ▶ Run with no arguments → an interactive MENU opens in the console.
    Pick a number. No Arguments field, no CLI knowledge needed.
  • Power/automation path (unchanged): pass args.
        python chihou.py --all            # sweep all owned hosts, markdown
        python chihou.py --all --json     # structured, for the vault pipeline
        python chihou.py example.com       # one host

SCOPE IS HARD-WIRED. The tool refuses any target that does not match the
owned-asset allowlist below — including a host you type into the menu. The
allowlist mirrors `Owned Assets.md` and is maintained by the operator; 斥候 does
not infer ownership and does not add targets. Off the list = OUT OF SCOPE, and
not one packet is sent to it.

AUTHORIZED SELF-ASSESSMENT ONLY. Point it at infrastructure you own.
"""

import re
import sys
import ssl
import json
import http.client

# ======================================================================
# SCOPE — mirrors Owned Assets.md (operator-maintained). Keep in sync.
# ======================================================================
# Owned apex zones: you own the zone/DNS, so any host under them is in scope
# at the HTTP-config layer. (Suffix match, mirroring recon_orchestrator._in_scope.)
OWNED_ZONES = (
    # >>> EDIT THESE. Your own apex zones only. Everything else is refused. <<<
    "example.com",
    "example.org",
)

# Named hosts actually served, used by --all and the menu. Each under an OWNED_ZONE.
DEFAULT_TARGETS = (
    # >>> EDIT THESE. The specific hosts --all / the menu will sweep. <<<
    # Each MUST fall under an OWNED_ZONE above.
    "example.com",
    "www.example.com",
    "api.example.com",
)

# Registry caveat carried into the report, not a scope grant:
#   The Cloudflare EDGE is NOT yours. 斥候 audits YOUR config as reflected in the
#   served response (headers, redirects, cookies, exposed paths). It does not and
#   must not stress-test Cloudflare's network. Header findings are config findings.
EDGE_CAVEAT = ("Responses are served through the Cloudflare edge; findings reflect "
               "your origin+edge CONFIG, which is in scope. The edge hardware is not.")

USER_AGENT = "chihou/1.0 (authorized owned-asset self-audit)"
TIMEOUT = 6.0

# ---- What a hardened edge should assert (header -> why it matters) ----
EXPECTED_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS — force HTTPS, block SSL-strip downgrade",
    "content-security-policy":   "CSP — constrain script/frame origins (XSS/clickjacking)",
    "x-content-type-options":    "nosniff — stop MIME-confusion script execution",
    "x-frame-options":           "framing control (clickjacking) — or CSP frame-ancestors",
    "referrer-policy":           "trim referrer leakage of internal URLs",
    "permissions-policy":        "disable unused browser features (camera/mic/geo)",
}
# ---- Headers that hand an attacker a free fingerprint ----
LEAKY_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "via", "x-backend-server", "x-served-by", "x-runtime",
)
# ---- Read-only path probes. Benign paths are informational, never flagged. ----
BENIGN_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
SENSITIVE_PATHS = (
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
    "/config.json", "/secrets.json", "/server-status", "/.DS_Store",
    "/.htaccess", "/.htpasswd", "/backup.zip", "/backup.sql", "/db.sql",
    "/dump.sql", "/.npmrc", "/wp-config.php", "/phpinfo.php", "/review",
)
# Edge-set cookies we do NOT own and cannot fix (Cloudflare Access / CDN).
# Flagging these is noise — the operator doesn't set their flags.
EDGE_COOKIE_PREFIXES = ("cf_", "__cf", "__secure-cf", "cf-")

# ---- Content predicates: does the body ACTUALLY look like the file? ----
# v1.2 fix: the old substring signatures ('=', ':') matched any HTML page, so a
# Cloudflare catch-all 200 read as an exposed .env/.htpasswd. These predicates
# require the real structure AND reject anything containing HTML tags.
def _has_html(body):
    head = body[:600].lower()
    return ("<html" in head) or ("<!doctype" in head) or ("<head" in head) or ("<body" in head)

def _is_dotenv(body):
    if _has_html(body):
        return False
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(export\s+)?[A-Za-z_][A-Za-z0-9_]*=", line):
            return True
    return False

def _is_htpasswd(body):
    if _has_html(body):
        return False
    for line in body.splitlines():
        line = line.strip()
        # user:$apr1$… / user:$2y$… / user:{SHA}… / user:<13-char crypt>
        if re.match(r"^[^:\s]+:(\$[16a-z]|\{SHA\}|[A-Za-z0-9./]{13}$)", line):
            return True
    return False

def _is_git_head(body):
    head = body.strip()
    if head.startswith("ref:"):
        return True
    h = head[:40]
    return len(h) == 40 and all(c in "0123456789abcdef" for c in h.lower())

def _is_git_config(body):
    return any(s in body for s in ("[core]", "[remote ", "[branch "))

def _is_server_status(body):
    # Apache mod_status is HTML, so this one is allowed to contain tags.
    return "Apache Server Status" in body or "Server Version:" in body

PATH_PREDICATES = {
    "/.git/HEAD": _is_git_head,
    "/.git/config": _is_git_config,
    "/.env": _is_dotenv,
    "/.env.local": _is_dotenv,
    "/.env.production": _is_dotenv,
    "/.htpasswd": _is_htpasswd,
    "/server-status": _is_server_status,
}


# ======================================================================
# Scope gate
# ======================================================================
def in_scope(host):
    """
    Returns (ok: bool, note: str). ok=False means DO NOT TOUCH.
    Suffix-matches the owned apex zones. Anything else is out of scope.
    """
    h = host.strip().lower().rstrip(".")
    if not h:
        return (False, "empty host")
    for zone in OWNED_ZONES:
        if h == zone or h.endswith("." + zone):
            return (True, f"in scope — under owned zone {zone}")
    return (False, f"NOT in Owned Assets registry (no owned zone matches '{h}')")


# ======================================================================
# Transport — one place, two TLS paths (verified, then unverified fallback)
# ======================================================================
def _request(host, path, method="GET", scheme="https", read_bytes=600):
    """
    Single request. Never follows redirects (we want the first response's
    headers). Returns a structured dict; a failure is a reported failure,
    never a silent empty.
    """
    out = {
        "scheme": scheme, "method": method, "path": path,
        "reachable": False, "tls_verified": None, "status": None,
        "reason": None, "headers": [], "set_cookie": [], "body_head": "",
        "error": None,
    }
    port = 443 if scheme == "https" else 80

    def _do(ctx):
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
        try:
            conn.request(method, path, headers={"Host": host, "User-Agent": USER_AGENT,
                                                "Accept": "*/*", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(read_bytes) if method == "GET" else b""
            hdrs = resp.getheaders()
            return resp.status, resp.reason, hdrs, body
        finally:
            conn.close()

    # Path 1: verified TLS (or plain HTTP)
    try:
        ctx = ssl.create_default_context() if scheme == "https" else None
        status, reason, hdrs, body = _do(ctx)
        out.update(reachable=True, tls_verified=(True if scheme == "https" else None),
                   status=status, reason=reason)
        _split_headers(out, hdrs)
        out["body_head"] = body.decode("utf-8", "replace")
        return out
    except ssl.SSLError as e:
        out["error"] = f"tls_verify_failed: {type(e).__name__}"
    except (OSError, http.client.HTTPException) as e:
        out["error"] = type(e).__name__
        return out

    # Path 2: unverified fallback — a broken cert still yields headers to read
    try:
        ctx = ssl._create_unverified_context()
        status, reason, hdrs, body = _do(ctx)
        out.update(reachable=True, tls_verified=False, status=status, reason=reason)
        _split_headers(out, hdrs)
        out["body_head"] = body.decode("utf-8", "replace")
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        out["error"] = (out["error"] or "") + f" | {type(e).__name__}"
    return out


def _split_headers(out, hdrs):
    """Lowercase header dict, but keep every Set-Cookie separately."""
    seen = {}
    for k, v in hdrs:
        lk = k.lower()
        if lk == "set-cookie":
            out["set_cookie"].append(v)
        else:
            seen[lk] = v
    out["headers"] = seen


def _finding(sev, fid, title, evidence, fix):
    return {"severity": sev, "id": fid, "title": title, "evidence": evidence, "fix": fix}


# ======================================================================
# Audit modules — each returns a list of findings, each citing its evidence
# ======================================================================
def audit_security_headers(resp):
    f = []
    h = resp["headers"]
    for name, why in EXPECTED_SECURITY_HEADERS.items():
        if name not in h:
            # X-Frame-Options is satisfied by CSP frame-ancestors
            if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
                continue
            sev = "MED" if name in ("content-security-policy", "x-content-type-options",
                                    "strict-transport-security") else "LOW"
            f.append(_finding(sev, "hdr-missing",
                              f"Missing {name}", f"header absent on {resp['scheme']}://…{resp['path']}", why))
    # HSTS value sanity
    hsts = h.get("strict-transport-security", "")
    if hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0])
            if age < 15552000:
                f.append(_finding("LOW", "hsts-short", "HSTS max-age under 180d",
                                  f"max-age={age}", "raise to >=15552000 and add includeSubDomains"))
        except (IndexError, ValueError):
            f.append(_finding("LOW", "hsts-malformed", "HSTS header malformed", hsts[:80],
                              "fix max-age directive"))
    return f


def audit_leaky_headers(resp):
    f = []
    for name in LEAKY_HEADERS:
        val = resp["headers"].get(name)
        if not val:
            continue
        # A bare 'server: cloudflare' is edge noise, not an origin leak.
        if name == "server" and val.strip().lower() in ("cloudflare", "cloudflare-nginx"):
            continue
        has_version = any(c.isdigit() for c in val)
        sev = "MED" if has_version else "INFO"
        f.append(_finding(sev, "hdr-leak", f"Fingerprintable header: {name}",
                          f"{name}: {val[:80]}",
                          "strip or genericize the header at the edge/origin"))
    return f


def audit_cookies(resp):
    f = []
    for c in resp["set_cookie"]:
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        if name.lower().startswith(EDGE_COOKIE_PREFIXES):
            continue  # edge-owned (Cloudflare) — not our config to fix
        missing = [a for a in ("secure", "httponly") if a not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            f.append(_finding("MED", "cookie-flags", f"Cookie '{name}' missing {', '.join(missing)}",
                              c[:90], "set Secure; HttpOnly; SameSite=Lax/Strict as applicable"))
    return f


def audit_https_redirect(host):
    """Plain HTTP must redirect to HTTPS. A 200 over :80 is a downgrade window."""
    r = _request(host, "/", method="GET", scheme="http")
    if not r["reachable"]:
        return ([], r)  # port 80 closed is fine (CF usually redirects; note it)
    loc = r["headers"].get("location", "")
    if r["status"] in (301, 302, 307, 308) and loc.lower().startswith("https://"):
        return ([], r)  # correct
    if r["status"] and r["status"] < 400:
        return ([_finding("MED", "no-https-redirect", "Plain HTTP not forced to HTTPS",
                          f"http://{host}/ -> {r['status']} {r['reason']} (location: {loc or 'none'})",
                          "enable Always Use HTTPS / 308 redirect at the edge")], r)
    return ([], r)


def audit_methods(host):
    r = _request(host, "/", method="OPTIONS")
    if not r["reachable"]:
        return ([], r)
    allow = r["headers"].get("allow", "")
    f = []
    risky = [m for m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH")
             if m in allow.upper()]
    if risky:
        f.append(_finding("MED", "risky-methods", f"Risky HTTP methods advertised: {', '.join(risky)}",
                          f"Allow: {allow}", "disable write/trace methods at the edge"))
    return (f, r)


def _looks_real(path, resp, baseline):
    """
    Distinguish a REAL exposed file from a 200 soft-404 catch-all page.
    Returns (is_real: bool, why: str).

    Order matters (v1.2): the soft-404 baseline gate runs FIRST, then a content
    predicate, then — for paths with no predicate — a non-HTML requirement. The
    old version ran weak substring signatures first and short-circuited the
    baseline guard, so a catch-all 200 read as an exposed secret.
    """
    if resp["status"] != 200:
        return (False, "")
    body = resp["body_head"]
    ctype = resp["headers"].get("content-type", "").lower()

    # 1) Soft-404 gate. Same shape as the known not-found page → not a real file.
    if baseline and baseline["status"] == 200:
        same_type = resp["headers"].get("content-type") == baseline["headers"].get("content-type")
        same_len = resp["headers"].get("content-length") == baseline["headers"].get("content-length")
        if same_type and (same_len or not resp["headers"].get("content-length")):
            return (False, "matches soft-404 baseline (catch-all page)")

    # 2) Known path → trust its content predicate (works even for HTML like server-status).
    pred = PATH_PREDICATES.get(path)
    if pred is not None:
        if pred(body):
            return (True, f"content matches {path} structure")
        return (False, "200 but body is not that file (catch-all/placeholder)")

    # 3) Unknown sensitive path that survived the baseline gate: a real exposed
    #    file is not served as the HTML catch-all. Require non-HTML to call it real.
    if _has_html(body) or "html" in ctype:
        return (False, "html catch-all, not a served file")
    return (True, f"non-HTML 200 (content-type={ctype or '?'}), distinct from soft-404")


def audit_paths(host):
    f = []
    notes = []
    # Learn the soft-404 signature first: a path that should NOT exist.
    baseline = _request(host, "/chihou-nonexistent-a7f3e9", method="GET")

    for p in BENIGN_PATHS:
        r = _request(host, p, method="GET")
        if r["reachable"] and r["status"] == 200:
            notes.append(f"{p} -> 200 (expected/benign)")

    for p in SENSITIVE_PATHS:
        r = _request(host, p, method="GET")
        if not r["reachable"]:
            continue
        real, why = _looks_real(p, r, baseline)
        if real:
            # /review is Access/token-gated by design — a 200 there is the finding.
            sev = "HIGH"
            f.append(_finding(sev, "path-exposed", f"Reachable sensitive path: {p}",
                              f"GET {p} -> {r['status']} ({why}); "
                              f"len={r['headers'].get('content-length','?')}",
                              "block the path at the edge / remove from webroot / require auth"))
        elif r["status"] in (401, 403):
            notes.append(f"{p} -> {r['status']} (gated — good)")
    return (f, notes, baseline)


# ======================================================================
# Orchestration
# ======================================================================
SEV_RANK = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3}


def scout(host):
    ok, scope_note = in_scope(host)
    rec = {"host": host, "in_scope": ok, "scope_note": scope_note,
           "reachable": False, "findings": [], "notes": [], "edge_caveat": EDGE_CAVEAT}
    if not ok:
        return rec

    root = _request(host, "/", method="GET")
    rec["reachable"] = root["reachable"]
    rec["status"] = root["status"]
    rec["tls_verified"] = root["tls_verified"]
    if not root["reachable"]:
        rec["notes"].append(f"root unreachable: {root['error']}")
        return rec

    if root["tls_verified"] is False:
        rec["findings"].append(_finding("HIGH", "tls-unverified",
            "TLS certificate did not verify", f"handshake to {host}:443 failed CA validation",
            "fix cert chain/hostname (cross-check cert_inspector.py)"))

    # Behind Cloudflare Access? — auth wall is expected, not a bug.
    server = root["headers"].get("server", "").lower()
    if root["status"] in (302, 403) and ("cloudflare" in server or "location" in root["headers"]):
        loc = root["headers"].get("location", "")
        if "cloudflareaccess.com" in loc or "access" in loc.lower():
            rec["notes"].append("fronted by Cloudflare Access (auth wall) — header/path audit limited, expected")

    rec["findings"] += audit_security_headers(root)
    rec["findings"] += audit_leaky_headers(root)
    rec["findings"] += audit_cookies(root)

    mf, _ = audit_methods(host); rec["findings"] += mf
    rf, _ = audit_https_redirect(host); rec["findings"] += rf
    pf, pnotes, _ = audit_paths(host); rec["findings"] += pf; rec["notes"] += pnotes

    rec["findings"].sort(key=lambda x: SEV_RANK.get(x["severity"], 9))
    rec["severity_counts"] = {s: sum(1 for f in rec["findings"] if f["severity"] == s)
                              for s in ("HIGH", "MED", "LOW", "INFO")}
    return rec


def summarize(report):
    """Obsidian-friendly digest (matches recon_orchestrator.summarize)."""
    lines = ["# 斥候 scout: owned HTTP surface", ""]
    for rec in report["hosts"]:
        if not rec["in_scope"]:
            lines.append(f"## {rec['host']}  — OUT OF SCOPE")
            lines.append(f"   {rec['scope_note']} — refused, not probed.")
            lines.append("")
            continue
        if not rec["reachable"]:
            lines.append(f"## {rec['host']}  — UNREACHABLE")
            lines.append(f"   {'; '.join(rec['notes']) or 'no response'}")
            lines.append("")
            continue
        sc = rec.get("severity_counts", {})
        tls = {True: "verified", False: "UNVERIFIED", None: "n/a"}[rec["tls_verified"]]
        lines.append(f"## {rec['host']}  (HTTP {rec['status']}, TLS {tls})")
        lines.append(f"   HIGH {sc.get('HIGH',0)} | MED {sc.get('MED',0)} | "
                     f"LOW {sc.get('LOW',0)} | INFO {sc.get('INFO',0)}")
        for fnd in rec["findings"]:
            lines.append(f"   [{fnd['severity']}] {fnd['title']}")
            lines.append(f"         evidence: {fnd['evidence']}")
            lines.append(f"         fix:      {fnd['fix']}")
        for n in rec["notes"]:
            lines.append(f"   · {n}")
        lines.append("")
    lines.append(f"> scope: Owned Assets registry. {report['edge_caveat']}")
    return "\n".join(lines)


def run_targets(targets, want_json=False):
    """Scout each target and print the report. Returns the report dict."""
    report = {"hosts": [scout(h) for h in targets], "edge_caveat": EDGE_CAVEAT}
    print()
    print(json.dumps(report, indent=2) if want_json else summarize(report))
    return report


# ======================================================================
# Interactive menu — the default when run with no arguments (Pythonista-friendly)
# ======================================================================
def _prompt(msg):
    """input() that treats EOF / Ctrl-C as 'quit' instead of crashing."""
    try:
        return input(msg).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "q"


def menu():
    fmt_json = False
    while True:
        print()
        print("=" * 52)
        print(" 斥候 (Chìhòu) — owned-surface HTTP posture scout")
        print(" owned zones : " + ", ".join(OWNED_ZONES))
        print(" output      : " + ("JSON" if fmt_json else "markdown"))
        print("-" * 52)
        print("  1) Scan ALL owned hosts")
        print("  2) Scan ONE owned host (pick from list)")
        print("  3) Scan a CUSTOM host (scope-gated — refuses if off-list)")
        print("  4) Toggle output format (markdown / JSON)")
        print("  5) Quit")
        print("=" * 52)
        choice = _prompt("select> ").lower()

        if choice == "1":
            print(f"\n[*] scanning {len(DEFAULT_TARGETS)} owned hosts — a few seconds…")
            run_targets(list(DEFAULT_TARGETS), fmt_json)
        elif choice == "2":
            for i, h in enumerate(DEFAULT_TARGETS, 1):
                print(f"  {i}) {h}")
            sel = _prompt("host #> ")
            if sel.isdigit() and 1 <= int(sel) <= len(DEFAULT_TARGETS):
                host = DEFAULT_TARGETS[int(sel) - 1]
                print(f"\n[*] scanning {host}…")
                run_targets([host], fmt_json)
            else:
                print("  ! not a listed number")
        elif choice == "3":
            host = _prompt("host> ")
            if not host:
                print("  ! no host entered")
                continue
            ok, note = in_scope(host)
            if not ok:
                print(f"  ✗ OUT OF SCOPE — {note}. Not probed.")
            else:
                print(f"\n[*] {note} — scanning {host}…")
                run_targets([host], fmt_json)
        elif choice == "4":
            fmt_json = not fmt_json
            print("  output now: " + ("JSON" if fmt_json else "markdown"))
        elif choice in ("5", "q", "quit", "exit"):
            print("斥候 stood down.")
            return
        else:
            print("  ! pick 1–5")


# ======================================================================
# Entry point — no args → menu; args → one-shot CLI (automation/vault pipeline)
# ======================================================================
def main():
    argv = sys.argv[1:]
    if not argv:
        menu()
        return

    want_json = "--json" in argv
    if "--all" in argv:
        targets = list(DEFAULT_TARGETS)
    else:
        targets = [a for a in argv if not a.startswith("--")]

    if not targets:
        print("No host given. Run with no arguments for the menu, "
              "or pass a host / --all [--json].")
        return
    run_targets(targets, want_json)


if __name__ == "__main__":
    main()
