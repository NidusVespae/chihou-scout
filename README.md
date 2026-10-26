# 斥候 (Chìhòu) — owned-surface HTTP posture scout

> **斥候** — the scout of an ancient Chinese army: the rider sent ahead of the
> column to observe the ground and report back. 斥 = *to probe, to survey*; 候 =
> *to watch, to keep lookout*. This tool is the counterpart to a KEV beacon: where
> that one waits and raises the alarm, 斥候 walks out to **your own** wall and
> reports what an attacker sees when they look at it.

A single-file, standard-library-only HTTP posture auditor for **infrastructure you
own**. It fingerprints the response surface — security headers, header leakage,
cookie flags, HTTPS redirect, risky methods, exposed sensitive paths — ranks every
finding by severity with its evidence and a fix, and prints vault-ready markdown or
JSON.

Runs anywhere Python 3 runs, including **Pythonista on iOS** (no third-party deps).

---

## It is a posture auditor, not a weapon

Every request is a plain `GET` / `HEAD` / `OPTIONS`. 斥候 **fingerprints, reads, and
ranks** — it does **not** fuzz, inject, brute-force, or exploit. There is no payload
in this file and there never will be. Validate exposures here, then drive the fix;
run actual exploitation through tooling built for it (Metasploit, Burp, nuclei) —
against targets you are authorized to test.

## Scope is hard-wired

The tool refuses any target that does not match the `OWNED_ZONES` allowlist at the
top of the file — **including a host you type into the menu**. A target off the list
is not "probably fine"; it is out of scope and **not one packet is sent to it**.

**This is the whole discipline.** Before you run it, edit `OWNED_ZONES` and
`DEFAULT_TARGETS` to **your own** domains. Do not point it at anything you do not
own and are not authorized to assess. The author is not responsible for misuse.

```python
OWNED_ZONES = (
    "example.com",
    "example.org",
)
```

Matching is suffix-based (an apex and anything under it), case-insensitive, and
trailing-dot tolerant — so `blog.example.com` is in scope under `example.com`, while
a lookalike like `example.com.attacker.net` is refused.

---

## Usage

```bash
# No arguments → interactive menu (easiest; great on mobile)
python chihou.py

# Or one-shot CLI (for automation / a vault pipeline)
python chihou.py --all            # sweep every host in DEFAULT_TARGETS (markdown)
python chihou.py --all --json     # same, structured JSON
python chihou.py example.com      # one host (still scope-gated)
```

The menu:

```
1) Scan ALL owned hosts
2) Scan ONE owned host (pick from list)
3) Scan a CUSTOM host (scope-gated — refuses if off-list)
4) Toggle output format (markdown / JSON)
5) Quit
```

### Pythonista (iOS)

Drop `chihou.py` in, tap ▶ Run → the menu opens in the console. No Arguments field
needed.

---

## What it checks

| Check | Flags |
|---|---|
| Security headers | missing HSTS / CSP / `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy` / `Permissions-Policy`; short/malformed HSTS |
| Header leakage | version-bearing `Server` / `X-Powered-By` / `X-AspNet-Version` / … |
| Cookies | `Set-Cookie` missing `Secure` / `HttpOnly` / `SameSite` (CDN-owned cookies skipped) |
| Transport | plain HTTP not forced to HTTPS; TLS cert that fails verification |
| Methods | risky verbs advertised via `OPTIONS` (`TRACE`, `PUT`, `DELETE`, …) |
| Exposed paths | reachable `/.git/HEAD`, `/.env*`, `/.htpasswd`, `/server-status`, backups, etc. |

### No crying wolf

Static sites and SPAs often return `200` for *everything* (a catch-all page). A
naive scanner reads that as a dozen exposed secrets. 斥候 learns each host's
**soft-404 signature** first (fetches a path that cannot exist), then only flags a
sensitive path when the response is genuinely distinct **and** its body actually
looks like the file in question (a real `.env` has `KEY=VALUE` lines and no HTML; a
real `.git/HEAD` has a ref or an object hash). A finding you can't trust is worse
than no finding.

---

## Output

Severity-ranked (`HIGH` → `INFO`), each finding carrying its **evidence** and a
**fix**, as markdown (drop straight into notes) or JSON (for a pipeline). Example:

```
## example.com  (HTTP 200, TLS verified)
   HIGH 0 | MED 1 | LOW 2 | INFO 0
   [MED] Missing content-security-policy
         evidence: header absent on https://…/
         fix:      CSP — constrain script/frame origins (XSS/clickjacking)
   · /robots.txt -> 200 (expected/benign)
   · /.git/config -> 403 (gated — good)
```

---

## A note on CDNs / edge providers

If your site sits behind a CDN (Cloudflare, etc.), the response headers reflect your
**origin + edge configuration**, which is yours to fix — but the edge *hardware* is
not yours and must not be stress-tested. 斥候 audits config, never capacity. Header
present ≠ page renders: after any header change, re-open the page in a browser and
confirm it still works.

---

## Requirements

Python 3.8+. Standard library only (`http.client`, `ssl`, `socket`, `json`, `re`).
No `pip install`, no dependencies, no network calls except to the hosts you scope.

## License

Do what you like with it; keep the scope gate. Point it only at what you own.
