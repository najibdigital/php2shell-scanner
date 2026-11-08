#!/usr/bin/env python3
"""
php2shell Scanner — CVE-2026-109618 / CVE-2026-109619
(+ related advisory CVE-2026-115560)
Safe, defensive scanner for YOUR OWN websites.

WHAT IT DOES (safe by design)
  1. Passive fingerprinting: reads PHP version from response headers
     (X-Powered-By), cookies, page body / generator tags, and common
     version-leak pages (phpinfo) — plain GET requests only.
  2. Version verdict: compares any version found against the fixed
     releases 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
  3. CVE-2026-115560 exposure check (related, UNPATCHED as of the
     23 Oct 2026 PHP informational advisory — it affects even the fixed
     releases above): when a phpinfo page is exposed, it reads the
     session configuration values phpinfo itself prints
     (session.serialize_handler, session.upload_progress.enabled,
     session.upload_progress.name) and reports which of the advisory's
     preconditions are externally visible. The third precondition — an
     application switching the serialize handler at runtime with
     ini_set() before session_start() — is application code and can
     NEVER be seen from outside; the scanner says so instead of
     guessing. No version is "patched" for this CVE yet: PHP's own
     suggested protection until the next regular release is
     session.upload_progress.enabled = 0.
  3. OPTIONAL benign probe (--active-probe, off by default):
     sends ONE small multipart POST containing a harmless canary in the
     PHP_SESSION_UPLOAD_PROGRESS field (plain text, no PHP code, no
     serialized objects, no large headers). It only checks whether the
     upload_progress path is reachable / blocked by a WAF.
     It NEVER attempts RCE, session injection, or OOM triggering.

WHAT IT NEVER DOES
  - No exploit payloads, no <?php in filenames, no serialized objects
  - No header bombs / nested-array bombs / oversized bodies (no DoS)
  - No command execution on the target

Use only on sites you own or are authorised to test.

Usage:
  python3 scanner.py https://example.com
  python3 scanner.py https://example.com --active-probe
  python3 scanner.py https://example.com --json
  python3 scanner.py --batch sites.txt --json -o results.json
"""
import argparse, html, json, re, secrets, ssl, sys, time
import urllib.request, urllib.error, urllib.parse

FIXED = {(8,2): (8,2,35), (8,3): (8,3,36), (8,4): (8,4,27), (8,5): (8,5,12)}
VERSION_RE = re.compile(r"PHP[/\s]?(\d+)\.(\d+)\.(\d+)", re.I)
PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/php-info.php"]
REMEDIATION = [
    "Update PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or newer, then RESTART PHP-FPM / Apache / LiteSpeed workers (patch without restart leaves old code running).",
    "CVE-2026-115560 (related, no patch yet — fix comes in PHP's next regular release, and it affects even the patched versions above): set session.upload_progress.enabled = 0/Off in php.ini and reload PHP until that release ships — this is PHP's own suggested protection (advisory, 23 Oct 2026). Most urgent if session.serialize_handler is php_binary or php_serialize in your server config.",
    "Interim only: set session.upload_progress.enabled = Off in php.ini if you don't use upload progress bars, and reload PHP.",
    "Interim only: block PHP_SESSION_UPLOAD_PROGRESS in multipart POST bodies at your WAF/CDN (a simple ModSecurity rule: deny multipart POSTs whose body contains PHP_SESSION_UPLOAD_PROGRESS).",
    "Remove any public phpinfo pages, and hide X-Powered-By (expose_php = Off) — this reduces fingerprinting, it is not a fix.",
    "After patching, review web/PHP logs around Oct 20-21 2026 onwards for multipart POSTs containing PHP_SESSION_UPLOAD_PROGRESS and PHP processes spawning shells.",
]
UA = "php2shell-scanner/1.0 (+defensive; owner-authorised check)"
TIMEOUT = 12
CTX = ssl.create_default_context()

def fetch(url, method="GET", body=None, headers=None, timeout=TIMEOUT):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers: h.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            data = r.read(512_000)
            return {"status": r.status, "headers": dict(r.headers.items()),
                    "body": data.decode("utf-8", "replace"), "final_url": r.geturl(), "error": None}
    except urllib.error.HTTPError as e:
        try: data = e.read(512_000).decode("utf-8", "replace")
        except Exception: data = ""
        return {"status": e.code, "headers": dict(e.headers.items()) if e.headers else {},
                "body": data, "final_url": url, "error": None}
    except Exception as e:
        return {"status": None, "headers": {}, "body": "", "final_url": url, "error": str(e)}

def parse_version(text):
    if not text: return None
    m = VERSION_RE.search(text)
    if not m: return None
    return tuple(int(x) for x in m.groups())

def version_verdict(ver):
    """Return (verdict, detail) for a version tuple."""
    if ver is None: return ("UNKNOWN", "No PHP version could be detected from outside.")
    major, minor, patch = ver
    vs = ".".join(map(str, ver))
    if (major, minor) in FIXED:
        fixed = FIXED[(major, minor)]
        if ver >= fixed:
            return ("PATCHED", f"PHP {vs} is at/above the fixed release {'.'.join(map(str,fixed))} for this branch. "
                                "Note: distro packages can backport fixes under an older-looking number — check the package changelog for CVE-2026-109618/109619 to confirm.")
        return ("VULNERABLE", f"PHP {vs} is below the fixed release {'.'.join(map(str,fixed))} for the {major}.{minor} branch.")
    if major > 8 or (major == 8 and minor > 5):
        return ("PATCHED", f"PHP {vs} is newer than the last affected branch (8.5). Confirm it is an official fixed build.")
    # 5.4 – 8.1 : affected, no official fixed release
    return ("VULNERABLE_EOL", f"PHP {vs} is in the affected range (reported from 5.4) and this branch has NO official fixed release. "
                              "Upgrade to 8.2.35+, 8.3.36+, 8.4.27+ or 8.5.12+ (or a vendor LTS build containing both CVE fixes).")

def parse_phpinfo_config(body):
    """Extract the session directives a phpinfo() page itself prints.

    phpinfo renders directives as table rows (directive / local / master);
    stripping tags leaves e.g. 'session.serialize_handler php_serialize
    php_serialize'. We take the first value after the directive name.
    Returns a dict with only the directives actually found — absence of a
    value is reported as unknown by the caller, never assumed.
    """
    if not body: return {}
    text = re.sub(r"<[^>]+>", " ", body)
    text = re.sub(r"\s+", " ", html.unescape(text))
    cfg = {}
    m = re.search(r"session\.upload_progress\.enabled\s+([A-Za-z0-9]+)", text)
    if m: cfg["upload_progress_enabled"] = m.group(1)
    m = re.search(r"session\.serialize_handler\s+([A-Za-z_]+)", text)
    if m: cfg["serialize_handler"] = m.group(1)
    m = re.search(r"session\.upload_progress\.name\s+([^\s]+)", text)
    if m: cfg["upload_progress_name"] = m.group(1)
    return cfg

def _is_on(v):
    return str(v).strip().lower() in ("on", "1", "true", "yes")

def assess_115560(cfg, phpinfo_leaked):
    """CVE-2026-115560 exposure assessment from externally visible config.

    PHP advisory (23 Oct 2026) preconditions — ALL must hold:
      (a) session.serialize_handler = php_binary or php_serialize in the
          server CONFIGURATION,
      (b) the application switches it to 'php' at runtime via ini_set()
          before session_start()  — application code, NOT externally
          observable, so this is always reported as 'check your code',
      (c) session.upload_progress still enabled (on by default).
    No fixed PHP release exists yet; PHP suggests
    session.upload_progress.enabled=0 until the next regular release.
    """
    base = {"cve": "CVE-2026-115560", "config_seen": cfg or {},
            "preconditions": {
                "config_serialize_handler_nondefault": None,
                "runtime_ini_set_switch": None,  # never observable externally
                "upload_progress_enabled": None},
            "waf_name_note": None}
    if cfg:
        h = (cfg.get("serialize_handler") or "").lower()
        if h: base["preconditions"]["config_serialize_handler_nondefault"] = h in ("php_binary", "php_serialize")
        e = cfg.get("upload_progress_enabled")
        if e is not None: base["preconditions"]["upload_progress_enabled"] = _is_on(e)
        name = cfg.get("upload_progress_name")
        if name:
            if name == "PHP_SESSION_UPLOAD_PROGRESS":
                base["waf_name_note"] = ("Uses the DEFAULT upload-progress field name — Cloudflare's default "
                                         "php2shell WAF rules cover this field name (their rule #6 also covers "
                                         "CVE-2026-115560). A WAF is an interim layer, not a fix.")
            else:
                base["waf_name_note"] = (f"Uses a CUSTOM upload-progress field name ({name}) — Cloudflare states its "
                                         "default php2shell WAF coverage assumes the default field name, so sites "
                                         "that changed session.upload_progress.name are NOT covered by it.")
    enabled = base["preconditions"]["upload_progress_enabled"]
    nondefault = base["preconditions"]["config_serialize_handler_nondefault"]
    if enabled is False:
        base.update({"status": "MITIGATED",
                     "detail": "phpinfo shows session.upload_progress.enabled = Off — PHP's suggested mitigation "
                               "for CVE-2026-115560 is in place. Keep it off until PHP's next regular release "
                               "ships the fix, then re-check."})
    elif nondefault and enabled:
        base.update({"status": "CONFIG_PRECONDITIONS_PRESENT",
                     "detail": "phpinfo confirms 2 of the 3 CVE-2026-115560 preconditions: "
                               "session.serialize_handler is php_binary/php_serialize in server config AND "
                               "session.upload_progress is enabled. The third — app code switching the handler "
                               "to 'php' via ini_set() before session_start() — cannot be seen from outside: "
                               "audit your code for it. Until that audit clears you, treat this as AT RISK: "
                               "set session.upload_progress.enabled = 0 (PHP's suggested protection) — note this "
                               "CVE affects even PHP versions patched for php2shell."})
    elif enabled and nondefault is False:
        base.update({"status": "PRECONDITIONS_NOT_PRESENT_EXTERNALLY",
                     "detail": "phpinfo shows session.upload_progress enabled but session.serialize_handler is "
                               "the default 'php', so the configuration precondition for CVE-2026-115560 is NOT "
                               "met. The runtime precondition is application code and cannot be verified from "
                               "outside. PHP still suggests session.upload_progress.enabled = 0 until the next "
                               "regular release if you don't need upload progress."})
    elif enabled:
        base.update({"status": "POSSIBLE_UNVERIFIED",
                     "detail": "phpinfo shows session.upload_progress enabled, but the serialize_handler value "
                               "could not be read, so the CVE-2026-115560 preconditions cannot be confirmed or "
                               "ruled out externally. Check on the server (php -i | grep -E "
                               "'serialize_handler|upload_progress') and your code for ini_set() handler switches."})
    elif phpinfo_leaked:
        base.update({"status": "UNKNOWN",
                     "detail": "A phpinfo page is exposed but the session directives could not be read from it, "
                               "so CVE-2026-115560 exposure cannot be determined externally. Check on the server "
                               "(php -i | grep -E 'serialize_handler|upload_progress')."})
    else:
        base.update({"status": "UNKNOWN",
                     "detail": "CVE-2026-115560 exposure cannot be determined from outside — no configuration is "
                               "exposed (which is good hygiene). Owner-side check: php -i | grep -E "
                               "'serialize_handler|upload_progress', plus a code search for ini_set() switching "
                               "session.serialize_handler before session_start(). PHP suggests "
                               "session.upload_progress.enabled = 0 until the next regular release ships the fix."})
    return base

def detect_cms(body, headers):
    b = (body or "")[:200_000].lower()
    found = []
    if "wp-content" in b or "wordpress" in b: found.append("WordPress")
    if "joomla" in b: found.append("Joomla")
    if "drupal" in b: found.append("Drupal")
    if "laravel" in b or "laravel_session" in str(headers).lower(): found.append("Laravel (possible)")
    if "magento" in b or "mage-" in b: found.append("Magento (possible)")
    return found

def benign_probe(base_url):
    """One harmless multipart POST. Returns dict; never sends exploit content."""
    canary = "php2shell-scan-" + secrets.token_hex(6)
    boundary = "----php2shellscan" + secrets.token_hex(4)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{canary}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="scanfile"; filename="php2shell-scan.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nbenign scanner canary - no code\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    r = fetch(base_url, method="POST", body=body,
              headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    if r["error"]:
        return {"ran": True, "result": "inconclusive", "status": None,
                "detail": f"Probe request failed: {r['error']}"}
    if r["status"] in (403, 406, 429):
        return {"ran": True, "result": "blocked", "status": r["status"],
                "detail": "Probe was blocked (HTTP %s) — a WAF/rule blocking PHP_SESSION_UPLOAD_PROGRESS is likely active. "
                          "That is a useful interim mitigation, not a substitute for patching PHP." % r["status"]}
    if r["status"] and 500 <= r["status"] < 600:
        return {"ran": True, "result": "server_error", "status": r["status"],
                "detail": "Server returned 5xx to the benign probe. Investigate logs; do not interpret this as proof of RCE."}
    return {"ran": True, "result": "reachable", "status": r["status"],
            "detail": "Server accepted a benign PHP_SESSION_UPLOAD_PROGRESS multipart POST (no code was sent). "
                      "If the PHP version is vulnerable, the upload_progress attack surface is reachable. Patch — don't rely on obscurity."}

def scan(target, active_probe=False):
    if "://" not in target: target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    out = {"target": target, "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "cves": ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"],
           "evidence": [], "php_version": None, "sources": [], "cms": [], "probe": {"ran": False}}
    main = fetch(base)
    if main["error"]:
        out.update({"verdict": "UNREACHABLE", "detail": f"Could not reach target: {main['error']}",
                    "phpinfo_leak": [], "http_status": None, "remediation": REMEDIATION,
                    "cve_2026_115560": assess_115560({}, False)})
        return out
    out["http_status"] = main["status"]
    # 1) headers
    for hk, hv in main["headers"].items():
        v = parse_version(hv)
        if v:
            out["php_version"] = ".".join(map(str, v)); out["sources"].append(f"header {hk}: {hv}")
            out["evidence"].append(f"{hk}: {hv}")
        if hk.lower() == "set-cookie" and "phpsessid" in hv.lower():
            out["evidence"].append("PHPSESSID cookie present (PHP sessions in use)")
    # 2) body
    if not out["php_version"]:
        v = parse_version(main["body"])
        if v:
            out["php_version"] = ".".join(map(str, v)); out["sources"].append("page body")
    out["cms"] = detect_cms(main["body"], main["headers"])
    if out["cms"]: out["evidence"].append("Platform hints: " + ", ".join(out["cms"]))
    # 3) phpinfo leaks (GET only)
    root = f"{parsed.scheme}://{parsed.netloc}"
    leaked = []
    PHPINFO_MARKERS = ["php license", "configuration", "php core", "zend engine", "php credits", "php version"]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as ex:
        probe_results = list(ex.map(lambda p: (p, fetch(root + p, timeout=7)), PHPINFO_PATHS))
    for p, r in probe_results:
        # Must still be AT that path (no redirect elsewhere) and look like a
        # real phpinfo() table, not a docs/search page mentioning PHP.
        same_path = urllib.parse.urlparse(r.get("final_url") or "").path.rstrip("/") == p.rstrip("/")
        marker_hits = sum(1 for m in PHPINFO_MARKERS if m in r["body"].lower())
        if r["status"] == 200 and same_path and marker_hits >= 3:
            leaked.append(p)
            v = parse_version(r["body"])
            if v and not out["php_version"]:
                out["php_version"] = ".".join(map(str, v)); out["sources"].append(f"phpinfo page {p}")
            elif v:
                out["sources"].append(f"phpinfo page {p} (PHP {'.'.join(map(str,v))})")
    out["phpinfo_leak"] = leaked
    if leaked: out["evidence"].append("phpinfo exposed at: " + ", ".join(leaked) + " — remove it; it leaks full config.")
    # CVE-2026-115560: read the config phpinfo itself exposes (first leaked page)
    phpinfo_cfg = {}
    for p, r in probe_results:
        if p in leaked:
            phpinfo_cfg = parse_phpinfo_config(r["body"])
            if phpinfo_cfg: break
    if phpinfo_cfg:
        out["evidence"].append("phpinfo session config: " + ", ".join(f"{k}={v}" for k, v in phpinfo_cfg.items()))
    out["cve_2026_115560"] = assess_115560(phpinfo_cfg, bool(leaked))
    if out["cve_2026_115560"]["status"] == "CONFIG_PRECONDITIONS_PRESENT":
        out["evidence"].append("CVE-2026-115560: configuration preconditions present (see advisory detail below) — "
                               "this CVE is unpatched and affects even php2shell-patched PHP.")
    # verdict (php_version is stored as a bare "x.y.z" string)
    ver_tuple = tuple(int(x) for x in out["php_version"].split(".")) if out["php_version"] else None
    verdict, detail = version_verdict(ver_tuple)
    if verdict == "UNKNOWN":
        verdict = "INCONCLUSIVE"
        detail = ("No PHP version leaked externally. That does NOT mean safe — most hardened sites hide the version, "
                  "and every unpatched PHP < fixed release is affected. Check on the server: php -v, and patch regardless.")
    out["verdict"] = verdict; out["detail"] = detail
    if active_probe:
        out["probe"] = benign_probe(base)
    out["remediation"] = REMEDIATION
    return out

def print_human(r):
    print(f"\n{'='*68}\nTarget: {r['target']}   [{r.get('scanned_at','')}]\n{'='*68}")
    print(f"VERDICT: {r['verdict']}")
    print(f"PHP version detected: {r.get('php_version') or 'not exposed'}"
          + (f"  (via {', '.join(r['sources'])})" if r.get('sources') else ""))
    print(f"Detail: {r['detail']}")
    a = r.get("cve_2026_115560") or {}
    if a:
        print(f"CVE-2026-115560 (related, unpatched): {a.get('status')} — {a.get('detail')}")
        if a.get("waf_name_note"): print(f"  WAF note: {a['waf_name_note']}")
    if r.get("evidence"):
        print("Evidence:"); [print(f"  - {e}") for e in r["evidence"]]
    if r.get("probe", {}).get("ran"):
        print(f"Benign upload_progress probe: {r['probe']['result']} (HTTP {r['probe'].get('status')}) — {r['probe']['detail']}")
    else:
        print("Benign upload_progress probe: not run (add --active-probe on sites you own)")
    print("Fix:"); [print(f"  {i+1}. {s}") for i, s in enumerate(r.get("remediation") or [])]

def main():
    ap = argparse.ArgumentParser(description="php2shell (CVE-2026-109618/109619) safe scanner — for your own sites only")
    ap.add_argument("target", nargs="?", help="URL, e.g. https://example.com")
    ap.add_argument("--batch", help="File with one URL per line")
    ap.add_argument("--active-probe", action="store_true", help="Send ONE benign upload_progress probe (own sites only)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--output", help="Write JSON results to file")
    a = ap.parse_args()
    targets = []
    if a.batch:
        targets = [l.strip() for l in open(a.batch) if l.strip() and not l.startswith("#")]
    if a.target: targets.append(a.target)
    if not targets: ap.error("give a target URL or --batch file")
    results = [scan(t, active_probe=a.active_probe) for t in targets]
    if a.json or a.output:
        payload = json.dumps(results, indent=2)
        if a.output: open(a.output, "w").write(payload); print(f"Wrote {a.output}")
        if a.json: print(payload)
    if not a.json:
        for r in results: print_human(r)
    # exit code: 2 if any vulnerable, or if CVE-2026-115560 config
    # preconditions are confirmed present — handy for CI
    sys.exit(2 if any(r["verdict"].startswith("VULNERABLE") or
                      (r.get("cve_2026_115560") or {}).get("status") == "CONFIG_PRECONDITIONS_PRESENT"
                      for r in results) else 0)

if __name__ == "__main__":
    main()
