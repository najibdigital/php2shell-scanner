# php2shell Scanner

**Is your website vulnerable to php2shell? Find out in seconds — safely.**

A free, open-source checker for **CVE-2026-109618** and **CVE-2026-109619**
("php2shell") — two critical, pre-authentication remote code execution
vulnerabilities in **PHP itself**, disclosed in October 2026 and rated
**CVSS 9.2**. Every unpatched PHP installation serving web requests is
affected, including sites running WordPress, Joomla, Drupal, Magento,
Laravel, and custom PHP applications.

🌐 **Try it live (nothing to install):**
https://php2shell-scanner.vercel.app

---

## Why this exists

When a vulnerability of this severity drops, most site owners have the same
question — *"does this affect my site?"* — and no easy way to answer it.
Manually checking PHP versions across shared hosting, VPSs, and client
sites is slow, and the public proof-of-concept code that appears after a
disclosure is exploit code: running it against a production site risks
crashing it, and running it against someone else's site is illegal.

This scanner answers the question **without exploit traffic**:

- It never sends code execution payloads.
- It never triggers the out-of-memory condition the vulnerabilities rely on.
- Its optional active probe sends **one tiny, harmless request** and only
  observes whether a web application firewall blocks it.
- It is designed, documented, and safe to run against production sites you
  own.

## What it checks

| Check | How | Intrusive? |
|---|---|---|
| **PHP version fingerprint** | Reads `X-Powered-By` and other headers, page content, and generator metadata | No — plain GET |
| **Exposed `phpinfo()` pages** | GETs `/phpinfo.php`, `/info.php`, `/php-info.php` and verifies the response is a genuine phpinfo table served at that exact path (redirects and documentation pages do not count) | No — plain GET |
| **Session usage** | Notes whether the site sets a `PHPSESSID` cookie | No |
| **Platform hints** | Detects WordPress / Joomla / Drupal / Magento signals, which raise impact | No |
| **Upload-progress reachability** *(optional, off by default)* | One small `multipart/form-data` POST with a plain-text random canary in the `PHP_SESSION_UPLOAD_PROGRESS` field — **no PHP code, no serialized objects, no oversized headers or bodies** — and reports the HTTP status | Minimal — one benign POST, own sites only |

## Verdicts

| Verdict | Meaning |
|---|---|
| 🔴 **VULNERABLE** | A PHP version below the fixed release for its branch was detected. Patch now. |
| 🔴 **VULNERABLE_EOL** | PHP 5.4–8.1 detected — affected, with **no official fixed release**. Upgrade to a supported branch. |
| 🟢 **PATCHED** | Detected version is at or above the fixed release. See the distro-backport note below. |
| 🟠 **INCONCLUSIVE** | No version is exposed externally. **This does not mean safe** — hardened sites hide their version. Check server-side with `php -v` and patch regardless. |
| ⚪ **UNREACHABLE** | The site could not be fetched (offline, blocking bots, TLS failure, …). |

### Fixed versions

| PHP branch | Fixed in | Status |
|---|---|---|
| 8.5 | **8.5.12** | Supported |
| 8.4 | **8.4.27** | Supported |
| 8.3 | **8.3.36** | Supported |
| 8.2 | **8.2.35** | Supported (EOL 31 Dec 2026 — plan your upgrade) |
| 8.1 and older | — | **No official release.** Minimal source backports exist for 7.4 / 8.0 / 8.1; upgrade or use a vendor LTS build that contains both CVE fixes |

> **Distro backport caveat.** Debian, Ubuntu, CloudLinux and other vendors
> sometimes backport security fixes into packages whose version number
> *looks* older than the fixed release. If this scanner reports your site
> as vulnerable but you installed a vendor security update, check the
> package changelog for `CVE-2026-109618` and `CVE-2026-109619`. If both
> are named, you are patched. If they are not, you are not.

## Quick start

### Option 1 — Web scanner (for everyone)

Open the live scanner, enter your site's URL, and read the verdict:

👉 https://php2shell-scanner.vercel.app

Tick *"This is my website"* if you also want the optional benign
upload-progress probe. Private and internal addresses are refused by design.

### Option 2 — CLI scanner (for owners, sysadmins, CI)

Requires only **Python 3.8+** — standard library only, nothing to install.

```bash
# Scan one site (passive checks only)
python3 scanner.py https://example.com

# Add the benign upload-progress probe (your own sites only)
python3 scanner.py https://example.com --active-probe

# Machine-readable output
python3 scanner.py https://example.com --json

# Scan many sites and save the report
python3 scanner.py --batch sites.txt --json -o results.json
```

`sites.txt` contains one URL per line (`#` comments allowed).

**Exit code:** `2` if any target is `VULNERABLE` / `VULNERABLE_EOL`,
otherwise `0` — so it drops straight into a CI pipeline as a regression
gate after patching.

Example output:

```text
====================================================================
Target: https://example.com   [2026-10-22T02:41:39Z]
====================================================================
VERDICT: VULNERABLE
PHP version detected: 8.2.34  (via header X-Powered-By: PHP/8.2.34)
Detail: PHP 8.2.34 is below the fixed release 8.2.35 for the 8.2 branch.
Evidence:
  - X-Powered-By: PHP/8.2.34
  - PHPSESSID cookie present (PHP sessions in use)
  - phpinfo exposed at: /phpinfo.php — remove it; it leaks full config.
Benign upload_progress probe: reachable (HTTP 200)
Fix:
  1. Update PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or newer, then
     RESTART PHP-FPM / Apache / LiteSpeed workers ...
```

### Option 3 — Deploy your own copy of the web scanner

This repository is a complete [Vercel](https://vercel.com) app
(static UI in `public/`, one serverless function in `api/`):

```bash
git clone https://github.com/najibdigital/php2shell-scanner.git
cd php2shell-scanner
npx vercel deploy --prod
```

Any static host plus a Node 18+ runtime for `api/scan.js` works too.

## How to fix a vulnerable site

Patching is the **only** complete fix. In order:

1. **Update PHP** to 8.2.35, 8.3.36, 8.4.27, or 8.5.12 (or newer).
2. **Restart the PHP workers** — PHP-FPM, Apache, or LiteSpeed. Installing
   the package without restarting leaves the old, vulnerable code running.
3. **Verify** — run this scanner again, and run `php -v` on the server.
4. **Review logs** from 20 October 2026 onward for `multipart/form-data`
   POSTs containing `PHP_SESSION_UPLOAD_PROGRESS`, and for PHP processes
   spawning shells (`sh`, `curl`, `wget`) — both CVEs were reported under
   active exploitation attempts within a day of disclosure.

**Interim mitigations (they reduce risk; they are *not* fixes):**

- Set `session.upload_progress.enabled = Off` in `php.ini` if your
  application does not use upload progress bars, then reload PHP.
- Block `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST bodies at your
  WAF/CDN. This field has near-zero legitimate use. Example ModSecurity
  rule:

  ```apache
  SecRule REQUEST_METHOD "POST" \
      "id:1000010,phase:2,deny,status:403,log,\
      msg:'php2shell interim mitigation: PHP_SESSION_UPLOAD_PROGRESS blocked',chain"
      SecRule REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" "chain"
      SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data"
  ```

- Remove public `phpinfo()` pages and set `expose_php = Off`. This reduces
  fingerprinting — including by this scanner — but changes nothing about
  the underlying vulnerability.

## Security design

A public scanner is itself an attack surface, so this one is built
defensively:

- **SSRF protection.** The web API resolves the target host before every
  request and every redirect hop, and refuses loopback, private,
  link-local (including cloud metadata `169.254.169.254`), CGNAT,
  multicast, and reserved addresses. Only `http`/`https` are allowed.
- **No exploit content, ever.** No code in filenames, no serialized
  objects, no header bombs, no chunked-encoding tricks, no oversized
  bodies. The code is small enough to audit before you run it — please do.
- **Ownership attestation.** The active probe is unavailable until the
  user confirms the site is theirs or they are authorised to test it, and
  it is off by default in both the web UI and the CLI.
- **No tracking.** The web scanner sets no cookies, keeps no scan history,
  and logs no target URLs server-side beyond the host platform's standard
  request logs.
- **Bounded work.** 512 KB response cap and 12-second timeouts per request,
  so a hostile or broken target cannot tie up the scanner.

## Limitations — please read

- **Version-based, not exploit-based.** The verdict is only as certain as
  the version evidence. Hidden version + unpatched PHP = *INCONCLUSIVE*
  here and vulnerable in reality. When in doubt, patch.
- **Backports** can make the version number lie in the safe direction
  (see the caveat above).
- A **WAF-blocked probe** means one attack path is filtered today; WAF
  rules change and bypasses happen. Patch anyway.
- This tool checks for **these two CVEs only**. A `PATCHED` verdict is not
  a general security audit of your site.

## Project structure

```text
php2shell-scanner/
├── scanner.py          # CLI scanner (Python 3 stdlib only)
├── api/
│   └── scan.js         # Web scanner API (Vercel serverless, Node 18+)
├── public/
│   └── index.html      # Web UI (no build step, no dependencies)
├── vercel.json         # Deployment config
├── README.md
├── SECURITY.md         # Responsible disclosure for this project
├── CONTRIBUTING.md
└── LICENSE             # MIT
```

## Contributing

Contributions are welcome — accuracy fixes, additional *safe* detection
methods, translations, and UI improvements especially. See
[CONTRIBUTING.md](CONTRIBUTING.md). The hard rule: **no exploit
functionality.** Pull requests that add payload delivery, code-execution
checks, or denial-of-service techniques will be closed.

## References

- CVE-2026-109618 — PHP security advisory GHSA-w8hw-w9fx-j79w
- CVE-2026-109619 — PHP security advisory GHSA-6wmf-4rv5-p3rp
- Fixed releases: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (21 October 2026),
  announced by the PHP security team at [php.net](https://www.php.net)

## Legal & responsible use

Scan **only** websites you own or are explicitly authorised to test.
Unauthorised scanning may be illegal in your jurisdiction. This tool is
provided for defensive purposes, without warranty of any kind; the
authors accept no liability for misuse or for decisions made based on
its results.

## License

[MIT](LICENSE) © Najib Digital
