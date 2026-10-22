// php2shell web scanner API — Vercel serverless function (Node 18+)
// Safe by design: passive fingerprinting + ONE benign probe (only when the
// caller ticks the own-site attestation). No exploit payloads, no OOM, no RCE.
// SSRF guard: public http(s) only, DNS resolved and checked against
// private / loopback / link-local / reserved ranges on every redirect hop.
const dns = require("dns").promises;
const net = require("net");

const FIXED = { "8.2": [8,2,35], "8.3": [8,3,36], "8.4": [8,4,27], "8.5": [8,5,12] };
const PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/php-info.php"];
const UA = "php2shell-scanner/1.0 (+defensive; owner-authorised check)";

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a,b] = ip.split(".").map(Number);
    if (a===10 || a===127 || a===0) return true;
    if (a===172 && b>=16 && b<=31) return true;
    if (a===192 && b===168) return true;
    if (a===169 && b===254) return true;          // link-local / cloud metadata
    if (a===100 && b>=64 && b<=127) return true;   // CGNAT
    if (a>=224) return true;                        // multicast/reserved
  }
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    if (s==="::1" || s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb")) return true;
    if (s.startsWith("fc") || s.startsWith("fd") || s.startsWith("::ffff:127.") || s.startsWith("::ffff:10.") || s.startsWith("::ffff:192.168.")) return true;
  }
  return false;
}
async function assertPublicHost(hostname) {
  if (hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal")) throw new Error("Private/local hosts cannot be scanned");
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length) throw new Error("Host does not resolve");
  for (const a of addrs) if (isPrivateIP(a.address)) throw new Error("Host resolves to a private/reserved IP — refused (SSRF guard)");
}
function parseVersion(text) {
  if (!text) return null;
  const m = String(text).match(/PHP[/\s]?(\d+)\.(\d+)\.(\d+)/i);
  return m ? [+m[1], +m[2], +m[3]] : null;
}
function verdictFor(ver) {
  if (!ver) return ["INCONCLUSIVE", "No PHP version leaked externally. That does NOT mean safe — hardened sites hide the version and every unpatched PHP is affected. Check on the server with `php -v` and patch regardless."];
  const vs = ver.join("."), key = ver[0]+"."+ver[1], fixed = FIXED[key];
  if (fixed) {
    const cmp = ver[0]-fixed[0] || ver[1]-fixed[1] || ver[2]-fixed[2];
    return cmp >= 0
      ? ["PATCHED", `PHP ${vs} is at/above the fixed release ${fixed.join(".")} for this branch. Distro backports can make an older-looking number patched too — confirm the package changelog names CVE-2026-109618/109619.`]
      : ["VULNERABLE", `PHP ${vs} is below the fixed release ${fixed.join(".")} for the ${key} branch. Patch and restart PHP workers now.`];
  }
  if (ver[0] > 8 || (ver[0]===8 && ver[1] > 5)) return ["PATCHED", `PHP ${vs} is newer than the last affected branch (8.5).`];
  return ["VULNERABLE_EOL", `PHP ${vs} is in the affected range (reported from 5.4) with NO official fixed release for this branch. Upgrade to a fixed 8.2/8.3/8.4/8.5 build or a vendor LTS build containing both fixes.`];
}
async function fetchSafe(url, opts={}, hops=0) {
  if (hops > 4) throw new Error("Too many redirects");
  const u = new URL(url);
  if (!["http:","https:"].includes(u.protocol)) throw new Error("Only http/https");
  await assertPublicHost(u.hostname);
  const ctrl = new AbortController(); const t = setTimeout(()=>ctrl.abort(), 12000);
  try {
    const r = await fetch(url, { ...opts, redirect: "manual", signal: ctrl.signal, headers: { "User-Agent": UA, ...(opts.headers||{}) } });
    if ([301,302,303,307,308].includes(r.status) && r.headers.get("location")) {
      const next = new URL(r.headers.get("location"), url).toString();
      return fetchSafe(next, { ...opts, method: (r.status===303 ? "GET" : opts.method), body: r.status===303 ? undefined : opts.body }, hops+1);
    }
    const body = (await r.text()).slice(0, 512000);
    const headers = {}; r.headers.forEach((v,k)=> headers[k]=v);
    return { status: r.status, headers, body, finalUrl: url };
  } finally { clearTimeout(t); }
}

module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  let target = (req.body && req.body.url) || "";
  const ownSite = !!(req.body && req.body.ownSite);
  const activeProbe = !!(req.body && req.body.activeProbe);
  if (activeProbe && !ownSite) return res.status(400).json({ error: "The active probe requires confirming this is your site / you are authorised to test it." });
  if (!target) return res.status(400).json({ error: "Enter a website URL" });
  if (!/^https?:\/\//i.test(target)) target = "https://" + target;
  let u; try { u = new URL(target); } catch { return res.status(400).json({ error: "That URL doesn't parse" }); }
  try {
    const main = await fetchSafe(target);
    const evidence = [], sources = [];
    let version = null;
    for (const [k,v] of Object.entries(main.headers)) {
      const ver = parseVersion(v); if (ver && !version) { version = ver; sources.push(`header ${k}`); }
      if (k.toLowerCase()==="set-cookie" && /phpsessid/i.test(v)) evidence.push("PHPSESSID cookie present (PHP sessions in use)");
      if (k.toLowerCase()==="x-powered-by" && /php/i.test(v)) evidence.push(`${k}: ${v}`);
    }
    if (!version) { const ver = parseVersion(main.body); if (ver) { version = ver; sources.push("page body"); } }
    const leaks = [];
    await Promise.all(PHPINFO_PATHS.map(async (p) => {
      try {
        const r = await fetchSafe(`${u.protocol}//${u.host}${p}`);
        const samePath = new URL(r.finalUrl).pathname.replace(/\/$/,"") === p.replace(/\/$/,"");
        const markers = ["php license","configuration","php core","zend engine","php credits","php version"];
        const hits = markers.filter(m => r.body.toLowerCase().includes(m)).length;
        if (r.status===200 && samePath && hits>=3) {
          leaks.push(p);
          const ver = parseVersion(r.body); if (ver && !version) { version = ver; sources.push(`phpinfo page ${p}`); }
        }
      } catch {}
    }));
    if (leaks.length) evidence.push(`phpinfo exposed at ${leaks.join(", ")} — remove it, it leaks full server config`);
    const cms = [];
    const b = (main.body||"").toLowerCase();
    if (b.includes("wp-content")||b.includes("wordpress")) cms.push("WordPress");
    if (b.includes("joomla")) cms.push("Joomla");
    if (b.includes("drupal")) cms.push("Drupal");
    if (b.includes("magento")) cms.push("Magento (possible)");
    let probe = { ran: false };
    if (activeProbe) {
      const boundary = "----php2shellscan" + Math.random().toString(16).slice(2,10);
      const canary = "php2shell-scan-" + Math.random().toString(16).slice(2,14);
      const body = `--${boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n${canary}\r\n--${boundary}\r\nContent-Disposition: form-data; name="scanfile"; filename="php2shell-scan.txt"\r\nContent-Type: text/plain\r\n\r\nbenign scanner canary - no code\r\n--${boundary}--\r\n`;
      try {
        const r = await fetchSafe(target, { method: "POST", body, headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` } });
        probe = { ran: true, status: r.status,
          result: [403,406,429].includes(r.status) ? "blocked" : (r.status>=500 ? "server_error" : "reachable"),
          detail: [403,406,429].includes(r.status)
            ? "Probe blocked (WAF rule on PHP_SESSION_UPLOAD_PROGRESS likely active). Useful interim mitigation — not a substitute for patching."
            : "Server accepted a benign PHP_SESSION_UPLOAD_PROGRESS multipart POST (no code was sent). If PHP is vulnerable, the attack surface is reachable." };
      } catch(e) { probe = { ran: true, result: "inconclusive", detail: String(e.message||e) }; }
    }
    const [verdict, detail] = verdictFor(version);
    return res.status(200).json({
      target, verdict, detail, php_version: version ? version.join(".") : null, sources,
      http_status: main.status, evidence, cms, phpinfo_leak: leaks, probe,
      cves: ["CVE-2026-109618","CVE-2026-109619"],
      remediation: [
        "Update PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+, then restart PHP-FPM / Apache / LiteSpeed workers.",
        "Interim: session.upload_progress.enabled = Off in php.ini (if unused), and reload PHP.",
        "Interim: block PHP_SESSION_UPLOAD_PROGRESS in multipart POSTs at WAF/CDN (e.g. a ModSecurity rule denying multipart POST bodies containing that field).",
        "Remove public phpinfo pages; set expose_php = Off (reduces fingerprinting, not a fix).",
        "Review logs from Oct 20, 2026 onward for multipart POSTs with PHP_SESSION_UPLOAD_PROGRESS and PHP processes spawning shells."
      ]
    });
  } catch(e) {
    return res.status(200).json({ target, verdict: "UNREACHABLE", detail: String(e.message||e), php_version: null, evidence: [], cms: [], probe: { ran:false }, remediation: [] });
  }
};
