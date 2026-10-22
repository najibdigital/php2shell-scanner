# Security Policy

## Reporting a vulnerability in this scanner

If you find a security problem in php2shell Scanner itself — for example a
way to bypass the SSRF guard, make the web API fetch internal services, or
cause it to send traffic it is designed never to send — please report it
privately before disclosing it publicly:

- Open a **private** report via GitHub Security Advisories on this
  repository (Security → Report a vulnerability), or
- Contact the maintainer through https://najibdigital.com

Please include steps to reproduce and the version/commit you tested.
We aim to acknowledge reports within 3 working days.

## Scope notes

- The scanner intentionally sends **no** exploit payloads. Reports that it
  "does not achieve RCE" are by design, not vulnerabilities — see the
  README's *Security design* and *Limitations* sections.
- False verdicts caused by hidden PHP versions or vendor backports are
  documented behaviour; reports with concrete evidence of a *wrong*
  verdict (e.g. a misparsed version string) are welcome as regular issues.

## Supported versions

Only the latest commit on `main` (and the live deployment built from it)
is supported.
