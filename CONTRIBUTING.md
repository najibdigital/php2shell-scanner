# Contributing

Thanks for helping keep the web a little safer. Contributions of all sizes
are welcome.

## The one hard rule

**No exploit functionality.** This project exists so site owners can check
their own sites safely. Pull requests that add any of the following will be
closed:

- Code-execution payloads or "verification" by executing commands
- Session-file injection, serialized-object injection, or filename payloads
- Out-of-memory triggers, header bombs, oversized-body techniques, or any
  other denial-of-service behaviour
- Features aimed at scanning third parties at scale (bulk target lists
  beyond an owner's own sites, credential checks, stealth/evasion options)

## Good contributions

- More accurate version parsing or platform fingerprints
- New *passive* detection signals
- Translations of the web UI
- Accessibility and mobile improvements to `public/index.html`
- Tests, documentation, and clearer remediation guidance

## Development

- CLI: `scanner.py` must remain **Python 3 standard library only** — no
  new dependencies.
- Web API: `api/scan.js` must remain dependency-free Node 18+ and keep the
  SSRF guard intact; changes to `fetchSafe` / `assertPublicHost` need a
  clear explanation in the PR.
- Keep the CLI and web verdict logic in sync: the fixed-version table and
  verdict wording should match in both files.
- Test your change against a site you control (a local PHP server is
  ideal) and describe the before/after verdicts in the PR.

## Pull requests

1. Fork, branch from `main`, and keep the PR focused on one change.
2. Use a clear title and explain *why*, not just *what*.
3. By contributing you agree your work is released under the MIT license
   in this repository.
