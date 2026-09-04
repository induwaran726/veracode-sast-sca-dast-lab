# SECURITY-TESTING.md — SAST vs SCA vs DAST

```
SAST ─ Analyzes source code            → coding flaws (SQLi, XSS patterns, MD5, hardcoded keys)
SCA  ─ Analyzes dependencies           → known CVEs in npm packages (lodash, axios, …)
DAST ─ Tests the running application   → runtime/web flaws (headers, session, XSS execution, IDOR, open redirect)
```

## Lab examples

| Question | Answer with an example from this repo |
|---|---|
| SAST-only | Hardcoded synthetic key `ENCRYPTION_KEY` in `a02-crypto.js` — never visible at runtime |
| SCA-only | `lodash 4.17.15` flagged via `package-lock.json`, not source |
| DAST-only | Missing `Content-Security-Policy` on `/` — a runtime header observation |
| Overlaps | Stored XSS: SAST flags `<%- %>` + raw insert; DAST proves execution by posting a payload |

## Scanner limitations & expectations

- **False positives**: e.g. `md5()` in fixtures may be flagged even where used only for synthetic seed data. Triage as informative.
- **False negatives**: EJS raw-output and broad Express CORS patterns are sometimes low/not flagged.
- **Runtime-guarded vulns** (see below) require **code review** as primary evidence.

## Runtime safety guards (why DAST won't fully exploit some vulns)

This lab keeps intentionally vulnerable *code patterns* detectable by SAST while preventing live exploitation of the hosted Render service (free tier, single container). Each guard is labeled in code and view text:

| Area | Code pattern (flagged by SAST) | Runtime guard |
|---|---|---|
| Command injection (`src/vulnerabilities/a03-injection.js`) | `exec("echo " + host)` (CWE-78) | `isRuntimeSafeForDemo`: allowlist `[a-zA-Z0-9 _-]{≤32}` before `exec` |
| Path traversal (`src/routes/upload.js`) | `path.join(UPLOAD_DIR, name)` with `X-File-Name` (CWE-22) | `path.resolve` containment check against `data/uploads` |
| SSRF (`src/routes/api.js`) | `fetchUrlVulnerable(url)` (CWE-918) | Only URLs starting with the app's own origin are fetched |
| MD5 / hardcoded key | Synthetic fixtures | Not real credentials — noted as `SYNTHETIC` |

These guards do **not** hide the vulnerable source from SAST; they only constrain what an HTTP request can actually do at runtime.

## Manual follow-up (recommended)

For every expected finding, exercise both endpoints:

- Vulnerable: `/products/1`, `/search?q=<svg…>`, `/comments` (raw), `POST /orders` with client `total`, `/admin/users?role=admin`, `/redirect?url=…`, `GET /api/users` (exposes hashes)
- Secure: `…-secure` counterparts, `/search-secure`, `/comments-secure`, `POST /orders-secure`, `/api/users-secure`, `/admin` (proper 403)

## Not fabricating results

All `EXPECTED-*` documents say *expected* severity. Only after Veracode actually scans should findings be copied into an `ACTUAL-*` record. Never invent scan IDs or severities.
