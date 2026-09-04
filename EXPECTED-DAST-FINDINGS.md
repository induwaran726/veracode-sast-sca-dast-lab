# Expected DAST Findings

> **Expected, not guaranteed.** Actual results depend on crawl coverage, authenticated-scan setup, and Veracode rule updates. Record `Actual` only after a scan against the Render HTTPS URL.

## Unaffected by SAST-only

DAST will generally **not** flag pure code-pattern issues like hardcoded keys or MD5 — those are SAST/SCA. DAST excels at runtime observables.

## Expected runtime findings

| ID | Finding | OWASP | Where | Expected severity | Auth needed? | How to confirm manually |
|---|---|---|---|---|---|---|
| DAST-001 | Missing security headers (CSP, X-Frame-Options, HSTS, etc.) | A05 | Any non-`/security-lab` response (e.g. `/`, `/health`) | Medium | no | `curl -i https://<host>/` — no `Content-Security-Policy` / `Strict-Transport-Security` |
| DAST-002 | Session cookie missing Secure/HttpOnly/SameSite | A02/A07 | `Set-Cookie: lab.sid` on any response | Medium | no | Inspect `Set-Cookie` headers |
| DAST-003 | Stored XSS execution (comments) | A03 | `POST /comments` then `GET /comments` with `<script>` payload | High | yes | Post payload as logged-in user, reload as same user |
| DAST-004 | Reflected XSS (search `q`) | A03 | `GET /search?q=<script>` | High | yes | Inject `<svg onload=…>` and observe raw reflection |
| DAST-005 | IDOR — unauthenticated order/user enumeration | A01 | `GET /orders/:id`, `GET /api/users/:id` | High | yes (but DAST can test with stolen session) | Login as user A, fetch user B's order id |
| DAST-006 | Broken access control — admin endpoint without proper authz (client role) | A01 | `GET /admin/users?role=admin` | High | yes | Compare `GET /admin` (403 for user) vs `?role=admin` (200) |
| DAST-007 | Open redirect | A01 | `GET /redirect?url=https://example.com` | Medium | yes | Follow redirect `Location` |
| DAST-008 | Sensitive data exposure (API returns hashes/keys) | A01/A02 | `GET /api/users` | Medium | yes | Observe `password_hash`, `api_key` in JSON |
| DAST-009 | Path traversal (filename) | A01 | `POST /upload` with `X-File-Name: ../../…` | Medium | yes | Runtime guard blocks write but path-construction is exercised |
| DAST-010 | Authentication/session issues (fixation, long-lived session) | A07 | `/login` → `/auth/callback` → `Set-Cookie` | Medium/Low | yes | Check session id reuse across login |
| DAST-011 | Verbose error disclosure (stack trace) | A05 | Trigger 500 (e.g. malformed `products/:id`) | Low | no | Observe `stack` in JSON error |

`/security-lab` itself sets strict headers (`Content-Security-Policy`, `X-Frame-Options`, `HSTS`, etc.) — DAST should show that path as **pass** and everything else as **fail**, which doubles as a before/after example for header remediation.

## Coverage notes

- Authenticated scan requires Entra ID login → see `DAST-TEST-PLAN.md` (AI-assisted login or SIDE script).
- SSRF (`/api/ssrf-vulnerable`) is scope-guarded to the app's own origin, so DAST will not flag SSRF against private/metadata IPs — SSRF SAST coverage remains the evidence for A10.
- Command injection `exec` is behind a runtime allowlist to keep the Render container safe; DAST will not achieve code execution. SAST coverage is the evidence for CWE-78.
