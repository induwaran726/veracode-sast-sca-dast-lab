# Veracode SAST + SCA + DAST Security Lab

Intentionally vulnerable Node.js/Express lab for demonstrating **Veracode SAST**, **SCA**, and **DAST** together against the [OWASP Top 10](https://owasp.org/Top10/) — plus API, dependency, and CI/CD security gates. Every vulnerability is synthetic, governed by runtime safety guards, and shipped with a secure alternative for before/after comparison.

> **Controlled lab — do NOT use in production or expose to real data.**

## Architecture

```
Laptop (OpenCode + GitHub + Render MCP + Veracode)
  │
  ├─ GitHub ── veracode-sast-sca-dast-lab (this repo)
  │              ├─ src/        vulnerable + secure variants
  │              ├─ package.json / package-lock.json  (SCA)
  │              └─ tests/
  │
  ├─ Render Free Web Service (Node.js)
  │              └─ https://<service>.onrender.com  (/health, /login, …)
  │                    └─ Microsoft Entra ID (authorization-code flow)
  │
  └─ Veracode
                 ├─ SAST → GitHub source
                 ├─ SCA  → package.json + package-lock.json
                 └─ DAST → Render HTTPS URL
```

## Technology

Node.js 20+, Express 4, EJS, `node:sqlite` (built-in), `express-session`, Microsoft Entra ID OIDC (hand-rolled authorization-code flow), Axios/node-fetch for SSRF demo, synthetic lodash/minimist/jsonwebtoken etc. pinned at historically-vulnerable versions for SCA.

## Quick start (local)

```bash
cp .env.example .env   # fill ENTRA_* only if you want SSO locally
npm install
npm test
npm audit
npm start              # http://localhost:3000
```

Public routes need no login: `/`, `/health`, `/login`, `/auth/callback`, `/logout`.
Protected routes redirect to Entra ID when not authenticated.

## Auth

Microsoft Entra ID via `openid profile email`, authorization-code flow.
Callback is derived from `BASE_URL` (never hard-coded): `BASE_URL + /auth/callback`.
`ADMIN_EMAIL` determines who can access `/admin` (normal user → 403).
Dashboard renders `AUTHENTICATED_DAST_TEST_USER` after login for authenticated DAST.

Env vars: `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID`, `SESSION_SECRET`, `BASE_URL`, `ADMIN_EMAIL`. Only `.env.example` is committed.

## Routes

- Public: `/`, `/health`, `/login`, `/auth/callback`, `/logout`
- Authenticated: `/dashboard`, `/profile`, `/products`, `/orders`, `/admin`, `/search`, `/comments`, `/upload`, `/redirect`, `/api`, `/security-lab`
- API: `/api/users`, `/api/products`, `/api/orders`, `/api/profile` plus `-secure` variants and synthetic `/api/lab-target`

## Security Lab

`/security-lab` (login required) lists every OWASP category with vulnerable/secure endpoints. Runtime guards (see `SECURITY-TESTING.md`) keep live demos contained:

- SSRF fetches only this app's own origin.
- Command-injection `exec` is gated to `[a-zA-Z0-9 _-]{≤32}` against `echo`.
- Path traversal resolves inside `data/uploads/`.
- No real secrets, reverse shells, or cloud-metadata access.

## Documentation

| Document | Purpose |
|---|---|
| `SAST-TEST-PLAN.md` | How to run Veracode SAST |
| `SCA-TEST-PLAN.md` | How to run Veracode SCA + remediation workflow |
| `DAST-TEST-PLAN.md` | Unauthenticated + authenticated DAST, Entra login, SIDE |
| `OWASP-MAPPING.md` | OWASP → CWE → file → SAST/SCA/DAST coverage |
| `EXPECTED-SAST-FINDINGS.md` | Expected (not guaranteed) SAST findings |
| `EXPECTED-SCA-FINDINGS.md` | Vulnerable deps, CVEs, fixed versions |
| `EXPECTED-DAST-FINDINGS.md` | Expected runtime findings |
| `SECURITY-TESTING.md` | SAST vs SCA vs DAST comparison + manual tests |

## CI/CD

`.github/workflows/security.yml` is a template with `Veracode` placeholders (no credentials committed). Fill `VERACODE_API_ID`/`VERACODE_API_KEY` as GitHub Actions secrets to enable Pipeline Scanner.

## Deployment (Render)

Free web service, `npm install` → `npm start`, health check at `/health`. `render.yaml` is included; env vars are configured as `sync: false` (prompted at deploy time). See `DAST-TEST-PLAN.md` for DAST URL handling.

## Limitations

See `SECURITY-TESTING.md` for scanner limitations, false positives/negatives, and findings that require manual verification.

## License

MIT — lab fixtures only.
