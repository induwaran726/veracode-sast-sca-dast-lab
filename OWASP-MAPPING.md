# OWASP Top 10 Coverage Matrix

| OWASP | CWE (primary) | Source file | SAST | SCA | DAST | Manual |
|---|---|---|---|---|---|---|
| A01 Broken Access Control | CWE-639/862/863 | `src/vulnerabilities/a01-access-control.js`, `src/middleware/adminMiddleware.js`, `src/routes/{orders,admin}.js` | ✓ |  | ✓ | ✓ |
| A02 Cryptographic Failures | CWE-327/328/338/614 | `src/vulnerabilities/a02-crypto.js`, `src/server.js` | ✓ |  | ✓ | ✓ |
| A03 Injection | CWE-78/79/89 | `src/vulnerabilities/a03-injection.js`, `src/routes/{products,comments,search}.js`, `src/views/comments.ejs` | ✓ |  | ✓ | ✓ |
| A04 Insecure Design | CWE-602 | `src/vulnerabilities/a04-design.js`, `src/routes/orders.js` | ✓ |  | ✓ | ✓ |
| A05 Security Misconfiguration | CWE-16/209/614/942 | `src/vulnerabilities/a05-misconfiguration.js`, `src/server.js` | ✓ |  | ✓ | ✓ |
| A06 Vulnerable Components | — (CVE) | `package.json`, `package-lock.json` |  | ✓ |  | ✓ |
| A07 Identification & Authentication Failures | CWE-347/384/778 | `src/vulnerabilities/a07-authentication.js`, `src/routes/auth.js` | ✓ |  | ✓ | ✓ |
| A08 Software & Data Integrity Failures | CWE-345/502 | `src/vulnerabilities/a08-integrity.js`, `src/routes/profile.js` | ✓ | ✓ | ✓ | ✓ |
| A09 Security Logging & Monitoring Failures | CWE-532/778 | `src/vulnerabilities/a09-logging.js`, `src/routes/dashboard.js` | ✓ |  |  | ✓ |
| A10 SSRF | CWE-918 | `src/vulnerabilities/a10-ssrf.js`, `src/routes/api.js` | ✓ |  | ✓ | ✓ |

Additional SAST-only/file patterns in the catalog: path traversal (CWE-22, `src/routes/upload.js`), open redirect (CWE-601, `src/routes/redirect.js`), sensitive data exposure (CWE-200, `src/routes/api.js`), hardcoded secret (CWE-798, `src/vulnerabilities/a02-crypto.js`), insecure random (CWE-330/338), ReDoS/unsafe regex (transitive `qs`/`path-to-regexp` via `npm audit`).

## Method legend

- **SAST** — flags vulnerable source patterns (string-concatenated SQL, raw `<%- %>`, `exec` with concat, MD5/ECB, weak `Math.random`, missing authz, verbose errors, etc.)
- **SCA** — flags vulnerable direct deps in `package-lock.json` (see `EXPECTED-SCA-FINDINGS.md`)
- **DAST** — observes runtime: missing headers, authz bypass, stored/reflected XSS execution, crawling, session handling
- **Manual** — requires code review or targeted request replay (use `tests/app.test.js` and curl against `/…-secure` vs vulnerable endpoints)
