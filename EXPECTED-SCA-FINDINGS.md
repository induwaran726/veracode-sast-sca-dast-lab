# Expected SCA Findings

Source: `npm audit` on the baseline `package.json` / `package-lock.json` (Node 24, npm 11).
Run `npm audit` locally after `npm install` to reproduce. **Do not upgrade before the baseline Veracode SCA scan.**

Summary (at time of scaffolding): **18 vulnerabilities — 5 low, 2 moderate, 9 high, 2 critical** across 104 prod dependencies.

## Direct dependencies pinned to historically-vulnerable versions

| SCA ID | Package | Pinned version | Known CVEs (examples) | Severity (npm) | Fixed version | Direct vs transitive | Reason for pin |
|---|---|---|---|---|---|---|---|
| SCA-001 | lodash | 4.17.15 | CVE-2020-8203, CVE-2021-23337, GHSA-4xc9-xhrj-v574 | high | 4.17.21 | direct | Vulnerable but still widely-referenced; safe transitive usage here |
| SCA-002 | axios | 0.21.1 | CVE-2021-3749 ReDoS (GHSA-cph5-m8f7-6c5x) + multiple GHSA advisories on ≤0.32.0 | high | 0.21.4 (then 1.x) | direct | Historical vulnerable release, still installable |
| SCA-003 | jsonwebtoken | 8.5.1 | CVE-2022-23529 et al. (GHSA-8cf7-32cx-wr33, etc.) | high | 9.0.0 | direct | Historic JWT lib vulns |
| SCA-004 | node-fetch | 2.6.0 | CVE-2020-15168, GHSA-r683-j2x4-v87g, GHSA-w7rc-rwvf-8q5r | high | 2.6.7 / 3.x | direct | Used intentionally in SSRF module |
| SCA-005 | minimist | 1.2.0 | CVE-2020-7598, CVE-2021-44906 (GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h) | critical | 1.2.8 | direct | Classic prototype-pollution demo |
| SCA-006 | express-fileupload | 1.1.6 | CVE-2020-7699 (GHSA-wm7h-9275-46v2 via dicer/busboy) | high | 1.1.8 / 1.5.x | direct | Safe file-upload demo |

## Notable transitive findings (also surfaced by Veracode SCA via dependency paths)

- `qs ≤6.15.3` — moderate, DoS via `isBuffer` / arrayLimit bypass (via Express)
- `ejs <3.1.10` — moderate, pollution protection (GHSA-ghr5-ch3p-vcr6)
- `path-to-regexp ≤0.1.12` — high, ReDoS (via Express)
- `send <0.19.0` / `serve-static` — high, template injection / XSS vector
- `cookie <0.7.0`, `on-headers <1.1.0`, `body-parser` — low/high, header/cookie issues
- `busboy ≤0.3.1` / `dicer *` — high, HeaderParser crash

Dependency paths are visible in `npm audit --json` under `vulnerabilities[].via` / `.nodes` and in Veracode SCA's dependency graph.

## Remediation (after baseline)

For each direct finding:

1. Identify CVE + severity + path.
2. Upgrade to the fixed version (`npm install <pkg>@<fixed> --save`).
3. `npm audit` again and diff.
4. Run `npm test` and smoke-test `/health`, `/products`, `/orders`, `/comments`, `/upload`, `/api`.
5. Commit as `fix(sca): upgrade <pkg> to <fixed>` on a remediation branch.
6. Re-run Veracode SCA and compare.

Do not batch all upgrades into one commit if you want per-finding before/after evidence.
