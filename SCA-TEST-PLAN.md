# SCA Test Plan

## Baseline

1. With the pinned vulnerable `package.json` / `package-lock.json` committed and tagged `sast-sca-baseline`, run:
   ```
   npm audit
   npm audit --json > audit-baseline.json   # optional local record
   ```
2. In Veracode, run **Software Composition Analysis** against the same commit (repo import or upload). SCA analyzes the dependency graph, not source.

## What to capture (per finding)

- Package, version, CVE/GHSA, severity, direct vs transitive, dependency path, fixed version, remediation recommendation.

## Analysis

- Map to `EXPECTED-SCA-FINDINGS.md`. Veracode's graph will surface transitive advisories (`qs`, `send`, `path-to-regexp`, `busboy/dicer`, `cookie`, `on-headers`) in addition to the 6 pinned direct deps — record all.
- Keep the baseline commit unpatched until the baseline scan is captured.

## Remediation pass

1. Create a remediation branch (e.g. `fix/sca-001-lodash`).
2. `npm install lodash@4.17.21 --save` (or the fixed version from the finding), `npm audit` again, `npm test`, commit.
3. Push, re-run Veracode SCA, compare.
4. Repeat per finding or per CVE group.

Template commit message:
```
fix(sca): upgrade lodash 4.17.15 -> 4.17.21 (CVE-2020-8203)
```

## Notes

- `npm audit fix --force` would jump major versions for many packages; prefer explicit per-package upgrades so the lab stays on Express 4 / node-fetch 2 unless intentionally changing them.
- Veracode may report different CVE IDs or severities than `npm audit` — treat the Veracode report as authoritative for the POC and note the discrepancy.
