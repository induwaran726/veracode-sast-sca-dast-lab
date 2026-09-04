# SAST Test Plan

## Baseline

1. Commit `package.json`, `package-lock.json`, `src/`, `tests/`, docs. Tag `sast-sca-baseline`.
2. Push to GitHub (`veracode-sast-sca-dast-lab`, public per this lab's config).
3. In Veracode, create/ou update the application and run a **Static Application Security Testing** scan against the GitHub repo / uploaded artifact.
   - Pipeline Scanner: `veracode pipeline-scan` on the built artifact, or
   - Veracode Platform / GitHub integration: link the repo and start a scan.

## What to capture

- Scan ID, build/version, date, files analyzed, findings, CWE, severity, file + line, remediation guidance, any false positives.

## Analysis

- Map each finding to `EXPECTED-SAST-FINDINGS.md` (Expected vs Actually detected).
- Do **not** assume every intentionally planted pattern is detected — note false negatives.
- Keep the baseline branch intentionally vulnerable; remediation goes on a separate branch.

## Remediation pass

For each finding: fix using the `*-secure` function already in the repo, run `npm test`, commit, re-scan, compare before/after.

## Limitations

Some patterns (e.g. view-level XSS via `<%- %>`, broad CORS) may be flagged as low or not at all depending on Veracode's EJS/Express coverage. Record that explicitly.
