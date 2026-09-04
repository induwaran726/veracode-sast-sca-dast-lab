"use strict";

const minimist = require("minimist"); // intentionally pinned vulnerable version (see SCA plan)

/**
 * A06 - Vulnerable and Outdated Components
 * Demonstrated primarily through Veracode SCA on package.json/package-lock.json.
 * This module documents (in code) the intentionally pinned vulnerable direct
 * dependencies. See EXPECTED-SCA-FINDINGS.md for the full catalog.
 *
 * SCA-001 lodash 4.17.15        - CVE-2020-8203, CVE-2021-23337 (fixed 4.17.21)
 * SCA-002 axios 0.21.1          - CVE-2021-3749 ReDoS (fixed 0.21.4)
 * SCA-003 jsonwebtoken 8.5.1    - CVE-2022-23529 et al. (fixed 9.0.0)
 * SCA-004 node-fetch 2.6.0      - CVE-2020-15168, CVE-2022-0235 (fixed 2.6.1 / 2.6.7)
 * SCA-005 minimist 1.2.0        - CVE-2020-7598, CVE-2021-44906 (fixed 1.2.3+)
 * SCA-006 express-fileupload 1.1.6 - CVE-2020-7699 (fixed 1.1.8)
 */

function parseArgsVulnerable(argv) {
  // minimist 1.2.0 is vulnerable to prototype pollution via --__proto__ payloads
  return minimist(argv || []);
}

module.exports = { parseArgsVulnerable };
