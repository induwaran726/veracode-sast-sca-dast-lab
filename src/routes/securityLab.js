"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");

const CATALOG = [
  {
    owasp: "A01 Broken Access Control",
    file: "src/vulnerabilities/a01-access-control.js",
    cases: [
      { id: "idor", name: "IDOR on orders", vulnerable: "/orders/1 vs /orders-secure/1" },
      { id: "role", name: "Client-controlled role", vulnerable: "/admin/users?role=admin (403 without it)" },
    ],
  },
  {
    owasp: "A02 Cryptographic Failures",
    file: "src/vulnerabilities/a02-crypto.js",
    cases: [{ id: "crypto", name: "MD5/ECB/weak-random", vulnerable: "unit demonstration (see SAST-004..007)" }],
  },
  {
    owasp: "A03 Injection",
    file: "src/vulnerabilities/a03-injection.js",
    cases: [
      { id: "sqli", name: "SQL injection (products/:id)", vulnerable: "/products/1 OR 1=1" },
      { id: "xss-stored", name: "Stored XSS (comments)", vulnerable: "/comments vs /comments-secure" },
      { id: "cmdi", name: "Command injection pattern (guarded)", vulnerable: "unit demonstration" },
    ],
  },
  {
    owasp: "A04 Insecure Design",
    file: "src/vulnerabilities/a04-design.js",
    cases: [{ id: "price", name: "Client-controlled order total", vulnerable: "POST /orders {total: 1}" }],
  },
  {
    owasp: "A05 Security Misconfiguration",
    file: "src/vulnerabilities/a05-misconfiguration.js",
    cases: [
      { id: "headers", name: "Missing security headers (global)", vulnerable: "any response (DAST)" },
      { id: "debug", name: "Debug info disclosure", vulnerable: "/admin/debug" },
      { id: "cors", name: "Permissive CORS demo", vulnerable: "unit demonstration" },
    ],
  },
  {
    owasp: "A06 Vulnerable Components",
    file: "package.json",
    cases: [{ id: "sca", name: "Vulnerable npm dependencies", vulnerable: "Veracode SCA scan" }],
  },
  {
    owasp: "A07 Authentication Failures",
    file: "src/vulnerabilities/a07-authentication.js",
    cases: [{ id: "session", name: "Session fixation / weak JWT", vulnerable: "unit demonstration" }],
  },
  {
    owasp: "A08 Software and Data Integrity Failures",
    file: "src/vulnerabilities/a08-integrity.js",
    cases: [{ id: "deser", name: "Untrusted JSON state merge", vulnerable: "POST /profile/state" }],
  },
  {
    owasp: "A09 Security Logging and Monitoring Failures",
    file: "src/vulnerabilities/a09-logging.js",
    cases: [{ id: "logs", name: "Sensitive data in logs / missing audit", vulnerable: "code review (SAST)" }],
  },
  {
    owasp: "A10 SSRF",
    file: "src/vulnerabilities/a10-ssrf.js",
    cases: [
      { id: "ssrf", name: "Unvalidated fetch (scope-guarded)", vulnerable: "/api/ssrf-vulnerable?url=<own origin>" },
    ],
  },
];

router.get("/", requireLogin, (req, res) => {
  res.render("security-lab", { user: req.session.user, catalog: CATALOG });
});

module.exports = router;
