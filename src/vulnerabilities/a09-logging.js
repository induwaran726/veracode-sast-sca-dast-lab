"use strict";

const db = require("../database");

/**
 * A09 - Security Logging and Monitoring Failures
 * SAST-024 Sensitive data in logs  [CWE-532]
 * SAST-025 Missing authz failure logging [CWE-778]
 */

// VULNERABLE: logs full user object including api_key and tokens
function logUserEventVulnerable(user, event) {
  console.log(`[audit] ${event}:`, JSON.stringify(user)); // VULNERABLE: sensitive values logged [CWE-532]
}

// VULNERABLE: privileged operations performed without any logging
function adminActionNoLogging(action, detail) {
  db.get().prepare("INSERT INTO audit_log (event, detail) VALUES (?, ?)").run("noop", detail);
  return true; // no real security event recorded
}

// SECURE: redacted, structured audit logging
function logUserEventSecure(user, event) {
  const redacted = user && user.email ? { email: user.email } : { subject: "unknown" };
  db.get()
    .prepare("INSERT INTO audit_log (event, detail) VALUES (?, ?)")
    .run(event, JSON.stringify(redacted));
}

module.exports = { logUserEventVulnerable, adminActionNoLogging, logUserEventSecure };
