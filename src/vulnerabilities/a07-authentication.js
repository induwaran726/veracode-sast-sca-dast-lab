"use strict";

const jwt = require("jsonwebtoken"); // intentionally pinned vulnerable version (see SCA plan)
const db = require("../database");

/**
 * A07 - Identification and Authentication Failures
 * SAST-019 JWT with none-weak secret fallback    [CWE-347]
 * SAST-020 Session fixation (session not regenerated on login) [CWE-384]
 * SAST-021 Missing auth-failure logging          [CWE-778]
 *
 * NOTE: per lab policy, NO credential phishing/harvesting/spraying patterns
 * are implemented. Entra ID remains the authentication provider.
 */

// VULNERABLE: weak hardcoded fallback secret + alg not pinned
const JWT_SECRET = process.env.SESSION_SECRET || "lab-super-secret-fallback"; // SAST: hardcoded secret

function signTokenVulnerable(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "24h" }); // 24h session lifetime
}

function verifyTokenVulnerable(token) {
  try {
    return jwt.verify(token, JWT_SECRET); // does not pin algorithms
  } catch (e) {
    return null;
  }
}

// SECURE: strong secret required, algorithm pinned, short lifetime
function signTokenSecure(payload, secret) {
  if (!secret || secret.length < 32) throw new Error("secret too weak");
  return jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "15m" });
}

function verifyTokenSecure(token, secret) {
  try {
    return jwt.verify(token, secret, { algorithms: ["HS256"] });
  } catch (e) {
    return null;
  }
}

// VULNERABLE: authentication failure not logged at all
function recordAuthEventVulnerable(event, user) {
  // intentionally does nothing - A09/A07 finding
  return;
}

// SECURE: security events recorded to audit log without sensitive values
function recordAuthEventSecure(event, user) {
  const email = user && user.email ? user.email : "anonymous";
  db.get()
    .prepare("INSERT INTO audit_log (event, detail) VALUES (?, ?)")
    .run(event, `user=${email} outcome=recorded`);
}

module.exports = {
  signTokenVulnerable,
  verifyTokenVulnerable,
  signTokenSecure,
  verifyTokenSecure,
  recordAuthEventVulnerable,
  recordAuthEventSecure,
};
