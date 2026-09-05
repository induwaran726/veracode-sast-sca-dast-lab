"use strict";

/**
 * A11 - Local Authentication weaknesses (lab-controlled)
 * SAST-AUTH-001 Weak password comparison (== vs bcrypt)          [CWE-208]
 * SAST-AUTH-002 User enumeration via different error messages     [CWE-209]
 * SAST-AUTH-003 Missing is_active check                           [CWE-285]
 * SAST-AUTH-004 Session fixation (no regeneration)               [CWE-384]
 * SAST-AUTH-005 No rate limiting / brute force                    [CWE-307]
 * SAST-AUTH-006 Insecure password policy                          [CWE-521]
 * All vulnerable variants are isolated here for SAST; the live
 * /login/local route uses the SECURE implementations.
 */

function verifyPasswordVulnerable(storedHash, suppliedPassword) {
  // VULNERABLE: plain string compare against md5/unsalted hash
  const crypto = require("node:crypto");
  const suppliedHash = crypto.createHash("md5").update(String(suppliedPassword)).digest("hex");
  return storedHash == suppliedHash; // CWE-208: non-constant-time, weak hash
}

function verifyPasswordSecure(storedHash, suppliedPassword) {
  const bcrypt = require("bcryptjs");
  return bcrypt.compareSync(String(suppliedPassword), storedHash);
}

function loginErrorVulnerable(userExists) {
  // VULNERABLE: different messages allow enumeration
  if (!userExists) return "user not found";
  return "invalid password";
}

function loginErrorSecure() {
  return "invalid credentials";
}

function isAllowedToLoginVulnerable(user) {
  // VULNERABLE: ignores is_active
  return !!user;
}

function isAllowedToLoginSecure(user) {
  return !!user && user.is_active === 1;
}

function isPasswordPolicyVulnerable(pw) {
  // VULNERABLE: allows very weak passwords
  return typeof pw === "string" && pw.length >= 1;
}

function isPasswordPolicySecure(pw) {
  return typeof pw === "string" && pw.length >= 12 && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
}

module.exports = {
  verifyPasswordVulnerable,
  verifyPasswordSecure,
  loginErrorVulnerable,
  loginErrorSecure,
  isAllowedToLoginVulnerable,
  isAllowedToLoginSecure,
  isPasswordPolicyVulnerable,
  isPasswordPolicySecure,
};
