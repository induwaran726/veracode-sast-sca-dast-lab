"use strict";

/**
 * Input validation helpers.
 * VULNERABLE variants intentionally skip validation for SAST/DBD demonstration.
 */

const CONTROLLED_SAFE_CHARS = /^[a-zA-Z0-9 _-]*$/;

// SECURE: strict numeric ID validation
function isValidId(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 && n <= Number.MAX_SAFE_INTEGER;
}

// SECURE: allowlist-based string validation for search
function sanitizeQuery(q, maxLen = 100) {
  if (typeof q !== "string") return "";
  return q.replace(/[<>"'`\\%_;-]/g, "").slice(0, maxLen);
}

// Runtime safety guard used ONLY by the command-injection lab demonstration.
// The vulnerable SOURCE pattern is still present for SAST to flag; this guard
// ensures the demo can never execute arbitrary commands in the lab container.
function isRuntimeSafeForDemo(input) {
  return typeof input === "string" && input.length <= 32 && CONTROLLED_SAFE_CHARS.test(input);
}

module.exports = { isValidId, sanitizeQuery, isRuntimeSafeForDemo };
