"use strict";

/**
 * Security header helpers.
 * VULNERABLE (lab default): helmet is intentionally NOT enabled globally so
 * that DAST can detect missing security headers (OWASP A05).
 *
 * applySecureHeaders is the SECURE variant, wired to /security-lab/a05/*
 * demonstrations.
 */

const SECURE_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

function applySecureHeaders(req, res, next) {
  for (const [h, v] of Object.entries(SECURE_HEADERS)) res.setHeader(h, v);
  next();
}

module.exports = { applySecureHeaders, SECURE_HEADERS };
