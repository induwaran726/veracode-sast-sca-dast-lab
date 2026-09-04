"use strict";

const { isAdminEmail } = require("../auth");

/**
 * VULNERABLE [SAST-011][CWE-862][OWASP A01]
 * checkAdminVulnerable trusts the client-supplied role claim.
 * Any caller can pass role=admin (query, body, or header) to bypass.
 *
 * Mitigation: use middleware/authMiddleware.js requireAdmin instead.
 */
function checkAdminVulnerable(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) return res.status(401).json({ error: "authentication required" });

  // VULNERABLE: role comes from client-controlled input, not the server session
  const role =
    req.query.role || (req.body && req.body.role) || req.headers["x-role"] || user.role;

  if (role === "admin") return next();
  return res.status(403).json({ error: "forbidden" });
}

module.exports = { checkAdminVulnerable };
