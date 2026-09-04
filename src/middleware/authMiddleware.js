"use strict";

const { isAdminEmail } = require("../auth");

/**
 * requireLogin - SECURE baseline middleware: rejects unauthenticated requests.
 */
function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.accepts("html")) return res.redirect("/login");
  return res.status(401).json({ error: "authentication required" });
}

/**
 * requireAdmin - SECURE baseline: server-side role check against configured
 * ADMIN_EMAIL. Never trusts client-supplied role/headers.
 */
function requireAdmin(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) {
    if (req.accepts("html")) return res.redirect("/login");
    return res.status(401).json({ error: "authentication required" });
  }
  if (!isAdminEmail(user.email) && user.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  return next();
}

module.exports = { requireLogin, requireAdmin };
