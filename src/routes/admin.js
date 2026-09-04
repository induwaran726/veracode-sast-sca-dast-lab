"use strict";

const express = require("express");
const router = express.Router();
const db = require("../database");
const { requireLogin, requireAdmin } = require("../middleware/authMiddleware");
const { checkAdminVulnerable } = require("../middleware/adminMiddleware");

// SECURE baseline: server-side admin check (normal user -> 403)
router.get("/admin", requireLogin, requireAdmin, (req, res) => {
  const users = db.get().prepare("SELECT id, email, name, role, balance FROM users").all();
  res.render("admin", { user: req.session.user, users });
});

// VULNERABLE (SAST-018 / CWE-863): role accepted from client input
router.get("/admin/users", requireLogin, checkAdminVulnerable, (req, res) => {
  const users = db.get().prepare("SELECT id, email, name, role, balance, api_key FROM users").all();
  res.json({ users }); // VULNERABLE: also leaks api_key [CWE-200]
});

// VULNERABLE (A05): debug endpoint exposing environment details
router.get("/admin/debug", requireLogin, (req, res) => {
  res.json({
    node: process.version,
    env: process.env.NODE_ENV,
    cwd: process.cwd(), // VULNERABLE: server info disclosure
    uptime: process.uptime(),
  });
});

// VULNERABLE (A01): balance update without authorization (mass assignment style)
router.post("/admin/balance", requireLogin, (req, res) => {
  const dbmod = require("../vulnerabilities/a01-access-control");
  try {
    const updated = dbmod.updateUserBalanceVulnerable(req.body.userId, req.body.balance);
    res.json({ updated });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// SECURE variant with authorization
router.post("/admin/balance-secure", requireLogin, requireAdmin, (req, res) => {
  const dbmod = require("../vulnerabilities/a01-access-control");
  try {
    const updated = dbmod.updateUserBalanceSecure(req.session.user, req.body.userId, req.body.balance);
    res.json({ updated });
  } catch (e) {
    res.status(e.status || 400).json({ error: e.message });
  }
});

module.exports = router;
