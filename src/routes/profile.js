"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");
const a04 = require("../vulnerabilities/a04-design");
const a09 = require("../vulnerabilities/a09-logging");

router.get("/profile", requireLogin, (req, res) => {
  res.render("profile", { user: req.session.user, result: null });
});

// VULNERABLE (A08/A04): accepts client JSON state and merges without validation
router.post("/profile/state", requireLogin, (req, res) => {
  const merged = a04.applyUserPreferencesVulnerable(req.session.user, req.body.state || "{}");
  req.session.user = { ...req.session.user, ...merged }; // VULNERABLE: role override possible
  res.json({ ok: true, user: req.session.user });
});

// SECURE variant
router.post("/profile/state-secure", requireLogin, (req, res) => {
  const merged = a04.applyUserPreferencesSecure(req.session.user, req.body.state || "{}");
  req.session.user = { ...req.session.user, ...merged };
  a09.logUserEventSecure(req.session.user, "profile-state-secure");
  res.json({ ok: true, user: { email: req.session.user.email, name: req.session.user.name } });
});

module.exports = router;
