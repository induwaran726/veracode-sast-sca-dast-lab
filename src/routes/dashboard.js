"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");
const a09 = require("../vulnerabilities/a09-logging");

router.get("/dashboard", requireLogin, (req, res) => {
  // VULNERABLE (SAST-024): sensitive session material logged
  a09.logUserEventVulnerable(req.session.user, "dashboard-view");
  res.render("dashboard", {
    user: req.session.user,
    banner: "AUTHENTICATED_DAST_TEST_USER",
  });
});

module.exports = router;
