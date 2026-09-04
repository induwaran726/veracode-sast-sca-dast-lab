"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");

// VULNERABLE (SAST-010 / CWE-79): reflected XSS - q is rendered raw via <%- %>
router.get("/search", requireLogin, (req, res) => {
  res.render("search", {
    user: req.session.user,
    q: req.query.q || "",
    qRaw: req.query.q || "", // rendered unescaped in view (lab)
  });
});

// SECURE variant: output escaped
router.get("/search-secure", requireLogin, (req, res) => {
  const a03 = require("../vulnerabilities/a03-injection");
  res.render("search-secure", {
    user: req.session.user,
    q: a03.escapeHtml(req.query.q || ""),
  });
});

module.exports = router;
