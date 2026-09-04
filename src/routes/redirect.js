"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");

// VULNERABLE (SAST-017 / CWE-601): unvalidated open redirect
router.get("/redirect", requireLogin, (req, res) => {
  const url = req.query.url || "/";
  res.redirect(url); // VULNERABLE: arbitrary off-site redirect
});

// SECURE variant: relative-path allowlist
router.get("/redirect-secure", requireLogin, (req, res) => {
  const url = req.query.url || "/";
  if (typeof url === "string" && url.startsWith("/") && !url.startsWith("//")) {
    return res.redirect(url);
  }
  res.status(400).send("redirect target not allowed");
});

module.exports = router;
