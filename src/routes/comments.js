"use strict";

const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");
const a03 = require("../vulnerabilities/a03-injection");

router.get("/comments", requireLogin, (req, res) => {
  const comments = a03.listComments();
  res.render("comments", {
    user: req.session.user,
    comments,
    mode: "vulnerable", // view renders body raw via <%- %>
  });
});

// SECURE variant: input sanitized
router.get("/comments-secure", requireLogin, (req, res) => {
  const comments = a03.listComments();
  res.render("comments", {
    user: req.session.user,
    comments,
    mode: "secure", // view escapes body via <%= %>
  });
});

// VULNERABLE: stores raw user input (stored XSS payload survives)
router.post("/comments", requireLogin, (req, res) => {
  const author = (req.session.user && req.session.user.name) || "anonymous";
  a03.addCommentVulnerable(author, String(req.body.body || ""));
  res.redirect("/comments");
});

// SECURE variant
router.post("/comments-secure", requireLogin, (req, res) => {
  const author = (req.session.user && req.session.user.name) || "anonymous";
  a03.addCommentSecure(author, String(req.body.body || ""));
  res.redirect("/comments-secure");
});

module.exports = router;
