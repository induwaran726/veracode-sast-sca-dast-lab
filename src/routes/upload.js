"use strict";

const express = require("express");
const path = require("node:path");
const fs = require("node:fs");
const router = express.Router();
const { requireLogin } = require("../middleware/authMiddleware");

const UPLOAD_DIR = path.join(__dirname, "..", "..", "data", "uploads");

router.get("/upload", requireLogin, (req, res) => {
  res.render("upload", { user: req.session.user, result: null });
});

// VULNERABLE (SAST-003 / CWE-22): user-controlled filename joined into a path
router.post("/upload", requireLogin, (req, res) => {
  const name = req.headers["x-file-name"] || "default.txt";
  const target = path.join(UPLOAD_DIR, name); // VULNERABLE: no validation ("../../" escapes)
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  let written = "";
  if (req.body && typeof req.body.content === "string") {
    // Restrict writes to the lab upload dir at RUNTIME to keep the lab safe,
    // while the vulnerable path-construction remains for SAST detection.
    const resolved = path.resolve(UPLOAD_DIR, name);
    if (!resolved.startsWith(path.resolve(UPLOAD_DIR))) {
      return res.status(400).send("lab runtime guard: path traversal blocked (see SECURITY-TESTING.md)");
    }
    fs.writeFileSync(resolved, req.body.content);
    written = resolved;
  }
  res.render("upload", { user: req.session.user, result: { target, written } });
});

// SECURE variant: sanitized filename + containment check
router.post("/upload-secure", requireLogin, (req, res) => {
  const name = req.headers["x-file-name"] || "default.txt";
  const safe = path.basename(String(name)).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 64);
  const resolved = path.resolve(UPLOAD_DIR, safe);
  if (!resolved.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) {
    return res.status(400).send("invalid path");
  }
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.writeFileSync(resolved, String((req.body && req.body.content) || ""));
  res.render("upload", { user: req.session.user, result: { target: safe, written: resolved } });
});

module.exports = router;
