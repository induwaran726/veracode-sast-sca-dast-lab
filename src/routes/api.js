"use strict";

const express = require("express");
const router = express.Router();
const db = require("../database");
const { requireLogin } = require("../middleware/authMiddleware");
const a01 = require("../vulnerabilities/a01-access-control");
const a10 = require("../vulnerabilities/a10-ssrf");

router.get("/api", requireLogin, (req, res) => {
  res.json({
    version: "1.0.0",
    endpoints: [
      "/api/users (VULNERABLE: excessive data exposure)",
      "/api/users/:id (VULNERABLE: IDOR)",
      "/api/users-secure/:id (SECURE)",
      "/api/products",
      "/api/orders",
      "/api/orders/:id (VULNERABLE: IDOR) | /api/orders-secure/:id (SECURE)",
      "/api/profile",
      "/api/lab-target (synthetic SSRF target)",
    ],
  });
});

// VULNERABLE (SAST-008 / CWE-200): returns password_hash and api_key
router.get("/api/users", requireLogin, (req, res) => {
  const users = db.get().prepare("SELECT * FROM users").all();
  res.json({ users }); // excessive data exposure
});

// SECURE variant
router.get("/api/users-secure", requireLogin, (req, res) => {
  const users = db
    .get()
    .prepare("SELECT id, email, name, role FROM users")
    .all();
  res.json({ users });
});

// VULNERABLE (CWE-639): fetches any user by id, no ownership/admin check
router.get("/api/users/:id", requireLogin, (req, res) => {
  const row = db.get().prepare("SELECT * FROM users WHERE id = " + Number(req.params.id)).get();
  if (!row) return res.status(404).json({ error: "not found" });
  res.json({ user: row }); // leaks api_key/password_hash
});

// SECURE variant
router.get("/api/users-secure/:id", requireLogin, (req, res) => {
  const row = db
    .get()
    .prepare("SELECT id, email, name, role FROM users WHERE id = ?")
    .get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json({ user: row });
});

router.get("/api/products", requireLogin, (req, res) => {
  res.json({ products: db.get().prepare("SELECT id, name, price, stock FROM products").all() });
});

router.get("/api/orders", requireLogin, (req, res) => {
  res.json({ orders: db.get().prepare("SELECT * FROM orders").all() }); // VULNERABLE: all users' orders
});

router.get("/api/orders/:id", requireLogin, (req, res) => {
  const order = a01.getOrderVulnerable(req.params.id);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json({ order });
});

router.get("/api/orders-secure/:id", requireLogin, (req, res) => {
  const order = a01.getOrderSecure(req.params.id, req.session.user.dbId || 0);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json({ order });
});

router.get("/api/profile", requireLogin, (req, res) => {
  res.json({ profile: req.session.user });
});

// Synthetic endpoint used as the ONLY in-app fetch target for the SSRF lab.
// Serves synthetic lab data only - no internal network access involved.
router.get("/api/lab-target", (req, res) => {
  res.json({ synthetic: true, message: "SSRF lab synthetic target", ts: Date.now() });
});

// SSRF demonstration endpoints.
// Runtime scope guard: during demos the vulnerable fetch is only followed when
// the URL points back at this app's own public origin, preventing abuse against
// third-party or private networks. The unvalidated code pattern remains for SAST.
router.get("/api/ssrf-vulnerable", requireLogin, (req, res) => {
  const url = req.query.url || "";
  const ownOrigin = `${req.protocol}://${req.get("host")}`;
  if (!url.startsWith(ownOrigin)) {
    return res
      .status(400)
      .send("lab runtime guard: fetch limited to this app's origin (see SECURITY-TESTING.md)");
  }
  a10
    .fetchUrlVulnerable(url)
    .then((body) => res.type("text").send(body))
    .catch(() => res.status(502).send("fetch failed"));
});

router.get("/api/ssrf-secure", requireLogin, (req, res) => {
  const url = req.query.url || "";
  const ownOrigin = `${req.protocol}://${req.get("host")}`;
  try {
    a10
      .fetchUrlSecure(url, [req.get("host")])
      .then((body) => res.type("text").send(body))
      .catch((e) => res.status(400).send(e.message));
  } catch (e) {
    res.status(400).send(e.message);
  }
});

module.exports = router;
