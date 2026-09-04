"use strict";

const express = require("express");
const router = express.Router();
const db = require("../database");
const { requireLogin } = require("../middleware/authMiddleware");
const a01 = require("../vulnerabilities/a01-access-control");
const a04 = require("../vulnerabilities/a04-design");

router.get("/orders", requireLogin, (req, res) => {
  const orders = db
    .get()
    .prepare("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC")
    .all(req.session.user.dbId || 0);
  res.render("orders", { user: req.session.user, orders });
});

// VULNERABLE (SAST-001 / CWE-639): no ownership check - classic IDOR
router.get("/orders/:id", requireLogin, (req, res) => {
  const order = a01.getOrderVulnerable(req.params.id);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json({ order }); // any user's order returned
});

// SECURE variant
router.get("/orders-secure/:id", requireLogin, (req, res) => {
  const order = a01.getOrderSecure(req.params.id, req.session.user.dbId || 0);
  if (!order) return res.status(404).json({ error: "not found" });
  res.json({ order });
});

// VULNERABLE (A04): client-supplied total trusted
router.post("/orders", requireLogin, (req, res) => {
  const { productId, quantity, total } = req.body;
  const order = a04.createOrderVulnerable(req.session.user.dbId || 0, productId, quantity, total);
  res.status(201).json({ order });
});

// SECURE variant: server computes price
router.post("/orders-secure", requireLogin, (req, res) => {
  try {
    const order = a04.createOrderSecure(req.session.user.dbId || 0, req.body.productId, req.body.quantity);
    res.status(201).json({ order });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

module.exports = router;
