"use strict";

const express = require("express");
const router = express.Router();
const db = require("../database");
const { requireLogin } = require("../middleware/authMiddleware");
const a03 = require("../vulnerabilities/a03-injection");

router.get("/products", requireLogin, (req, res) => {
  const products = db.get().prepare("SELECT id, name, description, price, stock FROM products").all();
  res.render("products", { user: req.session.user, products });
});

// VULNERABLE (A03): id interpolated into SQL
router.get("/products/:id", requireLogin, (req, res) => {
  const query = "SELECT * FROM products WHERE id = " + req.params.id; // VULNERABLE [CWE-89]
  let product;
  try {
    product = db.get().prepare(query).get();
  } catch (e) {
    return res.status(400).send("Bad request");
  }
  if (!product) return res.status(404).render("error", { message: "Product not found", user: req.session.user });
  res.render("product", { user: req.session.user, product });
});

// SECURE variant
router.get("/products-secure/:id", requireLogin, (req, res) => {
  const product = db
    .get()
    .prepare("SELECT * FROM products WHERE id = ?")
    .get(req.params.id);
  if (!product) return res.status(404).render("error", { message: "Product not found", user: req.session.user });
  res.render("product", { user: req.session.user, product });
});

// VULNERABLE search (SQL LIKE injection); SECURE variant also exposed
router.get("/products/search", requireLogin, (req, res) => {
  const term = req.query.q || "";
  let products;
  try {
    products = a03.searchProductsVulnerable(term);
  } catch (e) {
    return res.status(400).json({ error: "bad query" });
  }
  res.json({ query: term, products });
});

router.get("/products/search-secure", requireLogin, (req, res) => {
  const products = a03.searchProductsSecure(req.query.q || "");
  res.json({ products });
});

module.exports = router;
