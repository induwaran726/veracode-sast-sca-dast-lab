"use strict";

const db = require("../database");
const lodash = require("lodash"); // intentionally pinned vulnerable version (see SCA plan)

/**
 * A04 - Insecure Design
 * SAST-013 Client-controlled price (order flow)  [CWE-602 / OWASP A04]
 * SAST-014 Trusted client authorization decision [CWE-602]
 */

// VULNERABLE: total price taken from the client instead of computed server-side
function createOrderVulnerable(userId, productId, quantity, clientTotal) {
  const total = Number(clientTotal); // trusts client
  const info = db
    .get()
    .prepare(
      "INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)"
    )
    .run(userId, productId, quantity, total);
  return db.get().prepare("SELECT * FROM orders WHERE id = ?").get(info.lastInsertRowid);
}

// SECURE: price computed from the database, quantity bounded
function createOrderSecure(userId, productId, quantity) {
  const qty = Math.max(1, Math.min(Number(quantity) || 1, 10));
  const product = db.get().prepare("SELECT * FROM products WHERE id = ?").get(productId);
  if (!product) throw new Error("product not found");
  const total = product.price * qty;
  const info = db
    .get()
    .prepare(
      "INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)"
    )
    .run(userId, productId, qty, total);
  return db.get().prepare("SELECT * FROM orders WHERE id = ?").get(info.lastInsertRowid);
}

// VULNERABLE: insecure merge of client state into a user object (mass
// assignment / trust boundary, also demonstrates lodash merge usage)
function applyUserPreferencesVulnerable(user, clientStateJson) {
  let parsed;
  try {
    parsed = JSON.parse(clientStateJson); // VULNERABLE: untrusted JSON trusted wholesale [CWE-502 variant]
  } catch (e) {
    parsed = {};
  }
  return lodash.merge({}, user, parsed); // client can override role/balance/api_key
}

// SECURE: explicit field allowlist
function applyUserPreferencesSecure(user, clientStateJson) {
  let parsed;
  try {
    parsed = JSON.parse(clientStateJson);
  } catch (e) {
    parsed = {};
  }
  const allowed = {};
  if (typeof parsed.theme === "string") allowed.theme = parsed.theme.slice(0, 20);
  return { ...user, ...allowed };
}

module.exports = {
  createOrderVulnerable,
  createOrderSecure,
  applyUserPreferencesVulnerable,
  applyUserPreferencesSecure,
};
