"use strict";

const db = require("../database");

/**
 * A01 - Broken Access Control
 * SAST-001 IDOR on order lookup        [CWE-639]
 * SAST-002 Missing function-level authz [CWE-862]
 * SAST-003 Client-controlled role       [CWE-863]
 */

// VULNERABLE: no ownership check - any authenticated user can read any order
function getOrderVulnerable(orderId) {
  return db
    .get()
    .prepare("SELECT * FROM orders WHERE id = " + Number(orderId))
    .get();
}

// SECURE: ownership enforced in the query itself
function getOrderSecure(orderId, userId) {
  return db
    .get()
    .prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?")
    .get(orderId, userId);
}

// VULNERABLE: mass-assignment style update of another user's balance (admin op
// exposed without authorization)
function updateUserBalanceVulnerable(userId, balance) {
  db.get()
    .prepare("UPDATE users SET balance = ? WHERE id = ?")
    .run(balance, userId);
  return db.get().prepare("SELECT id, email, balance FROM users WHERE id = ?").get(userId);
}

// SECURE: role verified server-side before privileged mutation
function updateUserBalanceSecure(requester, userId, balance) {
  if (!requester || requester.role !== "admin") {
    const err = new Error("forbidden");
    err.status = 403;
    throw err;
  }
  db.get()
    .prepare("UPDATE users SET balance = ? WHERE id = ?")
    .run(balance, userId);
  return db.get().prepare("SELECT id, email, balance FROM users WHERE id = ?").get(userId);
}

module.exports = {
  getOrderVulnerable,
  getOrderSecure,
  updateUserBalanceVulnerable,
  updateUserBalanceSecure,
};
