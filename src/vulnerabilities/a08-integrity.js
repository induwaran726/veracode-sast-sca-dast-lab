"use strict";

const db = require("../database");
const { applyUserPreferencesVulnerable } = require("./a04-design");

/**
 * A08 - Software and Data Integrity Failures
 * SAST-022 Untrusted deserialization / trust boundary [CWE-502]
 * SAST-023 Client-controlled integrity decision      [CWE-345]
 *
 * SAFE IMPLEMENTATION NOTE: no code-execution deserialization gadget is used
 * (e.g. no node-serialize). JSON-only patterns demonstrate the trust boundary.
 */

// VULNERABLE: client-supplied "state" is deserialized and merged without
// validation - caller can override role, balance, api_key fields.
function deserializeProfileStateVulnerable(user, clientStateJson) {
  return applyUserPreferencesVulnerable(user, clientStateJson);
}

// VULNERABLE: trust client-supplied checksum instead of computing one
function verifyOrderIntegrityVulnerable(orderId, clientChecksum, trustedChecksum) {
  return clientChecksum === trustedChecksum; // client decides integrity
}

// SECURE: server computes checksum over canonical order data
const crypto = require("node:crypto");
function computeOrderChecksum(order) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET || "lab-only-insecure-dev-secret")
    .update(`${order.id}|${order.user_id}|${order.product_id}|${order.quantity}|${order.total_price}`)
    .digest("hex");
}

function verifyOrderIntegritySecure(order, clientChecksum) {
  const expected = computeOrderChecksum(order);
  if (!clientChecksum || typeof clientChecksum !== "string") return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(clientChecksum, "hex"), Buffer.from(expected, "hex"));
  } catch (e) {
    return false;
  }
}

module.exports = {
  deserializeProfileStateVulnerable,
  verifyOrderIntegrityVulnerable,
  computeOrderChecksum,
  verifyOrderIntegritySecure,
};
