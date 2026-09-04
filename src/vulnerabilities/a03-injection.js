"use strict";

const db = require("../database");
const { isRuntimeSafeForDemo } = require("../middleware/validation");

/**
 * A03 - Injection
 * SAST-009 SQL Injection               [CWE-89]
 * SAST-010 Reflected XSS               [CWE-79]
 * SAST-011 Stored XSS                  [CWE-79]
 * SAST-012 Command Injection (guarded) [CWE-78]
 */

// VULNERABLE: string-concatenated SQL (classic CWE-89)
function findUserVulnerable(id) {
  const query = "SELECT id, email, name, role, balance FROM users WHERE id = " + id;
  return db.get().prepare(query).get();
}

// SECURE: parameterized
function findUserSecure(id) {
  if (!Number.isInteger(Number(id))) return undefined;
  return db
    .get()
    .prepare("SELECT id, email, name, role, balance FROM users WHERE id = ?")
    .get(Number(id));
}

// VULNERABLE: dynamic LIKE built from unsanitized input (SQLi via wildcard/quote)
function searchProductsVulnerable(term) {
  const query = "SELECT id, name, price FROM products WHERE name LIKE '%" + term + "%'";
  return db.get().prepare(query).all();
}

// SECURE: parameterized with escaped wildcards
function searchProductsSecure(term) {
  const safe = String(term).replace(/[%_]/g, "\\$&").slice(0, 100);
  return db
    .get()
    .prepare("SELECT id, name, price FROM products WHERE name LIKE '%' || ? || '%' ESCAPE '\\'")
    .all(safe);
}

// VULNERABLE: stored XSS payload persisted unescaped; rendered raw in view
function addCommentVulnerable(author, body) {
  db.get()
    .prepare("INSERT INTO comments (author, body) VALUES (?, ?)")
    .run(author, body);
}

// SECURE: sanitize on write (defense in depth; also escape on render)
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function addCommentSecure(author, body) {
  db.get()
    .prepare("INSERT INTO comments (author, body) VALUES (?, ?)")
    .run(escapeHtml(author), escapeHtml(body));
}

function listComments() {
  return db.get().prepare("SELECT * FROM comments ORDER BY id DESC LIMIT 50").all();
}

// VULNERABLE: command injection pattern (CWE-78).
// RUNTIME SAFETY GUARD: the lab route enforces an allowlist before reaching
// this function, so arbitrary commands cannot execute. The vulnerable SOURCE
// pattern is retained so SAST detects CWE-78. See SECURITY-TESTING.md.
const { exec } = require("node:child_process");
function pingHostVulnerable(host) {
  if (!isRuntimeSafeForDemo(host)) {
    const err = new Error("lab runtime guard: input rejected (see SECURITY-TESTING.md)");
    err.status = 400;
    throw err;
  }
  return new Promise((resolve) => {
    // SAST target: unsafe exec with concatenated input
    exec("echo simulated-ping-to " + host, { timeout: 2000 }, (err, stdout) => {
      resolve(stdout ? stdout.toString() : "");
    });
  });
}

function pingHostSecure(host) {
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) throw new Error("invalid host");
  return Promise.resolve(`simulated-ping-to ${host} (no shell used)`);
}

module.exports = {
  findUserVulnerable,
  findUserSecure,
  searchProductsVulnerable,
  searchProductsSecure,
  addCommentVulnerable,
  addCommentSecure,
  listComments,
  pingHostVulnerable,
  pingHostSecure,
  escapeHtml,
};
