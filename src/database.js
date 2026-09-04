"use strict";

const { DatabaseSync } = require("node:sqlite");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");

const DB_PATH = process.env.LAB_DB_PATH || path.join(__dirname, "..", "data", "lab.db");

let db;

function init() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new DatabaseSync(DB_PATH);

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      name TEXT,
      password_hash TEXT,
      role TEXT DEFAULT 'user',
      balance INTEGER DEFAULT 1000,
      api_key TEXT
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price INTEGER NOT NULL,
      stock INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER DEFAULT 1,
      total_price INTEGER NOT NULL,
      status TEXT DEFAULT 'new',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      author TEXT,
      body TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT,
      detail TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  seed();
  return db;
}

function seed() {
  const count = db.prepare("SELECT COUNT(*) AS c FROM products").get().c;
  if (count > 0) return;

  const insertProduct = db.prepare(
    "INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)"
  );
  insertProduct.run("Synthetic Widget", "Demo product A (synthetic data)", 25, 100);
  insertProduct.run("Demo Gadget", "Demo product B (synthetic data)", 50, 50);
  insertProduct.run("Lab Gismo", "Demo product C (synthetic data)", 10, 200);

  // NOTE: hash values below are synthetic lab fixtures, not real credentials.
  const insertUser = db.prepare(
    "INSERT INTO users (email, name, password_hash, role, balance, api_key) VALUES (?, ?, ?, ?, ?, ?)"
  );
  insertUser.run("dast-admin@example.com", "DAST Admin", md5("synthetic-lab-password"), "admin", 5000, "SYNTHETIC-ADMIN-KEY-0001");
  insertUser.run("dast-user@example.com", "DAST Test User", md5("synthetic-lab-password"), "user", 1000, "SYNTHETIC-USER-KEY-0002");
}

function md5(input) {
  // Intentionally weak (see vulnerabilities/a02-crypto.js) - fixtures only
  return crypto.createHash("md5").update(String(input)).digest("hex");
}

function get() {
  if (!db) init();
  return db;
}

module.exports = { init, get, md5, DB_PATH };
