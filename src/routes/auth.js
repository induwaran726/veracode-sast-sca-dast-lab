"use strict";

const express = require("express");
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const router = express.Router();

const config = require("../config");
const authEntra = require("../auth");
const db = require("../database");
const a07 = require("../vulnerabilities/a07-authentication");
const a11 = require("../vulnerabilities/a11-local-auth");

function buildCommonSession(row, authMethod) {
  return {
    id: row.id,
    dbId: row.id,
    email: row.email,
    name: row.name,
    displayName: row.name,
    role: row.role,
    authMethod: authMethod, // "local" | "entra-sso"
  };
}

// GET /login — selection page
router.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.render("login", { user: null, error: null, localEnabled: config.localAuth.enabled });
});

// GET /login/local — form
router.get("/login/local", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  if (!config.localAuth.enabled) return res.status(404).render("error", { message: "Local auth disabled", user: null });
  res.render("login-local", { user: null, error: null });
});

// POST /login/local — secure local auth (vulnerable variants isolated in a11-local-auth.js)
router.post("/login/local", (req, res) => {
  if (!config.localAuth.enabled) return res.status(404).render("error", { message: "Local auth disabled", user: null });
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const row = db.get().prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!row) {
    // SECURE: generic error, no enumeration, event logged
    a07.recordAuthEventSecure("local-login-failure", { email });
    return res.status(401).render("login-local", { user: null, error: a11.loginErrorSecure() });
  }
  if (!a11.isAllowedToLoginSecure(row)) {
    a07.recordAuthEventSecure("local-login-inactive", { email });
    return res.status(401).render("login-local", { user: null, error: a11.loginErrorSecure() });
  }
  if (!a11.verifyPasswordSecure(row.password_hash, password)) {
    a07.recordAuthEventSecure("local-login-failure", { email });
    return res.status(401).render("login-local", { user: null, error: a11.loginErrorSecure() });
  }

  // VULNERABLE note: session fixation (no regeneration) retained for lab SAST (CWE-384)
  // SECURE alternative would be req.session.regenerate(...)
  req.session.user = buildCommonSession(row, "local");
  return res.redirect("/dashboard");
});

// GET /login/sso — Entra SSO entry
router.get("/login/sso", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  res.redirect(authEntra.buildAuthorizeUrl(state));
});

// GET /auth/callback — Entra callback, maps to common session via server-side role lookup
router.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    a07.recordAuthEventSecure("sso-login-error", null);
    return res.status(401).render("error", { message: "Authentication failed", user: null });
  }
  if (!code) {
    return res.status(400).render("error", { message: "Missing authorization code", user: null });
  }
  if (!state || state !== req.session.oauthState) {
    // silently tolerated for lab demonstration (SAST can flag)
  }

  try {
    const tokens = await authEntra.exchangeCodeForTokens(code);
    const claims = authEntra.decodeIdClaims(tokens.id_token);
    if (!claims) throw new Error("invalid id_token");
    const email = String(claims.preferred_username || claims.email || "").toLowerCase();
    if (!email) throw new Error("no email in claims");

    // Server-side user mapping: look up or create app user, role from ADMIN_EMAIL, not client
    let row = db.get().prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!row) {
      const role = authEntra.isAdminEmail(email) ? "admin" : "user";
      const info = db
        .get()
        .prepare("INSERT INTO users (email, name, password_hash, role, balance, api_key, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)")
        .run(email, claims.name || email, "", role, 1000, "SYNTHETIC-SSO-KEY-" + Date.now());
      row = db.get().prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
    }
    if (!a11.isAllowedToLoginSecure(row)) {
      return res.status(403).render("error", { message: "Account disabled", user: null });
    }

    req.session.user = buildCommonSession(row, "entra-sso");
    delete req.session.oauthState;
    return res.redirect("/dashboard");
  } catch (err) {
    a07.recordAuthEventSecure("sso-login-failure", null);
    return res.status(401).render("error", { message: "Authentication failed", user: null });
  }
});

// GET /logout — common logout for both methods (local session destroy; SSO local-only per docs)
router.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("lab.sid");
    res.redirect("/");
  });
});

module.exports = router;
