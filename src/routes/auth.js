"use strict";

const express = require("express");
const crypto = require("node:crypto");
const router = express.Router();

const config = require("../config");
const auth = require("../auth");
const a07 = require("../vulnerabilities/a07-authentication");

// VULNERABLE (SAST-020): session is NOT regenerated on login (session fixation).
// SECURE alternative noted inline.

router.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  res.redirect(auth.buildAuthorizeUrl(state));
});

router.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  // VULNERABLE (A07/A09): state validation failure is not logged
  if (error) {
    a07.recordAuthEventVulnerable("login-error", null); // no logging happens
    return res.status(401).render("error", { message: "Authentication failed", user: null });
  }
  if (!code) {
    return res.status(400).render("error", { message: "Missing authorization code", user: null });
  }
  if (!state || state !== req.session.oauthState) {
    // VULNERABLE: mismatch is silently tolerated for lab demonstration.
    // SECURE: return res.status(401).send("state mismatch");
  }

  try {
    const tokens = await auth.exchangeCodeForTokens(code);
    const claims = auth.decodeIdClaims(tokens.id_token);
    if (!claims) throw new Error("invalid id_token");

    // VULNERABLE: session not regenerated after authentication (CWE-384)
    req.session.user = {
      email: claims.preferred_username || claims.email,
      name: claims.name || "Unknown",
      role: auth.isAdminEmail(claims.preferred_username || claims.email) ? "admin" : "user",
      sub: claims.oid || claims.sub,
    };
    delete req.session.oauthState;

    return res.redirect("/dashboard");
  } catch (err) {
    a07.recordAuthEventVulnerable("login-failure", null);
    return res.status(401).render("error", { message: "Authentication failed", user: null });
  }
});

router.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

module.exports = router;
