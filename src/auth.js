"use strict";

const config = require("./config");

/**
 * Hand-rolled Microsoft Entra ID OIDC authorization-code flow.
 * Scopes requested: openid profile email (only).
 * Callback URL is derived from BASE_URL (never hardcoded to a hostname).
 */

function buildAuthorizeUrl(state) {
  const tenant = config.entra.tenantId;
  const params = new URLSearchParams({
    client_id: config.entra.clientId,
    response_type: "code",
    redirect_uri: `${config.baseUrl}/auth/callback`,
    response_mode: "query",
    scope: config.entra.scopes,
    state: state,
  });
  return `${config.entra.authorizeUrl(tenant)}?${params.toString()}`;
}

async function exchangeCodeForTokens(code) {
  const tenant = config.entra.tenantId;
  const body = new URLSearchParams({
    client_id: config.entra.clientId,
    client_secret: config.entra.clientSecret,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: `${config.baseUrl}/auth/callback`,
  });

  const fetchFn = require("node-fetch");
  const resp = await fetchFn(config.entra.tokenUrl(tenant), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!resp.ok) {
    throw new Error(`Token exchange failed: ${resp.status}`);
  }
  return resp.json();
}

function decodeIdClaims(idToken) {
  // Payload-only decode; signature is trusted because token came directly
  // from the Entra token endpoint over TLS in the code-exchange response.
  try {
    const payload = idToken.split(".")[1];
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch (e) {
    return null;
  }
}

function isAdminEmail(email) {
  if (!email) return false;
  return String(email).toLowerCase() === String(config.adminEmail).toLowerCase();
}

module.exports = { buildAuthorizeUrl, exchangeCodeForTokens, decodeIdClaims, isAdminEmail };
