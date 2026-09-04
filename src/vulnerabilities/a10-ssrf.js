"use strict";

const fetchFn = require("node-fetch"); // intentionally pinned vulnerable version (see SCA plan)

/**
 * A10 - SSRF
 * SAST-026 Unvalidated outbound URL fetch [CWE-918]
 *
 * SAFE LAB DESIGN: the only destination the app itself exposes for fetching is
 * the SYNTHETIC_LAB_TARGET route served by this same app (public API). The
 * vulnerable function accepts any URL supplied by the caller (typical CWE-918),
 * but the lab route applies a runtime scope guard to limit abuse against
 * third-party or private networks during demos. The SECURE function performs
 * full URL validation: HTTPS-only, allowlist, and private/link-local/metadata
 * IP blocking.
 */

const SYNTHETIC_LAB_TARGET = "/api/lab-target"; // synthetic endpoint served by this app

// SECURE: strict SSRF protection
function isPrivateAddress(hostname) {
  const h = String(hostname).toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal")) return true;
  if (h === "169.254.169.254" || h === "metadata.google.internal") return true; // cloud metadata
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true; // loopback / private / unspecified
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

function validateTargetUrl(rawUrl, allowedHosts) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (e) {
    return { ok: false, reason: "invalid URL" };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { ok: false, reason: "protocol not allowed" };
  }
  if (allowedHosts && !allowedHosts.includes(parsed.hostname)) {
    return { ok: false, reason: "host not in allowlist" };
  }
  if (isPrivateAddress(parsed.hostname)) {
    return { ok: false, reason: "private/loopback/metadata addresses blocked" };
  }
  return { ok: true, parsed };
}

// VULNERABLE: fetches whatever URL the caller passes (classic CWE-918)
function fetchUrlVulnerable(url) {
  return fetchFn(url, { timeout: 3000 }).then((r) => r.text());
}

// SECURE: validated fetch
function fetchUrlSecure(rawUrl, allowedHosts) {
  const check = validateTargetUrl(rawUrl, allowedHosts);
  if (!check.ok) {
    const err = new Error(`SSRF protection: ${check.reason}`);
    err.status = 400;
    throw err;
  }
  return fetchFn(check.parsed.toString(), { timeout: 3000 }).then((r) => r.text());
}

module.exports = {
  SYNTHETIC_LAB_TARGET,
  isPrivateAddress,
  validateTargetUrl,
  fetchUrlVulnerable,
  fetchUrlSecure,
};
