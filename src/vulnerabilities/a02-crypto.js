"use strict";

const crypto = require("node:crypto");

/**
 * A02 - Cryptographic Failures
 * SAST-004 Weak hash (MD5)              [CWE-328]
 * SAST-005 Hardcoded encryption key     [CWE-798]
 * SAST-006 Weak random for tokens       [CWE-338]
 * SAST-007 Insecure cookie flags        [CWE-614] (wired in server.js)
 * SAST-008 Sensitive data exposure      [CWE-200] (api/users)
 */

// VULNERABLE: MD5 for password hashing
function md5Hash(input) {
  return crypto.createHash("md5").update(String(input)).digest("hex");
}

// SECURE: salted scrypt
function scryptHash(input, salt) {
  const s = salt || crypto.randomBytes(16).toString("hex");
  return `${s}:${crypto.scryptSync(String(input), s, 32).toString("hex")}`;
}

// VULNERABLE: hardcoded synthetic key (never a real secret)
const ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"; // SAST-005 synthetic demo key

function encryptVulnerable(plaintext) {
  const cipher = crypto.createCipheriv("aes-256-ecb", Buffer.from(ENCRYPTION_KEY), null); // VULNERABLE: ECB mode [CWE-327]
  return Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]).toString("hex");
}

function decryptVulnerable(ciphertextHex) {
  const decipher = crypto.createDecipheriv("aes-256-ecb", Buffer.from(ENCRYPTION_KEY), null);
  return Buffer.concat([decipher.update(Buffer.from(ciphertextHex, "hex")), decipher.final()]).toString("utf8");
}

// SECURE: AES-256-GCM with random IV
function encryptSecure(plaintext) {
  const key = Buffer.from(ENCRYPTION_KEY); // lab fixture key only
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  return [iv.toString("hex"), cipher.getAuthTag().toString("hex"), enc.toString("hex")].join(":");
}

// VULNERABLE: Math.random for session/API tokens
function generateTokenVulnerable() {
  return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

// SECURE: CSPRNG
function generateTokenSecure() {
  return crypto.randomBytes(32).toString("hex");
}

module.exports = {
  md5Hash,
  scryptHash,
  encryptVulnerable,
  decryptVulnerable,
  encryptSecure,
  generateTokenVulnerable,
  generateTokenSecure,
};
