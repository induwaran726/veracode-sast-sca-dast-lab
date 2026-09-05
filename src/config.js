"use strict";

const config = {
  env: process.env.NODE_ENV || "development",
  port: process.env.PORT || 3000,
  baseUrl: process.env.BASE_URL || "http://localhost:3000",
  sessionSecret: process.env.SESSION_SECRET || "lab-only-insecure-dev-secret",
  adminEmail: process.env.ADMIN_EMAIL || "dast-admin@example.com",
  localAuth: {
    enabled: process.env.LOCAL_AUTH_ENABLED !== "false",
    userPassword: process.env.LOCAL_USER_PASSWORD || "",
    adminPassword: process.env.LOCAL_ADMIN_PASSWORD || "",
  },
  entra: {
    clientId: process.env.ENTRA_CLIENT_ID || "",
    clientSecret: process.env.ENTRA_CLIENT_SECRET || "",
    tenantId: process.env.ENTRA_TENANT_ID || "common",
    scopes: "openid profile email",
    authorizeUrl(tenant) {
      return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
    },
    tokenUrl(tenant) {
      return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
    },
    issuer(tenant) {
      return `https://login.microsoftonline.com/${tenant}/v2.0`;
    },
  },
};

module.exports = config;
