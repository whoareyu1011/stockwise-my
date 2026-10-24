"use strict";
const { SecurityError } = require("./errors.cjs");

// Explicit trusted inputs only. No process.env access or automatic key fetch.
function createSecurityConfig(input = {}) {
  const fail = () => { throw new SecurityError("SECURITY_CONFIGURATION"); };
  if (!input || typeof input !== "object") fail();
  const { issuer, audience, jwksUrl, algorithms = ["ES256"],
    maxTokenLifetimeSeconds = 3600, sessionFreshnessSeconds = 30 } = input;
  let issuerUrl, keysUrl;
  try { issuerUrl = new URL(issuer); keysUrl = new URL(jwksUrl); } catch { fail(); }
  if (issuerUrl.protocol !== "https:" || keysUrl.protocol !== "https:" ||
      issuerUrl.username || issuerUrl.password || keysUrl.username || keysUrl.password ||
      issuerUrl.search || issuerUrl.hash || keysUrl.search || keysUrl.hash ||
      issuerUrl.origin !== keysUrl.origin ||
      keysUrl.pathname !== `${issuerUrl.pathname.replace(/\/$/, "")}/.well-known/jwks.json` ||
      typeof audience !== "string" || !audience || audience.length > 200 ||
      !Array.isArray(algorithms) || !algorithms.length ||
      algorithms.some(a => !["ES256", "RS256"].includes(a)) ||
      !Number.isSafeInteger(maxTokenLifetimeSeconds) ||
      maxTokenLifetimeSeconds < 1 || maxTokenLifetimeSeconds > 3600 ||
      !Number.isSafeInteger(sessionFreshnessSeconds) ||
      sessionFreshnessSeconds < 1 || sessionFreshnessSeconds > 30) fail();
  return Object.freeze({ issuer, audience, jwksUrl,
    algorithms: Object.freeze([...new Set(algorithms)]),
    maxTokenLifetimeSeconds, sessionFreshnessSeconds });
}

function createSecurityConfigFromEnv(env = process.env) {
  if (!env || typeof env !== "object" || Array.isArray(env))
    throw new SecurityError("SECURITY_CONFIGURATION");
  return createSecurityConfig({
    issuer: env.SUPABASE_AUTH_ISSUER,
    jwksUrl: env.SUPABASE_AUTH_JWKS_URL,
    audience: env.SUPABASE_AUTH_AUDIENCE,
    algorithms: ["ES256"],
  });
}

module.exports = { createSecurityConfig, createSecurityConfigFromEnv };
