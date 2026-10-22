"use strict";
const { SecurityError } = require("./errors.cjs");
const { createSecurityConfig } = require("./config.cjs");
const verified = new WeakSet();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isUuid = value => typeof value === "string" && uuid.test(value);
const isVerifiedPrincipal = value => Boolean(value && verified.has(value));

async function createTokenVerifier({ config, trustedJWKS, clock = () => Date.now() / 1000 } = {}) {
  config = createSecurityConfig(config);
  // Network fetching/rotation deliberately absent. Keys must be configured by
  // trusted server startup, never taken from a request or decoded token.
  if (!trustedJWKS || !Array.isArray(trustedJWKS.keys) || !trustedJWKS.keys.length)
    throw new SecurityError("SECURITY_CONFIGURATION");
  const keys = structuredClone(trustedJWKS);
  const kids = new Set();
  for (const key of keys.keys) {
    if (!key || typeof key.kid !== "string" || !key.kid || key.kid.length > 128 ||
        kids.has(key.kid) || !config.algorithms.includes(key.alg) || key.use !== "sig" ||
        (key.alg === "ES256" && (key.kty !== "EC" || key.crv !== "P-256")) ||
        (key.alg === "RS256" && key.kty !== "RSA") ||
        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some(p => Object.hasOwn(key, p)))
      throw new SecurityError("SECURITY_CONFIGURATION");
    kids.add(key.kid);
  }
  const { jwtVerify, decodeProtectedHeader, createLocalJWKSet } = await import("jose");
  const resolveKey = createLocalJWKSet(keys);
  return async function verifyToken(token) {
    try {
      if (typeof token !== "string" || Buffer.byteLength(token) > 8192 ||
          token.split(".").length !== 3) throw new Error();
      const header = decodeProtectedHeader(token);
      if (typeof header.kid !== "string" || !kids.has(header.kid) ||
          !config.algorithms.includes(header.alg) ||
          ["jku", "x5u", "jwk", "crit"].some(p => Object.hasOwn(header, p)) ||
          (header.typ !== undefined && header.typ !== "JWT")) throw new Error();
      const now = Math.floor(clock());
      if (!Number.isSafeInteger(now)) throw new Error();
      const { payload } = await jwtVerify(token, resolveKey, {
        issuer: config.issuer, audience: config.audience, algorithms: config.algorithms,
        requiredClaims: ["iss", "sub", "aud", "iat", "exp", "session_id"],
        currentDate: new Date(now * 1000), clockTolerance: 0,
        maxTokenAge: config.maxTokenLifetimeSeconds,
      });
      if (payload.role !== "authenticated" || payload.is_anonymous === true ||
          !isUuid(payload.sub) || !isUuid(payload.session_id) ||
          !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) ||
          payload.iat > now || payload.exp <= now || payload.exp <= payload.iat ||
          payload.exp - payload.iat > config.maxTokenLifetimeSeconds) throw new Error();
      const principal = Object.freeze({ issuer: payload.iss, subject: payload.sub,
        sessionId: payload.session_id, issuedAt: payload.iat, expiresAt: payload.exp });
      verified.add(principal);
      return principal;
    } catch {
      throw new SecurityError("AUTH_INVALID");
    }
  };
}

module.exports = { createTokenVerifier, isVerifiedPrincipal, isUuid };
