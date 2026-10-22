"use strict";
const { SecurityError } = require("./errors.cjs");
const { isVerifiedPrincipal } = require("./verify-token.cjs");
const attestations = new WeakMap();

function isCurrentSession(attestation, principal, now) {
  return Boolean(attestation && attestations.get(attestation) === principal &&
    Number.isFinite(now) && now < attestation.validUntil && now < principal.expiresAt);
}

// No Supabase/session implementation is supplied. Missing or failed trusted
// adapter ALWAYS denies; a JWT or browser "active" flag is not a status source.
function createSessionStatusVerifier({ lookup, freshnessSeconds = 30,
  clock = () => Date.now() / 1000 } = {}) {
  if (!Number.isSafeInteger(freshnessSeconds) || freshnessSeconds < 1 || freshnessSeconds > 30)
    throw new SecurityError("SECURITY_CONFIGURATION");
  return async principal => {
    const now = Math.floor(clock());
    if (!isVerifiedPrincipal(principal) || !Number.isSafeInteger(now) || principal.expiresAt <= now)
      throw new SecurityError("AUTH_INVALID");
    if (typeof lookup !== "function") throw new SecurityError("SESSION_UNAVAILABLE");
    let status;
    try { status = await lookup(principal); }
    catch { throw new SecurityError("SESSION_UNAVAILABLE"); }
    const checkedNow = Math.floor(clock());
    if (!status || status.issuer !== principal.issuer ||
        status.subject !== principal.subject || status.sessionId !== principal.sessionId ||
        status.active !== true || status.revoked !== false ||
        !Number.isSafeInteger(status.checkedAt) || status.checkedAt > checkedNow ||
        status.checkedAt + freshnessSeconds <= checkedNow ||
        !Number.isSafeInteger(status.expiresAt) || status.expiresAt <= checkedNow ||
        principal.expiresAt <= checkedNow)
      throw new SecurityError("AUTH_INVALID");
    const result = Object.freeze({ validUntil: Math.min(principal.expiresAt,
      status.expiresAt, status.checkedAt + freshnessSeconds) });
    attestations.set(result, principal);
    return result;
  };
}

module.exports = { createSessionStatusVerifier, isCurrentSession };
