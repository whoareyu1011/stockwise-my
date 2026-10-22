"use strict";
const { SecurityError } = require("./errors.cjs");
const { isVerifiedPrincipal } = require("./verify-token.cjs");
const { isCurrentSession } = require("./session-status.cjs");
const { createAuthorizer, isAuthorizedContext } = require("./authorize.cjs");
const { isPoolBoundary, acquire } = require("./pools.cjs");

// Deliberately no SQL adapter in Phase 1. These required semantic operations
// cannot succeed in ordinary use without separately reviewed implementations.
const methods = ["beginReadCommitted", "transactionIdentity", "issueProof",
  "activateProof", "authorizeInDatabase", "commit", "rollback", "reset"];

function createTransactionRunner({ verifyToken, verifySession, pools, adapter,
  repositoryFactory, clock = () => Date.now() / 1000, acquisitionTimeoutMs = 1000 } = {}) {
  return async function run({ token, companyId, action, resourceId, orderKind,
    targetIdentityId, requestedRole, work } = {}) {
    if (typeof verifyToken !== "function" || typeof verifySession !== "function" ||
        !isPoolBoundary(pools) || !adapter ||
        methods.some(m => typeof adapter[m] !== "function") ||
        typeof repositoryFactory !== "function" || typeof work !== "function" ||
        !Number.isSafeInteger(acquisitionTimeoutMs) || acquisitionTimeoutMs < 1 ||
        acquisitionTimeoutMs > 10000) throw new SecurityError("SECURITY_CONFIGURATION");
    let principal, session;
    try { principal = await verifyToken(token); }
    catch (error) { throw new SecurityError(error instanceof SecurityError ? error.code : "AUTH_INVALID"); }
    if (!isVerifiedPrincipal(principal)) throw new SecurityError("AUTH_INVALID");
    try { session = await verifySession(principal); }
    catch (error) { throw new SecurityError(error instanceof SecurityError ? error.code : "SESSION_UNAVAILABLE"); }
    if (!isCurrentSession(session, principal, clock())) throw new SecurityError("SESSION_UNAVAILABLE");
    let client, verifier, begun = false, committed = false, destroy = false;
    try {
      client = await acquire(pools.runtimePool, acquisitionTimeoutMs);
      begun = true;
      await adapter.beginReadCommitted(client);
      const target = await adapter.transactionIdentity(client);
      if (!target || !Number.isSafeInteger(target.pid) || target.pid <= 0 ||
          typeof target.xid !== "string" || !/^[1-9][0-9]{0,19}$/.test(target.xid) ||
          BigInt(target.xid) > 18446744073709551615n) throw new Error();
      verifier = await acquire(pools.verifierPool, acquisitionTimeoutMs);
      if (client === verifier) { destroy = true; throw new Error(); }
      const expiresAt = Math.min(principal.expiresAt, session.validUntil, Math.floor(clock()) + 30);
      if (expiresAt <= clock()) throw new SecurityError("SESSION_UNAVAILABLE");
      const proof = await adapter.issueProof(verifier, Object.freeze({
        issuer: principal.issuer, subject: principal.subject,
        sessionId: principal.sessionId, pid: target.pid, xid: target.xid, expiresAt }));
      // Issuer contract: committed in verifier autocommit before activation.
      if (typeof proof !== "string" || !/^[a-f0-9]{64}$/.test(proof)) throw new Error();
      await adapter.activateProof(client, proof);
      const authorize = createAuthorizer({ repository: repositoryFactory(client), clock });
      const context = await authorize({ principal, session, companyId, action,
        resourceId, orderKind, targetIdentityId, requestedRole });
      if (!isAuthorizedContext(context, principal)) throw new Error();
      const db = await adapter.authorizeInDatabase(client, context);
      if (!db || db.allowed !== true || db.companyId !== context.companyId ||
          db.identityId !== context.identityId || db.action !== context.action ||
          ["role", "resourceId", "orderKind", "targetIdentityId", "requestedRole"]
            .some(field => db[field] !== context[field]) ||
          db.sessionId !== principal.sessionId || db.pid !== target.pid || db.xid !== target.xid)
        throw new SecurityError("AUTHORIZATION_DENIED");
      if (!isCurrentSession(session, principal, clock())) throw new SecurityError("SESSION_UNAVAILABLE");
      const value = await work(client, context);
      try { await adapter.commit(client); }
      catch { destroy = true; throw new SecurityError("COMMIT_UNCERTAIN"); }
      committed = true;
      return value;
    } catch (error) {
      if (client && begun && !committed) {
        try { await adapter.rollback(client); } catch { destroy = true; }
      }
      // Only our fixed safe errors escape; never propagate adapter/driver text.
      throw new SecurityError(error instanceof SecurityError ? error.code : "TRANSACTION_FAILED");
    } finally {
      if (client) {
        if (!destroy) try { await adapter.reset(client); } catch { destroy = true; }
        try { client.release(destroy); } catch { /* never expose raw pool errors */ }
      }
      if (verifier && verifier !== client) {
        try { verifier.release(); } catch { /* separately reviewed real pool required */ }
      }
    }
  };
}

module.exports = { createTransactionRunner };
