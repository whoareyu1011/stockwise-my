"use strict";
// SYNTHETIC ONLY. This file must never be imported by application modules.
const { createSecurityConfig } = require("../../server/security/config.cjs");
const { createTokenVerifier } = require("../../server/security/verify-token.cjs");
const { createSessionStatusVerifier } = require("../../server/security/session-status.cjs");
const { createPoolBoundary } = require("../../server/security/pools.cjs");
const { createTransactionRunner } = require("../../server/security/transaction.cjs");

const NOW = 2000000000;
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const A = id(1), B = id(2), SUBJECT = id(3), SESSION = id(4);
const IDENTITY = id(5), OTHER = id(6), ORDER = id(7);
const config = createSecurityConfig({ issuer: "https://stockwise-auth.invalid/auth/v1",
  audience: "authenticated",
  jwksUrl: "https://stockwise-auth.invalid/auth/v1/.well-known/jwks.json" });
let signing;
async function keys() {
  if (!signing) signing = (async () => {
    const jose = await import("jose");
    const good = await jose.generateKeyPair("ES256", { extractable: true });
    const wrong = await jose.generateKeyPair("ES256", { extractable: true });
    const jwk = { ...await jose.exportJWK(good.publicKey), alg: "ES256", use: "sig", kid: "offline-key" };
    return { jose, good, wrong, jwk };
  })();
  return signing;
}
async function token(overrides = {}, header = {}, privateKey) {
  const { jose, good } = await keys();
  return new jose.SignJWT({ iss: config.issuer, sub: SUBJECT, aud: config.audience,
    role: "authenticated", session_id: SESSION, iat: NOW - 1, exp: NOW + 300, ...overrides })
    .setProtectedHeader({ alg: "ES256", kid: "offline-key", typ: "JWT", ...header })
    .sign(privateKey || good.privateKey);
}
async function verifier(clock = () => NOW) {
  return createTokenVerifier({ config, trustedJWKS: { keys: [(await keys()).jwk] }, clock });
}
function status(principal, overrides = {}) {
  return { issuer: principal.issuer, subject: principal.subject,
    sessionId: principal.sessionId, active: true, revoked: false,
    checkedAt: NOW, expiresAt: NOW + 600, ...overrides };
}
function sessionVerifier(lookup = async p => status(p), clock = () => NOW) {
  return createSessionStatusVerifier({ lookup, clock });
}
function repository(overrides = {}) {
  const member = { issuer: config.issuer, subject: SUBJECT, identityId: IDENTITY,
    companyId: A, identityStatus: "active", companyStatus: "active", status: "active",
    role: "Staff" };
  const order = { id: ORDER, companyId: A, creatorIdentityId: IDENTITY, state: "draft", kind: "sale" };
  return {
    async findCurrentMembership() { return { ...member, ...overrides.member }; },
    async findOrder() { return { ...order, ...overrides.order }; },
    async findTargetMembership() { return { companyId: A, identityId: OTHER, role: "Staff", ...overrides.target }; },
  };
}
async function authorizationInput(overrides = {}) {
  const principal = await (await verifier())(await token());
  const session = await sessionVerifier()(principal);
  return { principal, session, companyId: A, action: "draft.edit", resourceId: ORDER, ...overrides };
}

async function transactionFixture(options = {}) {
  const events = [], releases = [];
  let sequence = 100;
  const runtimeClient = { release(destroy = false) { releases.push(["runtime", destroy]); } };
  const verifierClient = { release(destroy = false) { releases.push(["verifier", destroy]); } };
  const runtimePool = { async connect() { events.push("runtime.connect"); return runtimeClient; } };
  const verifierPool = { async connect() { events.push("verifier.connect"); return verifierClient; } };
  let transaction, proofDetails;
  const adapter = {
    async beginReadCommitted() { events.push("begin:read-committed"); },
    async transactionIdentity() { transaction = { pid: 42, xid: String(++sequence) }; return transaction; },
    async issueProof(client, details) {
      events.push("issue:committed"); proofDetails = details;
      return sequence.toString(16).padStart(64, "0");
    },
    async activateProof() { events.push("activate"); },
    async authorizeInDatabase(client, context) {
      events.push("database.authorize");
      return { ...context, allowed: true, ...transaction };
    },
    async commit() { events.push("commit"); },
    async rollback() { events.push("rollback"); },
    async reset() { events.push("reset"); },
    ...options.adapter,
  };
  const args = { verifyToken: await verifier(), verifySession: sessionVerifier(),
    pools: createPoolBoundary({ runtimePool, verifierPool }), adapter,
    repositoryFactory: () => repository(options.repository),
    clock: () => NOW, ...options.runner };
  const run = createTransactionRunner(args);
  const input = { token: await token(), companyId: A, action: "draft.edit", resourceId: ORDER,
    async work() { events.push("work"); return "synthetic-result"; } };
  return { run, input, args, events, releases, runtimeClient, verifierClient,
    runtimePool, verifierPool, adapter, proofDetails: () => proofDetails };
}

module.exports = { NOW, id, A, B, SUBJECT, SESSION, IDENTITY, OTHER, ORDER, config,
  keys, token, verifier, status, sessionVerifier, repository, authorizationInput, transactionFixture };
