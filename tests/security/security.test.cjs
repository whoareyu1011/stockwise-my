"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const net = require("node:net");
const tls = require("node:tls");
const dgram = require("node:dgram");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { createSecurityConfig } = require("../../server/security/config.cjs");
const { createTokenVerifier, isVerifiedPrincipal } = require("../../server/security/verify-token.cjs");
const { createSessionStatusVerifier } = require("../../server/security/session-status.cjs");
const { createAuthorizer } = require("../../server/security/authorize.cjs");
const { createPoolBoundary, acquire } = require("../../server/security/pools.cjs");
const { createTransactionRunner } = require("../../server/security/transaction.cjs");
const { roleAllows } = require("../../server/security/permissions.cjs");
const { SecurityError } = require("../../server/security/errors.cjs");
const f = require("./fixtures.cjs");
const rejects = (operation, code) => assert.rejects(operation, error =>
  error.code === code && error.name === "SecurityError" && !error.cause);
const allow = (repo = f.repository()) => createAuthorizer({ repository: repo, clock: () => f.NOW });

test("kernel network denial is active for TCP, TLS, UDP, fetch and descendants", async t => {
  for (const [name, connect] of [
    ["TCP", () => net.connect({ host: "127.0.0.1", port: 9 })],
    ["TLS", () => tls.connect({ host: "127.0.0.1", port: 9 })],
  ]) await t.test(name, async () => {
    await assert.rejects(new Promise((resolve, reject) => {
      const socket = connect();
      socket.once("error", error => { socket.destroy(); reject(error); });
      socket.once("connect", () => { socket.destroy(); resolve(); });
    }), error => error.code === "EPERM");
  });
  await t.test("UDP", async () => {
    const socket = dgram.createSocket("udp4");
    await assert.rejects(new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.send("offline", 9, "127.0.0.1", error => error ? reject(error) : resolve());
    }),
    error => error.code === "EPERM");
    try { socket.close(); } catch { /* socket creation itself was blocked */ }
  });
  await t.test("fetch", async () => {
    await assert.rejects(fetch("http://127.0.0.1:43219"), error => error.cause?.code === "EPERM");
  });
  await t.test("child inherits filter and no database secrets", async () => {
    const { stdout } = await promisify(execFile)(process.execPath, ["-e", `
      if (process.env.DATABASE_URL || process.env.SESSION_SECRET) process.exit(2);
      require('net').connect({host:'127.0.0.1',port:9}).on('error', e => {
        if (e.code !== 'EPERM') process.exit(3);
        console.log('blocked');
      });
    `]);
    assert.equal(stdout.trim(), "blocked");
  });
});

test("trusted configuration rejects unsafe or missing key settings", async t => {
  for (const overrides of [
    { issuer: undefined }, { audience: "" }, { issuer: "http://offline.invalid/auth/v1" },
    { jwksUrl: "https://attacker.invalid/jwks" },
    { jwksUrl: "https://stockwise-auth.invalid/arbitrary" },
    { jwksUrl: `${f.config.jwksUrl}?token=synthetic` },
    { algorithms: ["HS256"] }, { algorithms: ["none"] }, { algorithms: [] },
    { maxTokenLifetimeSeconds: 3601 }, { sessionFreshnessSeconds: 31 },
  ]) await t.test(JSON.stringify(Object.keys(overrides)), () => {
    assert.throws(() => createSecurityConfig({ ...f.config, ...overrides }),
      { code: "SECURITY_CONFIGURATION" });
  });
  await rejects(() => createTokenVerifier({ config: f.config }), "SECURITY_CONFIGURATION");
  await rejects(async () => createTokenVerifier({ config: f.config,
    trustedJWKS: { keys: [{ ...(await f.keys()).jwk, d: "synthetic-private-material" }] } }),
  "SECURITY_CONFIGURATION");
});

test("jose verifies synthetic signatures and returns only a branded minimal identity", async () => {
  const principal = await (await f.verifier())(await f.token({
    company_id: f.B, user_id: f.OTHER, member_role: "Owner", session_status: "active" }));
  assert.equal(isVerifiedPrincipal(principal), true);
  assert.deepEqual(Object.keys(principal).sort(),
    ["issuer", "subject", "sessionId", "issuedAt", "expiresAt"].sort());
  assert.equal(isVerifiedPrincipal({ ...principal }), false);
  assert.equal(Object.isFrozen(principal), true);
});

test("configured RS256 uses jose; a different configured algorithm is rejected", async () => {
  const { jose } = await f.keys();
  const pair = await jose.generateKeyPair("RS256", { extractable: true });
  const jwk = { ...await jose.exportJWK(pair.publicKey), kid: "rsa-offline", alg: "RS256", use: "sig" };
  const raw = await new jose.SignJWT({ iss: f.config.issuer, aud: f.config.audience,
    sub: f.SUBJECT, session_id: f.SESSION, role: "authenticated",
    iat: f.NOW - 1, exp: f.NOW + 60 })
    .setProtectedHeader({ kid: "rsa-offline", alg: "RS256" }).sign(pair.privateKey);
  const verify = await createTokenVerifier({ config: { ...f.config, algorithms: ["RS256"] },
    trustedJWKS: { keys: [jwk] }, clock: () => f.NOW });
  assert.equal((await verify(raw)).subject, f.SUBJECT);
  await rejects(() => verify("forged"), "AUTH_INVALID");
  await rejects(() => createTokenVerifier({ config: f.config, trustedJWKS: { keys: [jwk] } }),
    "SECURITY_CONFIGURATION");
});

test("jose rejects invalid token classes, claims, keys and token-controlled key URLs", async t => {
  const verify = await f.verifier();
  for (const [name, claims, header] of [
    ["wrong issuer", { iss: "https://other.invalid" }],
    ["wrong audience", { aud: "other" }],
    ["expired", { exp: f.NOW }],
    ["future iat", { iat: f.NOW + 1 }],
    ["future nbf", { nbf: f.NOW + 1 }],
    ["missing subject", { sub: undefined }],
    ["missing session", { session_id: undefined }],
    ["invalid session", { session_id: "browser-session" }],
    ["service role", { role: "service_role" }],
    ["anonymous key", { role: "anon" }],
    ["anonymous auth user", { is_anonymous: true }],
    ["excess lifetime", { exp: f.NOW + 3600 }],
    ["inverted lifetime", { iat: f.NOW - 1, exp: f.NOW - 2 }],
    ["fractional exp", { exp: f.NOW + 1.5 }],
    ["unknown kid", {}, { kid: "unknown" }],
    ["jku", {}, { jku: "https://attacker.invalid" }],
    ["x5u", {}, { x5u: "https://attacker.invalid" }],
    ["embedded jwk", {}, { jwk: (await f.keys()).jwk }],
  ]) await t.test(name, async () =>
    rejects(async () => verify(await f.token(claims, header || {})), "AUTH_INVALID"));
  for (const value of [undefined, "", "not-a-jwt", "a".repeat(8193),
    `${Buffer.from('{"alg":"none"}').toString("base64url")}.e30.`]) {
    await t.test("malformed/unsigned/oversize", () => rejects(() => verify(value), "AUTH_INVALID"));
  }
  await t.test("wrong signature", async () => rejects(
    async () => verify(await f.token({}, {}, (await f.keys()).wrong.privateKey)), "AUTH_INVALID"));
  await t.test("raw token never appears in error", async () => {
    const raw = await f.token({ iss: "https://other.invalid" });
    try { await verify(raw); assert.fail(); }
    catch (error) { assert.equal(String(error).includes(raw), false); assert.equal(error.code, "AUTH_INVALID"); }
  });
});

test("session adapter is mandatory; synthetic statuses are never provider evidence", async t => {
  const principal = await (await f.verifier())(await f.token());
  await t.test("missing adapter", () => rejects(
    () => createSessionStatusVerifier()(principal), "SESSION_UNAVAILABLE"));
  await t.test("outage is sanitized", () => rejects(
    () => f.sessionVerifier(async () => { throw new Error("synthetic-secret-marker"); })(principal),
    "SESSION_UNAVAILABLE"));
  for (const [name, overrides] of [
    ["revoked", { revoked: true }], ["inactive", { active: false }],
    ["wrong subject", { subject: f.OTHER }], ["wrong session", { sessionId: f.id(80) }],
    ["wrong issuer", { issuer: "https://other.invalid" }],
    ["expired source", { expiresAt: f.NOW }], ["stale", { checkedAt: f.NOW - 30 }],
    ["future status", { checkedAt: f.NOW + 1 }], ["incomplete", { revoked: undefined }],
  ]) await t.test(name, () => rejects(
    () => f.sessionVerifier(async p => f.status(p, overrides))(principal), "AUTH_INVALID"));
  await t.test("forged browser principal", () => rejects(
    () => f.sessionVerifier()({ ...principal }), "AUTH_INVALID"));
  await t.test("browser active flag is not an attestation", async () =>
    rejects(() => allow()({ principal, session: { active: true, validUntil: f.NOW + 100 },
      companyId: f.A, action: "product.basic.read" }), "SESSION_UNAVAILABLE"));
});

test("company, identity, membership and role are freshly authorized", async t => {
  const input = await f.authorizationInput();
  for (const [name, changes] of [
    ["wrong company", { companyId: f.B }], ["revoked membership", { status: "revoked" }],
    ["disabled identity", { identityStatus: "disabled" }],
    ["suspended company", { companyStatus: "suspended" }],
    ["wrong subject", { subject: f.OTHER }], ["Operator deprecated", { role: "Operator" }],
    ["unknown role", { role: "root" }], ["wrong issuer", { issuer: "https://other.invalid" }],
  ]) await t.test(name, async () => rejects(
    () => allow(f.repository({ member: changes }))(input), "AUTHORIZATION_DENIED"));
  await t.test("missing membership repository", () => rejects(
    () => allow(null)(input), "MEMBERSHIP_UNAVAILABLE"));
  await t.test("membership lookup outage", () => rejects(
    () => allow({ async findCurrentMembership() { throw new Error("synthetic-secret-marker"); } })(input),
    "MEMBERSHIP_UNAVAILABLE"));
  await t.test("malformed company", () => rejects(
    () => allow()({ ...input, companyId: "not-a-company" }), "AUTHORIZATION_DENIED"));
  await t.test("browser role/user metadata ignored", () => rejects(
    () => allow()({ ...input, action: "order.post", role: "Owner", userId: f.OTHER }),
    "AUTHORIZATION_DENIED"));
  await t.test("revocation reread on next operation", async () => {
    let active = true, reads = 0;
    const base = f.repository();
    const repo = { ...base, async findCurrentMembership() {
      reads++; return { ...await base.findCurrentMembership(), status: active ? "active" : "revoked" };
    } };
    await allow(repo)(input);
    active = false;
    await rejects(() => allow(repo)(input), "AUTHORIZATION_DENIED");
    assert.equal(reads, 2);
  });
  await t.test("no current membership", () => rejects(() => allow({
    async findCurrentMembership() { return null; },
  })(input), "AUTHORIZATION_DENIED"));
  await t.test("changed role applies on next operation", async () => {
    let role = "Admin";
    const base = f.repository();
    const auth = allow({ ...base, async findCurrentMembership() {
      return { ...await base.findCurrentMembership(), role };
    } });
    await auth({ ...input, action: "product.write" });
    role = "Staff";
    await rejects(() => auth({ ...input, action: "product.write" }), "AUTHORIZATION_DENIED");
  });
  await t.test("expired branded session", async () => {
    await rejects(() => createAuthorizer({ repository: f.repository(), clock: () => f.NOW + 31 })(input),
      "SESSION_UNAVAILABLE");
  });
});

test("four-role permission matrix denies unapproved actions", async t => {
  const matrix = {
    "product.basic.read": ["Owner", "Admin", "Staff", "Viewer"],
    "product.sales.read": ["Owner", "Admin", "Staff"],
    "stock.quantity.read": ["Owner", "Admin", "Staff", "Viewer"],
    "product.cost.read": ["Owner", "Admin"], "product.write": ["Owner", "Admin"],
    "stock.history.read": ["Owner", "Admin"], "audit.read": ["Owner", "Admin"],
    "export": ["Owner", "Admin"], "stock.adjust": ["Owner", "Admin"],
    "order.post": ["Owner", "Admin"], "order.reverse": ["Owner", "Admin"],
    "ownership.transfer": [], "draft.reassign": [], "arbitrary.action": [],
  };
  for (const role of ["Owner", "Admin", "Staff", "Viewer", "Operator"])
    for (const [action, permitted] of Object.entries(matrix))
      await t.test(`${role}: ${action}`, () => assert.equal(roleAllows(role, action), permitted.includes(role)));
});

test("draft/posted resource checks do not trust browser ownership, kind or state", async t => {
  const input = await f.authorizationInput();
  await t.test("Staff own sales draft", async () => {
    assert.equal((await allow()(input)).projection, "own-sales-work");
  });
  for (const [name, order] of [
    ["another Staff creator", { creatorIdentityId: f.OTHER }],
    ["missing creator", { creatorIdentityId: undefined }],
    ["other company", { companyId: f.B }],
    ["wrong returned ID", { id: f.id(90) }],
    ["posted", { state: "posted" }], ["cancelled", { state: "cancelled" }],
    ["purchase work", { kind: "purchase" }],
  ]) await t.test(name, () => rejects(
    () => allow(f.repository({ order }))({ ...input, creatorIdentityId: f.IDENTITY,
      state: "draft", orderKind: "sale" }), "AUTHORIZATION_DENIED"));
  for (const role of ["Owner", "Admin"])
    await t.test(`${role} manages other creator within company`, async () => {
      const ctx = await allow(f.repository({ member: { role },
        order: { creatorIdentityId: f.OTHER } }))(input);
      assert.equal(ctx.projection, "company-business");
      await rejects(() => allow(f.repository({ member: { role }, order: { companyId: f.B } }))(input),
        "AUTHORIZATION_DENIED");
    });
  await t.test("Viewer basic status but no draft body", async () => {
    const auth = allow(f.repository({ member: { role: "Viewer" } }));
    assert.equal((await auth({ ...input, action: "order.basic.read" })).projection, "basic-only");
    await rejects(() => auth(input), "AUTHORIZATION_DENIED");
  });
  await t.test("Staff own posted projection read-only", async () => {
    const auth = allow(f.repository({ order: { state: "posted" } }));
    await auth({ ...input, action: "order.work.read" });
    await rejects(() => auth(input), "AUTHORIZATION_DENIED");
    await rejects(() => auth({ ...input, action: "order.post" }), "AUTHORIZATION_DENIED");
  });
  await t.test("create kind restrictions", async () => {
    await allow()({ ...input, action: "draft.create", orderKind: "sale" });
    await rejects(() => allow()({ ...input, action: "draft.create", orderKind: "purchase" }),
      "AUTHORIZATION_DENIED");
  });
  await t.test("cancellation predicate own eligible draft only", async () => {
    await allow()({ ...input, action: "draft.cancel" });
    await rejects(() => allow(f.repository({ order: { state: "posted" } }))({
      ...input, action: "draft.cancel" }), "AUTHORIZATION_DENIED");
  });
});

test("membership ceilings prevent self-elevation and Owner/peer takeover", async t => {
  const input = { ...await f.authorizationInput(), action: "membership.manage",
    targetIdentityId: f.OTHER, requestedRole: "Viewer" };
  for (const role of ["Owner", "Admin"])
    await t.test(`${role} ordinary membership`, () => allow(f.repository({ member: { role } }))(input));
  for (const [name, role, requestedRole, target] of [
    ["Staff denied", "Staff", "Viewer", {}],
    ["Admin cannot appoint Owner", "Admin", "Owner", {}],
    ["Owner additional Owner excluded", "Owner", "Owner", {}],
    ["Admin cannot appoint Admin", "Admin", "Admin", {}],
    ["Admin cannot demote peer", "Admin", "Viewer", { role: "Admin" }],
    ["Admin cannot remove Owner", "Admin", "Viewer", { role: "Owner" }],
    ["cross-company target", "Owner", "Viewer", { companyId: f.B }],
  ]) await t.test(name, () => rejects(() => allow(f.repository({ member: { role }, target }))({
    ...input, requestedRole }), "AUTHORIZATION_DENIED"));
  await t.test("self role change", () => rejects(() => allow(f.repository({
    member: { role: "Owner" } }))({ ...input, targetIdentityId: f.IDENTITY }), "AUTHORIZATION_DENIED"));
});

test("pool interfaces reject missing/shared/administrative fallback", async () => {
  assert.throws(() => createPoolBoundary(), { code: "SECURITY_CONFIGURATION" });
  const pool = { async connect() {} };
  assert.throws(() => createPoolBoundary({ runtimePool: pool, verifierPool: pool }),
    { code: "SECURITY_CONFIGURATION" });
  assert.throws(() => createPoolBoundary({ runtimePool: pool, verifierPool: { connect() {} },
    administrativePool: pool }), { code: "SECURITY_CONFIGURATION" });
  assert.throws(() => createPoolBoundary({ databaseUrl: "not-used" }),
    { code: "SECURITY_CONFIGURATION" });
});

test("semantic transaction flow binds proof/context and commits only after database authorization", async () => {
  const fx = await f.transactionFixture();
  assert.equal(await fx.run(fx.input), "synthetic-result");
  assert.deepEqual(fx.events, ["runtime.connect", "begin:read-committed", "verifier.connect",
    "issue:committed", "activate", "database.authorize", "work", "commit", "reset"]);
  assert.deepEqual(fx.releases, [["runtime", false], ["verifier", false]]);
  assert.equal(fx.proofDetails().subject, f.SUBJECT);
  assert.equal(fx.proofDetails().sessionId, f.SESSION);
  assert.equal(fx.proofDetails().expiresAt, f.NOW + 30);
  assert.equal(Object.hasOwn(fx.proofDetails(), "token"), false);
  const first = fx.proofDetails().xid;
  await fx.run(fx.input);
  assert.notEqual(fx.proofDetails().xid, first);
});

test("transaction failures are sanitized, roll back and never use administrative fallback", async t => {
  for (const method of ["beginReadCommitted", "transactionIdentity", "issueProof", "activateProof",
    "authorizeInDatabase"]) await t.test(method, async () => {
    const fx = await f.transactionFixture({ adapter: { async [method]() {
      throw new Error("synthetic-secret-marker");
    } } });
    await rejects(() => fx.run(fx.input), "TRANSACTION_FAILED");
    assert.equal(fx.events.includes("work"), false);
    assert.equal(fx.events.includes("commit"), false);
    assert.equal(fx.events.includes("rollback"), true);
  });
  await t.test("database denies even if Node policy permits", async () => {
    const fx = await f.transactionFixture({ adapter: { async authorizeInDatabase() { return { allowed: false }; } } });
    await rejects(() => fx.run(fx.input), "AUTHORIZATION_DENIED");
    assert.equal(fx.events.includes("work"), false);
  });
  await t.test("database authorizes wrong target/context", async () => {
    const fx = await f.transactionFixture({ adapter: {
      async authorizeInDatabase(client, ctx) { return { ...ctx, allowed: true,
        resourceId: f.id(88), pid: 42, xid: "101" }; },
    } });
    await rejects(() => fx.run(fx.input), "AUTHORIZATION_DENIED");
  });
  await t.test("application work failure", async () => {
    const fx = await f.transactionFixture();
    await rejects(() => fx.run({ ...fx.input, async work() {
      throw new Error("synthetic-secret-marker");
    } }), "TRANSACTION_FAILED");
    assert.equal(fx.events.includes("rollback"), true);
  });
  await t.test("even decorated SecurityError cannot leak adapter text/cause", async () => {
    const fx = await f.transactionFixture();
    const bad = new SecurityError("AUTHORIZATION_DENIED");
    bad.message = "synthetic-secret-marker";
    bad.cause = new Error("synthetic-secret-marker");
    await assert.rejects(() => fx.run({ ...fx.input, async work() { throw bad; } }),
      error => error.code === "AUTHORIZATION_DENIED" && !error.cause &&
        !String(error).includes("synthetic-secret-marker"));
  });
  await t.test("commit uncertainty destroys connection, no retry", async () => {
    let commits = 0;
    const fx = await f.transactionFixture({ adapter: { async commit() { commits++; throw new Error(); } } });
    await rejects(() => fx.run(fx.input), "COMMIT_UNCERTAIN");
    assert.equal(commits, 1);
    assert.deepEqual(fx.releases[0], ["runtime", true]);
  });
  await t.test("rollback failure destroys connection", async () => {
    const fx = await f.transactionFixture({ adapter: {
      async activateProof() { throw new Error(); }, async rollback() { throw new Error(); },
    } });
    await rejects(() => fx.run(fx.input), "TRANSACTION_FAILED");
    assert.deepEqual(fx.releases[0], ["runtime", true]);
  });
  await t.test("reset failure discards already committed connection", async () => {
    const fx = await f.transactionFixture({ adapter: { async reset() { throw new Error(); } } });
    assert.equal(await fx.run(fx.input), "synthetic-result");
    assert.deepEqual(fx.releases[0], ["runtime", true]);
  });
  await t.test("missing adapter fails before acquiring connection", async () => {
    const fx = await f.transactionFixture({ runner: { adapter: undefined } });
    await rejects(() => fx.run(fx.input), "SECURITY_CONFIGURATION");
    assert.deepEqual(fx.events, []);
  });
  await t.test("missing session verifier cannot run work", async () => {
    const fx = await f.transactionFixture({ runner: { verifySession: createSessionStatusVerifier() } });
    await rejects(() => fx.run(fx.input), "SESSION_UNAVAILABLE");
    assert.deepEqual(fx.events, []);
  });
  await t.test("invalid token cannot acquire any connection", async () => {
    const fx = await f.transactionFixture();
    await rejects(() => fx.run({ ...fx.input, token: "forged" }), "AUTH_INVALID");
    assert.deepEqual(fx.events, []);
  });
  await t.test("unbranded injected principal rejected", async () => {
    const fx = await f.transactionFixture({ runner: { async verifyToken() {
      return { subject: f.SUBJECT, role: "Owner" };
    } } });
    await rejects(() => fx.run(fx.input), "AUTH_INVALID");
    assert.deepEqual(fx.events, []);
  });
  await t.test("unbranded session status rejected", async () => {
    const fx = await f.transactionFixture({ runner: { async verifySession() { return { active: true }; } } });
    await rejects(() => fx.run(fx.input), "SESSION_UNAVAILABLE");
    assert.deepEqual(fx.events, []);
  });
  await t.test("same client behind distinct pools rejected and destroyed", async () => {
    const fx = await f.transactionFixture();
    fx.verifierPool.connect = async () => fx.runtimeClient;
    await rejects(() => fx.run(fx.input), "TRANSACTION_FAILED");
    assert.deepEqual(fx.releases, [["runtime", true]]);
  });
  await t.test("acquisition timeout destroys late arrival", async () => {
    const releases = [];
    const pending = acquire({ async connect() {
      await new Promise(resolve => setTimeout(resolve, 20));
      return { release(destroy) { releases.push(destroy); } };
    } }, 2);
    await rejects(() => pending, "DATABASE_UNAVAILABLE");
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.deepEqual(releases, [true]);
  });
});
