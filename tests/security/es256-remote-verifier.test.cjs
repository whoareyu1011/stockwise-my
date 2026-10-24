"use strict";

// Isolated unit coverage for ES256 verification with a mocked remote JWKS.
// Uses generated test keys only; it does not contact Supabase or use real tokens.
const assert = require("node:assert/strict");
const test = require("node:test");
const { createTrustedRemoteJwks } = require("../../server/security/trusted-jwks.cjs");
const { createTokenVerifier } = require("../../server/security/verify-token.cjs");

const NOW = 1_800_000_000;
const ISSUER = "https://stockwise-unit.invalid/auth/v1";
const AUDIENCE = "stockwise-unit-test";
const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;
const KEY_ID = "unit-es256-key";
const SUBJECT = "10000000-0000-4000-8000-000000000001";
const SESSION_ID = "20000000-0000-4000-8000-000000000002";
const CONFIG = Object.freeze({
  issuer: ISSUER,
  audience: AUDIENCE,
  jwksUrl: JWKS_URL,
  algorithms: ["ES256"],
  maxTokenLifetimeSeconds: 3600,
});

function invalid(verify, token) {
  return assert.rejects(() => verify(token), error =>
    error?.name === "SecurityError" && error?.code === "AUTH_INVALID" &&
    !error?.cause);
}

function tamperSignature(token) {
  const parts = token.split(".");
  const signature = Buffer.from(parts[2], "base64url");
  signature[0] ^= 1;
  parts[2] = signature.toString("base64url");
  return parts.join(".");
}

test("remote JWKS verifier accepts synthetic ES256 tokens and rejects invalid classes", async t => {
  const jose = await import("jose");
  const pair = await jose.generateKeyPair("ES256", { extractable: true });
  const publicJwk = {
    ...await jose.exportJWK(pair.publicKey),
    kid: KEY_ID,
    alg: "ES256",
    use: "sig",
  };
  const fetchRequests = [];
  const trustedRemoteJwks = await createTrustedRemoteJwks({
    config: CONFIG,
    fetchImpl: async (resource, options) => {
      const url = String(resource);
      assert.equal(url, JWKS_URL);
      assert.equal(options.method, "GET");
      assert.equal(options.redirect, "manual");
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      fetchRequests.push({ url, method: options.method });
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  // Resolver construction is lazy; all later key fetches use the mocked transport.
  assert.equal(fetchRequests.length, 0);
  const verify = await createTokenVerifier({
    config: CONFIG,
    trustedRemoteJwks,
    clock: () => NOW,
  });

  async function sign(overrides = {}, {
    kid = KEY_ID,
    alg = "ES256",
    key = pair.privateKey,
  } = {}) {
    const claims = {
      iss: ISSUER,
      aud: AUDIENCE,
      sub: SUBJECT,
      session_id: SESSION_ID,
      role: "authenticated",
      iat: NOW - 1,
      exp: NOW + 300,
      ...overrides,
    };
    return new jose.SignJWT(claims)
      .setProtectedHeader({ alg, kid, typ: "JWT" })
      .sign(key);
  }

  await t.test("accepts a valid synthetic ES256 token", async () => {
    const principal = await verify(await sign());
    assert.deepEqual(principal, {
      issuer: ISSUER,
      subject: SUBJECT,
      sessionId: SESSION_ID,
      issuedAt: NOW - 1,
      expiresAt: NOW + 300,
    });
  });

  await t.test("rejects a tampered signature", async () => {
    await invalid(verify, tamperSignature(await sign()));
  });

  await t.test("rejects the wrong issuer", async () => {
    await invalid(verify, await sign({ iss: "https://wrong-unit.invalid/auth/v1" }));
  });

  await t.test("rejects the wrong audience", async () => {
    await invalid(verify, await sign({ aud: "wrong-unit-audience" }));
  });

  await t.test("rejects an expired token", async () => {
    await invalid(verify, await sign({ iat: NOW - 120, exp: NOW - 60 }));
  });

  await t.test("rejects an unknown key ID", async () => {
    await invalid(verify, await sign({}, { kid: "unknown-unit-key" }));
  });

  await t.test("rejects HS256", async () => {
    const secret = new TextEncoder().encode("synthetic-unit-test-secret-only");
    const token = await sign({}, { alg: "HS256", key: secret });
    await assert.rejects(() => verify(token), error =>
      error?.name === "SecurityError" &&
      ["AUTH_INVALID", "AUTH_PROVIDER_UNAVAILABLE"].includes(error?.code) &&
      !error?.cause);
  });

  assert.ok(fetchRequests.length >= 1);
  assert.ok(fetchRequests.every(request =>
    request.url === JWKS_URL && request.method === "GET"));
});
