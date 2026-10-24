"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createSupabaseAuthBootstrap } = require("../../server/security/auth-bootstrap.cjs");
const { createTokenVerifier } = require("../../server/security/verify-token.cjs");

const env = Object.freeze({
  SUPABASE_AUTH_ISSUER: "https://stockwise-bootstrap.invalid/auth/v1",
  SUPABASE_AUTH_JWKS_URL:
    "https://stockwise-bootstrap.invalid/auth/v1/.well-known/jwks.json",
  SUPABASE_AUTH_AUDIENCE: "authenticated",
});

test("auth bootstrap validates explicit environment and constructs a lazy trusted resolver", async () => {
  let fetchCalls = 0;
  const bootstrap = await createSupabaseAuthBootstrap({
    env,
    fetchImpl: async () => {
      fetchCalls++;
      throw new Error("mock fetch must not run during bootstrap");
    },
  });

  assert.deepEqual(bootstrap.config.algorithms, ["ES256"]);
  assert.equal(bootstrap.config.issuer, env.SUPABASE_AUTH_ISSUER);
  assert.equal(typeof bootstrap.trustedRemoteJwks, "function");
  assert.equal(Object.isFrozen(bootstrap), true);

  // A verifier can accept this resolver as trusted without fetching keys yet.
  const verifier = await createTokenVerifier({
    config: bootstrap.config,
    trustedRemoteJwks: bootstrap.trustedRemoteJwks,
  });
  assert.equal(typeof verifier, "function");
  assert.equal(fetchCalls, 0);
});

test("auth bootstrap fails closed on incomplete configuration without fetching", async () => {
  let fetchCalls = 0;
  await assert.rejects(
    () => createSupabaseAuthBootstrap({
      env: {
        SUPABASE_AUTH_ISSUER: env.SUPABASE_AUTH_ISSUER,
        SUPABASE_AUTH_JWKS_URL: env.SUPABASE_AUTH_JWKS_URL,
      },
      fetchImpl: async () => {
        fetchCalls++;
        throw new Error("mock fetch must not run");
      },
    }),
    error => error?.name === "SecurityError" &&
      error?.code === "SECURITY_CONFIGURATION" &&
      !error?.cause,
  );
  assert.equal(fetchCalls, 0);
});
