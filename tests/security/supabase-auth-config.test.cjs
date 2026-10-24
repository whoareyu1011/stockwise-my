"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createSecurityConfigFromEnv } = require("../../server/security/config.cjs");

const validEnv = Object.freeze({
  SUPABASE_AUTH_ISSUER: "https://stockwise-unit.invalid/auth/v1",
  SUPABASE_AUTH_JWKS_URL:
    "https://stockwise-unit.invalid/auth/v1/.well-known/jwks.json",
  SUPABASE_AUTH_AUDIENCE: "authenticated",
});

function isConfigurationError(error) {
  return error?.name === "SecurityError" &&
    error?.code === "SECURITY_CONFIGURATION" &&
    !error?.cause;
}

test("Supabase environment configuration validates the required values and pins ES256", () => {
  const config = createSecurityConfigFromEnv(validEnv);

  assert.equal(config.issuer, validEnv.SUPABASE_AUTH_ISSUER);
  assert.equal(config.jwksUrl, validEnv.SUPABASE_AUTH_JWKS_URL);
  assert.equal(config.audience, validEnv.SUPABASE_AUTH_AUDIENCE);
  assert.deepEqual(config.algorithms, ["ES256"]);
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.algorithms), true);
  assert.deepEqual(Object.keys(validEnv).sort(), [
    "SUPABASE_AUTH_AUDIENCE",
    "SUPABASE_AUTH_ISSUER",
    "SUPABASE_AUTH_JWKS_URL",
  ]);
});

test("Supabase environment configuration fails closed when required values are missing", () => {
  for (const name of [
    "SUPABASE_AUTH_ISSUER",
    "SUPABASE_AUTH_JWKS_URL",
    "SUPABASE_AUTH_AUDIENCE",
  ]) {
    assert.throws(
      () => createSecurityConfigFromEnv({ ...validEnv, [name]: undefined }),
      isConfigurationError,
    );
  }
});

test("Supabase environment configuration rejects invalid trusted URL relationships", () => {
  for (const overrides of [
    { SUPABASE_AUTH_ISSUER: "http://stockwise-unit.invalid/auth/v1" },
    { SUPABASE_AUTH_JWKS_URL: "https://other-unit.invalid/auth/v1/.well-known/jwks.json" },
    { SUPABASE_AUTH_JWKS_URL: "https://stockwise-unit.invalid/other/.well-known/jwks.json" },
    { SUPABASE_AUTH_AUDIENCE: "" },
  ]) {
    assert.throws(
      () => createSecurityConfigFromEnv({ ...validEnv, ...overrides }),
      isConfigurationError,
    );
  }
});

test("the environment cannot enable HS256 or replace the ES256-only policy", () => {
  const config = createSecurityConfigFromEnv({
    ...validEnv,
    SUPABASE_AUTH_ALGORITHMS: "HS256",
  });

  assert.deepEqual(config.algorithms, ["ES256"]);
});

test("invalid environment container fails with a sanitized configuration error", () => {
  for (const env of [null, [], "invalid"]) {
    assert.throws(() => createSecurityConfigFromEnv(env), isConfigurationError);
  }
});
