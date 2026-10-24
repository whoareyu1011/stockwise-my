"use strict";

const assert = require("node:assert/strict");
const { once } = require("node:events");
const test = require("node:test");
const { createApp } = require("../../server.js");
const { isPublicSupabaseKey, readSupabasePublicConfig } =
  require("../../server/security/public-auth-config.cjs");

const publicConfig = Object.freeze({
  SUPABASE_URL: "https://stockwise-auth-test.supabase.co/",
  SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test-key",
});

async function withServer(env, run) {
  const server = createApp({ env }).listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
}

test("public auth configuration accepts HTTPS URL and publishable key only", () => {
  assert.deepEqual(readSupabasePublicConfig(publicConfig), {
    projectUrl: "https://stockwise-auth-test.supabase.co",
    publishableKey: publicConfig.SUPABASE_PUBLISHABLE_KEY,
  });
  assert.equal(isPublicSupabaseKey("sb_secret_test-key"), false);
  const serviceRoleJwt = [
    "header",
    Buffer.from(JSON.stringify({ iss: "supabase", role: "service_role" })).toString("base64url"),
    "signature",
  ].join(".");
  assert.equal(isPublicSupabaseKey(serviceRoleJwt), false);
});

test("legacy anon JWT public key remains supported without accepting service-role keys", () => {
  const legacyAnonKey = [
    "header",
    Buffer.from(JSON.stringify({ iss: "supabase", role: "anon" })).toString("base64url"),
    "signature",
  ].join(".");
  assert.equal(isPublicSupabaseKey(legacyAnonKey), true);
  assert.equal(readSupabasePublicConfig({
    SUPABASE_URL: publicConfig.SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY: legacyAnonKey,
  })?.publishableKey, legacyAnonKey);
});

test("missing or invalid public settings fail closed without exposing values", async () => {
  assert.equal(readSupabasePublicConfig({}), null);
  assert.equal(readSupabasePublicConfig({
    SUPABASE_URL: "http://stockwise-auth-test.supabase.co",
    SUPABASE_PUBLISHABLE_KEY: publicConfig.SUPABASE_PUBLISHABLE_KEY,
  }), null);

  await withServer({}, async baseUrl => {
    const response = await fetch(`${baseUrl}/api/auth/config`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), { configured: false });
  });
});

test("configured endpoint returns only the public Supabase URL and key", async () => {
  await withServer(publicConfig, async baseUrl => {
    const response = await fetch(`${baseUrl}/api/auth/config`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      configured: true,
      projectUrl: "https://stockwise-auth-test.supabase.co",
      publishableKey: publicConfig.SUPABASE_PUBLISHABLE_KEY,
    });
  });
});

test("the official browser SDK is served from the installed local package", async () => {
  await withServer({}, async baseUrl => {
    const response = await fetch(`${baseUrl}/assets/supabase.js`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") || "", /javascript/);
    assert.match(await response.text(), /createClient/);
  });
});
