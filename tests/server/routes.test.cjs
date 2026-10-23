"use strict";

const assert = require("node:assert/strict");
const { once } = require("node:events");
const test = require("node:test");
const { createApp } = require("../../server.js");

let server;
let baseUrl;

test.before(async () => {
  server = createApp().listen(0, "127.0.0.1");
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  if (!server?.listening) return;
  await new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
});

test("liveness is application-only and does not report database readiness", async () => {
  const response = await fetch(`${baseUrl}/api/health/live`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    success: true,
    status: "ok",
    check: "application-only",
  });
});

test("the old database health route is disabled without a connection attempt", async () => {
  const response = await fetch(`${baseUrl}/api/health/db`);
  assert.equal(response.status, 410);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal((await response.json()).code, "DATABASE_HEALTH_DISABLED");
});

test("products fail closed and never return demo or business data", async () => {
  const response = await fetch(`${baseUrl}/api/products`);
  assert.equal(response.status, 501);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    success: false,
    code: "PRODUCTS_API_NOT_CONFIGURED",
    error: "Secure product reads are not configured.",
  });
});

test("forged browser identity headers and invalid bearer tokens cannot enable product reads", async t => {
  const cases = [
    ["malformed bearer", "/api/products", { authorization: "Bearer not-a-jwt" }],
    ["forged user and company headers", "/api/products", {
      "x-user-id": "00000000-0000-4000-8000-000000000001",
      "x-company-id": "00000000-0000-4000-8000-000000000002",
      "x-company-role": "Owner",
    }],
    ["forged privileged role headers", "/api/products", {
      "x-role": "Owner",
      "x-company-role": "Admin",
    }],
    ["forged user, company and role query parameters",
      "/api/products?user_id=00000000-0000-4000-8000-000000000001&company_id=00000000-0000-4000-8000-000000000002&role=Owner",
      {}],
  ];

  for (const [name, path, headers] of cases) {
    await t.test(name, async () => {
      const response = await fetch(`${baseUrl}${path}`, { headers });
      assert.equal(response.status, 501);
      const body = await response.json();
      assert.equal(body.code, "PRODUCTS_API_NOT_CONFIGURED");
      assert.equal(Object.hasOwn(body, "products"), false);
    });
  }
});

test("product writes are not exposed", async () => {
  const response = await fetch(`${baseUrl}/api/products`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      company_id: "00000000-0000-4000-8000-000000000002",
      role: "Owner",
      name: "synthetic-only",
    }),
  });
  assert.equal(response.status, 404);
});
