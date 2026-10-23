"use strict";

// UNIT TESTS ONLY: synthetic JWTs, mocked JWKS transport, membership,
// repositories, and idempotency. These do not test PostgreSQL/RLS or Supabase.
const assert = require("node:assert/strict");
const test = require("node:test");
const fixtures = require("./fixtures.cjs");
const { createAuthorizer } = require("../../server/security/authorize.cjs");
const {
  createAuthenticationMiddleware,
  createAuthorizationMiddleware,
  createSecurityComponents,
  createSecurityErrorHandler,
  getRequestSecurity,
  getVerifiedAccessToken,
} = require("../../server/security/middleware.cjs");
const { createTrustedRemoteJwks } = require("../../server/security/trusted-jwks.cjs");
const { SecurityError } = require("../../server/security/errors.cjs");
const { createProductInventoryService } = require("../../server/services/product-inventory.cjs");

const rejectsCode = (operation, code) =>
  assert.rejects(operation, error => error instanceof SecurityError && error.code === code);

function invoke(middleware, request) {
  return new Promise(resolve => {
    middleware(request, {}, error => resolve({ error, request }));
  });
}

function productRow(overrides = {}) {
  return {
    id: fixtures.OTHER,
    sku: "SKU-1",
    name: "Demo item",
    category: "General",
    unit_code: "EA",
    is_active: true,
    stock_quantity: 8,
    selling_price: "12.500000",
    cost_price: "4.250000",
    low_stock_threshold: 2,
    classification_code: "CLASS-A",
    unexpected_private_field: "must-not-escape",
    ...overrides,
  };
}

async function createService(role = "Staff", {
  memberCompanyId = fixtures.A,
  repositoryOverrides = {},
} = {}) {
  const principal = await (await fixtures.verifier())(await fixtures.token());
  const session = await fixtures.sessionVerifier()(principal);
  const membershipRepository = fixtures.repository({
    member: { role, companyId: memberCompanyId },
  });
  const authorize = createAuthorizer({
    repository: membershipRepository,
    clock: () => fixtures.NOW,
  });
  const calls = [];
  const effects = [];
  const idempotency = new Map();
  async function atomic(method, args, operation) {
    calls.push([method, args]);
    const { idempotencyKey, ...payload } = args;
    const identity = `${args.companyId}:${method}:${idempotencyKey}`;
    const request = JSON.stringify(payload);
    const prior = idempotency.get(identity);
    if (prior) {
      if (prior.request !== request) throw new SecurityError("IDEMPOTENCY_CONFLICT");
      return prior.promise;
    }
    const entry = { request, promise: Promise.resolve().then(operation) };
    idempotency.set(identity, entry);
    try {
      return await entry.promise;
    } catch (error) {
      if (idempotency.get(identity) === entry) idempotency.delete(identity);
      throw error;
    }
  }
  const repository = {
    async listProducts(args) {
      calls.push(["listProducts", args]);
      return [productRow()];
    },
    async getProduct(args) {
      calls.push(["getProduct", args]);
      return productRow({ id: args.productId });
    },
    async createProduct(args) {
      return atomic("createProduct", args, async () => {
        effects.push(["createProduct", args]);
        return productRow({ ...args.product });
      });
    },
    async updateProduct(args) {
      return atomic("updateProduct", args, async () => {
        effects.push(["updateProduct", args]);
        return productRow({ ...args.changes });
      });
    },
    async archiveProduct(args) {
      return atomic("archiveProduct", args, async () => {
        effects.push(["archiveProduct", args]);
        return { id: args.productId, is_active: false };
      });
    },
    async adjustStock(args) {
      return atomic("adjustStock", args, async () => {
        effects.push(["adjustStock", args]);
        return { movementId: fixtures.ORDER, balanceBefore: 8, balanceAfter: 10 };
      });
    },
    ...repositoryOverrides,
  };
  const service = createProductInventoryService({
    authorize,
    repository,
  });
  return { service, principal, session, calls, effects, repository, authorize };
}

test("remote Supabase JWKS is pinned to validated startup configuration and uses jose lazily", async () => {
  const { jwk, wrong } = await fixtures.keys();
  let requested;
  const trustedRemoteJwks = await createTrustedRemoteJwks({
    config: fixtures.config,
    fetchImpl: async (url, options) => {
      requested = { url, options };
      return new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  assert.equal(requested, undefined, "resolver creation must not make a network request");

  const verify = await require("../../server/security/verify-token.cjs")
    .createTokenVerifier({ config: fixtures.config, trustedRemoteJwks, clock: () => fixtures.NOW });
  const principal = await verify(await fixtures.token());
  assert.equal(principal.subject, fixtures.SUBJECT);
  assert.equal(requested.url, fixtures.config.jwksUrl);
  assert.equal(requested.options.method, "GET");
  assert.equal(requested.options.redirect, "manual");
  const wrongToken = await fixtures.token({}, {}, wrong.privateKey);
  await rejectsCode(
    () => require("../../server/security/verify-token.cjs")
      .createTokenVerifier({
        config: {
          ...fixtures.config,
          issuer: "https://other.invalid/auth/v1",
          jwksUrl: "https://other.invalid/auth/v1/.well-known/jwks.json",
        },
        trustedRemoteJwks,
        clock: () => fixtures.NOW,
      }),
    "SECURITY_CONFIGURATION",
  );
  await rejectsCode(
    () => verify(wrongToken),
    "AUTH_INVALID",
  );
});

test("remote JWKS redirects or provider failures fail closed as unavailable", async () => {
  const token = await fixtures.token();
  const remote = await createTrustedRemoteJwks({
    config: fixtures.config,
    fetchImpl: async () => new Response(null, {
      status: 302,
      headers: { location: "https://attacker.invalid/keys" },
    }),
  });
  const verify = await require("../../server/security/verify-token.cjs")
    .createTokenVerifier({ config: fixtures.config, trustedRemoteJwks: remote, clock: () => fixtures.NOW });
  await rejectsCode(() => verify(token), "AUTH_PROVIDER_UNAVAILABLE");
});

test("security runtime requires trusted session and membership adapters and remains explicit", async () => {
  const { jwk } = await fixtures.keys();
  await rejectsCode(() => createSecurityComponents({
    config: fixtures.config,
    trustedJWKS: { keys: [jwk] },
  }), "SECURITY_CONFIGURATION");
  const components = await createSecurityComponents({
    config: fixtures.config,
    trustedJWKS: { keys: [jwk] },
    sessionLookup: async principal => fixtures.status(principal),
    membershipRepository: fixtures.repository(),
    clock: () => fixtures.NOW,
  });
  assert.equal(typeof components.authenticate, "function");
  assert.equal(typeof components.authorize, "function");
  assert.equal(typeof components.errorHandler, "function");
});

test("authentication middleware accepts only a verified bearer and keeps it off enumerable request state", async () => {
  const token = await fixtures.token();
  const middleware = createAuthenticationMiddleware({
    verifyToken: await fixtures.verifier(),
    verifySession: fixtures.sessionVerifier(),
    clock: () => fixtures.NOW,
  });
  const request = { headers: { authorization: `Bearer ${token}` } };
  const result = await invoke(middleware, request);
  assert.equal(result.error, undefined);
  assert.equal(getRequestSecurity(request).principal.subject, fixtures.SUBJECT);
  assert.equal(getVerifiedAccessToken(request), token);
  assert.equal(Object.keys(request).includes("security"), false);
  assert.equal(Object.keys(request).includes("authorization"), false);
});

test("missing, malformed and failed-auth requests stop before downstream handlers", async t => {
  const verifyToken = await fixtures.verifier();
  const verifySession = fixtures.sessionVerifier();
  const middleware = createAuthenticationMiddleware({ verifyToken, verifySession, clock: () => fixtures.NOW });
  for (const [name, authorization] of [
    ["missing", undefined],
    ["malformed", "Bearer not-a-jwt"],
    ["non-bearer", "Basic synthetic"],
  ]) {
    await t.test(name, async () => {
      const request = { headers: authorization ? { authorization } : {} };
      const result = await invoke(middleware, request);
      assert.equal(result.error.code, "AUTH_INVALID");
      assert.equal(getRequestSecurity(request), null);
      assert.equal(getVerifiedAccessToken(request), undefined);
    });
  }
});

test("session-status failure denies an otherwise valid JWT", async () => {
  const middleware = createAuthenticationMiddleware({
    verifyToken: await fixtures.verifier(),
    verifySession: async () => { throw new SecurityError("SESSION_UNAVAILABLE"); },
    clock: () => fixtures.NOW,
  });
  const result = await invoke(middleware, {
    headers: { authorization: `Bearer ${await fixtures.token()}` },
  });
  assert.equal(result.error.code, "SESSION_UNAVAILABLE");
  assert.equal(getRequestSecurity(result.request), null);
});

test("company middleware uses server-fixed action and membership lookup, not forged browser role or user fields", async () => {
  const { principal, session, authorize } = await createService("Staff");
  const request = {
    headers: {
      authorization: `Bearer ${await fixtures.token()}`,
      "x-user-id": fixtures.OTHER,
      "x-company-role": "Owner",
    },
    params: { companyId: fixtures.A, orderId: fixtures.ORDER },
    body: { role: "Owner", user_id: fixtures.OTHER, company_id: fixtures.B },
  };
  const authRequest = request;
  const auth = createAuthenticationMiddleware({
    verifyToken: async () => principal,
    verifySession: async () => session,
    clock: () => fixtures.NOW,
  });
  const authResult = await invoke(auth, authRequest);
  assert.equal(authResult.error, undefined);
  const gate = createAuthorizationMiddleware({
    authorize,
    action: "draft.edit",
    resolveScope: req => ({ companyId: req.params.companyId, resourceId: req.params.orderId }),
  });
  const result = await invoke(gate, Object.assign(authRequest, request));
  assert.equal(result.error, undefined);
  assert.equal(getRequestSecurity(authRequest).authorization.role, "Staff");
  assert.equal(getRequestSecurity(authRequest).authorization.identityId, fixtures.IDENTITY);
});

test("company middleware denies a cross-company selector and rejects extra caller-supplied scope", async () => {
  const { principal, session, authorize } = await createService("Owner");
  const auth = createAuthenticationMiddleware({
    verifyToken: async () => principal,
    verifySession: async () => session,
    clock: () => fixtures.NOW,
  });
  const crossCompanyRequest = { headers: { authorization: "Bearer synthetic" } };
  await invoke(auth, crossCompanyRequest);
  const crossCompany = createAuthorizationMiddleware({
    authorize,
    action: "product.write",
    resolveScope: () => ({ companyId: fixtures.B }),
  });
  const denied = await invoke(crossCompany, crossCompanyRequest);
  assert.equal(denied.error.code, "AUTHORIZATION_DENIED");

  const extraScope = createAuthorizationMiddleware({
    authorize,
    action: "product.write",
    resolveScope: () => ({ companyId: fixtures.A, role: "Owner" }),
  });
  const rejected = await invoke(extraScope, crossCompanyRequest);
  assert.equal(rejected.error.code, "AUTHORIZATION_DENIED");
});

test("product list applies the fixed role projection and discards unexpected repository fields", async t => {
  for (const [role, visible, hidden] of [
    ["Owner", ["cost_price", "selling_price", "classification_code"], []],
    ["Admin", ["cost_price", "selling_price", "classification_code"], []],
    ["Staff", ["selling_price", "low_stock_threshold"], ["cost_price", "classification_code"]],
    ["Viewer", ["stock_quantity"], ["selling_price", "cost_price", "classification_code"]],
  ]) {
    await t.test(role, async () => {
      const { service, principal, session, calls } = await createService(role);
      const rows = await service.listProducts({
        principal, session, companyId: fixtures.A,
        role: "Owner", fields: ["cost_price"],
      });
      assert.equal(rows.length, 1);
      for (const field of visible) assert.equal(Object.hasOwn(rows[0], field), true);
      for (const field of hidden) assert.equal(Object.hasOwn(rows[0], field), false);
      assert.equal(Object.hasOwn(rows[0], "unexpected_private_field"), false);
      assert.deepEqual(calls[0][1].companyId, fixtures.A);
      assert.equal(Object.hasOwn(calls[0][1], "fields"), false);
    });
  }
});

test("product read denies a company selector without an active membership", async () => {
  const { service, principal, session, calls } = await createService("Owner");
  await rejectsCode(() => service.listProducts({
    principal, session, companyId: fixtures.B,
  }), "AUTHORIZATION_DENIED");
  assert.equal(calls.length, 0);
});

test("single product read is company-scoped by the repository and uses the role projection", async () => {
  const { service, principal, session, calls } = await createService("Viewer");
  const row = await service.getProduct({
    principal, session, companyId: fixtures.A, productId: fixtures.OTHER,
    cost_price: true,
  });
  assert.equal(row.id, fixtures.OTHER);
  assert.equal(Object.hasOwn(row, "cost_price"), false);
  assert.equal(calls[0][1].companyId, fixtures.A);
  assert.equal(calls[0][1].productId, fixtures.OTHER);
  await rejectsCode(() => service.getProduct({
    principal, session, companyId: fixtures.B, productId: fixtures.OTHER,
  }), "AUTHORIZATION_DENIED");
});

test("product create/update/archive require Owner or Admin and reject forged scope fields", async t => {
  const validProduct = { sku: "sku-2", name: "New item", selling_price: "10.500000" };
  await t.test("Owner can create with server-derived identity and company", async () => {
    const { service, principal, session, calls } = await createService("Owner");
    const result = await service.createProduct({
      principal, session, companyId: fixtures.A, idempotencyKey: "product-create-0001",
      product: validProduct,
    });
    assert.equal(result.sku, validProduct.sku);
    assert.equal(Object.hasOwn(result, "unexpected_private_field"), false);
    assert.equal(calls[0][1].companyId, fixtures.A);
    assert.equal(calls[0][1].actorIdentityId, undefined);
  });
  await t.test("Admin can edit; caller cannot change company or role", async () => {
    const { service, principal, session, calls } = await createService("Admin");
    await service.updateProduct({
      principal, session, companyId: fixtures.A, productId: fixtures.OTHER,
      idempotencyKey: "product-update-0001", changes: { name: "Renamed" },
    });
    assert.equal(calls[0][0], "updateProduct");
    await rejectsCode(() => service.createProduct({
      principal, session, companyId: fixtures.A, idempotencyKey: "product-create-0002",
      product: { ...validProduct, company_id: fixtures.B, role: "Owner" },
    }), "REQUEST_INVALID");
  });
  await t.test("Staff cannot create/update/archive products", async () => {
    const { service, principal, session, calls } = await createService("Staff");
    await rejectsCode(() => service.createProduct({
      principal, session, companyId: fixtures.A, idempotencyKey: "product-create-0003",
      product: validProduct,
    }), "AUTHORIZATION_DENIED");
    await rejectsCode(() => service.updateProduct({
      principal, session, companyId: fixtures.A, productId: fixtures.OTHER,
      idempotencyKey: "product-update-0002", changes: { name: "No" },
    }), "AUTHORIZATION_DENIED");
    await rejectsCode(() => service.archiveProduct({
      principal, session, companyId: fixtures.A, productId: fixtures.OTHER,
      idempotencyKey: "product-archive-0001",
    }), "AUTHORIZATION_DENIED");
    assert.equal(calls.length, 0);
  });
});

test("product validation rejects unsafe monetary formats and caller-controlled identity", async () => {
  const { service, principal, session, calls } = await createService("Owner");
  for (const invalidProduct of [
    { sku: "A", name: "x", cost_price: "-1" },
    { sku: "A", name: "x", cost_price: "1.1234567" },
    { sku: "A", name: "x", selling_price: "1e3" },
    { sku: "A", name: "x", company_id: fixtures.B },
  ]) {
    await rejectsCode(() => service.createProduct({
      principal, session, companyId: fixtures.A, idempotencyKey: "product-create-invalid",
      product: invalidProduct,
    }), "REQUEST_INVALID");
  }
  assert.equal(calls.length, 0);
});

test("product creation sends stable idempotency keys for database-owned replay and conflict handling", async () => {
  const { service, principal, session, calls, effects } = await createService("Owner");
  const input = {
    principal, session, companyId: fixtures.A, idempotencyKey: "product-create-retry-1",
    product: { sku: "retry", name: "Retry item" },
  };
  const first = await service.createProduct(input);
  const second = await service.createProduct(input);
  assert.deepEqual(first, second);
  assert.equal(calls.filter(([method]) => method === "createProduct").length, 2);
  assert.equal(effects.filter(([method]) => method === "createProduct").length, 1);
  await rejectsCode(() => service.createProduct({
    ...input,
    product: { sku: "different", name: "Different payload" },
  }), "IDEMPOTENCY_CONFLICT");
});

test("stock adjustment is Owner/Admin-only, validated, audited-attributed and idempotent by contract", async t => {
  const request = {
    companyId: fixtures.A,
    productId: fixtures.OTHER,
    direction: "in",
    quantity: 2,
    reason: "Opening correction",
    idempotencyKey: "stock-adjust-retry-001",
  };
  await t.test("Owner adjustment invokes one repository operation and returns safe receipt", async () => {
    const { service, principal, session, calls } = await createService("Owner");
    const result = await service.adjustStock({ principal, session, ...request });
    assert.deepEqual(result, {
      movementId: fixtures.ORDER,
      balanceBefore: 8,
      balanceAfter: 10,
    });
    assert.equal(calls[0][0], "adjustStock");
    assert.equal(calls[0][1].actorIdentityId, undefined);
    assert.equal(calls[0][1].companyId, fixtures.A);
  });
  await t.test("Admin may adjust; Staff and Viewer may not", async () => {
    for (const role of ["Admin", "Staff", "Viewer"]) {
      const { service, principal, session, calls } = await createService(role);
      if (role === "Admin") {
        await service.adjustStock({ principal, session, ...request });
        assert.equal(calls.length, 1);
      } else {
        await rejectsCode(() => service.adjustStock({ principal, session, ...request }),
          "AUTHORIZATION_DENIED");
        assert.equal(calls.length, 0);
      }
    }
  });
  await t.test("invalid or non-idempotent adjustments fail before repository writes", async () => {
    const { service, principal, session, calls, effects } = await createService("Owner");
    await rejectsCode(() => service.adjustStock({
      principal, session, ...request, quantity: -1,
    }), "REQUEST_INVALID");
    await rejectsCode(() => service.adjustStock({
      principal, session, ...request, direction: "transfer",
    }), "REQUEST_INVALID");
    assert.equal(calls.length, 0);
  });
  await t.test("same stock-adjustment key replays one result; changed payload conflicts", async () => {
    const { service, principal, session, calls } = await createService("Owner");
    const input = { principal, session, ...request };
    const first = await service.adjustStock(input);
    const retry = await service.adjustStock(input);
    assert.deepEqual(retry, first);
    assert.equal(calls.length, 3);
    assert.equal(effects.length, 1);
    await rejectsCode(() => service.adjustStock({
      ...input,
      quantity: request.quantity + 1,
    }), "IDEMPOTENCY_CONFLICT");
  });
});

test("repository and authorization failures return fixed safe errors", async () => {
  const { service, principal, session } = await createService("Owner", {
    repositoryOverrides: {
      async createProduct() { throw new Error("raw database URL or SQL text"); },
    },
  });
  await rejectsCode(() => service.createProduct({
    principal, session, companyId: fixtures.A, idempotencyKey: "product-create-error",
    product: { sku: "err", name: "Error item" },
  }), "DATABASE_UNAVAILABLE");

  let status, body;
  const response = {
    headersSent: false,
    set() { return this; },
    status(value) { status = value; return this; },
    json(value) { body = value; return this; },
  };
  createSecurityErrorHandler()(new Error("private stack or credential"), {}, response, () => {});
  assert.equal(status, 500);
  assert.equal(body.code, "INTERNAL_ERROR");
  assert.doesNotMatch(JSON.stringify(body), /private stack|credential|database URL/i);
});
