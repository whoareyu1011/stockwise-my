"use strict";

const { createHash } = require("node:crypto");
const { SecurityError } = require("../security/errors.cjs");
const { isAuthorizedContext } = require("../security/authorize.cjs");
const { isUuid } = require("../security/verify-token.cjs");

const BASIC_FIELDS = Object.freeze([
  "id", "sku", "name", "category", "unit_code", "is_active", "stock_quantity",
]);
const ROLE_FIELDS = Object.freeze({
  Owner: Object.freeze([...BASIC_FIELDS, "selling_price", "cost_price",
    "low_stock_threshold", "classification_code"]),
  Admin: Object.freeze([...BASIC_FIELDS, "selling_price", "cost_price",
    "low_stock_threshold", "classification_code"]),
  Staff: Object.freeze([...BASIC_FIELDS, "selling_price", "low_stock_threshold"]),
  Viewer: BASIC_FIELDS,
});

const WRITE_FIELDS = Object.freeze([
  "sku", "name", "category", "unit_code", "selling_price", "cost_price",
  "low_stock_threshold", "classification_code",
]);
const ID_KEY = /^[A-Za-z0-9._~-]{8,128}$/;
const DECIMAL_20_6 = /^(?:0|[1-9][0-9]{0,13})(?:\.[0-9]{1,6})?$/;
const CODES = new Set(["Owner", "Admin", "Staff", "Viewer"]);

function invalid() {
  throw new SecurityError("REQUEST_INVALID");
}

function dependencyUnavailable() {
  throw new SecurityError("DATABASE_UNAVAILABLE");
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function text(value, { max, min = 0, trim = true } = {}) {
  if (typeof value !== "string") invalid();
  const result = trim ? value.trim() : value;
  if (result.length < min || result.length > max || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(result)) {
    invalid();
  }
  return result;
}

function decimal(value) {
  if (typeof value !== "string" || !DECIMAL_20_6.test(value)) invalid();
  return value;
}

function productInput(input, { partial = false } = {}) {
  if (!plainObject(input)) invalid();
  const keys = Object.keys(input);
  if (keys.some(key => !WRITE_FIELDS.includes(key)) ||
      (partial && keys.length === 0) ||
      (!partial && (!Object.hasOwn(input, "sku") || !Object.hasOwn(input, "name")))) {
    invalid();
  }
  const result = {};
  if (Object.hasOwn(input, "sku")) result.sku = text(input.sku, { min: 1, max: 128 });
  if (Object.hasOwn(input, "name")) result.name = text(input.name, { min: 1, max: 255 });
  if (Object.hasOwn(input, "category")) result.category = text(input.category, { max: 120 });
  if (Object.hasOwn(input, "unit_code")) result.unit_code = text(input.unit_code, { min: 1, max: 16 });
  if (Object.hasOwn(input, "selling_price")) result.selling_price = decimal(input.selling_price);
  if (Object.hasOwn(input, "cost_price")) result.cost_price = decimal(input.cost_price);
  if (Object.hasOwn(input, "low_stock_threshold")) {
    if (!Number.isSafeInteger(input.low_stock_threshold) || input.low_stock_threshold < 0) invalid();
    result.low_stock_threshold = input.low_stock_threshold;
  }
  if (Object.hasOwn(input, "classification_code")) {
    result.classification_code = input.classification_code === null
      ? null
      : text(input.classification_code, { max: 64 });
  }
  return Object.freeze(result);
}

function productProjection(row, role) {
  if (!plainObject(row) || !CODES.has(role)) dependencyUnavailable();
  const result = {};
  for (const field of ROLE_FIELDS[role]) {
    if (Object.hasOwn(row, field)) result[field] = row[field];
  }
  return Object.freeze(result);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function requestHash(value) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function validateIdempotencyKey(value) {
  if (typeof value !== "string" || !ID_KEY.test(value)) invalid();
  return value;
}

function validateSecurityInput({ principal, session, companyId }) {
  if (!principal || !session || !isUuid(companyId)) invalid();
}

function validateServiceInput(input) {
  if (!plainObject(input)) invalid();
}

function createProductInventoryService({ authorize, repository, idempotencyStore } = {}) {
  if (typeof authorize !== "function" || !repository ||
      !idempotencyStore || typeof idempotencyStore.run !== "function") {
    throw new SecurityError("SECURITY_CONFIGURATION");
  }

  async function authorized(input, action, resourceId) {
    validateSecurityInput(input);
    let context;
    try {
      context = await authorize({
        principal: input.principal,
        session: input.session,
        companyId: input.companyId,
        action,
        resourceId,
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("MEMBERSHIP_UNAVAILABLE");
    }
    if (!isAuthorizedContext(context, input.principal) ||
        context.companyId !== input.companyId || context.action !== action ||
        !CODES.has(context.role)) {
      throw new SecurityError("AUTHORIZATION_DENIED");
    }
    return context;
  }

  async function callRepository(method, args) {
    if (typeof repository[method] !== "function") dependencyUnavailable();
    try {
      return await repository[method](Object.freeze(args));
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("DATABASE_UNAVAILABLE");
    }
  }

  async function idempotent(context, action, keyValue, payload, operation) {
    const key = validateIdempotencyKey(keyValue);
    const scope = Object.freeze({
      companyId: context.companyId,
      identityId: context.identityId,
      action,
    });
    try {
      return await idempotencyStore.run({
        scope,
        key,
        requestHash: requestHash(payload),
        operation,
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("DATABASE_UNAVAILABLE");
    }
  }

  return Object.freeze({
    async listProducts(input) {
      validateServiceInput(input);
      const context = await authorized(input, "product.basic.read");
      const filters = input.filters === undefined ? {} : input.filters;
      if (!plainObject(filters) ||
          Object.keys(filters).some(key => !["search", "active", "limit"].includes(key))) invalid();
      const normalized = {};
      if (Object.hasOwn(filters, "search")) normalized.search = text(filters.search, { max: 100 });
      if (Object.hasOwn(filters, "active")) {
        if (typeof filters.active !== "boolean") invalid();
        normalized.active = filters.active;
      }
      const limit = filters.limit === undefined ? 100 : filters.limit;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) invalid();
      normalized.limit = limit;

      const rows = await callRepository("listProducts", {
        companyId: context.companyId,
        filters: Object.freeze(normalized),
      });
      if (!Array.isArray(rows) || rows.length > limit) dependencyUnavailable();
      return Object.freeze(rows.map(row => productProjection(row, context.role)));
    },

    async getProduct(input) {
      validateServiceInput(input);
      if (!isUuid(input.productId)) invalid();
      const context = await authorized(input, "product.basic.read", input.productId);
      const row = await callRepository("getProduct", {
        companyId: context.companyId,
        productId: input.productId,
      });
      if (row === null) throw new SecurityError("RESOURCE_NOT_FOUND");
      return productProjection(row, context.role);
    },

    async createProduct(input) {
      validateServiceInput(input);
      const product = productInput(input.product);
      const context = await authorized(input, "product.write");
      const payload = { companyId: context.companyId, product };
      return idempotent(context, "product.create", input.idempotencyKey, payload,
        async () => productProjection(await callRepository("createProduct", {
          companyId: context.companyId,
          actorIdentityId: context.identityId,
          product,
        }), context.role));
    },

    async updateProduct(input) {
      validateServiceInput(input);
      if (!isUuid(input.productId)) invalid();
      const changes = productInput(input.changes, { partial: true });
      const context = await authorized(input, "product.write", input.productId);
      const payload = { companyId: context.companyId, productId: input.productId, changes };
      return idempotent(context, "product.update", input.idempotencyKey, payload,
        async () => productProjection(await callRepository("updateProduct", {
          companyId: context.companyId,
          productId: input.productId,
          actorIdentityId: context.identityId,
          changes,
        }), context.role));
    },

    async archiveProduct(input) {
      validateServiceInput(input);
      if (!isUuid(input.productId)) invalid();
      const context = await authorized(input, "product.write", input.productId);
      const payload = { companyId: context.companyId, productId: input.productId };
      return idempotent(context, "product.archive", input.idempotencyKey, payload,
        async () => {
          const result = await callRepository("archiveProduct", {
            companyId: context.companyId,
            productId: input.productId,
            actorIdentityId: context.identityId,
          });
          if (!plainObject(result) || result.id !== input.productId || result.is_active !== false) {
            dependencyUnavailable();
          }
          return Object.freeze({ id: result.id, is_active: false });
        });
    },

    async adjustStock(input) {
      validateServiceInput(input);
      if (!isUuid(input.productId) ||
          !["in", "out"].includes(input.direction) ||
          !Number.isSafeInteger(input.quantity) || input.quantity < 1 ||
          input.quantity > 1000000000) invalid();
      const reason = text(input.reason, { min: 3, max: 300 });
      const context = await authorized(input, "stock.adjust", input.productId);
      const payload = {
        companyId: context.companyId,
        productId: input.productId,
        direction: input.direction,
        quantity: input.quantity,
        reason,
      };
      return idempotent(context, "stock.adjust", input.idempotencyKey, payload,
        async () => {
          const result = await callRepository("adjustStock", {
            ...payload,
            actorIdentityId: context.identityId,
          });
          if (!plainObject(result) || typeof result.movementId !== "string" ||
              !isUuid(result.movementId) ||
              !Number.isSafeInteger(result.balanceBefore) ||
              !Number.isSafeInteger(result.balanceAfter)) dependencyUnavailable();
          return Object.freeze({
            movementId: result.movementId,
            balanceBefore: result.balanceBefore,
            balanceAfter: result.balanceAfter,
          });
        });
    },
  });
}

// Adapter contract (not implemented here):
// - Every repository method must scope reads/writes by companyId and use the
//   authenticated Data API identity or an independently reviewed DB command.
// - adjustStock must append a ledger movement, update the trigger-maintained
//   balance, and append an actor-attributed audit entry in one DB transaction;
//   it must lock/check the balance so concurrent operations cannot oversell.
// - idempotencyStore.run must atomically persist the result with the mutation,
//   replay the same key+hash, and reject same-key/different-hash requests across
//   processes and restarts. The test implementation is only an in-memory mock.

module.exports = {
  createProductInventoryService,
  productInput,
  productProjection,
  requestHash,
  validateIdempotencyKey,
};
