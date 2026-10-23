"use strict";

const { SecurityError } = require("../security/errors.cjs");
const { getVerifiedAccessToken } = require("../security/middleware.cjs");

const RPC = Object.freeze({
  listProducts: "list_products",
  getProduct: "get_product",
  createProduct: "create_product",
  updateProduct: "update_product",
  archiveProduct: "archive_product",
  adjustStock: "adjust_stock",
});
const MAX_RESPONSE_BYTES = 32 * 1024;
const MAX_TIMEOUT_MS = 15_000;

function safeError(code) {
  throw new SecurityError(code);
}

function isPublishableKey(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 4096) return false;
  if (value.startsWith("sb_publishable_")) return true;
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload?.role === "anon";
  } catch {
    return false;
  }
}

function validateProjectUrl(value) {
  if (typeof value !== "string") safeError("SECURITY_CONFIGURATION");
  let url;
  try {
    url = new URL(value);
  } catch {
    safeError("SECURITY_CONFIGURATION");
  }
  if (url.protocol !== "https:" || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash) {
    safeError("SECURITY_CONFIGURATION");
  }
  return url.origin;
}

function safeSqlError(status, sqlState, mutating) {
  if (status === 401 || sqlState === "28000") return "AUTH_INVALID";
  if (status === 403 || sqlState === "42501") return "AUTHORIZATION_DENIED";
  if (status === 404 || sqlState === "P0002") return "RESOURCE_NOT_FOUND";
  if (sqlState === "PZ001") return "IDEMPOTENCY_CONFLICT";
  if (sqlState === "PZ002") return "STOCK_INSUFFICIENT";
  if (sqlState === "PZ003") return "STOCK_LIMIT";
  if (sqlState === "22023") return "REQUEST_INVALID";
  if (status === 409 || sqlState === "23505") return "RESOURCE_CONFLICT";
  return mutating ? "COMMIT_UNCERTAIN" : "DATABASE_UNAVAILABLE";
}

function createRequestScopedProductRepository({
  request,
  projectUrl,
  publishableKey,
  fetchImpl = globalThis.fetch,
  timeoutMs = 8_000,
} = {}) {
  const origin = validateProjectUrl(projectUrl);
  if (!isPublishableKey(publishableKey) ||
      typeof fetchImpl !== "function" ||
      !Number.isInteger(timeoutMs) || timeoutMs < 250 || timeoutMs > MAX_TIMEOUT_MS ||
      !request || typeof request !== "object") {
    safeError("SECURITY_CONFIGURATION");
  }

  async function rpc(name, args, { mutating = false } = {}) {
    const token = getVerifiedAccessToken(request);
    if (!token) safeError("AUTH_INVALID");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    timeout.unref?.();
    let response;
    try {
      response = await fetchImpl(`${origin}/rest/v1/rpc/${RPC[name]}`, {
        method: "POST",
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
        headers: {
          apikey: publishableKey,
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "accept-profile": "stockwise_api",
          "content-profile": "stockwise_api",
          accept: "application/json",
        },
        body: JSON.stringify(args),
      });
    } catch {
      clearTimeout(timeout);
      safeError(mutating ? "COMMIT_UNCERTAIN" : "DATABASE_UNAVAILABLE");
    } finally {
      clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
      safeError(mutating ? "COMMIT_UNCERTAIN" : "DATABASE_UNAVAILABLE");
    }
    let text;
    try {
      const length = response.headers?.get?.("content-length");
      if (length && Number(length) > MAX_RESPONSE_BYTES) {
        safeError("DATABASE_UNAVAILABLE");
      }
      text = await response.text();
    } catch {
      safeError(mutating ? "COMMIT_UNCERTAIN" : "DATABASE_UNAVAILABLE");
    }
    if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
      safeError(mutating ? "COMMIT_UNCERTAIN" : "DATABASE_UNAVAILABLE");
    }

    let body;
    try {
      body = text.length ? JSON.parse(text) : null;
    } catch {
      safeError(mutating ? "COMMIT_UNCERTAIN" : "DATABASE_UNAVAILABLE");
    }
    if (!response.ok) {
      safeError(safeSqlError(response.status, body?.code, mutating));
    }
    return body;
  }

  return Object.freeze({
    async listProducts({ companyId, filters }) {
      if (filters.search !== undefined || filters.active !== undefined) {
        safeError("REQUEST_INVALID");
      }
      const rows = await rpc("listProducts", {
        p_company_id: companyId,
        p_limit: filters.limit,
        p_after_sku: null,
        p_after_id: null,
      });
      if (!Array.isArray(rows)) safeError("DATABASE_UNAVAILABLE");
      return rows;
    },
    async getProduct({ companyId, productId }) {
      const row = await rpc("getProduct", {
        p_company_id: companyId,
        p_product_id: productId,
      });
      return row;
    },
    async createProduct({ companyId, idempotencyKey, product }) {
      return rpc("createProduct", {
        p_company_id: companyId,
        p_idempotency_key: idempotencyKey,
        p_product: product,
      }, { mutating: true });
    },
    async updateProduct({ companyId, productId, idempotencyKey, changes }) {
      return rpc("updateProduct", {
        p_company_id: companyId,
        p_product_id: productId,
        p_idempotency_key: idempotencyKey,
        p_changes: changes,
      }, { mutating: true });
    },
    async archiveProduct({ companyId, productId, idempotencyKey }) {
      return rpc("archiveProduct", {
        p_company_id: companyId,
        p_product_id: productId,
        p_idempotency_key: idempotencyKey,
      }, { mutating: true });
    },
    async adjustStock({
      companyId, productId, direction, quantity, reason, idempotencyKey,
    }) {
      return rpc("adjustStock", {
        p_company_id: companyId,
        p_product_id: productId,
        p_direction: direction,
        p_quantity: quantity,
        p_reason: reason,
        p_idempotency_key: idempotencyKey,
      }, { mutating: true });
    },
  });
}

module.exports = {
  createRequestScopedProductRepository,
  isPublishableKey,
};
