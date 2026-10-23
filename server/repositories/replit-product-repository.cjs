"use strict";

const { SecurityError } = require("../security/errors.cjs");
const { isUuid } = require("../security/verify-token.cjs");

const WRITE_COLUMNS = Object.freeze({
  sku: "sku",
  name: "name",
  category: "category",
  unit_code: "unit_code",
  selling_price: "selling_price",
  cost_price: "cost_price",
  low_stock_threshold: "low_stock_threshold",
  classification_code: "classification_code",
});
const TEXT_LIMITS = Object.freeze({
  sku: [1, 128],
  name: [1, 255],
  category: [0, 120],
  unit_code: [1, 16],
});
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._~-]{8,128}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,13})(?:\.[0-9]{1,6})?$/;

function fail(code) {
  throw new SecurityError(code);
}

function validateScope(companyId, actorMembershipId) {
  if (!isUuid(companyId) || !isUuid(actorMembershipId)) fail("REQUEST_INVALID");
}

function validateKey(key) {
  if (typeof key !== "string" || !IDEMPOTENCY_KEY.test(key)) {
    fail("REQUEST_INVALID");
  }
}

function validateProduct(product, { partial = false } = {}) {
  if (!product || typeof product !== "object" || Array.isArray(product) ||
      Object.getPrototypeOf(product) !== Object.prototype) fail("REQUEST_INVALID");
  const keys = Object.keys(product);
  if (keys.some(key => !Object.hasOwn(WRITE_COLUMNS, key)) ||
      (!partial && (!Object.hasOwn(product, "sku") || !Object.hasOwn(product, "name"))) ||
      (partial && keys.length === 0)) fail("REQUEST_INVALID");

  for (const [key, [min, max]] of Object.entries(TEXT_LIMITS)) {
    if (!Object.hasOwn(product, key)) continue;
    const value = product[key];
    if (typeof value !== "string" || value !== value.trim() ||
        value.length < min || value.length > max ||
        /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(value)) fail("REQUEST_INVALID");
  }
  for (const key of ["selling_price", "cost_price"]) {
    if (Object.hasOwn(product, key) &&
        (typeof product[key] !== "string" || !DECIMAL.test(product[key]))) {
      fail("REQUEST_INVALID");
    }
  }
  if (Object.hasOwn(product, "low_stock_threshold") &&
      (!Number.isSafeInteger(product.low_stock_threshold) || product.low_stock_threshold < 0)) {
    fail("REQUEST_INVALID");
  }
  if (Object.hasOwn(product, "classification_code") &&
      product.classification_code !== null &&
      (typeof product.classification_code !== "string" ||
       product.classification_code.length > 64 ||
       /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(product.classification_code))) {
    fail("REQUEST_INVALID");
  }
}

function normalizeDbError(error) {
  if (error instanceof SecurityError) return error;
  if (error?.code === "23505") return new SecurityError("RESOURCE_CONFLICT");
  if (error?.code === "PZ002") return new SecurityError("STOCK_INSUFFICIENT");
  if (error?.code === "PZ003") return new SecurityError("STOCK_LIMIT");
  if (error?.code === "PZ001") return new SecurityError("IDEMPOTENCY_CONFLICT");
  return error;
}

function createReplitProductRepository({ pool } = {}) {
  if (!pool || typeof pool.connect !== "function") {
    fail("SECURITY_CONFIGURATION");
  }

  const productSelect = `
    SELECT p.id::text AS id, p.sku, p.name, p.category, p.unit_code,
           p.is_active, p.selling_price::text AS selling_price,
           p.cost_price::text AS cost_price,
           p.low_stock_threshold::text AS low_stock_threshold,
           p.classification_code,
           COALESCE(b.quantity, 0)::text AS stock_quantity
    FROM stockwise_mvp.products AS p
    LEFT JOIN stockwise_mvp.stock_balances AS b
      ON b.company_id = p.company_id AND b.product_id = p.id`;

  async function fetchProduct(client, companyId, productId) {
    const { rows } = await client.query(
      `${productSelect} WHERE p.company_id = $1 AND p.id = $2`,
      [companyId, productId],
    );
    return rows[0] || null;
  }

  async function runIdempotent({
    companyId, actorMembershipId, command, idempotencyKey, payload, execute,
  }) {
    validateScope(companyId, actorMembershipId);
    validateKey(idempotencyKey);
    const client = await pool.connect();
    let began = false;
    let committing = false;
    let discardClient = false;
    try {
      await client.query("BEGIN");
      began = true;
      const lockName = [
        companyId, actorMembershipId, command, idempotencyKey,
      ].join(":");
      await client.query(
        "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))",
        [lockName],
      );

      const prior = await client.query(
        `SELECT request_payload = $5::jsonb AS same_payload, response_payload
           FROM stockwise_mvp.command_idempotency
          WHERE company_id = $1 AND actor_membership_id = $2
            AND command = $3 AND idempotency_key = $4
          FOR UPDATE`,
        [companyId, actorMembershipId, command, idempotencyKey, JSON.stringify(payload)],
      );
      if (prior.rowCount) {
        if (!prior.rows[0].same_payload) fail("IDEMPOTENCY_CONFLICT");
        committing = true;
        await client.query("COMMIT");
        began = false;
        return prior.rows[0].response_payload;
      }

      const result = await execute(client);
      await client.query(
        `INSERT INTO stockwise_mvp.command_idempotency
          (company_id, actor_membership_id, command, idempotency_key,
           request_payload, response_payload)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)`,
        [
          companyId, actorMembershipId, command, idempotencyKey,
          JSON.stringify(payload), JSON.stringify(result),
        ],
      );
      committing = true;
      await client.query("COMMIT");
      began = false;
      return result;
    } catch (error) {
      if (began) {
        try {
          await client.query("ROLLBACK");
        } catch {
          discardClient = true;
        }
      }
      if (committing) {
        discardClient = true;
        throw new SecurityError("COMMIT_UNCERTAIN");
      }
      throw normalizeDbError(error);
    } finally {
      client.release(discardClient ? new Error("Discard uncertain database client") : undefined);
    }
  }

  async function writeProduct(client, companyId, actorMembershipId, product) {
    const keys = Object.keys(product);
    const columns = keys.map(key => WRITE_COLUMNS[key]);
    const values = keys.map(key => product[key]);
    const names = ["company_id", ...columns];
    const parameters = [companyId, ...values];
    const placeholders = parameters.map((_, index) => `$${index + 1}`);
    const inserted = await client.query(
      `INSERT INTO stockwise_mvp.products (${names.join(", ")})
       VALUES (${placeholders.join(", ")})
       RETURNING id::text AS id`,
      parameters,
    );
    const row = await fetchProduct(client, companyId, inserted.rows[0].id);
    await writeAudit(client, {
      companyId,
      actorMembershipId,
      action: "product.created",
      productId: row.id,
      details: { fields: Object.keys(product) },
    });
    return row;
  }

  async function writeAudit(client, {
    companyId, actorMembershipId, action, productId, details,
  }) {
    await client.query(
      `INSERT INTO stockwise_mvp.product_audit_events
        (company_id, actor_membership_id, action, product_id, details)
       VALUES ($1, $2, $3, $4, $5::jsonb)`,
      [companyId, actorMembershipId, action, productId, JSON.stringify(details)],
    );
  }

  async function updateProduct(client, companyId, actorMembershipId, productId, changes) {
    const keys = Object.keys(changes);
    const assignments = keys.map((key, index) =>
      `${WRITE_COLUMNS[key]} = $${index + 3}`);
    const values = [companyId, productId, ...keys.map(key => changes[key])];
    const updated = await client.query(
      `UPDATE stockwise_mvp.products
          SET ${assignments.join(", ")}, updated_at = pg_catalog.transaction_timestamp()
        WHERE company_id = $1 AND id = $2
        RETURNING id::text AS id`,
      values,
    );
    if (!updated.rowCount) fail("RESOURCE_NOT_FOUND");
    const row = await fetchProduct(client, companyId, productId);
    await writeAudit(client, {
      companyId,
      actorMembershipId,
      action: "product.updated",
      productId,
      details: { changedFields: keys },
    });
    return row;
  }

  return Object.freeze({
    async listProducts({ companyId, filters }) {
      if (!isUuid(companyId) || !filters ||
          !Number.isSafeInteger(filters.limit) || filters.limit < 1 || filters.limit > 100) {
        fail("REQUEST_INVALID");
      }
      const { rows } = await pool.query(
        `${productSelect}
          WHERE p.company_id = $1
          ORDER BY pg_catalog.lower(p.sku), p.id
          LIMIT $2`,
        [companyId, filters.limit],
      );
      return rows;
    },

    async getProduct({ companyId, productId }) {
      if (!isUuid(companyId) || !isUuid(productId)) fail("REQUEST_INVALID");
      return fetchProduct(pool, companyId, productId);
    },

    async createProduct({ companyId, actorMembershipId, idempotencyKey, product }) {
      validateProduct(product);
      return runIdempotent({
        companyId, actorMembershipId, command: "product.create", idempotencyKey,
        payload: { product },
        execute: client => writeProduct(client, companyId, actorMembershipId, product),
      });
    },

    async updateProduct({
      companyId, actorMembershipId, productId, idempotencyKey, changes,
    }) {
      if (!isUuid(productId)) fail("REQUEST_INVALID");
      validateProduct(changes, { partial: true });
      return runIdempotent({
        companyId, actorMembershipId, command: "product.update", idempotencyKey,
        payload: { productId, changes },
        execute: client => updateProduct(
          client, companyId, actorMembershipId, productId, changes,
        ),
      });
    },

    async archiveProduct({ companyId, actorMembershipId, productId, idempotencyKey }) {
      if (!isUuid(productId)) fail("REQUEST_INVALID");
      return runIdempotent({
        companyId, actorMembershipId, command: "product.archive", idempotencyKey,
        payload: { productId },
        execute: async client => {
          const result = await client.query(
            `UPDATE stockwise_mvp.products
                SET is_active = false, updated_at = pg_catalog.transaction_timestamp()
              WHERE company_id = $1 AND id = $2
              RETURNING id::text AS id`,
            [companyId, productId],
          );
          if (!result.rowCount) fail("RESOURCE_NOT_FOUND");
          await writeAudit(client, {
            companyId,
            actorMembershipId,
            action: "product.archived",
            productId,
            details: { is_active: false },
          });
          return { id: result.rows[0].id, is_active: false };
        },
      });
    },

    async adjustStock({
      companyId, actorMembershipId, productId, direction, quantity, reason, idempotencyKey,
    }) {
      if (!isUuid(productId) || !["in", "out"].includes(direction) ||
          !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 1000000000 ||
          typeof reason !== "string" || reason.trim().length < 3 || reason.length > 300) {
        fail("REQUEST_INVALID");
      }
      return runIdempotent({
        companyId, actorMembershipId, command: "stock.adjust", idempotencyKey,
        payload: { productId, direction, quantity, reason: reason.trim() },
        execute: async client => {
          const product = await client.query(
            `SELECT id
               FROM stockwise_mvp.products
              WHERE company_id = $1 AND id = $2 AND is_active = true
              FOR UPDATE`,
            [companyId, productId],
          );
          if (!product.rowCount) fail("RESOURCE_NOT_FOUND");

          const beforeResult = await client.query(
            `SELECT quantity::text AS quantity
               FROM stockwise_mvp.stock_balances
              WHERE company_id = $1 AND product_id = $2`,
            [companyId, productId],
          );
          const before = BigInt(beforeResult.rows[0]?.quantity || "0");
          const delta = BigInt(direction === "in" ? quantity : -quantity);
          const after = before + delta;
          if (after < 0n) fail("STOCK_INSUFFICIENT");
          if (after > BigInt(Number.MAX_SAFE_INTEGER)) fail("STOCK_LIMIT");

          const movement = await client.query(
            `INSERT INTO stockwise_mvp.stock_movements
              (company_id, product_id, actor_membership_id, movement_kind,
               quantity_delta, reason, idempotency_key)
             VALUES ($1, $2, $3, 'adjustment', $4, $5, $6)
             RETURNING id::text AS id`,
            [
              companyId, productId, actorMembershipId,
              delta.toString(), reason.trim(), idempotencyKey,
            ],
          );
          await writeAudit(client, {
            companyId,
            actorMembershipId,
            action: "stock.adjusted",
            productId,
            details: {
              movementId: movement.rows[0].id,
              direction,
              quantity: String(quantity),
              balanceBefore: before.toString(),
              balanceAfter: after.toString(),
            },
          });
          return {
            movementId: movement.rows[0].id,
            balanceBefore: before.toString(),
            balanceAfter: after.toString(),
          };
        },
      });
    },
  });
}

module.exports = { createReplitProductRepository };
