"use strict";

const { SecurityError } = require("../security/errors.cjs");

function configurationError() {
  throw new SecurityError("SECURITY_CONFIGURATION");
}

function validateReplitConnectionString(value) {
  if (typeof value !== "string" || value.length > 8192) configurationError();
  let url;
  try {
    url = new URL(value);
  } catch {
    configurationError();
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol) ||
      !url.hostname || !url.username || !url.password ||
      url.hostname.toLowerCase().includes("supabase")) {
    configurationError();
  }
  return value;
}

async function createRestrictedReplitPool({
  env = process.env,
  PoolClass,
} = {}) {
  if (!env || typeof env !== "object") configurationError();
  const connectionString = validateReplitConnectionString(env.STOCKWISE_DATABASE_URL);
  const Pool = PoolClass || require("pg").Pool;
  const pool = new Pool({
    connectionString,
    max: 4,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    application_name: "stockwise-mvp",
  });

  let client;
  try {
    client = await pool.connect();
    const { rows } = await client.query(`
      SELECT r.rolcanlogin, r.rolsuper, r.rolbypassrls,
             r.rolcreatedb, r.rolcreaterole, r.rolreplication,
             EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_auth_members AS m
                WHERE m.member = current_user::regrole
             ) AS has_role_memberships
        FROM pg_catalog.pg_roles AS r
       WHERE r.rolname = current_user
    `);
    const role = rows[0];
    if (!role || role.rolcanlogin !== true ||
        role.rolsuper === true || role.rolbypassrls === true ||
        role.rolcreatedb === true || role.rolcreaterole === true ||
        role.rolreplication === true || role.has_role_memberships === true) {
      throw new SecurityError("SECURITY_CONFIGURATION");
    }
    return pool;
  } catch (error) {
    client?.release();
    client = undefined;
    await pool.end().catch(() => {});
    if (error instanceof SecurityError) throw error;
    throw new SecurityError("DATABASE_UNAVAILABLE");
  } finally {
    client?.release();
  }
}

module.exports = { createRestrictedReplitPool };
