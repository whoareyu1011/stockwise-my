"use strict";
const { SecurityError } = require("./errors.cjs");
const boundaries = new WeakSet();

// Adapter injection only. Never imports pg, reads environment variables or
// opens sockets. Object separation is NOT verification of actual SQL roles.
function createPoolBoundary(input = {}) {
  if (!input || typeof input !== "object") throw new SecurityError("SECURITY_CONFIGURATION");
  const { runtimePool, verifierPool } = input;
  if (Object.keys(input).some(k => !["runtimePool", "verifierPool"].includes(k)) ||
      !runtimePool || !verifierPool || runtimePool === verifierPool ||
      typeof runtimePool.connect !== "function" || typeof verifierPool.connect !== "function")
    throw new SecurityError("SECURITY_CONFIGURATION");
  const result = Object.freeze({ runtimePool, verifierPool });
  boundaries.add(result);
  return result;
}

function isPoolBoundary(value) { return Boolean(value && boundaries.has(value)); }

// Timeout late arrivals are destroyed rather than leaked into a pool.
async function acquire(pool, timeoutMs) {
  let timedOut = false, timer;
  const pending = Promise.resolve().then(() => pool.connect());
  pending.then(client => {
    if (timedOut) try { client?.release?.(true); } catch { /* destroy best effort */ }
  }, () => {});
  try {
    const client = await Promise.race([pending, new Promise((_, reject) => {
      timer = setTimeout(() => { timedOut = true;
        reject(new SecurityError("DATABASE_UNAVAILABLE")); }, timeoutMs);
    })]);
    if (!client || typeof client.release !== "function") throw new Error();
    return client;
  } catch { throw new SecurityError("DATABASE_UNAVAILABLE"); }
  finally { clearTimeout(timer); }
}

module.exports = { createPoolBoundary, isPoolBoundary, acquire };
