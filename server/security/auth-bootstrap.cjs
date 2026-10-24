"use strict";

const { createSecurityConfigFromEnv } = require("./config.cjs");
const { createTrustedRemoteJwks } = require("./trusted-jwks.cjs");

// Explicit opt-in bootstrap. Importing this module has no environment or network side effects.
async function createSupabaseAuthBootstrap({
  env = process.env,
  fetchImpl = globalThis.fetch,
} = {}) {
  const config = createSecurityConfigFromEnv(env);
  const trustedRemoteJwks = await createTrustedRemoteJwks({ config, fetchImpl });
  return Object.freeze({ config, trustedRemoteJwks });
}

module.exports = { createSupabaseAuthBootstrap };
