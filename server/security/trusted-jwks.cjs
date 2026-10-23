"use strict";

const { SecurityError } = require("./errors.cjs");
const { createSecurityConfig } = require("./config.cjs");

const trustedResolvers = new WeakMap();

// Creates a jose remote JWKS resolver only from validated, explicit server
// configuration. jose fetches keys lazily, caches them and handles rotation.
// This factory does not fetch at construction time.
async function createTrustedRemoteJwks({ config, timeoutDuration = 5000,
  cooldownDuration = 30000, cacheMaxAge = 300000,
  fetchImpl = globalThis.fetch } = {}) {
  const trusted = createSecurityConfig(config);
  if (!Number.isSafeInteger(timeoutDuration) || timeoutDuration < 100 ||
      timeoutDuration > 10000 ||
      !Number.isSafeInteger(cooldownDuration) || cooldownDuration < 1000 ||
      cooldownDuration > 300000 ||
      !Number.isSafeInteger(cacheMaxAge) || cacheMaxAge < 1000 ||
      cacheMaxAge > 3600000 || typeof fetchImpl !== "function") {
    throw new SecurityError("SECURITY_CONFIGURATION");
  }

  try {
    const { createRemoteJWKSet, customFetch } = await import("jose");
    const expectedUrl = new URL(trusted.jwksUrl).href;
    const boundedFetch = async (resource, options) => {
      if (resource !== expectedUrl || options?.method !== "GET" ||
          options?.redirect !== "manual" || !options?.signal) {
        throw new Error("Rejected JWKS request");
      }
      const response = await fetchImpl(resource, {
        ...options,
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
      });
      if (!response || response.status !== 200 || response.redirected ||
          (response.url && response.url !== expectedUrl)) {
        throw new Error("Rejected JWKS response");
      }
      const contentType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase();
      if (!["application/json", "application/jwk-set+json"].includes(contentType)) {
        throw new Error("Unexpected JWKS content type");
      }
      const declaredLength = response.headers.get("content-length");
      if (declaredLength !== null &&
          (!/^[0-9]+$/.test(declaredLength) || Number(declaredLength) > 1024 * 1024)) {
        throw new Error("JWKS response too large");
      }
      const bytes = await response.arrayBuffer();
      if (bytes.byteLength > 1024 * 1024) throw new Error("JWKS response too large");
      return new Response(bytes, {
        status: response.status,
        headers: response.headers,
      });
    };
    const resolver = createRemoteJWKSet(new URL(trusted.jwksUrl), {
      timeoutDuration,
      cooldownDuration,
      cacheMaxAge,
      [customFetch]: boundedFetch,
    });
    trustedResolvers.set(resolver, trusted.jwksUrl);
    return resolver;
  } catch {
    throw new SecurityError("SECURITY_CONFIGURATION");
  }
}

function isTrustedRemoteJwks(value, expectedUrl) {
  return typeof value === "function" && trustedResolvers.get(value) === expectedUrl;
}

module.exports = { createTrustedRemoteJwks, isTrustedRemoteJwks };
