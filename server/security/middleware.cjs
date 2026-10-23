"use strict";

const { SecurityError } = require("./errors.cjs");
const { createAuthorizer } = require("./authorize.cjs");
const { createSessionStatusVerifier, isCurrentSession } = require("./session-status.cjs");
const { createTokenVerifier, isVerifiedPrincipal } = require("./verify-token.cjs");
const { actions } = require("./permissions.cjs");

const requestPrincipals = new WeakMap();
const requestSessions = new WeakMap();
const requestTokens = new WeakMap();
const allowedScopeKeys = new Set([
  "companyId", "resourceId", "orderKind", "targetIdentityId", "requestedRole",
]);

function getBearerToken(request) {
  const header = request?.headers?.authorization;
  if (typeof header !== "string" || Buffer.byteLength(header) > 8200) return null;
  const match = /^Bearer ([A-Za-z0-9._~-]{1,8192})$/i.exec(header);
  return match?.[1] || null;
}

function createAuthenticationMiddleware({ verifyToken, verifySession,
  clock = () => Date.now() / 1000 } = {}) {
  if (typeof verifyToken !== "function" || typeof verifySession !== "function" ||
      typeof clock !== "function") {
    throw new SecurityError("SECURITY_CONFIGURATION");
  }

  return async function authenticate(request, _response, next) {
    const token = getBearerToken(request);
    if (!token) return next(new SecurityError("AUTH_INVALID"));
    let principal;
    try {
      principal = await verifyToken(token);
    } catch (error) {
      const code = error instanceof SecurityError ? error.code : "AUTH_INVALID";
      return next(new SecurityError(code));
    }
    if (!isVerifiedPrincipal(principal)) return next(new SecurityError("AUTH_INVALID"));

    let session;
    try {
      session = await verifySession(principal);
    } catch (error) {
      const code = error instanceof SecurityError ? error.code : "SESSION_UNAVAILABLE";
      return next(new SecurityError(code));
    }
    if (!isCurrentSession(session, principal, clock())) {
      return next(new SecurityError("SESSION_UNAVAILABLE"));
    }

    requestPrincipals.set(request, principal);
    requestSessions.set(request, session);
    requestTokens.set(request, token);
    return next();
  };
}

function createAuthorizationMiddleware({ authorize, action, resolveScope } = {}) {
  if (typeof authorize !== "function" || !Object.hasOwn(actions, action) ||
      typeof resolveScope !== "function") {
    throw new SecurityError("SECURITY_CONFIGURATION");
  }
  return async function authorizeRequest(request, _response, next) {
    const principal = requestPrincipals.get(request);
    const session = requestSessions.get(request);
    if (!principal || !session) return next(new SecurityError("AUTH_INVALID"));

    try {
      const scope = resolveScope(request);
      if (!scope || typeof scope !== "object" || Array.isArray(scope) ||
          Object.getPrototypeOf(scope) !== Object.prototype ||
          Object.keys(scope).some(key => !allowedScopeKeys.has(key))) {
        throw new SecurityError("AUTHORIZATION_DENIED");
      }
      const context = await authorize({ principal, session, action, ...scope });
      requestAuthorizations.set(request, context);
      return next();
    } catch (error) {
      const code = error instanceof SecurityError ? error.code : "MEMBERSHIP_UNAVAILABLE";
      return next(new SecurityError(code));
    }
  };
}

const requestAuthorizations = new WeakMap();

function getRequestSecurity(request) {
  const principal = requestPrincipals.get(request);
  const session = requestSessions.get(request);
  const authorization = requestAuthorizations.get(request);
  if (!principal || !session) return null;
  return Object.freeze({ principal, session, authorization });
}

// Deliberately separate from enumerable request properties to reduce the risk
// of accidental token logging. A future Data API adapter may forward this exact
// verified bearer token; it must never persist or log it.
function getVerifiedAccessToken(request) {
  return requestTokens.get(request);
}

function createSecurityErrorHandler() {
  return function securityErrorHandler(error, _request, response, next) {
    if (response.headersSent) return next(error);
    const safe = error instanceof SecurityError
      ? error
      : new SecurityError("INTERNAL_ERROR");
    response.set("Cache-Control", "no-store");
    return response.status(safe.status).json({
      success: false,
      code: safe.code,
      error: safe.message,
    });
  };
}

async function createSecurityComponents({ config, trustedJWKS, trustedRemoteJwks,
  sessionLookup, membershipRepository, clock = () => Date.now() / 1000 } = {}) {
  if (typeof sessionLookup !== "function" ||
      !membershipRepository ||
      typeof membershipRepository.findCurrentMembership !== "function" ||
      typeof clock !== "function") {
    throw new SecurityError("SECURITY_CONFIGURATION");
  }
  const verifyToken = await createTokenVerifier({
    config, trustedJWKS, trustedRemoteJwks, clock,
  });
  const verifySession = createSessionStatusVerifier({ lookup: sessionLookup, clock });
  const authorize = createAuthorizer({ repository: membershipRepository, clock });
  return Object.freeze({
    authenticate: createAuthenticationMiddleware({ verifyToken, verifySession, clock }),
    authorize: (action, resolveScope) => createAuthorizationMiddleware({
      authorize, action, resolveScope,
    }),
    errorHandler: createSecurityErrorHandler(),
    getRequestSecurity,
    getVerifiedAccessToken,
  });
}

module.exports = {
  createAuthenticationMiddleware,
  createAuthorizationMiddleware,
  createSecurityErrorHandler,
  createSecurityComponents,
  getBearerToken,
  getRequestSecurity,
  getVerifiedAccessToken,
};
