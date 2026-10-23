"use strict";

// Fixed, non-secret-bearing messages. Never attach driver/JWT errors as causes.
const messages = Object.freeze({
  AUTH_INVALID: [401, "Authentication required"],
  AUTH_PROVIDER_UNAVAILABLE: [503, "Authentication service unavailable"],
  AUTHORIZATION_DENIED: [403, "Operation not permitted"],
  REQUEST_INVALID: [400, "Request is invalid"],
  RESOURCE_NOT_FOUND: [404, "Resource not found"],
  RESOURCE_CONFLICT: [409, "Resource conflicts with an existing record"],
  IDEMPOTENCY_CONFLICT: [409, "Idempotency key conflicts with an earlier request"],
  STOCK_INSUFFICIENT: [409, "Stock is insufficient for this adjustment"],
  STOCK_LIMIT: [409, "Stock quantity exceeds the supported exact range"],
  INTERNAL_ERROR: [500, "Request could not be completed"],
  SECURITY_CONFIGURATION: [503, "Security configuration unavailable"],
  SESSION_UNAVAILABLE: [503, "Session verification unavailable"],
  MEMBERSHIP_UNAVAILABLE: [503, "Authorization service unavailable"],
  DATABASE_UNAVAILABLE: [503, "Restricted database capability unavailable"],
  TRANSACTION_FAILED: [503, "Protected transaction failed"],
  COMMIT_UNCERTAIN: [503, "Transaction outcome requires reconciliation"],
});

class SecurityError extends Error {
  constructor(code) {
    const entry = messages[code] || messages.SECURITY_CONFIGURATION;
    super(entry[1]);
    this.name = "SecurityError";
    this.code = Object.hasOwn(messages, code) ? code : "SECURITY_CONFIGURATION";
    this.status = entry[0];
  }
}

module.exports = { SecurityError };
