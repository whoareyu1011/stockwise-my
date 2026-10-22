"use strict";

// Fixed, non-secret-bearing messages. Never attach driver/JWT errors as causes.
const messages = Object.freeze({
  AUTH_INVALID: [401, "Authentication required"],
  AUTHORIZATION_DENIED: [403, "Operation not permitted"],
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
