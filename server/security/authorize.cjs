"use strict";
const { SecurityError } = require("./errors.cjs");
const { isVerifiedPrincipal, isUuid } = require("./verify-token.cjs");
const { isCurrentSession } = require("./session-status.cjs");
const { roleAllows, resourceAllows, requiresOrder, grantableRoles } = require("./permissions.cjs");
const issued = new WeakMap();

function isAuthorizedContext(context, principal) {
  return Boolean(context && issued.get(context) === principal);
}

function createAuthorizer({ repository, clock = () => Date.now() / 1000 } = {}) {
  return async function authorize({ principal, session, companyId, action,
    resourceId, orderKind, targetIdentityId, requestedRole } = {}) {
    const deny = () => { throw new SecurityError("AUTHORIZATION_DENIED"); };
    if (!isVerifiedPrincipal(principal)) throw new SecurityError("AUTH_INVALID");
    if (!isCurrentSession(session, principal, clock())) throw new SecurityError("SESSION_UNAVAILABLE");
    if (!isUuid(companyId)) deny();
    if (!repository || typeof repository.findCurrentMembership !== "function")
      throw new SecurityError("MEMBERSHIP_UNAVAILABLE");
    let member;
    try { member = await repository.findCurrentMembership({
      issuer: principal.issuer, subject: principal.subject, companyId }); }
    catch { throw new SecurityError("MEMBERSHIP_UNAVAILABLE"); }
    if (!member || member.issuer !== principal.issuer || member.subject !== principal.subject ||
        member.companyId !== companyId || !isUuid(member.identityId) ||
        member.identityStatus !== "active" || member.companyStatus !== "active" ||
        member.status !== "active" || !roleAllows(member.role, action)) deny();
    let order;
    if (requiresOrder(action)) {
      if (!isUuid(resourceId)) deny();
      if (typeof repository.findOrder !== "function") throw new SecurityError("MEMBERSHIP_UNAVAILABLE");
      try { order = await repository.findOrder({ companyId, orderId: resourceId }); }
      catch { throw new SecurityError("MEMBERSHIP_UNAVAILABLE"); }
      if (!order || order.companyId !== companyId || order.id !== resourceId) deny();
    }
    if (!resourceAllows({ role: member.role, identityId: member.identityId,
      action, order, orderKind })) deny();
    if (action === "membership.manage") {
      const ceiling = grantableRoles(member.role);
      if (!isUuid(targetIdentityId) || targetIdentityId === member.identityId ||
          !ceiling.includes(requestedRole)) deny();
      if (typeof repository.findTargetMembership !== "function")
        throw new SecurityError("MEMBERSHIP_UNAVAILABLE");
      let target;
      try { target = await repository.findTargetMembership({ companyId, identityId: targetIdentityId }); }
      catch { throw new SecurityError("MEMBERSHIP_UNAVAILABLE"); }
      if (!target || target.companyId !== companyId || target.identityId !== targetIdentityId ||
          !ceiling.includes(target.role)) deny();
    }
    if (!isCurrentSession(session, principal, clock())) throw new SecurityError("SESSION_UNAVAILABLE");
    const context = Object.freeze({ companyId, identityId: member.identityId,
      role: member.role, action, resourceId: requiresOrder(action) ? resourceId : undefined,
      orderKind: order ? order.kind : action === "draft.create" ? orderKind : undefined,
      targetIdentityId: action === "membership.manage" ? targetIdentityId : undefined,
      requestedRole: action === "membership.manage" ? requestedRole : undefined,
      sessionId: principal.sessionId,
      projection: member.role === "Viewer" ? "basic-only" :
        member.role === "Staff" ? "own-sales-work" : "company-business" });
    issued.set(context, principal);
    return context;
  };
}

module.exports = { createAuthorizer, isAuthorizedContext };
