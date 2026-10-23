"use strict";
// Fixed server-side action vocabulary. These are policy predicates, NOT APIs,
// database grants or claims that SQL/RLS currently enforce the new design.
const roles = Object.freeze(["Owner", "Admin", "Staff", "Viewer"]);
const all = roles;
const operational = ["Owner", "Admin", "Staff"];
const managers = ["Owner", "Admin"];
const actions = Object.freeze({
  "product.basic.read": all,
  "product.sales.read": operational,
  "product.cost.read": managers,
  "product.write": managers,
  "stock.quantity.read": all,
  "stock.history.read": managers,
  "contact.select": operational,
  "contact.manage": managers,
  "contact.work.read": operational,
  "draft.create": operational,
  "draft.read": operational,
  "draft.edit": operational,
  "draft.cancel": operational,
  "order.basic.read": all,
  "order.work.read": operational,
  "order.post": managers,
  "order.reverse": managers,
  "stock.adjust": managers,
  "export": managers,
  "membership.manage": managers,
  "audit.read": managers,
});
const needsOrder = new Set(["draft.read", "draft.edit", "draft.cancel",
  "contact.work.read", "order.basic.read", "order.work.read", "order.post", "order.reverse"]);

function roleAllows(role, action) {
  return roles.includes(role) && Object.hasOwn(actions, action) && actions[action].includes(role);
}

function resourceAllows({ role, identityId, action, order, orderKind }) {
  if (!roleAllows(role, action)) return false;
  if (action === "draft.create")
    return ["sale", "purchase"].includes(orderKind) && (role !== "Staff" || orderKind === "sale");
  if (!needsOrder.has(action)) return true;
  if (!order || !["draft", "posted", "reversed", "cancelled"].includes(order.state)) return false;
  if (["draft.read", "draft.edit", "draft.cancel", "order.post"].includes(action) &&
      order.state !== "draft") return false;
  if (action === "order.reverse" && order.state !== "posted") return false;
  if (role === "Staff" && (order.creatorIdentityId !== identityId || order.kind !== "sale")) return false;
  if (["draft.read", "draft.edit", "draft.cancel", "order.post"].includes(action) &&
      !["sale", "purchase"].includes(order.kind)) return false;
  return true;
}

function grantableRoles(role) {
  return Object.freeze(role === "Owner" ? ["Admin", "Staff", "Viewer"] :
    role === "Admin" ? ["Staff", "Viewer"] : []);
}

module.exports = { actions, roleAllows, resourceAllows,
  requiresOrder: action => needsOrder.has(action), grantableRoles };
