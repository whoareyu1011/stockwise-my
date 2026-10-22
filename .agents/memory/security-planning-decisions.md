---
name: Approved security planning decisions
description: User-confirmed StockWise MY security requirements and the limits of that approval.
---

The user approved these design decisions for planning:

- Authentication provider: Supabase Auth.
- Product creation and editing: Owner/Admin only.
- Staff draft scope: own drafts only. Staff may create drafts and view/edit only drafts they created, subject to company isolation; not other Staff members' drafts.
- Owner/Admin may view and manage all drafts within their own company.
- Owner/Admin and Staff may create drafts.
- Viewer cannot create/edit drafts and may view only permitted basic order status.
- Staff cannot post orders or directly modify posted orders. Only Owner/Admin may post.
- Do not implement draft reassignment, transfer or takeover for now.
- Data exports: Owner/Admin only.
- Owner/Admin: access to company business data required for their duties. Staff: only customer, order and financial fields required for their assigned work.
- Viewer: products, stock quantities and basic order status only; no contacts, costs, financial details, stock movement history or audit logs.
- Allow cancellation of eligible drafts with appropriate audit records. Never directly delete or silently modify posted orders; posted cancellation/reversal must use an authorized audited workflow.
- Exports must use permitted business datasets, exclude credentials/secrets/auth tokens and apply normal company isolation and field permissions.
- Owner may manage company membership/roles. Admin may manage ordinary membership within explicit limits. Neither Admin nor Staff may create an Owner, transfer ownership or elevate their own privileges. Ownership transfer is out of scope until separately designed and approved.
- Stock adjustments and order reversals: Owner/Admin only.
- Company creation and first-owner onboarding: trusted backend workflow with an invitation process.
- Administrative database credentials must be separated from business-runtime credentials.
- Every business operation must enforce company-level authorization.

Approval covers planning only, not implementation or deployment.

Staff cannot post, adjust stock, reverse orders, manage members or export
company data unless a separately approved exception is documented. Operator is
deprecated and excluded from authorization.

**Why:** The user explicitly confirmed these decisions in the attached planning instructions.

**How to apply:** Preserve these requirements when proposing subsequent work. Do not treat other role permissions or existing prototype behavior as approved. Obtain explicit implementation and target-specific database/deployment approval before acting.
