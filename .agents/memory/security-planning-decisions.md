---
name: Approved security planning decisions
description: User-confirmed StockWise MY security requirements and the limits of that approval.
---

The user approved these design decisions for planning:

- Authentication provider: Supabase Auth.
- Product creation and editing: Owner/Admin only.
- Staff draft scope: own drafts only. Staff may create drafts and view/edit only drafts they created, subject to company isolation; not other Staff members' drafts.
- Owner/Admin may view and manage all drafts within their own company.
- Viewer cannot create/edit drafts and may view only permitted basic order status.
- Staff cannot post orders or directly modify posted orders. Only Owner/Admin may post.
- Do not implement draft reassignment, transfer or takeover for now.
- Data exports: Owner/Admin only.
- Viewer: may see products, stock quantities and basic order status only. Hide contact details, costs and audit logs.
- Membership management: Owner/Admin.
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
