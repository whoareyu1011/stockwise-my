---
name: Approved security planning decisions
description: User-confirmed StockWise MY security requirements and the limits of that approval.
---

The user approved these design decisions for planning:

- Authentication provider: Supabase Auth.
- Viewer: read-only access to products, inventory and orders.
- Stock adjustments and order reversals: Owner/Admin only.
- Company creation and first-owner onboarding: trusted backend workflow with an invitation process.
- Administrative database credentials must be separated from business-runtime credentials.
- Every business operation must enforce company-level authorization.

Approval covers planning only, not implementation or deployment.

**Why:** The user explicitly confirmed these decisions in the attached planning instructions.

**How to apply:** Preserve these requirements when proposing subsequent work. Do not treat other role permissions or existing prototype behavior as approved. Obtain explicit implementation and target-specific database/deployment approval before acting.
