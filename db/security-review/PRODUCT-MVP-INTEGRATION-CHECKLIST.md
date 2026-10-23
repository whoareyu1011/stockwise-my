# Product and inventory MVP integration gate

**Status: implementation interfaces only.** The live server does not mount these
components, no Supabase configuration is installed, and no database adapter is
implemented. Unit tests use synthetic JWTs and mocked repositories. They are not
PostgreSQL, RLS, Supabase Auth, or hosted integration tests.

## Before configuring a real server

- Identify the exact Supabase project and obtain its Auth issuer and JWKS URL
  from trusted project configuration. Configure the expected audience and
  permitted signing algorithms from that project's supported Auth settings;
  do not infer values from a request or invent defaults.
- The JWKS URL must be HTTPS, share the issuer origin, and use the expected
  `/.well-known/jwks.json` path. The JOSE remote resolver is lazy, bounded,
  refuses redirects, limits response size, caches keys, and refreshes keys;
  actual key retrieval and rotation behavior still needs a reviewed hosted
  test.
- Define a real authoritative session-status adapter or explicitly approve a
  documented session-revocation limitation. Missing, stale, or unavailable
  status data must deny access. The test fixture is not a revocation service.
- Provision the authenticated-user-to-company membership records through an
  approved, audited first-Owner/invitation process. Every request must reread
  active identity, company, membership, and role; browser user IDs, company
  selectors, and role claims are not authority.

## Database and API prerequisites

- Independently review and test `db/migrations/0001_inventory.sql`,
  `db/deployment/01_create_roles.sql`,
  `db/deployment/02_grant_migration_access.sql`,
  `db/deployment/03_harden_owner_function_defaults.sql`,
  `db/security-review/PRODUCT-READ-PROPOSAL.sql`, and
  `db/security-review/PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql`.
  None is applied or verified against the current Supabase project by this work.
- Expose only the approved `stockwise_api` Data API schema. Do not expose the
  business base schema or private membership schema. Grant only the exact
  reviewed RPC signatures to the intended authenticated role; do not grant
  ordinary business requests table access, owner/migrator membership, or
  service-role access.
- The existing product-read SQL is read-only. A separately reviewed additive
  database design is still required for product create/update/archive and stock
  adjustment commands. The HTTP-facing service interfaces here do not grant
  database permissions or create those commands.
- Never use the administrative `DATABASE_URL` for business requests. A future
  Supabase Data API adapter must be request-scoped and forward only the same
  verified user bearer token, plus the approved public/publishable API key.
  Service-role and database-owner credentials must remain outside that
  request dependency graph.

## Required real integration tests before mounting business routes

- Missing, malformed, expired, wrong-issuer, wrong-audience, wrong-signature,
  unknown-key, anonymous, and unavailable-JWKS requests fail closed.
- Anonymous, inactive, pending, revoked, or stale sessions are denied using the
  real status source; a synthetic session lookup is insufficient evidence.
- A valid user cannot read or mutate another company's products by changing a
  URL, query, body, JWT custom claim, pagination cursor, or product identifier.
- Owner/Admin can create, update, and archive products only in their active
  company. Staff and Viewer cannot. Returned fields match the approved role
  projection even when a caller requests additional fields.
- Only Owner/Admin can adjust stock. Invalid quantities and reasons are rejected;
  retries with the same company/user/action/idempotency key and same payload
  return the original result; reuse with a different payload is rejected.
- PostgreSQL tests must prove a stock movement, balance update, and audit record
  commit or roll back together; concurrent adjustments serialize correctly,
  cannot oversell, and cannot create duplicate effects.
- Verify effective grants, role membership closure, SECURITY DEFINER owners,
  fixed search paths, exposed schemas, RLS behavior, and cross-company denial
  using genuinely restricted database sessions on a separately approved
  PostgreSQL 17 target.

## Enabling condition

Keep demo mode and the existing fail-closed `/api/products` route until the
target-specific SQL and adapters have passed independent review and real
integration tests, then obtain separate explicit approval before mounting or
enabling the API.
