# Product and inventory MVP integration gate

**Status: unmounted implementation interfaces and review-only SQL proposals.**
The live server does not mount these components, no Supabase configuration is
installed, and no real membership/session adapter is configured. A request-
scoped Data API product repository exists but is not configured or mounted.
Unit tests use synthetic JWTs and mocked repositories. They are not PostgreSQL,
RLS, Supabase Auth, or hosted integration tests.

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
  `db/security-review/PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql`,
  `db/security-review/PRODUCT-WRITE-ROLE-PROVISIONING-PROPOSAL.sql`, and
  `db/security-review/PRODUCT-WRITE-PROPOSAL.sql`.
  None is applied or verified against the current Supabase project by this work.
- Expose only the approved `stockwise_api` Data API schema. Do not expose the
  business base schema or private membership schema. Grant only the exact
  reviewed RPC signatures to the intended authenticated role; do not grant
  ordinary business requests table access, owner/migrator membership, or
  service-role access.
- The product-read SQL is a review-only proposal. An additive review-only
  product-write/stock-adjustment SQL proposal now exists as a separate file;
  neither proposal has been independently approved, applied, or database-tested.
  The HTTP-facing services and adapter do not themselves grant database
  permissions or expose business routes.
- Product and stock writes are each one `stockwise_api` RPC/transaction. The
  database RPC—not a Node memory cache—locks `(company, auth user, command,
  idempotency key)`, compares the submitted JSON payload, performs the change,
  writes its actor-attributed private audit event, and stores the original
  response before commit. Do not automatically retry a write after a timeout;
  surface an uncertain outcome and retry only with the same key and payload.
- A completed adjustment uses the existing `stockwise.post_order(uuid,uuid,uuid)`
  path with one `adjustment_in` or `adjustment_out` item. Existing movement
  validation, balance-update trigger, nonnegative constraint, and deferred
  ledger/order integrity checks must all pass in the same transaction.
- The additive SQL returns `NUMERIC` and `BIGINT` values as text to avoid
  JavaScript precision loss. The read RPC proposal was updated accordingly.
  Search/active filters are not part of the current RPC contract; the service
  rejects them rather than silently ignoring them.
- The API adapter is `server/repositories/supabase-product-repository.cjs`.
  It is request-scoped, obtains its bearer only from the authentication
  middleware's private request context, sends a publishable/anon API key, and
  calls only the fixed `stockwise_api` RPC allowlist. It has no `DATABASE_URL`,
  service-role, or administrative fallback and is not mounted by `server.js`.
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
- Product command SQL test cases are specified in
  `db/security-review/PRODUCT-WRITE-TEST-PLAN.md`. The current Replit process
  has no approved isolated PostgreSQL target. The Phase 2 launcher remains
  blocked; do not execute these SQL proposals through another path.

## Safe separate-test-database sequence (not performed)

1. The project owner supplies or approves a disposable PostgreSQL 17 test
   target that is separate from the existing Supabase project. Confirm who
   owns it, how it is isolated, and that it contains no production data or
   credentials. No target is currently approved by this work.
2. Before any SQL, a second reviewer verifies the Phase 2 source manifest.
   It currently covers protected source files, including `server/security/errors.cjs`;
   any hash mismatch must be reviewed and the manifest refreshed only through
   its documented review process. Keep the launcher block intact.
3. Use a separate, short-lived migration credential through the approved
   database administration path. Provision the roles in the exact reviewed
   order: base role/deployment prerequisites, read-role provisioning,
   product-read SQL, write-role provisioning, then the additive write SQL.
   Never provide `DATABASE_URL` to the runtime adapter or test request process.
4. Apply SQL manually only after separate approval. Do not place migration
   execution in `npm start` or another application startup path.
5. Configure the application only for the test project using trusted project
   metadata: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`,
   `SUPABASE_AUTH_ISSUER`, `SUPABASE_AUTH_JWKS_URL`, and
   `SUPABASE_AUTH_AUDIENCE`. These are names only; no values are present in
   this repository and no configuration is changed here. Do not use a
   service-role key, database owner, migrator, or `DATABASE_URL` for requests.
6. Verify project URL/key class, Data API exposed schemas, exact function
   grants, role attributes/membership closure, function owners/search paths,
   RLS policies, and absence of direct API-role table access before tests.
7. Run only the reviewed migration test command in the approved isolated
   environment. Capture sanitized SQLSTATEs and assertion results, not tokens,
   key values, connection strings, or business data. A failure stops the run;
   it does not authorize a production workaround.
8. Destroy the test database and short-lived migration credential, verify both
   are gone, then retain only the approved sanitized report.

The existing Supabase project must not be treated as a disposable target merely
because its Table Editor appears empty. The requested development target and
runtime Auth/session/membership adapters remain unresolved.

## Enabling condition

Keep demo mode and the existing fail-closed `/api/products` route until the
target-specific SQL and adapters have passed independent review and real
integration tests, then obtain separate explicit approval before mounting or
enabling the API.
