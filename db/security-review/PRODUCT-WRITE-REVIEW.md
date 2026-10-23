# Product write and stock-adjustment preparation

**Status: review-only.** The new SQL is not in the normal migration directory,
has not been executed, and has not been compiled by PostgreSQL. The existing
server routes remain unmounted. No Supabase project or database was contacted.

## Proposed database objects

- `stockwise_private.command_results` stores the original JSON request and
  response, scoped by company, authenticated Supabase user, command, and
  idempotency key. It is not exposed to API roles.
- `stockwise_private.user_audit_events` records the verified database actor,
  company, action, product/order target, and limited event details. Base
  product/order audit triggers remain in place; this adds actor attribution
  that those triggers cannot derive from the current DB owner connection.
- `stockwise_private.lock_company_role`, `begin_command`, `finish_command`,
  `record_user_event`, and `validate_product_payload` are private helpers.
- `stockwise_api.get_product`, `create_product`, `update_product`,
  `archive_product`, and `adjust_stock` are the proposed narrow RPC surface.
  Their function owners are non-login writer roles. The RPCs derive identity
  from `auth.uid()` and independently enforce the active company membership.

The role prerequisite is separate in
`PRODUCT-WRITE-ROLE-PROVISIONING-PROPOSAL.sql`; it creates only non-login,
non-superuser, non-BYPASSRLS writer roles and grants the migrator SET-only
membership. It grants no writer role to `anon`, `authenticated`,
`service_role`, or `authenticator`.

## Authorization and transaction boundary

Owner/Admin may create, update, archive products, and adjust stock in their
active company. Staff and Viewer may not invoke these write commands. Active
membership is checked again inside the database command; browser-supplied
company IDs only select a target and do not establish authorization.

Each write is intended to run as one Data API RPC and one PostgreSQL transaction:

1. Lock and verify the caller's active company membership.
2. Take a transaction-scoped idempotency lock. A repeated key with the same
   normalized request returns the exact stored response; the same key with a
   different payload is rejected.
3. Perform the product write or create one ordinary adjustment order and one
   order item.
4. For stock adjustment, call the existing
   `stockwise.post_order(uuid,uuid,uuid)` path. The base stock-movement trigger
   updates `stock_balances`; the base nonnegative and deferred
   ledger/order-integrity constraints remain authoritative.
5. Write the actor event and save the idempotency response before commit.

An error before commit is intended to roll back all business, audit, and
idempotency rows together. The app performs no automatic retry. A lost response
is returned to the caller as uncertain; a retry must use the same identity,
company, command, key, and payload. The database—not a process-local cache—is
the idempotency authority.

The adjustment function relies on the existing `guard_order_item()` trigger,
which locks the parent order with `SELECT ... FOR UPDATE`. The proposed
inventory writer therefore receives SELECT on only the parent columns needed
by that trigger plus column-level UPDATE on `orders.notes` to satisfy
PostgreSQL's row-lock privilege requirement. No API function exposes an order
notes update; status/posting fields remain ungranted. This compatibility grant
needs independent review and an actual PostgreSQL test.

`NUMERIC` prices and `BIGINT` quantities are serialized as decimal strings;
JavaScript numbers are not used for money or large quantities. The first RPC
contract supports only the list limit, not search or active filters.

## Implementation status

- `server/services/product-inventory.cjs` contains validated service contracts
  for product reads/writes and stock adjustment. It performs application-level
  role checks but is not mounted into the live server.
- `server/repositories/supabase-product-repository.cjs` is a request-scoped
  Data API adapter. It only accepts a publishable/anon API key, forwards the
  verified request token from private middleware context, calls a fixed RPC
  allowlist, and has no administrative `DATABASE_URL` or service-role
  fallback. It is not configured or mounted.
- `tests/security/components.test.cjs` uses synthetic JWTs and mocked
  repositories/fetch. These are unit tests only.
- `PRODUCT-WRITE-ROLE-PROVISIONING-PROPOSAL.sql` and
  `PRODUCT-WRITE-PROPOSAL.sql` are review-only SQL source. Their existence does
  not establish that the grants, policies, triggers, types, or function bodies
  are accepted by PostgreSQL.
- `PRODUCT-WRITE-TEST-PLAN.md` lists the required isolated PostgreSQL tests.

## Remaining blockers and risks

1. The membership/session adapter for the live Express request path remains
   unconfigured. The current authorization interfaces require trusted session
   and membership data; no fake or local-demo adapter may be used to enable
   real API mode.
2. The SQL references the previously proposed
   `stockwise_private.company_memberships` and
   `current_company_role(uuid)` objects. Neither is confirmed deployed.
3. Supabase Auth issuer/JWKS/audience configuration, Data API exposed schemas,
   API-key class, callable roles, Auth schema grants, and hosted JWT/session
   behavior remain unverified.
4. The existing `DATABASE_URL` health-check role may bypass RLS. The new
   request adapter does not use it, but the live server still has the existing
   DB health-check configuration until separately changed.
5. A valid JWT does not by itself establish immediate session revocation.
   The request session-status adapter is still required; database membership
   deactivation is rechecked by the RPC and serialized with active writes.
6. `stockwise.post_order` is privileged. The grant to
   `stockwise_inventory_writer`, function ownership, trigger compatibility,
   RLS, exact grants, and catalog postflight must be independently reviewed and
   tested in a fresh isolated PostgreSQL 17 database.
7. Idempotency records have no cleanup/retention policy yet. Audit details and
   reason text need a retention/privacy decision.
8. The existing Phase 2 launcher remains blocked. Its reviewed-source manifest
   may be stale after protected security-source edits. Do not bypass the
   launcher or use the existing Supabase project as a test target.

## Verification status

Only the offline Node unit suite is eligible in this environment. No SQL,
PostgreSQL, RLS, Data API, hosted authentication, Supabase, or concurrency
integration tests have been executed for these additions.
