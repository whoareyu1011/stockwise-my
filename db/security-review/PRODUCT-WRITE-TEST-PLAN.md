# Product and stock-adjustment test plan

**Status: test specification only.** SQL in the write proposals has not been
executed. The Replit environment has no approved isolated PostgreSQL target;
the local Phase 2 launcher remains blocked and must not be bypassed.

## Unit tests (mock-only)

`npm run test:security:components` exercises:

- Product service validation, role denials, company-scope arguments, and
  response field allowlists.
- Supabase repository URL/key checks, request-scoped verified-bearer
  forwarding, fixed RPC paths, and publishable-key-only behavior.
- Exactly one Data API RPC per write; no client-side multi-call transaction
  and no automatic retry. A transport failure is returned as an uncertain
  outcome so a later retry must retain the same idempotency key and payload.
- Mock-repository idempotency replay/conflict behavior and safe error mapping.

These tests do not prove PostgreSQL atomicity, RLS, role grants, trigger
behavior, or concurrency. The mock represents those database contracts; it is
not evidence that SQL implements them correctly.

## Required isolated PostgreSQL 17 integration cases

Use a fresh disposable target and synthetic companies/users/products only.
Connect each request test as the restricted Data API role with a valid
synthetic/approved test identity; do not run them as table owner or migrator.

### Installation and permissions

1. Verify all preflight checks pass only with the exact approved base/read
   prerequisites and write-owner roles.
2. Apply each approved SQL file in the documented order; verify any statement
   failure rolls the transaction back without leaving partial objects.
3. Confirm exactly one overload for each RPC name, exact argument signatures,
   owner role, `SECURITY DEFINER`, `search_path = pg_catalog, pg_temp`, and
   EXECUTE ACL.
4. Confirm `anon`, `service_role`, and `PUBLIC` cannot execute the write RPCs;
   `authenticated` can execute only approved API RPCs; no API role can directly
   read or modify base/private tables.
5. Confirm writer roles are `NOLOGIN`, `NOBYPASSRLS`, cannot create API schema
   objects after installation, cannot directly change balances or movements,
   and cannot update order posting state.

### Product commands

6. Owner/Admin create, update, and archive products in their active company.
   Staff/Viewer and anonymous callers are denied by both RPC checks and
   effective database permissions.
7. A valid user cannot create, read, update, or archive a product in another
   company by forging `p_company_id`, product IDs, body fields, or URL values.
8. Reject unknown/forged input fields, malformed decimal strings, unsafe
   thresholds, empty names/SKUs, duplicate company SKU, and writes to archived
   products. Confirm values outside the approved response precision are not
   rounded.
9. Viewer/Staff/Owner/Admin product read projections expose exactly the
   approved fields. A direct base-table query by an API role still fails.
10. Verify a product creation's zero balance, base `audit_logs` catalogue
    record, private actor audit event, and idempotency result are all present
    after commit. Force an error at each late step and verify all effects roll
    back together.

### Stock adjustment, ledger integrity, and retry behavior

11. Owner/Admin inbound and outbound adjustments create one draft adjustment
    order, one item, one posted order, one correctly signed stock movement, one
    actor-attributed private event, and matching base audit evidence.
12. Staff/Viewer/anonymous callers are denied by the database command itself;
    direct inserts into orders, order items, stock movements, and balance
    edits remain unavailable to API roles.
13. Reject invalid direction, reason, quantity, inactive/missing product,
    missing membership, forged company/product pair, and insufficient stock.
    For every rejection, verify no order, item, movement, audit event, balance
    change, or idempotency result was committed.
14. Repeat the same request after a simulated lost response with the same
    user, company, command, key, and payload. The exact original result is
    returned and no second order/movement/audit effect appears. Reuse that key
    with a different payload or another command and verify conflict.
15. Submit simultaneous requests with the same key and same payload; verify
    they serialize to one result/effect. Submit same key with different
    payloads; exactly one payload wins and the other receives conflict.
16. Run two or more concurrent stock-outs whose combined quantity exceeds the
    balance. At most the affordable total may post; no balance becomes
    negative, no movement is duplicated, and deferred ledger/balance integrity
    checks pass. Also test concurrent inbound operations and mixed in/out
    requests on the same product.
17. Force failures after order creation, after item insertion, after posting,
    after audit insertion, and before idempotency result storage. Verify every
    failure rolls back all business effects.
18. Revoke a membership concurrently with an adjustment. Because the RPC
    locks the membership row, verify the write completes wholly before
    deactivation or is denied after it; never allow a partially authorized
    transaction.

## Planned evidence

- PostgreSQL version, sanitized role/effective-grant summary, exact function
  signatures/owners/configuration, RLS and policy state.
- Per-case PASS/FAIL with case identifier, sanitized SQLSTATE, and row counts
  for synthetic data only.
- Concurrent-runner summary and final stock-ledger equality query results.
- Rollback and cleanup confirmation.

Do not retain tokens, API keys, database URLs, real business rows, or full
database error messages in the report.
