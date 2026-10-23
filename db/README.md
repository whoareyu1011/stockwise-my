# StockWise inventory migration — preparation only

**Status: repository records the migration as NOT APPLIED.** Retained reports
document historical disposable PostgreSQL 17.6 tests of the inventory migration
and role prerequisites. The later product-read proposals have not been executed.

This folder is review material. Nothing here is imported by `server.js`,
`package.json`, or the Run workflow. Do not paste the SQL into a database editor
and execute it merely to review it.

## Files

- `migrations/0001_inventory.sql`: one manually applied, transactional migration.
- `tests/TEST_PLAN.md`: proposed acceptance and concurrent-session tests.
- `tests/check_preparation.py`: offline structural checks; no database connection.

Exactly eight tables are proposed in a new `stockwise` schema:

| Table | Purpose |
| --- | --- |
| companies | Business identity, Malaysian tax/registration details and defaults |
| products | Catalogue, whole-unit stock metadata, six-decimal cost/price estimates |
| contacts | Customer/supplier details, without treating names or TINs as unique |
| orders | Draft/post/reverse command headers, references and idempotency keys |
| order_items | Quantities, prices, discounts and immutable posted product snapshots |
| stock_balances | Trigger-maintained summary, one row per company/product |
| stock_movements | Append-only stock ledger, linked to source lines or originals |
| audit_logs | Append-only posting/reversal and catalogue-change metadata |

Invoices, submission tracking, attachments, memberships, authentication, OCR,
Gmail, MyInvois integration, payments and browser-data import are not included.
User identities and password/credential columns are not added.

## Inspection and isolated-test status

The retained read-only inspection of the connected Supabase project reported no
application objects in `public`; managed schemas were present, and the inspected
connection role bypassed RLS. Those are historical findings, not a current
inspection of Supabase.

`test-reports/local-postgresql17.md` records 58 grouped checks against the
prepared `0001_inventory.sql` in a disposable PostgreSQL 17.6 cluster.
`test-reports/prerequisites-postgresql17.md` records 40 grouped checks against
the then-current role prerequisite SQL and unchanged migration. Both reports
say their temporary clusters were stopped and removed; neither is a Supabase
deployment result.

The product-read SQL and role-provisioning proposals were prepared later. Their
review explicitly says they were not executed or tested. No current database or
Supabase state was inspected for this update.

The connected Supabase database is not a test fallback. Do not use
`DATABASE_URL` as an implicit test target. Any future database-changing test
requires an explicitly identified and separately approved isolated database.

## Review-only instructions

1. Open the migration as text in the editor; do not execute it.
2. Review table fields, constraints, function bodies and permissions below.
3. Run `python3 -B db/tests/check_preparation.py` for non-mutating structural
   checks. This does not parse/execute PostgreSQL SQL or validate concurrency.
4. Review `tests/TEST_PLAN.md` and identify an approved isolated test database.
5. Review owner-role provisioning and migration-operator privileges separately.
6. Approve testing on that specific isolated database before any DDL/DML tests.
7. Review test results, backup/recovery arrangements and the exact live target.
8. Give separate explicit approval before applying to connected Supabase.

This is deliberately not a migration runner. There are no startup hooks,
automatic schema changes, test-target fallbacks or credential-bearing commands.
Use an administrator-reviewed manual workflow only after approval.

## Prerequisites deliberately NOT implemented

The migration fails closed unless a separately approved administrator has:

- Provisioned `stockwise_owner` with NOLOGIN, NOSUPERUSER, NOBYPASSRLS,
  NOCREATEROLE, NOCREATEDB and NOINHERIT.
- Kept that owner out of every other role and kept API/runtime roles out of it.
- Used a clean owner with no custom default-privilege entries. The preflight
  rejects existing entries rather than accidentally inheriting global grants
  which cannot be undone with per-schema default revocations.
- Given a separate migration operator membership with permission to SET ROLE
  to that owner, plus CREATE on the target database for schema creation.
- Verified that `stockwise` is not an exposed Supabase Data API schema.
- Reviewed default privileges, event triggers, role inheritance and the complete
  privilege graph on the actual target. Revoking a direct grant does not remove
  access inherited through an unrelated role or a privileged administrator.

The migration creates the schema as the migration operator, assigns it to the
non-login owner, then SET LOCAL ROLEs to that owner to create its objects.
It does not create/alter roles or grant runtime access. It does revoke access to
its new objects from PUBLIC and any existing named Supabase API roles. Those
revocations exist only in the prepared file and have not been executed.

All DDL is in one transaction. An existing `stockwise` schema causes failure;
there is no IF NOT EXISTS behavior hiding incompatible objects. The schema
comment records version 0001; maintain applied-version records in the future
approved migration workflow, not in app startup. No ninth tracking table is
silently created here.

## Stock posting design

`post_order(company_id, order_id, operation_key)` operates on an existing draft.
It takes IDs only, not a mutable item payload:

1. Lock the header; reject the wrong company, empty order or wrong status.
2. On a retry, return the same order for its original key without new writes,
   even if it has since been reversed. Another key is rejected.
3. Lock product masters in UUID order for stable catalogue snapshots.
4. Lock product balances in UUID order. Sum repeated product lines before
   checking outgoing quantities against balances.
5. Copy SKU/name/unit/current unit-cost estimates into the draft items.
6. Compute totals from generated line totals and move the header to posted.
7. Insert one movement per item in deterministic product order.
8. Insert a posting audit event. Everything commits or rolls back together.

No BEGIN/COMMIT inside the functions: PostgreSQL runs each call in its caller's
transaction. Do not catch an error and then pretend the command succeeded.
Use READ COMMITTED for initial testing. If SERIALIZABLE/REPEATABLE READ is later
chosen, serialization failures must retry the entire transaction with the same
key. Lock timeouts/deadlocks likewise require a whole-transaction retry.

Header idempotency is a unique `(company_id, posting_key)`. Reusing a key for a
different order cannot create a second posting; the unique constraint rejects
and rolls back the competing operation. Item payload cannot change once posted.
An eventual HTTP API also needs its own request-validation/retry contract.

Draft item changes lock their parent header. Future draft-edit command functions
must lock the header before editing lines to avoid unnecessary deadlocks with
posting. Raw multi-statement administrator editing is not a runtime API.

### Ledger, balance and commit-time checks

- Product creation initializes a zero balance through an AFTER INSERT trigger.
- A BEFORE INSERT movement trigger validates company, posted source, line,
  product, direction, date and, for reversals, the exact opposite original.
- An AFTER INSERT movement trigger atomically changes the balance only when
  it stays nonnegative. A missing balance or numeric overflow fails the command.
- Row updates/deletes and truncation of stock movements are rejected.
- Runtime ACLs deny direct movement/balance DML. A balance trigger also rejects
  direct edits; legitimate writes are nested in product/ledger triggers.
  Trigger-depth checking is defense in depth, not an authorization mechanism.
- Deferred constraint triggers compare final balances to ledger sums and verify
  posted order totals, complete source/reversal movement counts and matching
  operation-key audit events at commit. Reversals cannot contain ordinary items
  or change the original contact.
- Both deferred validators are SECURITY DEFINER read-check functions, so final
  checks do not depend on a future caller having direct table-read privileges
  after the command function returns. No additional caller grants are added.
- Posted header/item changes are blocked. Generated total columns are not
  compared as populated NEW values in BEFORE triggers.

With constraints left INITIALLY DEFERRED, an order can temporarily have a posted
header before its movements are inserted, but cannot commit in that state.
Do not SET CONSTRAINTS ALL IMMEDIATE before calling these multi-step functions;
that unsupported mode fails closed rather than accepting a partial posting.
To exercise final checks in tests, call SET CONSTRAINTS ALL IMMEDIATE *after*
the function finishes.

Only trusted owners/administrators can bypass triggers or change ownership.
These protections do not claim to resist a database administrator.

### Reversals

`reverse_order(company_id, order_id, operation_key, business_date, reason)`
locks the original header, then balance rows in product order. It creates a
new reversal header and exactly opposite movements and marks the original
reversed, in one transaction. No original movement is removed.

An identical retry returns the existing reversal. A different key, date, or
reason is rejected. Unique constraints permit only one full reversal per order
and movement. A reversal that would consume unavailable stock is rejected.
Partial reversals, reversing a reversal and automatic invoice-driven stock
changes are not supported.

### Opening stock and browser history

No import is implemented or executed. An eventual approved snapshot cutover must:

1. Export and preserve browser data without deleting it.
2. Agree an as-of time and quantities with the owner.
3. Insert each nonzero approved quantity once using an opening-balance order.
4. Never replay the same pre-cutover transactions into that opening quantity.
5. Keep old history separately until a historical-only import/archive design is
   approved; this migration does not provide a historical-only bypass status.
6. Record zero openings in a later import manifest/audit design, without
   inventing zero-quantity ledger movements.

Opening postings require no previous movements for the affected products and
one item per product. A partial unique index permits only one opening movement
per company/product, including after reversal. Use later adjustments for
corrections, not a second opening. Historical replay needs a separately reviewed
reconciliation plan because the frontend allows unrecorded direct stock edits.

## Security before any business-data API

The existing connection role was observed to bypass RLS. Company-aware FKs stop
cross-company links, not cross-company reads. RLS enabled without policies denies
ordinary non-owner roles, but cannot protect against BYPASSRLS or a table owner.
SECURITY DEFINER posting functions run as the owner and can bypass owner RLS.

Consequently this migration grants **no access**, even to the two command
functions. They accept a company ID but do not implement user authorization.
Do not grant them to clients/API roles and call that tenant security.

Before exposure, a separately approved access-control phase must:

- Establish authenticated identities and trustworthy company memberships.
- Provision a distinct non-superuser, non-BYPASSRLS runtime identity with no
  membership in the owner/migration roles and no direct ledger/balance DML.
- Add membership checks to authorized command entry points and scoped read
  access. A browser-supplied company/user ID or settable SQL variable is not
  proof of identity.
- Use either a server-only runtime role behind an authenticated Express API,
  or a separately designed Supabase Auth/JWT/RLS approach. Both must enforce
  membership inside privileged posting boundaries before granting EXECUTE.
- Keep the private schema outside Data API exposure and test the entire grant
  matrix, including inherited role grants.
- Store any future login credential only in a secure secrets flow, not in SQL,
  source code, audit rows or any business table.

None of that authorization, role provisioning, credential switching, new APIs
or policy granting is implemented in this preparation. DATABASE_URL is unchanged.

### Explicit SECURITY DEFINER inventory

All seven are created while SET LOCAL ROLE is `stockwise_owner`, have fixed
`pg_catalog, pg_temp` search paths, fully qualified application relations, no
dynamic SQL, and no PUBLIC/API/runtime EXECUTE grant:

- `initialize_balance`: initializes a new product's zero balance.
- `audit_catalogue_change`: records catalogue field-name metadata.
- `apply_movement`: atomically maintains a nonnegative balance.
- `check_balance_integrity`: reads final ledger/balance state at deferred check.
- `check_order_integrity`: reads final header/items/movements/audit state.
- `post_order`: privileged, idempotent posting command.
- `reverse_order`: privileged, idempotent full reversal command.

The other seven helpers remain security-invoker functions; immediate trigger
calls inside the command/maintenance functions execute under that active owner
context. Deferred callbacks deliberately use their own definer context.
The migration's intended ownership/ACLs are a static property of the script,
not evidence of objects installed in the live database. Verify actual ownership,
grants, inherited memberships and RLS behavior on the approved test target.

## Scope and limitations

- MYR and whole units only; no warehouse/batch/serial allocation.
- Prices/discounts preserve six decimals; this is not final invoice tax/rounding
  or legally compliant accounting design. Payment status is a fixed posting
  snapshot, not a payment ledger; later payment changes need their own records.
- Cost snapshots are estimates copied at posting, not FIFO/weighted-average
  valuation or cost-layer reversals.
- Catalogue create/update events and posting/reversal commands are audited
  automatically. Draft line edits/deletions do not yet have detailed audit
  events; future authorized editing commands must add those if required.
- Actor is the database session identity, not an authenticated person.
- Application development is deliberately blocked until access control exists;
  a schema alone does not make the current frontend database-backed.

## Recovery review

A failed migration transaction rolls back its DDL. A committed migration is not
automatically reversed. Before later live execution, agree a backup/restore
point and confirm all prerequisites on the exact target. After real data exists,
use a reviewed forward correction or approved recovery; do not casually DROP
the schema, truncate the ledger, disable triggers or delete browser records.
