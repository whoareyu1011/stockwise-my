# StockWise MY — disposable PostgreSQL 17 test report

## Outcome

**58 grouped PostgreSQL checks passed. No migration implementation failure was
observed in the completed checks.** One initial balance-corruption fixture was
blocked by PostgreSQL before reaching its intended assertion; the corrected
fixture passed. A separate initial harness launch could not reach the stopped
local server. Both harness issues are disclosed below.

These are actual PostgreSQL executions, not results from the offline structural
checker. This report is not approval to migrate Supabase or expose business APIs.

## Target, scope and preservation

- Execution: 2026-10-22 approximately 17:03–17:12 UTC
  (2026-10-23 approximately 01:03–01:12 Asia/Kuala_Lumpur).
- PostgreSQL **17.6**, x86_64 Linux; existing binaries, no installation.
- Fresh disposable cluster under `/tmp/swpg-m3t9pz8j`, with its own roles,
  databases, catalogs and synthetic fixtures.
- Private Unix socket only, socket directory/file permissions 0700.
  `listen_addresses` was empty and `inet_server_addr()` was NULL.
  No TCP listener or public port was enabled.
- Every client explicitly specified the private socket, port 6543, local user
  and local database. DB commands/test processes ran with a scrubbed environment.
  `DATABASE_URL` was not read or used. No Supabase connection was opened.
- Exact tested migration: `db/migrations/0001_inventory.sql`.
- SHA-256:
  `b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0`.
- The unchanged migration completed COMMIT in the isolated cluster. It also
  installed successfully in a separate database inside that same cluster using
  a non-superuser, non-BYPASSRLS migration role with explicit test-only owner
  membership/database CREATE permission.
- No application/runtime grants were added. Required synthetic API/test roles,
  owner/migrator memberships and fault-injection objects existed only in this
  disposable cluster. Fault injection did not modify the migration file.
- Checksums confirmed `index.html`, `server.js`, `server.py`, `.replit`,
  `package.json`, `package-lock.json`, `certs/supabase-ca.crt` and the migration
  were unchanged. No existing secrets, roles, workflows or browser data changed.
- Application/database health endpoints were deliberately not called: the
  existing DB health endpoint would connect to Supabase.

## Method

The temporary Node harness used the project's existing `pg` dependency; nothing
was installed. Test SQL used explicit local clients and synthetic data.

Most individual scenarios ran in transactions and forced
`SET CONSTRAINTS ALL IMMEDIATE` **after** the completed command, before rollback.
Other scenarios committed fixtures and command results in separate transactions.
Negative audit/balance cases tested rejection at actual COMMIT and verified
rollback against a full company-state fingerprint.

Concurrency scenarios used separate connections and held transactions open.
Except for the deliberately induced deadlock schedule, the harness observed the
second connection waiting on an actual PostgreSQL transaction lock before
committing/rolling back the first. They were not merely sequential calls.

## Passed checks

Each row below is one grouped check; a row can contain several assertions or
expected database rejections. Expected rejections count as passes only when the
error and applicable unchanged-state assertions matched.

| # | Completed check | Result |
| --- | --- | --- |
| 1 | Unmodified migration compilation and installation | PASS |
| 2 | Missing owner rejected before schema creation | PASS |
| 3 | Unsafe owner flags rejected | PASS |
| 4 | Owner membership in another role rejected | PASS |
| 5 | API-role membership in owner rejected | PASS |
| 6 | Migrator without owner membership rejected | PASS |
| 7 | Migrator without database CREATE rejected | PASS |
| 8 | Unsafe owner default privileges rejected | PASS |
| 9 | Deliberate failure at migration end rolls back entire installation | PASS |
| 10 | Reapplying migration rejects existing schema without overwrite | PASS |
| 11 | Eight table owners/RLS flags, fourteen functions, seven definers, fixed paths, four deferred triggers and five unprivileged role ACLs | PASS |
| 12 | Catalogue creation, zero balances, purchase/sale, exact monetary totals and preserved snapshots | PASS |
| 13 | Sale exceeding available stock leaves full state unchanged | PASS |
| 14 | Repeated-product aggregate overselling rejected without partial effects | PASS |
| 15 | Multi-product insufficient stock rolls back whole command | PASS |
| 16 | Valid repeated-product/multi-product sale and full exact reversal | PASS |
| 17 | Same-key retries, conflicting/reused keys, repost after reversal, reversal retry conflicts, draft/reversal-of-reversal rejection | PASS |
| 18 | Reversing a purchase with consumed stock rejects and preserves original | PASS |
| 19 | Post then reverse in one transaction; all final deferred checks and COMMIT | PASS |
| 20 | Independent committed posting fixture | PASS |
| 21 | Reverse that independently committed posting; COMMIT | PASS |
| 22 | Opening stock, repeat opening before/after reversal and repeated opening product | PASS |
| 23 | Posted header/item immutability, direct balance edit/delete and append-only history protections | PASS |
| 24 | Deferred rejection of incomplete posted header and reversed source without full reversal | PASS |
| 25 | Deferred rejection of missing posting audit | PASS |
| 26 | Deferred rejection of wrong-key posting audit | PASS |
| 27 | Deferred validators succeed after effective role loses all object access; no test grants added | PASS |
| 28 | Five API/ordinary test roles denied table reads and command calls | PASS |
| 29 | Case-insensitive company SKU uniqueness, invalid prices and cross-company contact/product links | PASS |
| 30 | Wrong movement sign/date/product and duplicate source movement rejected | PASS |
| 31 | Bigint overflow rejects entire posting without stock corruption | PASS |
| 32 | Hostile caller search_path and same-named temporary tables do not redirect commands | PASS |
| 33 | Late reversal-audit error restores source/status/ledger/balances; same-key retry succeeds | PASS |
| 34 | Competing sales: first commits, second rejects; final stock 3 | PASS |
| 35 | Competing sales: first rolls back, second succeeds; final stock 3 | PASS |
| 36 | Identical concurrent posting retries return same ID, one movement/audit effect | PASS |
| 37 | Different concurrent orders reuse one key: one succeeds, other rejects without effects | PASS |
| 38 | Concurrent same-key reversals return one reversal | PASS |
| 39 | Concurrent different-key reversals allow only one reversal | PASS |
| 40 | Opposite UI product order still uses consistent locks; both valid sales succeed | PASS |
| 41 | Purchase reversal wins race against sale; sale rejects, stock 0 | PASS |
| 42 | Sale wins race against purchase reversal; reversal rejects, stock 3 | PASS |
| 43 | Concurrent repeated-product sales cannot oversell | PASS |
| 44 | REPEATABLE READ produces safe 40001 abort; whole-transaction same-key retry respects remaining stock | PASS |
| 45 | Initial committed fixtures reconcile every balance with its ledger sum | PASS |
| 46 | Migration installs with restricted, non-superuser/non-BYPASSRLS migrator | PASS |
| 47 | adjustment_in/out signs and their full reversals | PASS |
| 48 | Late posting-audit error rolls back earlier movements; original key retry succeeds | PASS |
| 49 | Deferred reversal check rejects ordinary reversal items | PASS |
| 50 | Deferred reversal check rejects changed contact | PASS |
| 51 | All three truncate guards reject after pending constraint events are drained | PASS |
| 52 | Zero/negative quantities, fractional text input and excess discount rejected | PASS |
| 53 | Actual COMMIT rejects missing audit and restores full prior state | PASS |
| 54 | Draft edit wins header lock before posting; changed draft posts correctly | PASS |
| 55 | Posting wins before draft edit; attempted item edit rejects | PASS |
| 56 | SERIALIZABLE competing sale safely aborts with 40001 | PASS |
| 57 | Deliberately induced 40P01 deadlock rolls back victim; same-key retry succeeds | PASS |
| 58 | Corrected owner-only balance corruption fixture fails actual COMMIT; all guards remain enabled and full state is restored | PASS |

The deadlock in check 57 was deliberately created by taking opposite balance
locks before calling the commands as a trusted test owner. It is not evidence
that ordinary ordered command calls deadlock. Exactly one transaction aborted;
the surviving sale committed, and the original key of the victim then succeeded.

Final committed fixtures contained 47 orders, 49 stock movements and 26 balances.
Every balance was nonnegative and equaled its complete ledger sum. Final catalog
inspection showed exactly eight application tables and fourteen functions;
fault-injection functions did not remain.

## Exact errors observed in expected negative tests

No SQL compilation error was observed. Representative exact messages:

| SQLSTATE | Exact message | Interpretation |
| --- | --- | --- |
| P0001 | Insufficient aggregate stock or missing balance | Expected overselling rejection; no partial posting |
| P0001 | Reversal would make stock negative or balance is missing | Expected consumed-purchase reversal rejection |
| P0001 | Posted orders are immutable except for a full reversal | Protected header update rejected |
| P0001 | Only ordinary draft order items may be changed | Posted item edit rejected |
| P0001 | Balances may only be maintained by inventory triggers | Direct balance mutation rejected |
| P0001 | This inventory history is append-only | Ledger/audit/balance truncate and history mutation rejected |
| P0001 | Posted order totals or movement count are inconsistent | Deferred incomplete-posting rejection |
| P0001 | Reversed order must have a complete posted reversal | Deferred incomplete-reversal rejection |
| P0001 | Posted order requires its matching operation audit event | Missing/wrong-key audit rejection, including actual COMMIT |
| P0001 | Balance and ledger disagree | Actual COMMIT rejects injected balance corruption |
| P0001 | A reversal has linked opposite movements, not ordinary order items | Invalid reversal shape rejected |
| P0001 | Full reversal is incomplete or does not match original | Changed reversal contact rejected |
| 23505 | duplicate key value violates unique constraint "orders_company_id_posting_key_key" | Reused logical posting key rejected |
| 23505 | duplicate key value violates unique constraint "stock_movements_one_original_item_uq" | Duplicate movement rejected |
| 42501 | permission denied for schema stockwise | API/ordinary roles remain excluded |
| 22003 | bigint out of range | Overflow rejected without wrapped stock |
| 40001 | could not serialize access due to concurrent update | Whole-transaction retry required at stronger isolation |
| 40P01 | deadlock detected | Intentional adverse lock schedule aborted one transaction safely |
| P0001 | INJECTED_TEST_AUDIT_FAILURE | Deliberate reversal fault; complete rollback verified |
| P0001 | INJECTED_POST_AUDIT_FAILURE | Deliberate posting fault; complete rollback verified |

## Failed harness attempts, correction and proposed fixes

These are disclosed separately from migration failures:

1. **Initial connection attempt**
   - Code: `ECONNREFUSED`
   - Exact message:
     `connect ECONNREFUSED /tmp/swpg-m3t9pz8j/socket/.s.PGSQL.6543`
   - The local server was no longer running between tool invocations.
   - Correction: scope server startup, tests and guaranteed shutdown to the same
     shell invocation. The full primary suite then completed: 45 PASS, 0 FAIL.
   - No migration or application change was needed.

2. **First balance-corruption fixture**
   - SQLSTATE: `55006`
   - Exact message:
     `cannot ALTER TABLE "stock_balances" because it has pending trigger events`
   - The fixture attempted to re-enable an immediate guard after deliberately
     updating a balance; PostgreSQL prevented that ALTER because a deferred event
     was queued. This did not reach the intended COMMIT assertion.
   - Correction: do not disable/re-enable the migration guard. Use an owner-only,
     transaction-local nested test trigger to inject corruption while leaving
     every installed guard enabled. Actual COMMIT then rejected it with
     `P0001: Balance and ledger disagree`, rolled back all changes and removed
     the test function. This is completed check 58.
   - The supplemental first attempt was 12 PASS, 1 fixture FAIL; the corrected
     check was 1 PASS, 0 FAIL. No migration edit was made.

**Proposed production SQL changes: none on the evidence of these tests.**
The fixture/lifecycle corrections concern the temporary harness only.

## Untested or not established

- Supabase PostgreSQL 17.11 specifically, managed auth/storage roles/extensions,
  hosted network/TLS/pooler behavior, Data API schema exposure and live role
  inheritance. No connection to Supabase occurred.
- Tenant authorization, authentication, a runtime role or business-data APIs.
  Function parameters alone still do not authorize a caller's company.
- A future EXECUTE-only caller design: role-dropping tests exercised deferred
  callbacks without SELECT privileges, but no runtime/test-role command grants
  were added to model a future API caller.
- RLS row-filtering with deliberately granted SELECT: tested roles had no schema
  or table access, so effective ACL denials were checked instead.
- Every possible invalid cross-company FK combination or every exceptional
  branch of every function. Contact/product cross-company links were exercised.
- Changed reversal date as an isolated retry variant; changed key and reason
  were exercised. Not every privacy-field or numeric precision boundary was
  exhaustively asserted.
- Large-ledger performance, sustained load, crash recovery guarantees, backup/
  restore and repeated randomized concurrency stress.
- Historical running-stock constraints, accounting-period close, browser-data
  import and the snapshot-versus-history cutover process.
- Tests do not establish a production security guarantee or migration approval.

## Cleanup and retained files

The local server was stopped with `pg_ctl -m fast -w stop`. Its log confirmed
`database system is shut down`; no postmaster PID file or PostgreSQL process
remained. The entire temporary cluster directory, including all test databases,
roles, fixtures, harness scripts and logs, was then removed and absence verified.

The only retained workspace change is this report. The prepared SQL, frontend,
server, startup files, dependency files, secrets and TLS certificate are unchanged.
