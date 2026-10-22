# Proposed inventory migration acceptance tests

**Not executed. No approved isolated test target was available during preparation.**
These cases require database-changing SQL, so they must not be run against the
connected Supabase database without separate explicit approval.

## Target and harness requirements

- Use a new, identified, approved disposable database, preferably PostgreSQL 17
  matching the connected Supabase server. Never fall back to DATABASE_URL.
- The operator must verify database identity and owner before enabling writes;
  no hostname/substring heuristic alone proves isolation.
- Use a dedicated test credential, saved securely, with no live-project access.
- Separately approve/provision the proposed non-login owner and migrator
  privileges. Create test-only ordinary/API roles when required. No production
  roles or database permissions may be changed by the harness.
- Run migration with stop-on-error and capture results without credentials.
- Baseline: exactly eight tables, correct ownership, constraints, triggers,
  indexes, RLS flags, private-schema exposure and grants.
- Most cases use transaction-local fixtures followed by ROLLBACK. Deferred
  consistency checks must be forced with SET CONSTRAINTS ALL IMMEDIATE after
  a completed command, since ROLLBACK alone does not test commit-time checks.
- Concurrency cases need approved committed fixtures and two or more separate
  connections. Isolate and clean them only inside that disposable database.
- Store credentials nowhere in fixtures, logs or application tables.

## Cases and expected results

| ID | Case | Expected result |
| --- | --- | --- |
| P01 | Missing owner, wrong owner flags, owner inherits another role, or missing migrator membership/CREATE | Preflight fails with no schema created |
| P02 | An API role is a member of the owner | Preflight rejects unsafe privilege graph |
| P03 | Run migration once with approved prerequisites | All objects owned by non-login owner; exactly eight tables |
| P04 | Reapply migration or precreate conflicting schema | Fails closed; existing objects unchanged |
| P05 | Introduce a deliberate error near migration end in a disposable copy | Transaction rolls back all new objects |
| S01 | Create company, products and customer/supplier | Each product has zero balance and no ledger entries; catalogue audit metadata created |
| S02 | Same SKU with different case in one company; same SKU in another | First rejected; second allowed |
| S03 | Blank names, negative/NaN prices, invalid quantities/discounts, unsupported currency | Checks reject; zero price remains allowed |
| S04 | Link order/contact/item/product/movement/reversal from different companies | Composite FK or trigger rejects every attempted cross-company link |
| S05 | Purchase 10 units | Balance +10; exactly one source movement per item; exact totals and one posting audit |
| S06 | Sale 4 from balance 10 | Balance 6; historical price/cost/name snapshots retained |
| S07 | Sale 11 from balance 10 | Whole command fails; no movement, balance, posting status or audit change |
| S08 | Two lines for same product, each 6, with only 10 available | Aggregate check rejects; no oversell |
| S09 | Multi-product order where one product lacks stock | Entire order rolls back, including earlier movement rows |
| S10 | Inject failure before audit insertion/commit in a disposable fixture | No partial posting; ledger equals balance afterward |
| S11 | Change product name, SKU, cost after posting | Posted snapshots and past totals unchanged |
| S12 | Directly update/delete posted header/items or change record company/ID | Rejected; only full posted-to-reversed transition allowed |
| S13 | Insert malformed movement: wrong sign/product/date/source/quantity, draft source | Validation rejects even under trusted test owner with table access |
| S14 | Duplicate original movement, duplicate reversal or second opening | Unique constraints reject |
| S15 | Direct balance insert/update/delete, ledger edit/delete/truncate, audit edit/delete/truncate | Denied by permissions for ordinary role; trigger guards also reject applicable owner mistakes |
| S16 | Compare every balance with SUM(quantity_delta), including products with no movements | All equal; nonnegative |
| S17 | Force an incomplete posted header with missing movements as trusted owner | Deferred integrity check rejects at commit/check |
| S18 | Numeric/bigint overflow and extreme totals | Whole command fails, never wraps or silently truncates stock |
| S19 | Trusted test owner assembles an otherwise complete posting but omits its audit, uses a different operation key in the audit, or injects a late audit error | Deferred check/command rejects; no committed unaudited posting |
| I01 | Post same company/order/key twice | Same ID; unchanged movement/audit counts |
| I02 | Repost with another key or reuse key for another order | Rejected, no second effect |
| I03 | Repost original key after full reversal | Returns original ID without reposting inventory |
| R01 | Reverse a sale | Equal opposite movements, original marked reversed, complete reversal header and one audit |
| R02 | Reverse a purchase whose stock has been consumed | Rejected when resulting stock would be negative |
| R03 | Retry same reversal key/date/reason | Same reversal ID; no additional movements/audit |
| R04 | Change retry key/date/reason, reverse draft, or reverse reversal | Rejected |
| R05 | Reverse multi-line order with repeated products | Full exact negation, same final per-product balances |
| R06 | Mark original reversed without a complete posted reversal | Deferred consistency rejects |
| R07 | Post and then reverse a multi-item order within the same transaction; force constraints only after both commands finish | Every deferred callback reads final rows; original is reversed, reversal is posted, both audit events exist, and net stock returns to the baseline |
| R08 | Reverse a posted order after committing it in a separate transaction | Same valid transition and stock effects; no dependence on posting's old trigger queue |
| R09 | Convert a trusted-owner draft with existing items into a reversal, or use a different contact while assembling a reversal | Deferred validation rejects ordinary items/contact mismatch on reversal headers |
| R10 | Put reversal in a savepoint, induce late failure, roll back that savepoint, then retry the same request | Original status/stock/audits restored; successful retry creates exactly one full reversal |
| O01 | Opening quantity 20 on a never-used product | Balance 20 and one +20 ledger row |
| O02 | Repeat opening, including after reversal or after previous non-opening movement | Rejected |
| O03 | Opening order repeats one product | Rejected |
| O04 | Zero cutover stock | Leave zero initialized balance; no zero-quantity movement |
| O05 | Proposed snapshot cutover + historical replay of same legacy history | Import design must prohibit replay; no importer/history bypass exists here |
| A01 | PUBLIC/anon/authenticated/service_role/ordinary non-owner uses new objects | No schema/table/function access granted by migration |
| A02 | Inspect every function, including trigger helpers | PUBLIC/API EXECUTE revoked; fixed search path; owner verified |
| A03 | Non-owner with artificially granted test-only SELECT but no RLS policy | No tenant data visible; confirm BYPASSRLS role is not protected by that policy test |
| A04 | Try changing search_path or creating same-named temp objects before posting | Fully qualified relations/functions resolve safely; no privilege escape |
| A05 | Future proposed runtime role is owner-member, superuser or BYPASSRLS | Security review rejects role design; do not expose APIs |
| A06 | Audit catalogue updates and posting/reversal | No tax IDs, personal values, passwords or URLs duplicated in audit details; database actor is not presented as a person |
| A07 | In an explicitly approved isolated test only, separately authorize a test role with schema USAGE and EXECUTE on exactly the two commands, but no table SELECT/DML or helper EXECUTE; run commands, return from definer, then force deferred checks/commit as caller | Both owner-side validators can read their final state; no table/helper privileges need to be widened. This tests internal mechanics, not tenant authorization; never expose this unauthenticated role |
| A08 | Inspect the seven intended SECURITY DEFINER functions and every helper after migration | Exact expected definer list from check_preparation.py; all owned by stockwise_owner, fixed search paths, no PUBLIC/API grants, and no dynamic SQL in function bodies |

## Concurrent-session schedules

Use explicit barriers and verify both final balances and ledger counts.

1. **Competing sales:** fixture stock 10; session A sells 7 and pauses before
   commit, session B sells 7. B waits for A, then fails after A commits.
   Final balance 3; one sale posted. Repeat with A rolling back: B succeeds.
2. **Identical posting retries:** two connections call the same order/key.
   Only one posts; both receive the same ID after the lock clears.
3. **Conflicting operation key:** two different orders share a key. At most one
   succeeds; the other fails and leaves no partial effects.
4. **Same-order reversal race:** two identical reversal requests yield one
   reversal. Different keys/reasons must not produce another reversal.
5. **Multi-product lock order:** create orders listing products in opposite UI
   order. Both functions lock product/balance rows by UUID, not UI line order.
   Assert no partial posting even if a lock timeout/deadlock is induced.
6. **Reversal versus sale:** sale competes with reversal of an earlier receipt.
   Whichever obtains the balance lock first determines availability; the loser
   rejects if necessary. Never allow a negative final balance.
7. **Draft edit versus posting:** authorized draft editing must acquire the
   parent header first. Post/edit cannot alter a posted snapshot. Raw admin
   row-first editing may deadlock; PostgreSQL aborts one whole transaction.
8. **Repeated same-product lines:** simultaneous orders each repeat the product.
   Aggregate checks and atomic ledger-trigger updates prevent overselling.
9. **Different transaction isolation:** run normal suite at READ COMMITTED;
   at stronger isolation, exercise whole-transaction retries for SQLSTATE 40001.
   Exercise 40P01 deadlock retries too, retaining the operation key.
10. **Reversal failure rollback:** hold stock locks in A while B attempts reversal;
    inject an error after B's ledger work or audit insertion, release A, then
    retry B's original operation key. Verify no partial header, movement, balance
    or audit changes survived the failed attempt.

## Review-specific assertions

- On a legitimate reversal, `guard_order` allows draft-to-posted on the new
  header and posted-to-reversed on the original. Original contact, reference,
  kind, date, currency, payment snapshot, notes, monetary source fields, posting
  key, original link, posting time and creation time are unchanged.
- Generated totals are not accessed as populated NEW fields in BEFORE triggers.
- Reversals contain no ordinary order items; each opposite movement links to one
  original movement, with unique full-reversal constraints.
- At final check time, each ordinary posting has its original `order_posted`
  audit, and each reversal has `order_reversed`, with matching operation keys.
- Deferral mode remains INITIALLY DEFERRED while the command executes. An early
  SET CONSTRAINTS ALL IMMEDIATE is unsupported and must fail without partial
  committed writes; it must not be used to dismiss a real end-of-command failure.
- Backdated effective dates do not recompute historical availability. Test and
  document that current stock is enforced at posting time; a separate approved
  policy is required before historical replay or period-close accounting.

## Acceptance gate before any live migration

- All cases pass on approved isolated target with final constraints checked.
- Independent review of role inheritance, function grants and definer bodies.
- Confirm schema is not exposed through Supabase Data API.
- Recheck live target catalogs read-only, identify any drift, and review backup.
- Obtain explicit approval for that exact live migration and target.
- Do not connect frontend, add business APIs or import browser data as a side effect.
