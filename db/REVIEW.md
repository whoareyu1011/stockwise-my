# Prepared migration static review

**Status: PREPARED ONLY. No SQL was executed and no test database was created.**
No isolated PostgreSQL target has explicit testing approval. Local binaries or
the working Supabase connection do not constitute permission to test.

## Reversal trace

No contradictory state transition was found in the existing command/guard flow.
`guard_order` did not need to be weakened or relaxed.

| Step in reverse_order | Guard / final check |
| --- | --- |
| Lock original posted header; check retry key/date/reason | Serializes competing full reversals; unique source/key indexes remain in force |
| Lock affected balances in product UUID order; sum original deltas | A repeated product is checked in aggregate; insufficient stock rejects the entire command |
| Insert new reversal as draft | INSERT guard requires draft; new header has no ordinary items |
| Update new header to posted with original totals and a new posting key | Draft-to-posted is explicitly allowed; row CHECKs require a key/time |
| Insert each exact opposite linked movement | BEFORE validator checks posted reversal, source, company/product/quantity/date; AFTER trigger changes balance |
| Update original posted-to-reversed | Only status/reversed_at/updated_at change; every protected ordinary column remains equal |
| Insert order_reversed audit for the new header | Original order_posted audit is retained |
| Run deferred checks against final transaction state | Original movement/item/totals remain intact; original has complete posted reversal; reversal sees original reversed and all opposite movements; both matching audit events exist |

The generated header total is derived from unchanged subtotal/discount and is
not read from NEW in the BEFORE guard. Reversed records are terminal; a reversal
cannot itself be reversed. Retrying the original posting after reversal does
not consume stock again. A failed reversal must leave the original posted.

This is a static control-flow conclusion, not a successful PostgreSQL test.

## Exact migration changes in this review

1. `check_balance_integrity()` header changed from security-invoker to
   `LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp`.
2. `check_order_integrity()` received the same explicit definer header.
   Deferred checks may run after a command's definer scope has ended; these
   read-only validators should not depend on caller table-read access.
3. The reversal branch of `check_order_integrity()` now explicitly rejects a
   missing/reversal original, ordinary reversal items, and changed contact.
4. At the end of `check_order_integrity()`, require the audit event for that
   header and key:
   - ordinary order: `order_posted`;
   - reversal header: `order_reversed`;
   - company, target/order ID and `details.operation_key` must match.
5. No edits to `guard_order`, `post_order`, `reverse_order`, grant statements,
   ownership setup, function search paths or runtime access. No relaxation of
   row checks, ledger immutability, negative-stock prevention or deferral rules.

These are targeted permission-context and integrity hardening changes. The
review did not establish that the original reversal command was broken.
The offline checker now verifies the exact seven-definer allowlist, absence of
dynamic SQL in functions, new checks and command statement ordering. It remains
a structural checker, not a PostgreSQL/PLpgSQL parser or concurrency simulator.

## Security conclusion

The intended seven definer functions belong to a non-login, non-BYPASSRLS owner.
They retain fixed trusted search paths and all PUBLIC/API EXECUTE revocations.
The two new definer validators only inspect private relations and raise generic
integrity errors; they expose neither table contents nor a new callable API.
Ownership/ACLs must still be verified after an approved isolated installation.

Do not grant either command to clients: company parameters are not an
authorization check. Table ownership lets a definer bypass owner RLS even when
the owner has no BYPASSRLS flag. The existing privileged connection also bypasses
RLS and must not become the business-data authorization boundary.

No runtime roles, policies, passwords, credentials or live permissions changed.

## Remaining untested risks and limitations

- SQL/PLpgSQL compilation and actual PostgreSQL 17 generated-column behavior.
- Trigger nesting/ordering and the depth-2 balance-write defense.
- Deferred checks after command return, real commit and savepoint rollback.
- Multi-item/repeated-product posting/reversal and late audit failure rollback.
- Two-session lock waits, duplicate keys, overselling, serialization/deadlock
  aborts and safe whole-transaction retry behavior.
- Actual role/ACL inheritance, temp-object shadowing tests and Data API exposure.
- Deferred checks currently rescan the affected order or product ledger for
  queued row events; performance can grow with history/order size. Benchmark
  before production; do not remove checks simply to make a test pass.
- Dates describe effective business dates but do not enforce historical running
  stock or accounting-period close rules. Current availability is checked at
  posting, not reconstructed at a backdated effective date.
- Trusted owners can alter/disable triggers or add grants. This design protects
  ordinary application paths, not against a database administrator.

Required next gate: explicit approval for an identified isolated test target,
then the expanded TEST_PLAN.md suite. Live migration approval remains separate.
