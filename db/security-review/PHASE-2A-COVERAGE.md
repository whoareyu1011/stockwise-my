# Phase 2A coverage map — all revised checks NOT RUN

This is a source/coverage map, **not a test report**. Historical local results:
58 inventory checks, 40 deployment-prerequisite checks, 51 checks for the older
runtime prototype and 196 Phase 1 offline tests/subtests were reported previously.
Those do not validate the new SQL, adapter, launcher or four-role integration.
Original inventory source was removed with its cluster; the new inventory
harness is a reconstruction, not a claim to have recovered that exact script.

`Txx` below refers to the existing `db/tests/prerequisites.local.cjs`, reused
unchanged in a separate fresh cluster. `Ixx` refers to groups in the new inventory
suite. Several original scenarios are grouped into one named assertion block;
do not present the number of groups as a new “58 passed” result.

## Previously reported inventory scenarios

| Historical scenario | Proposed reproducible coverage |
| --- | --- |
| 01 SQL compilation | I01; unchanged migration under actual restricted provisioner/migrator |
| 02 Missing owner | T03 |
| 03 Unsafe owner flags | T20 |
| 04 Owner parent role | T21 |
| 05 API owner membership | T22 |
| 06 Missing migrator/owner membership | T25 |
| 07 No database CREATE | T23 |
| 08 Unsafe owner defaults | T24 |
| 09 Failure near migration tail rolls back | I09, in-memory fault copy; original file untouched |
| 10 Reapplication refuses overwrite | T27 |
| 11 Table/function ownership, RLS, definers, deferred checks, ACLs | I11/I28 + T33–T35 |
| 12 Zero balances, purchase/sale calculations and snapshots | I12 |
| 13 Single-product insufficient-stock atomicity | I13 |
| 14 Repeated-product aggregate oversell | I14 |
| 15 Multi-product insufficient-stock atomicity | I15 |
| 16 Valid repeated/multi-product sale and full reversal | I16 |
| 17 Identical/conflicting/reused keys, reversed/draft/reversal retries | I17 + I36–I39 |
| 18 Reversing consumed purchase | I18 |
| 19 Post/reverse within one transaction | I19 |
| 20 Independently committed posting | I20 |
| 21 Independently committed reversal | I21 |
| 22 Opening once, reversal/reopening, repeated-product opening | I22 |
| 23 Posted immutability, balances, append-only history | I23 |
| 24 Deferred invalid posted/reversed states | I24 |
| 25 Missing posting audit | I25 |
| 26 Wrong-key audit | I26 |
| 27 Deferred validation under effective unprivileged caller | I27 |
| 28 Five API/ordinary-role access denials | I28 |
| 29 SKU, values and company-aware foreign keys | I29 |
| 30 Movement sign/date/product/duplicate validity | I30; malformed cases use fresh items to avoid duplicate-index false coverage |
| 31 Bigint overflow | I31 |
| 32 Hostile search path | I32 |
| 33 Late reversal audit fault/rollback/retry | I33 |
| 34 Competing sales, first commits | I34 |
| 35 Competing sales, first rolls back | I35 |
| 36 Same posting request races | I36 |
| 37 Different orders reuse operation key | I37 |
| 38 Identical reversal race | I38 |
| 39 Conflicting reversal race | I39 |
| 40 Opposite product UI ordering | I40 |
| 41 Purchase reversal wins sale race | I41 |
| 42 Sale wins purchase reversal race | I42 |
| 43 Concurrent repeated-product sales | I43 |
| 44 REPEATABLE READ 40001 and whole-transaction retry | I44, core-mechanics suite only |
| 45 Ledger/balance reconciliation | I45 + suite finals |
| 46 Actual restricted migration installer | I46 + T26 |
| 47 Adjustment signs and full reversal | I47 |
| 48 Late posting audit failure/rollback/retry | I48 |
| 49 Reversal cannot have ordinary items | I49 |
| 50 Reversal contact cannot change | I50 |
| 51 Truncate guards, pending events drained first | I51 |
| 52 Invalid quantities, fractional strings, excess discounts | I52 |
| 53 Actual COMMIT rejects missing audit | I53 |
| 54 Parent-locked draft edit wins post race | I54 |
| 55 Post wins item-edit race | I55 |
| 56 SERIALIZABLE 40001 whole-transaction retry | I56, core-mechanics suite only |
| 57 Deliberately induced 40P01 and same-key whole-transaction retry | I57 |
| 58 Owner corruption detected at actual COMMIT | I58, nested temporary trigger; installed guards remain enabled |

Inventory isolation/fault tests use synthetic data and explicitly trusted
diagnostic authority in the disposable cluster. The special `sw_invoker` is a
**test-only unauthenticated mechanics caller**, absent from the security suite
and from the security proposal. It must never be provisioned for the application.
No failed integrity test is fixed by granting runtime ownership or disabling RLS.
Negative audit fixtures temporarily inject NULL/wrong-key/error behavior, then
roll back or remove their temporary trigger. No source migration is changed.

## Revised runtime integration groups

| Group | Planned outcome |
| --- | --- |
| S01 | Original deployment/migration/default-hardening + new additive candidates compile; fail fast on first actual SQL error |
| S02 | Private role flags, no runtime/issuer/API owner inheritance, SET-disabled capability membership, RLS enabled, no PUBLIC function execution |
| S03 | Malformed/anonymous token denies before business work |
| S04 | All four roles basic reads; Viewer no finance/customer selector; Staff no cost |
| S05 | Trusted creator assigned; Staff sale-only; Viewer cannot create |
| S06 | Staff own-draft edit succeeds; another Staff/Owner draft denied by Node **and independently by SQL** |
| S07 | Owner/Admin manage all company drafts |
| S08 | Forged browser company/actor/role claims ignored; foreign company/contact rejected |
| S09 | Raw tables, balance edits, membership mutation, core/private functions and SET-role escalation denied to actual runtime LOGIN |
| S10 | Staff posting denied; Owner posting allowed; Staff posted edits denied; balances reconciled |
| S11 | SQL retry paths work without extra effects; existing Phase 1 post-retry denial explicitly recognized as a limitation |
| S12 | Viewer exact ID/status allowlist; Staff cannot use missing creator metadata |
| S13 | Cancellation audited/idempotent/terminal; no stock effect/reopening/posting |
| S14 | Locally revoked membership/identity/company/session denies next statement |
| S15 | Wrong PID, new XID and fabricated proof fail; next pooled transaction has no context |
| S16 | Database rejects role/Owner/self-escalation ceilings; allowed Owner authorization receipt is not a membership mutation implementation |
| S17 | A write followed by SQL failure rolls back core state AND security events; max-one runtime pool reused for a different verified actor |
| S18 | Exact function owners/paths and disclosure-tier column limits; effective API-role denials |
| S19 | Expired proof and runtime REPEATABLE READ fail closed; runtime design intentionally requires READ COMMITTED |
| S20 | Expiring proof before actual COMMIT rolls back earlier accepted write/events |
| S21 | Revocation waits behind already-authorized transaction; no “instant cancellation” claim |
| S22 | Stale synthetic observation or actual permission-denied status lookup fails before work; restore only the original narrow fixture grant |
| S23 | Actual company-B order inaccessible from A; foreign product reference rejected |
| S24 | Temporary spoof objects/search path do not replace qualified source objects |

The adapter connects to real local PostgreSQL in a future approved run; it is
not a canned database authorization success. Its JWT key/status source is
synthetic. Neither S14 nor S22 establishes hosted provider revocation.
Source mapping is not evidence that SQL compiles or any group passes.

## Expected state, errors and invariants to report later

- Count/ownership/ACL assertions must match catalogs and effective sessions,
  not merely SQL text. RLS owner exceptions must be identified explicitly.
- Unauthorized commands normally `42501`; original guards/stock failures
  normally `P0001`; unique/FK/check violations `23505`/`23503`/`23514`; overflow
  `22003`; unsupported isolation `25001`. A different error is a failed
  expectation to investigate, not permission to widen grants.
- Every committed balance must equal the signed ledger sum and remain
  nonnegative. Failed operations leave no partial inventory/business audit
  effects. Runtime rollback tests additionally check private security events.
- Concurrent tests observe actual PostgreSQL lock waits before releasing the
  winner; they do not assume overlap from a sleep alone. Bound the waits.
- Mark remaining groups UNTESTED after an early failure. Always report cleanup
  separately; a passing SQL suite with unconfirmed cleanup is not overall PASS.

## Still outside implemented/reproducible coverage

These must not be represented as tested by these harnesses:

- Complete original source equivalence: historical scenarios are reconstructed/
  delegated, not recovered; reviewing the assertions against original prose is
  necessary. This is not all possible invalid-input/concurrency testing.
- End-to-end idempotent command retries through unchanged Phase 1 after a
  successful state transition (known incompatible precondition); cancellation
  has the same effective-state issue.
- Positive catalogue/contact/membership mutations, onboarding/invitations,
  export datasets, finance/tax/rounding APIs, and full business workflow CRUD.
- Multi-company membership changes under load, very large orders, all lock
  schedules, permission drift, request cancellation, pool exhaustion, lost
  network/uncertain COMMIT recovery and destructive crash/WAL replay.
- Supabase's real role graph/default grants, PostgREST exposed schemas,
  auth-schema privileges/provider policies, managed PostgreSQL differences,
  Supavisor transaction pinning/reset behavior, production TLS and credentials.
- Hosted JWT key retrieval/rotation, provider logout/global-session revocation,
  authoritative status freshness/SLA and multi-instance cache invalidation.
- Durable denial logging, expired-proof/session retention, backup/restore and
  live operational monitoring.

Hosted checks require a separate design/approval. Do not contact Supabase,
read business data, call the current health check, or weaken security to fill
these gaps.
