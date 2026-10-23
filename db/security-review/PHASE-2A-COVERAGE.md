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
| 44 REPEATABLE READ 40001 and whole-transaction retry | I44: retry denied for insufficient remaining stock; I59: sufficient-stock retry specification |
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
| 56 SERIALIZABLE 40001 whole-transaction retry | I56: retry denied for insufficient remaining stock; I60: sufficient-stock retry specification |
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
| S11 | Direct SQL post/reversal retry probes; Phase 1 post/reversal retry denial explicitly recognized as a limitation, not successful full-path replay |
| S12 | Viewer exact ID/status allowlist; Staff cannot use missing creator metadata |
| S13 | Direct SQL cancellation retry, audit/stock-neutral/terminal checks; Phase 1 cancelled-state retry denial is a limitation probe |
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
| S01a/S01b | Stopped installation after stage 02 has no usable runtime/issuer login or API grant; final stage activates atomically |
| S17b | Session settings/temp object discarded before same-backend reuse; callback result-shape bug corrected in source |
| S25 | MultiCompany is Staff in A, Viewer in B; own A draft edit allowed, B creation and cross-company edit denied by SQL/backend |
| S26 | Pending identity and DisabledMember deny backend work and independent SQL authorization |
| S27 | All four roles denied stock.adjust and adjustment/opening draft creation |

S18 now compares full schema-qualified input-type signatures, checks private
helper and core inventories for overloads, definer owner/search_path, exact
runtime/issuer EXECUTE sets, API-role effective EXECUTE denials, and all seven
table privileges across the eight inventory tables. Operator/unknown role
values are rejected. These assertions are source only, **NOT EXECUTED**.

I59 (repeatable read) and I60 (serializable) start with 20 units, induce 40001,
restart the whole transaction with its original key, and expect two seven-unit
sales, balance six, two sale movements and two posting audits. I58 remains the
existing owner-corruption COMMIT scenario; no identifier is repurposed.

## Lost-response and idempotency acceptance specifications — NOT EXECUTED

The following R/D cases are **specifications, not executable harness cases**.
They require future receipt-aware Phase 1/SQL authorization and, for drafts,
new approved storage/interfaces. S11/S13 only probe current state-mismatch
denials and direct SQL retries; they do not simulate network loss.

| ID | Required future scenario and expected outcome |
| --- | --- |
| R01 | Commit posting, suppress response, retry through full authenticated path with same key/payload: original order result, one posting audit/event and one movement per original item, unchanged balance on replay |
| R02 | Commit reversal, suppress response, retry through full path: identical reversal ID, no second reversing movement/audit/event |
| R03 | Commit cancellation, suppress response, retry full path: original cancellation result, one cancellation event, no stock change and no reopened draft |
| R04 | For each R01–R03, changed key payload/resource/company conflicts; revoked membership, Staff post/reverse, Viewer cancellation and another Staff's draft remain denied before receipt disclosure |
| R05 | Unknown COMMIT outcome destroys connection; authorized receipt resolution returns committed result or known absence, otherwise remains unknown; never blindly replay or allocate a new key |
| D01 | Two simultaneous equal draft requests produce one order/creator/event/receipt and identical returned IDs |
| D02 | Same scoped key with changed canonical payload conflicts and leaves original draft untouched |
| D03 | Draft commit response lost: authorized same-key resolution returns original draft, no duplicate order |
| D04 | Failure before COMMIT rolls back draft, lines, creator, event and receipt together; known-aborted retry may create once |
| D05 | Key scope cannot reveal another company/creator's draft; revoked membership and Viewer denied; Staff ownership checked on replay |
| D06 | Receipt retention/expiry never silently reuses a formerly committed key; exact retention policy needs approval |

Adjustment/opening stock remains deliberately unavailable to runtime, not
implemented authorization. S27 denies creation/action; the posting wrapper
also restricts kinds to sale/purchase. Future A01 specification: seed a
synthetic special-kind draft using diagnostic authority, attempt each runtime
posting wrapper, expect denial and zero balance/movement/audit changes.
Also seed a diagnostic posted special-kind order and require runtime reversal
denial; the candidate reversal wrapper now checks sale/purchase kind.
Future A02: opening-stock cutoff import either uses opening balances plus
post-cutoff transactions or replays history, never both. Import workflow and
runtime adjustment/reversal scope require separate approval.

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
