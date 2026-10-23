# Phase 2A — review-only database security materials

## Status and authorization boundary

**PREPARED, NOT EXECUTED.** No PostgreSQL process was started, SQL executed,
tests run, packages installed, external service contacted or Supabase connection
used in this phase. There are **no new PostgreSQL test results**.

The SQL below is a **local-laboratory proposal**, not a deployed security boundary
or a production migration. The JavaScript/Python files are implemented test
materials whose syntax, SQL compilation and behavior remain unverified.
Do not equate source inspection or historical results with a passing revised
design. There are no mounted HTTP business-data APIs.

Existing migration/deployment SQL, application/security modules, frontend,
startup/package configuration, health-check behavior, credentials and TLS
certificate are unchanged. `runtime-boundary.sql` is not loaded or repurposed.

## Review-only materials (candidate files revised; protected files unchanged)

| File | Purpose |
| --- | --- |
| `db/security-review/phase2/01_identity.sql` | Laboratory-only role scaffold, identity/membership/session/proof tables, private context helpers and deferred identity validation |
| `db/security-review/phase2/02_policies_commands.sql` | Additive RLS/column ACL proposals, restricted readers/draft writer, checked post/reverse/cancel wrappers and terminal cancellation guards |
| `db/security-review/phase2/03_adapter_contract.sql` | Minimal repository/DB-authorization receipts, customer and redacted audit/movement projections, final grant cleanup |
| `db/tests/phase2/common.cjs` | Private-socket checks, original-file hash pin, restricted foundation installer, transactions and sanitized results |
| `db/tests/phase2/postgres-adapter.cjs` | Test-only, real `pg` implementation of Phase 1 adapter/repository/status lookup interfaces |
| `db/tests/phase2/fixtures.cjs` | Synthetic companies, identities, local status rows and inventory fixtures |
| `db/tests/phase2/inventory-cases.cjs` | Inventory integrity, negative, deferred/actual-COMMIT and fault-injection groups |
| `db/tests/phase2/inventory-concurrency.cjs` | Lock-observed two-connection schedules, 40001/40P01 rollback/retry groups |
| `db/tests/inventory.local.cjs` | Reconstructed inventory suite entry point; original 58-case source was not retained |
| `db/tests/runtime-security.local.cjs` | Revised four-role DB integration suite with real Phase 1 JOSE verification and synthetic issuer/status evidence |
| `db/tests/run-phase2-isolated.py` | Approval-gated, environment-scrubbed, Unix-only local cluster lifecycle |
| `db/security-review/PHASE-2A-COVERAGE.md` | Historical-scenario mapping, proposed checks and untested boundaries |
| `db/security-review/PHASE-2A.md` | This review, decisions, risks, prerequisites and future commands |
| `db/security-review/phase2/reviewed-source-sha256.json` | Exact source-byte snapshot, not security approval; both verification implementations require the same 26 paths |

## Architecture proposed for review

### Identity and authentication

1. Keep Phase 1's official `jose` verification: trusted issuer, audience, algorithm
   allowlist and configured local JWKS; reject browser-supplied key URLs and
   role/company/user claims as authority. This harness generates an ephemeral
   ES256 fixture key in memory. The `.invalid` issuer URL is never fetched.
2. Map **verified `(issuer, subject)`**, not submitted user IDs, to a private
   identity. Bind the verified session ID to that identity.
3. **Hosted session-status verification remains a blocker.** The proposed local
   `sessions.source` accepts only `synthetic-fixture-only`. Its lookup is an
   offline test double implemented with PostgreSQL, not Supabase logout,
   refresh-token or provider-session verification. Refreshing fixture timestamps
   deliberately simulates a trusted status observation; it proves no hosted
   revocation behavior.
4. Pending/inactive companies, identities, memberships, revoked/expired sessions
   and stale status observations deny access. Nothing may register/reactivate an
   identity or membership merely because a JWT claims it exists.

### Connection and privilege separation

| Principal | Proposed authority |
| --- | --- |
| `stockwise_owner` / `stockwise_migrator` | Existing private schema ownership/deployment design; no new role-parent edges |
| `sw2_business` → `sw2_runtime` | Test LOGIN inheriting only exact API-function EXECUTE capabilities; no SET into its capability role, table CRUD, schema CREATE or owner membership |
| `sw2_issuer` → `sw2_verifier` | Separate test LOGIN, only local-status lookup and proof issuance; cannot read business data or run inventory commands |
| `sw2_auth_owner` | NOLOGIN/NOBYPASSRLS owner of private security state/helpers; no ordinary handler credential |
| `sw2_basic_reader` | NOLOGIN/NOBYPASSRLS; column-limited products, quantities, basic status; customer names only through an additional sales-role policy |
| `sw2_sales_reader` | NOLOGIN/NOBYPASSRLS; permitted selling fields/own-sales work and linked customer billing details, never product cost |
| `sw2_business_reader` | NOLOGIN/NOBYPASSRLS; Owner/Admin company-business projections; audit getter excludes raw details/security state |
| `sw2_draft_writer` | NOLOGIN/NOBYPASSRLS; narrow header/item columns and policies, no post/status/cost/balance/movement writes |

No runtime membership in function-owner roles. Each definer has fixed
`pg_catalog, pg_temp` search path and qualified application object names.
There is no caller-supplied dynamic SQL in these privileged entry points.
The installer has constant-name, quoted DDL loops; it is not a runtime function.

The original seven owner-definer functions and the new explicitly checked
owner-context wrappers are **intentional owner/RLS exceptions**. ENABLE RLS
alone does not constrain a table owner. Keep their EXECUTE private, never grant
runtime membership in the owner, and validate live company authority inside
each public command wrapper **before idempotent early returns**.

PUBLIC execution is explicitly revoked before each SQL file commits. New
function owners also get global default EXECUTE revocation. Runtime EXECUTE is
an explicit signature list, not an all/future-functions grant. Stage 01 creates
NOLOGIN runtime/issuer placeholders without capability membership; stage 02
commits no runtime API EXECUTE grants. Stage 03 atomically grants the complete
API list, memberships and LOGIN capability. No temporary schema CREATE grants
are needed under the laboratory superuser installer. S01a checks the stopped
installation boundary before stage 03; this is not a tested recovery mechanism.
Future DDL
must create as the intended function owner or explicitly revoke PUBLIC within
the transaction: ALTER OWNER by itself does not apply that owner's defaults.

The test-only installer connects explicitly to local `runner` for laboratory
DDL/fixtures. That object is never passed to Phase 1 or a business work callback.
The adapter accepts a private cluster directory, **not a connection URL or env
fallback**. Production will require separately approved runtime/issuer
credentials, TLS and pool construction, with administrative `DATABASE_URL`
excluded from the ordinary request dependency graph. None is configured here.

### Company/role enforcement and drafts

- Every public command derives its identity/role from the bound proof and
  current private membership, not its arguments. Company/resource IDs are only
  requested selectors: membership, row ownership and composite foreign keys
  determine whether they are usable.
- Company/order/item/product relationships retain the original composite FKs.
  New creator/cancellation/event records also reference `(company, order)` and
  `(company, identity)` membership pairs; proof/event session IDs reference the
  same identity. Deactivate memberships rather than deleting historical actors.
- Owner/Admin manage all ordinary drafts in their own company. Staff create
  sales drafts only, see/edit/cancel only their own sales drafts, and retain
  limited own-origin order work access after posting/reversal. Missing creator
  provenance fails closed for Staff. Immutable creator records prevent transfer,
  reassignment or takeover. No reassignment function is proposed.
- Viewer receives product basics, quantities and opaque ID/status only. No
  contacts, costs, selling totals, movements or audit. SQL projection denials
  can be empty rows/NULL or `42501`; a mounted backend must still authorize
  first and map failures appropriately, not interpret empty data as login.
- Staff cannot post, adjust, reverse, mutate posted rows or gain raw ledger
  access. Owner/Admin command wrappers invoke the unchanged ledger functions.
  Direct balance/history editing remains inaccessible to runtime.
- Adjustment/opening-stock commands are deferred for **all** runtime users,
  including Owner/Admin. Their approved future permission is unchanged; there
  is no current implementation. Creation and posting wrappers reject those
  kinds, reversal rejects special-kind source orders, and SQL authorization rejects `stock.adjust`. Core mechanics tests
  using diagnostic authority do not establish runtime adjustment authorization.
- Cancellation is an immutable side record, not a change to the original status
  constraint. Only stock-neutral ordinary drafts qualify. Same key/reason retry
  is idempotent; another payload conflicts. Effective state is `cancelled`;
  extra guards prevent subsequent header/line changes or posting. No reopening
  or hard deletion is exposed.
- Owner can authorize management of existing Admin/Staff/Viewer members; Admin
  only Staff/Viewer. Self elevation, Owner appointments/transfer and Admin peer
  takeover are rejected. The proposal tests authorization receipts, **not an
  implemented membership/invitation management feature**.

### Transaction identity, concurrency and pooling

1. Runtime opens a bounded READ COMMITTED transaction on one pinned connection,
   obtaining PID and `xid8` from PostgreSQL.
2. Separate verifier connection commits a short-lived, opaque CSPRNG proof
   bound to that PID, transaction, identity and active local session. Only its
   SHA-256 digest is stored. Two UUIDs provide 244 random bits, not a claimed
   256-bit random source. No extension/secret signing key is introduced.
3. Activation uses a **transaction-local** GUC. A GUC alone is not authentication:
   every helper validates the private digest record, PID/XID, expiry and session.
   Proofs cannot be reused on another backend/transaction or replaced by user
   IDs/role settings. One issuance per PID/XID prevents identity switching.
4. The repository checks current membership and the SQL authorizer independently
   returns the receipt Phase 1 checks. Each actual command repeats its own
   authorization; a receipt is not a reusable bearer capability.
5. Member/company/identity/session rows are shared-locked during command
   authorization. Revocation/role changes wait for earlier authorized
   transactions; **not immediate cancellation of already-running work**.
   Newly authorized work after revocation commits must fail. Bounds on statement,
   lock and idle-transaction time limit blocking.
6. Successful command events carry actor identity/role/session, not a browser
   claim. A deferred event constraint revalidates identity at actual COMMIT;
   expired context must roll back data and events. Read-only operations still
   validate on each query. Audit attempt/denial logging requires a separate
   trusted sink; rolled-back SQL cannot durably log its own denial.
7. Rollback/COMMIT, then `DISCARD ALL` outside the transaction, then release.
   The test adapter clears session settings, temporary objects, prepared
   statements, listeners and advisory locks as well as identity context.
   Reset failure destroys the connection; uncertain/broken connections are discarded as Phase 1
   specifies. No automatic retry after uncertain COMMIT. Explicit inventory
   40001/40P01 tests retry a **whole transaction with its original operation key**.
8. Use separate verifier/runtime pools so a max-one business pool cannot deadlock
   acquiring its own proof issuer. Transaction pooling could be compatible only
   with BEGIN-to-COMMIT pinning; statement pooling is not. Actual Supavisor
   behavior/limits/prepared statements remain unverified.

## Important unresolved blockers / decisions

1. **No revised SQL has been compiled or tested.** Even the launcher/network
   filter and syntax are untested. Review then separately approve execution;
   do not treat this proposal as deployment-ready.
2. **Hosted authentication/status authority remains unresolved.** Decide exactly
   how a trusted backend establishes current provider-session status, observation
   freshness and logout semantics. Never deploy the synthetic registry as a
   substitute or claim immediate Supabase session revocation.
3. **Phase 1 retry/state mismatch:** its authorizer requires a draft for
   `order.post` and a posted state for `order.reverse`; a successful prior command
   changes those states. Direct SQL wrappers can return an authorized same-key
   retry, but the current full Phase 1 path can deny it first. S11 explicitly
   records this limitation, not a passed end-to-end retry. Resolving it needs
   separate approval to change existing modules and tests, preserving role checks.
   Cancellation retries have the same effective-state boundary.
4. **Production security-DDL authority not provisioned.** Laboratory SQL needs a
   local superuser, contains a local-data-directory guard and is NOT suitable for
   Supabase execution. Design a separate minimally scoped deployment authority
   for new function owners without adding parent roles to `stockwise_owner`.
   Managed-role flags, inherited/default grants, schema exposure and extension
   rules require a separately authorized Supabase inspection; local stand-ins
   cannot establish them.
5. **Projection/command candidates are not full business APIs.** Catalogue/contact
   writers, membership/invitation mutation, onboarding, export allowlists,
   pagination beyond fixed test limits, field-level edit validation and UI
   contracts remain future work. The authorization matrix does not imply those
   operations are implemented. Draft header monetary totals in the existing core
   are finalized at posting; the sample getter is not an approved draft pricing/
   Malaysian tax/rounding implementation. No OCR/invoice/MyInvois/Gmail work.
6. **Operational choices:** hosted runtime/issuer LOGIN design, connection limits,
   timeouts, revocation linearization, request idempotency persistence, denial
   logging, expired-proof pruning, session/audit retention and migration rollback
   procedures need review. No background cleanup or startup migration is added.
   A compromised trusted proof issuer can impersonate identities; protect that
   tier separately. Owners/superusers and compromised server code are outside
   ordinary RLS protection.
7. **Local isolation limits:** this is a private Unix-socket laboratory under the
   same OS user, not a VM or adversarial-SQL sandbox. Seccomp forbids non-Unix
   socket creation and inherited descriptors are closed; it does not make all
   filesystem access impossible. Only reviewed, trusted scripts may run.
   SIGKILL/host loss cannot guarantee automatic cleanup; unknown PID identity
   deliberately prevents deletion instead of risking the live application.

## Future execution prerequisites — NOT authorized by Phase 2A

- Explicit, separate approval for disposable-cluster execution and fault injection.
- Review all three candidate SQL files, adapters, launcher and coverage map.
- Existing PostgreSQL **17**/Node/libseccomp must be available. The launcher
  installs nothing and fails closed if its filter cannot be loaded/probed.
- Source pin for unchanged migration:
  `b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0`.
- Private `/tmp` space and permission to create/stop only the new cluster;
  existing socket/port/application/Supabase are never used. The same numeric port
  6543 is scoped to each unique Unix socket; TCP is disabled.
- Each report path below must be new. Historical reports must never be overwritten.

### Exact commands proposed after separate approval

Run from the repository root only after a separately approved isolation fix.
**Do not run these under the current approval. The launcher now unconditionally
refuses execution, even with the approval flag.** These are future command
shapes, not currently usable instructions.

```sh
python3 db/tests/run-phase2-isolated.py \
  --suite prerequisites --approved-local-execution \
  --report db/test-reports/phase2-prerequisites.json

python3 db/tests/run-phase2-isolated.py \
  --suite inventory --approved-local-execution \
  --report db/test-reports/phase2-inventory.json

python3 db/tests/run-phase2-isolated.py \
  --suite security --approved-local-execution \
  --report db/test-reports/phase2-security.json
```

The flag prevents accidental execution; it is **not** a substitute for approval.
The blocked lifecycle code is intended to create a fresh private cluster and construct a clean child
environment without inheriting credentials, PostgreSQL variables, proxy settings
or Node injection options. The launcher itself never reads secret values.
It starts PostgreSQL only after a network-filter self-check, verifies local server
identity before SQL installation, and checks marker/PID/data-directory identity
before stopping and removing the cluster. If shutdown cannot be confirmed, it
leaves the cluster untouched and reports its directory for manual inspection.

Expected retained artifacts: **new sanitized JSON reports only**, with actual
PASS/FAIL, SQLSTATE/sanitized error messages, version/hash and cleanup status.
Raw logs, proofs, keys, fixture data and cluster files are not retained.
Suites stop at the first failure; all later cases are UNTESTED. There is no claim
that the expected files already exist or that expected outcomes occurred.

**Stop here. Review and separate execution approval are required next.**

## Correction review: NOT READY FOR CONTROLLED LOCAL TESTING

All revised scenarios remain **NOT EXECUTED**. This document describes source
changes and future expectations, not PostgreSQL results.

### Proof-issuer trust boundary

`sw2_auth.issue(text,text,uuid,integer,xid8,timestamptz)` trusts the verifier
credential's supplied issuer, subject, session and target PID/XID. The SQL
checks active synthetic identity/session records but does not verify a JWT.
Possession of this credential can therefore impersonate an active recorded
identity. Separate pools in one Node process are dependency separation, not
protection from compromised server code. The lab adapter is not a production
issuer service.

Before production, design an independently protected issuer boundary that
verifies issuer/audience/keys and current hosted session evidence, derives
identity only from verified tokens, and binds the target to a server-created
transaction challenge. Business handlers must never possess the issuer/admin
credential or accept caller-supplied identity/transaction claims as authority.
Define credential custody, transport, replay/expiry, rate limits and denial
logging. Those controls and hosted revocation remain unresolved release
blockers; do not deploy the synthetic session registry as a substitute.

### Retry and uncertain-commit contract (specified, not implemented)

For posting, reversal and cancellation, keep one stable operation key per
logical request. A fresh authorized transaction must resolve the existing
receipt before enforcing first-execution state rules. Recheck current identity,
session, membership, company, role and resource scope even on a replay. Same key
and canonical payload returns the original result with no extra ledger/audit
effect; changed company/resource/action/payload must not reuse that receipt.
Record conflicts explicitly; never invent a new key to bypass a timeout.

The unchanged Phase 1 predicates require `draft` for posting/cancellation and
`posted` for reversal. The repository returns effective `cancelled` state from
the cancellation side record. Thus all three committed transitions can block
retries before their SQL wrappers run. SQL `authorize` repeats these state
restrictions. Both layers need separately approved receipt-aware interfaces;
do not simply relax state or role checks. S11/S13 include limitation probes,
not successful full-path retry assertions.

After known transaction abort (`40001`/`40P01`), bounded whole-transaction
retry may use the original key and fresh authorization. I44/I56 deliberately
end in insufficient-stock denial; I59/I60 specify sufficient-stock successful
retries. After uncertain COMMIT, destroy the connection and resolve the durable
receipt on a new authorized connection. No blind replay: unknown remains
unknown until resolution. Actual transport failure recovery is not implemented.

### Draft-creation idempotency (design only)

The current create function has no request-key parameter: it is **not**
idempotent. Proposed future storage has unique
`(company_id, creator_identity_id, request_key)` with operation version,
canonical payload fingerprint and resulting order ID. Include normalized kind,
contact, reference, date and any initial lines in that payload. Fingerprint
server-validated values, not arbitrary JSON ordering. Header, initial lines,
creator metadata, receipt and event must commit atomically. Concurrent equal
keys serialize on the unique receipt; same payload returns the original order,
different payload conflicts. Replays still require current company authority
and Staff ownership; a revoked membership cannot retrieve the prior result.
Retain receipts for the documented retry lifetime (not yet decided), without
allowing expired keys to silently create duplicate drafts. No new table or
protected interface is introduced in this correction.

### Static review findings and limitations

- Exact type signatures now cover the API, private helper/trigger and core
  function inventories, rejecting unexpected overloads. Effective runtime and
  verifier EXECUTE sets are compared by schema plus complete input types.
  API-role function and eight-table privilege denials are included.
- Definers are checked individually for owner and fixed `pg_catalog,pg_temp`
  search path. Qualified application references and private EXECUTE remain
  essential: table-owner functions intentionally bypass ordinary RLS.
- Fixed a source-level bug in the pooled-session test: its callback returns an
  object, not a row array. Runtime behavior still requires execution.
- The pool reset applies to business connections. The lab verifier only runs
  fixed autocommit status/issuance calls and is released without DISCARD ALL;
  it must never be handed to business work. Production verifier reset/error
  handling and pooler semantics still need design and testing.
- Removed a remaining redundant schema CREATE grant in stage 03.
- I58 retains its existing corruption scenario; new retry cases are I59/I60.
- Descriptor enumeration is snapshotted before closing; stdio sockets refuse
  execution. Process checks consider cwd, command and descendants. These checks
  cannot prove safety under PID reuse, hidden/unreadable processes, orphan
  races, SIGKILL or host loss. Cleanup must remain fail-closed on uncertainty.
- AF_UNIX permits local brokers/proxies and descriptor passing. The launcher
  remains blocked; no isolation solution was installed or tested.
- The hash manifest pins current SQL/test/Phase 1 bytes, not dependencies or
  operating-system binaries. It is not a signature or approval: someone able
  to modify both sources and manifest can replace the snapshot. Review changes
  to both; refresh after any further source edits.

Remaining blockers: isolation/cleanup validation, SQL compilation and effective
privilege validation, receipt-aware protected interfaces, draft idempotency,
hosted session authority and production issuer/deployment design. No claim of
implemented production tenant isolation is made.
