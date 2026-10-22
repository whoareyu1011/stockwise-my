# StockWise MY — next runtime-security implementation plan

**Status: planning only. No implementation or deployment approval.**
No SQL, provider requests, database tests, endpoints, credentials, grants or
application/configuration changes are performed by this plan.

## 1. Confirmed decisions and source review

The user's approved planning decisions are:

- Supabase Auth is the authentication provider.
- Viewer has read-only access to products, inventory and orders.
- Stock adjustments and order reversals are Owner/Admin only.
- Company creation and first-owner onboarding use a trusted backend workflow
  and an invitation process.
- Administrative and business-runtime database credentials must be separate.
- Every business operation must enforce company-level authorization.

These decisions do not approve implementation, additional role permissions,
new resources, schema deployment or hosted testing.

Reviewed: `db/migrations/0001_inventory.sql`, all three prerequisite SQL files
and guide in `db/deployment/`, the runtime prototype/design/references, current
server credential use, and the three retained reports:

| Retained report | Historical outcome | What it establishes |
| --- | --- | --- |
| db/test-reports/local-postgresql17.md | 58 grouped local PostgreSQL 17.6 passes | Original inventory commands, stock/deferred integrity, rollback and concurrency |
| db/test-reports/prerequisites-postgresql17.md | 40 grouped local passes | Original provisioning, ownership, membership and default-function permissions |
| db/security-review/TEST-REPORT.md | 51 grouped local passes | Earlier runtime prototype, proof/RLS/wrapper integration and offline JWT checks |

These are previous actual test runs, not tests rerun for this planning task.
They do not validate the revised permission/session/invitation design or hosted
Supabase. Their documented initial fixture/script failures remain unchanged.

### Conflicts with the earlier prototype

1. It included an **Operator** role. The requested matrix now covers Owner,
   Admin and Viewer. Do not carry Operator permissions forward or silently
   promote an Operator. Reject unmapped roles until a transition is approved.
2. Its Viewer could read all eight tables, including contacts and audit details.
   That exceeds the confirmed Viewer scope. The next proposal must withdraw
   broad base-table access and define narrow read contracts.
3. Its Owner/Admin sales, purchase, editing and other read permissions were
   proposed, not approved. They remain explicit decisions, not automatic grants.
4. Offline JWT validation alone does not establish provider-session revocation.
   A trusted session-status mechanism and tests are required.
5. Invitations, first-owner activation and last-owner protection were deferred;
   they must be designed and tested before onboarding is enabled.
6. `server.js` still has an administrative health-check pool. Ignoring that pool
   in new routes is insufficient: the credential must leave internet-facing
   processes before real records or business APIs are introduced.

Do not edit the earlier SQL/reports to make these conflicts disappear. Any
future implementation uses separate reviewed changes and new test evidence.

## 2. Permission matrix — no silent approvals

**A** = confirmed allowed; **D** = denied by confirmed read-only/restricted rule;
**P** = not explicitly approved, deny until decided. Parentheses are suggestions
for review, not permissions. There is no implicit “Owner can do everything”.

| Business operation | Owner | Admin | Viewer |
| --- | --- | --- | --- |
| Read products | P (allow proposed) | P (allow proposed) | A |
| Read inventory/balance and approved movement fields | P (allow proposed) | P (allow proposed) | A |
| Read orders and approved line fields | P (allow proposed) | P (allow proposed) | A |
| Create/edit/archive products | P (allow proposed) | P (allow proposed) | D |
| Receive stock by posting a purchase | P (allow proposed) | P (allow proposed) | D |
| Create/edit draft orders | P (allow proposed) | P (allow proposed) | D |
| Post sales/purchase orders | P (allow proposed) | P (allow proposed) | D |
| Adjust stock, including opening-balance entry | A | A | D |
| Reverse orders | A | A | D |
| Export/download bulk data | P | P | P — reading is not export approval |
| Invite/remove/change company members | P | P | D |
| Transfer ownership/promote another Owner | P — separate protected workflow | P (deny proposed) | D |
| Read contacts, tax IDs, company details or audit logs beyond minimal identity | P | P | P — no additional access approved |
| Create a company/appoint its first Owner directly | Trusted onboarding service only | Trusted onboarding service only | Trusted onboarding service only |
| Direct database writes or grant database privileges | D | D | D |

“Receiving” means a purchase posting, not an adjustment; approval to adjust does
not automatically approve purchase/order permissions. Every mutation must check
the actual operation and order kind, not its route name.

Before implementation, confirm the pending cells, product cost/pricing fields,
order/contact fields visible to Viewer, whether history is included, and who
may initiate trusted onboarding. Basic read projection proposed: product
ID/SKU/name/unit/category/status, inventory quantity/basic movement history,
and order reference/kind/date/status/approved lines. Exclude raw audit details,
tax/contact records and unapproved financial fields by default.

## 3. Implementation sequence and approval gates

### Step 1 — finalize contracts and risk decisions

Approve the complete matrix, field allowlists, first-owner identity rules,
onboarding initiator, invitation lifetime, session-revocation standard and
retention. Translate approved actions into a server/database permission catalogue.
Unknown actions and roles must deny. No deployment can compensate for an
unapproved permission matrix.

### Step 2 — separate deployment, verification and business identities

Retain NOLOGIN owner/migrator roles for reviewed deployments. Propose separate
per-environment runtime and verifier LOGIN accounts with no superuser,
BYPASSRLS, CREATEROLE, database CREATE or privileged inherited memberships.
Each inherits only its reviewed capability role, without ADMIN/SET delegation.

The business role should be **EXECUTE-only**, with no raw inventory/security
table access. It calls approved read/mutation entry points. The verifier may
issue context and perform narrowly scoped session checks, not read business
data or edit memberships. A separate onboarding worker capability may execute
approved onboarding/invitation functions, not arbitrary owner SQL.

No login/password/grant is created in this stage. Later secrets must use the
workspace secret mechanism, not source, SQL, URLs in logs or chat.

Before real data/API rollout:

- Remove administrative DATABASE_URL from all internet-facing application
  process environments; keep it solely in an approved deployment job/operator.
- Replace the health pool's connection identity with a restricted identity
  while preserving the endpoint's SELECT NOW() behavior.
- Reject missing restricted settings and incorrect role flags at startup.
  Never fall back to DATABASE_URL or a Supabase service-role credential.
- Preserve trusted CA/hostname verification for every new hosted pool.
- Prefer a small isolated verifier component with its own credential scope;
  two pools in one compromised process are not a process-security boundary.

These are future approval-required configuration changes; none is performed now.

### Step 3 — implement Supabase Auth verification and session policy

Use a maintained server-side provider/JWT library, not the small reference
verifier as finished production authentication. Pin issuer, audience, signing
algorithm and JWKS address in trusted configuration. Validate signature, kid,
expiry, nbf, iat and authenticated-user token class. Never follow JWT-supplied
key URLs. Unknown/rotated keys require bounded refresh and fail-closed handling.

Use verified `(issuer, sub)` as identity. Treat signed email/metadata/company
claims as neither membership nor role authority. Obtain invitation-recipient
email verification from trusted provider account data.

**Revocation requirement:** distinguish JWT validity from active provider
session status. Do not assume offline verification, or auth.getUser alone,
guarantees immediate logout revocation.

Recommended contract:

1. A signed provider session_id must match the verified subject.
2. The verifier requires an approved authoritative session-status source,
   rechecked for every business request if immediate revocation is required.
3. A local session registry/tombstone also denies locally revoked sessions,
   regardless of a still-valid JWT. Revoked entries cannot be reactivated by
   presenting the old JWT.
4. Possible hosted source: a tightly scoped session-ID/subject lookup against
   provider session state, if supported and explicitly authorized. Do not
   assume access to auth.sessions or grant broad managed-auth schema reads.
   A provider-supported status contract is an alternative if proven sufficient.
5. Session semantics, columns, expiry, logout deletion and available restricted
   privileges need separately approved hosted tests. If no reliable source
   satisfies the agreed revocation standard, block rollout; do not claim
   immediate revocation. A bounded JWT-lifetime alternative needs explicit
   acceptance of that weaker guarantee.
6. Provider outage or inconclusive required status fails closed.

The session registry is an additional denial control, not proof of provider
status merely because it contains an “active” row.

### Step 4 — implement transactional request identity

Retain the prototype's unforgeable transaction-bound proof approach, extended
to include the verified provider session and revocation state:

1. Verify token and required session status before business work.
2. Check out one runtime connection; BEGIN READ COMMITTED and allocate its full
   transaction ID. Obtain PID/xid from that connection, not a request body.
3. Via separate verifier autocommit, issue a hashed, random proof bound to that
   identity, session, PID and xid. Expiry is no later than JWT expiry,
   session-status freshness deadline or the short proof limit.
4. Activate via SET LOCAL. Every read/command helper validates proof, identity,
   session, company status, active membership and action permission.
5. COMMIT or ROLLBACK; discard broken connections. Never reuse raw proof across
   transactions or accept browser-provided database identity context.

Require distinct pools and acquisition/request deadlines. Plain user/company
GUCs are not trusted. READ COMMITTED is mandatory for the separately committed
proof; stronger snapshot modes fail closed until separately redesigned.
Do not cache memberships in JWTs or connection-local application variables.
Pooler reset is cleanup, not the source of authorization safety.

### Step 5 — implement protected company/invitation lifecycle

Default proposal: only an authorized platform-onboarding workflow may create
companies. Whether users may initiate that workflow remains a decision.

**Create:** the trusted worker validates a reviewed request and idempotency key.
One database transaction creates the company, pending security-state row,
first-owner invitation, delivery-outbox event and security audit. No active
membership is granted from browser owner_id/is_admin/company fields.
Same-key/same-payload retry returns the existing request; changed payload fails.

**First-owner invitation:** the worker selects intended verified recipient,
trusted issuer and Owner role. Use a CSPRNG token of at least 256 bits; store
only its hash, not the raw link/token. Proposed expiry is 48 hours, pending
approval. Use a unique pending first-owner invitation per company. Expiry is
checked at acceptance; never put volatile now() in a partial-index predicate.

**Delivery:** an outbox retries email independently of the creation transaction.
Do not store raw tokens in outbox/logs. A worker may generate/commit a new hash
per delivery generation and invalidate older links on retry; only the newest
link works. Document delayed-mail/retry behavior and use delivery idempotency
when supported. Delivery retries never extend the invitation's expiry;
extending it requires an explicitly authorized resend. No claim of exactly-once email delivery.
Delivery provider is unselected. Native provider invitations, if chosen, may
require an isolated Auth-admin worker credential; never place it in ordinary
business request handling. No emails/provider resources are created now.

**Accept:** require a currently verified session and verified intended recipient.
Lock company state and invitation, validate hash/status/expiry/recipient/issuer
and role, then atomically create the identity mapping if permitted, add the
Owner membership, mark invitation accepted, activate company and append audit.
Reject conflicting existing roles rather than silently promote. An identical
retry by that same recipient is idempotent; another account cannot replay it.
No activation/business operations before first-owner acceptance.

**Revoke/resend:** lock the same rows, invalidate the token/version and record
an event. Resending revokes the old link. Concurrent accept/revoke/expiry has
one serialized outcome, not two memberships. A pending expired row must be
retired explicitly before creating a replacement pending invitation.

**Member changes:** only approved membership-management actions may invite,
remove or change roles. Never let a caller assign a role it cannot grant,
approve its own elevation or create arbitrary Owner invitations.
Removal is soft revocation, not deletion of historic identities/audit.
Every subsequent operation rereads membership. Commands already authorized
under shared locks may finish before revocation completes; new work after
committed revocation denies, including idempotent command retries.

**Last Owner:** serialize ownership changes on the company-state row; do not
allow concurrent removals to leave an active company ownerless. Owner transfer
requires a separately approved workflow. Emergency account disabling must not
be blocked: suspend affected ownerless companies and use a trusted, audited
recovery invitation, never auto-promote Admin.

### Step 6 — implement authorized functions and resource-aware RLS

Keep all seven original definers unchanged:

- initialize_balance and audit_catalogue_change remain private trigger helpers.
- apply_movement remains the guarded stock-ledger update path.
- check_balance_integrity/check_order_integrity remain private owner-context
  deferred validators; they must still work at COMMIT after wrapper return.
- stockwise.post_order/reverse_order remain private internal commands.

New narrow wrappers authorize the requested company and actual operation/kind
before core calls, including before returning an idempotent result. Owner/Admin
adjust/reverse rules are explicit. Ordinary posting/receiving/editing remain
disabled until their matrix cells are approved. Write verified actor/session/
request audit in the same transaction; a failed command leaves no partial audit.

Proposed read entry points: list/get products, inventory, orders and order lines,
plus minimal authorized company enumeration. Use bounded pagination, explicit
column allowlists and company predicates on every related-table join. Do not
expose contacts/audit/tax details simply because a view joins those tables.

Recommended direct-Node design is EXECUTE-only runtime access; replace the old
broad SELECT proposal in a future separately reviewed change. Read definers
owned by the table owner bypass RLS, so their bodies must explicitly authorize,
scope and project every query. RLS is defense in depth, not an excuse to omit
those checks. Any non-owner read-function design needs a separately reviewed
ownership/grant topology; do not silently alter the owner/migrator invariants.

RLS remains enabled. Resource-aware read policies enforce active company,
verified session, membership and approved action; no Viewer contact/audit
policy, blanket SELECT or business write policies. No anon/authenticated/
service_role/authenticator grants or new exposed Supabase schemas.
Default-deny direct mutations plus guarded wrappers preserve ledger integrity.
Do not FORCE RLS on the existing owner command chain without redesign/testing.

All new definers need NOLOGIN ownership, fixed search_path, qualified references,
no unsafe dynamic SQL and explicit minimal EXECUTE grants. Recheck effective
privileges and caller search_path/temp-table attacks. Existing global owner
default hardening remains mandatory.

### Step 7 — implement backend contracts only after approval

Potential later CommonJS modules; no modules are created by this plan:

| Proposed module | Responsibility |
| --- | --- |
| server/security/config.cjs | Trusted provider/pool settings and fail-closed startup privilege checks |
| server/security/supabase-auth.cjs | Maintained JWT/provider validation adapter; no browser identity authority |
| server/security/session-status.cjs | Authoritative session checks, local tombstones, revocation/freshness contract |
| server/security/transaction.cjs | Separate pools, proof issuance/activation, deadlines, rollback/discard |
| server/security/permissions.cjs | Explicit action vocabulary and deny-unapproved behavior |
| server/security/invitations.cjs | Verified recipient acceptance; no generic membership writes |
| server/workers/onboarding.cjs | Separately scoped trusted company/first-owner workflow |
| server/workers/invite-delivery.cjs | Outbox delivery without raw-token logging/storage |
| server/workers/proof-cleanup.cjs | Bounded expiry cleanup without deleting active revocation protection |
| server/routes/business.cjs | Input validation and per-operation authorization around narrow DB entry points |
| server/security/errors.cjs | Generic 401/403 and allowlisted errors; no token/parameter/DB URL leakage |

Future API contracts, not endpoints created now:

- GET authorized companies/products/inventory/orders: verified session and
  read permission for the selected company; no body user_id is authoritative.
- Product/draft-order mutations and order posting/receiving: permission-specific
  and disabled until approval. Always validate ownership of all referenced IDs.
- Adjustment/reversal commands: Owner/Admin and valid company/order kind.
- Invitation acceptance: signed-in verified recipient plus valid opaque token.
- Member/export routes: absent or denied until explicit permission approval.
- Company creation: trusted onboarding channel, not a public create-owner API.

HTTP handlers never receive administrative pools or provider-admin secrets.
Use strict input schemas, parameterized SQL, idempotency keys and bounded
pagination. Actor fields are taken only from the security boundary.
Browser sign-in/token storage, CSRF/CORS and any UI changes need a later
approved integration scope; the existing localStorage prototype stays untouched.

### Step 8 — test locally, then request a separate hosted-test approval

Implement only after scope approval. Run the acceptance document in a fresh,
explicitly authorized disposable PostgreSQL 17 cluster with synthetic users/
companies and real restricted login sessions, not superuser impersonation.
Re-run original suites plus revised tests; retain per-case outcomes/hashes.
Stop/remove the cluster. Do not label old prototype passes as new coverage.

Hosted testing needs distinct approval for exact disposable project, resource
costs, read/write scope, roles and cleanup. Never assume the connected project
is staging. Provider and hosted assumptions below are release gates.

## 4. Proposed additive schema work — not SQL prepared or applied here

Use new reviewed files outside the current migration/startup path. Keep 0001
and all prerequisite SQL unchanged; future deployment may need a new explicit
permission/security phase, not edits to their historical checksums.

| Object/change | Purpose and constraints |
| --- | --- |
| identities / issuers refinement | Unique exact issuer/subject, enabled status; no passwords/JWTs/credentials; deterministic opaque-ID comparisons |
| company_memberships refinement | Company/identity composite key and FKs, Owner/Admin/Viewer only, status/revoked_at/version checks; no pending invitation treated as active membership |
| role_permissions | Reviewed role/action catalogue; unapproved action absent/denied; caller cannot edit it |
| company_security_state | One row per company FK, pending/active/suspended state, first-owner/recovery markers; avoids changing core 0001 |
| onboarding_requests | Trusted initiator, unique idempotency key and payload fingerprint, company FK, checked workflow state |
| company_invitations | Company-aware keys, recipient/issuer/role/purpose, unique token hash, expiry/revocation/acceptance fields, constrained first-owner pending uniqueness |
| invitation_outbox | Invitation/company FKs, delivery generation/idempotency, attempts/status; no raw token/link |
| verified_sessions | Issuer/session uniqueness, matching identity FK, expiry/revocation/version; tombstones cannot be reset by old JWT |
| request_proofs refinement | Required matching session+identity FK, PID/full-xid uniqueness, bounded expiry; no legacy proof path that omits session validation |
| security_events / command_audit | Append-only trusted actor kind/id, company/request/action/target, minimal before/after role metadata; company-aware order FKs and command idempotency |

Membership-changing functions and deferred integrity checks must prevent an
active company with no eligible Owner. Document a consistent lock order before
coding: company-state rows in sorted UUID order, then required authorization/
invitation rows, then order headers and sorted stock balances. Explicitly test
account disabling, membership changes and commands together for deadlocks and
revocation ordering; the earlier join-lock prototype is not a complete new
lock-order specification.

No invitation/session proof may cross company/identity relationships through
a global ID alone. Maintain audit history on removal. Retention must preserve
revocation tombstones for at least the maximum accepted credential/replay window.
Do not retain raw access/refresh tokens or plaintext invitation tokens.

## 5. Dependencies, hosted assumptions and release risks

- Full pending matrix and field-level/privacy approval.
- Authoritative provider-session revocation contract; actual project signing
  settings, key rotation, session IDs and available restricted validation.
- Provider email verification/alias behavior and invite delivery/rate limits.
- Hosted pooler custom-login support, username format, transaction affinity,
  TLS trust and connection quotas. No hosted value is assumed verified.
- Managed role/ACL/event-trigger behavior, exposed Data API/GraphQL schemas,
  Realtime scope and exact opaque-ID collation behavior.
- Separate secret/process scopes for deployment, verifier and trusted worker.
  No administrative or service-role key in ordinary business handling.
- Per-request proof write volume, pool exhaustion, cleanup and audit storage.
- Account recovery and last-owner policy; denial-of-service from repeated
  invitations/acceptance attempts; anti-enumeration and rate limits.
- Existing browser records are not imported or deleted. Their eventual
  transition into authenticated company records is a separate approved task.
- Security implementation is incomplete until provider/backend/database/
  negative/concurrency tests pass. Do not claim deployed tenant isolation.

**Next gate:** approve this implementation plan, resolve its pending permission
and lifecycle decisions, and explicitly authorize a bounded implementation/local
test scope. Any hosted resource, role/grant/secret change or persistent database
execution requires its own explicit target-specific approval. None is implied.
