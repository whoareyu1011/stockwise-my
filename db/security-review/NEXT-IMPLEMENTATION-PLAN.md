# StockWise MY — next runtime-security implementation plan

**Status: planning only. No implementation or deployment approval.**
No SQL, provider requests, database tests, endpoints, credentials, grants or
application/configuration changes are performed by this plan.

## 1. Confirmed decisions and source review

The user's approved planning decisions are:

- Supabase Auth is the authentication provider.
- Product creation/editing is Owner/Admin only.
- Owner/Admin and Staff may create ordinary order drafts. Staff may view/edit only drafts they created
  within their company. Owner/Admin may view/manage all drafts in their company.
  Only Owner/Admin may post; Staff cannot directly modify posted orders.
- Draft reassignment, transfer and takeover are out of scope.
- Exports and membership management are Owner/Admin only.
- Owner/Admin may access company business data needed for their duties; Staff
  receives only customer/order/financial fields necessary for assigned work.
  The conservative initial work/field defaults are specified in section 2.
- Eligible drafts may be cancelled with audit, not hard-deleted. Posted orders
  can change only through authorized audited workflows, never silent editing.
- Owner manages company roles; Admin manages ordinary membership only within
  the limits below. Admin/Staff cannot appoint Owner or elevate themselves.
  Company ownership transfer remains out of scope.
- Viewer sees products, stock quantities and basic order status only; contact
  details, costs and audit logs are hidden.
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

1. It included an **Operator** role. Operator is deprecated and excluded from
   authorization. The current roles are **Owner, Admin, Staff and Viewer**.
   Do not map Operator to Staff/Admin automatically; reject it until a separately
   approved transition exists.
2. Its Viewer could read all eight tables, including contacts and audit details.
   That exceeds the confirmed Viewer scope. The next proposal must withdraw
   broad base-table access and define narrow read contracts.
3. Owner/Admin product creation/editing, posting, exports and membership
   management are now confirmed. Staff draft permissions are confirmed, but
   Staff must not inherit the old Operator's posting permission.
   Section 2 now defines conservative field and grantable-role defaults;
   these are planning contracts, not implemented permissions.
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

**A** = allowed by the confirmed rules and documented safe planning defaults;
**D** = denied. **A(scope)** permits the workflow but not every field or
target role. There is no implicit “Owner can do everything”.

| Resource / operation | Owner | Admin | Staff | Viewer |
| --- | --- | --- | --- | --- |
| Product basic read | A | A | A(scope) — sales fields | A — no financial fields |
| Product create/edit | A(scope) | A(scope) | D | D |
| Product archive / hard delete | Archive only / D | Archive only / D | D | D |
| Product costs / valuation / margins | A | A | D | D |
| Stock quantities | A | A | A | A |
| Detailed stock movements/history | A | A | D | D |
| Contact details/list/edit | A(scope) | A(scope) | A(scope) — customer selector/linked work reads only; no contact edits | D |
| Create ordinary drafts | A | A | A(scope) — new own sales drafts | D |
| Edit existing ordinary drafts | A(scope) — all company drafts | A(scope) — all company drafts | A(scope) — own sales drafts only | D |
| Cancel eligible draft / hard delete | A / D | A / D | A(scope) — own sales draft / D | D / D |
| Read editable draft body/lines | A(scope) — all company drafts | A(scope) — all company drafts | A(scope) — own sales drafts only, approved fields | D |
| Basic order status, including draft/posted state | A | A | A(scope) — own sales work | A |
| Reassign / transfer / take over draft creator | D — out of scope | D — out of scope | D — out of scope | D |
| Posted-order body/lines beyond basic status | A(scope) | A(scope) | A(scope) — own-origin sales fields, read-only | D |
| Order financial fields: prices/discounts/totals/tax/cost/margin | A(scope) | A(scope) | A(scope) — sales price/discount/tax/total only; no cost/margin | D |
| Post ordinary orders / receive stock by posting a purchase | A | A | D | D |
| Adjust stock, including opening-balance entry | A | A | D | D |
| Reverse orders | A | A | D | D |
| Export/download company data | A(scope) | A(scope) | D | D |
| Company membership records and management | A(scope) | A(scope) | D (except own minimal context) | D (except own minimal context) |
| Transfer ownership / appoint additional Owners | D — out of scope | D | D | D |
| Read business audit logs | A(scope) | A(scope) | D | D |
| Modify/delete audit logs or direct database writes/grants | D | D | D | D |
| Company creation / first-owner appointment | Trusted onboarding workflow only | Trusted onboarding workflow only | Trusted onboarding workflow only | Trusted onboarding workflow only |

Staff has no exception to posting, adjustment, reversal, membership management
or export restrictions. A future exception requires explicit approval and
separate documentation/tests. Staff cannot modify products by nesting them in
a draft payload. Posted/reversed orders are immutable to draft editors.

**Confirmed Staff draft scope — own drafts only:** authorize both active
company membership and immutable creator identity for every draft list, detail,
search/count, header edit and line read/edit. Staff cannot view another creator's
draft, even its basic status, by guessing an ID or belonging to the same company.
Owner/Admin may create, view and edit ordinary drafts in their company
regardless of creator, but cannot bypass company or field restrictions. Their
management does not change the original creator. Viewer can see only the
permitted basic status projection and cannot create/edit drafts.

Derive the creator from the verified identity at creation, never request
user_id/created_by/owner fields. Persist immutable, company-aware creator
metadata, including for lines through their parent order. Use the stable identity
key, not current role, email or display name. Missing/unverified creator metadata
must not make a legacy draft available to Staff. No automatic ownership backfill,
reassignment, transfer or takeover, including by Owner/Admin or nested edits.

“Receiving” means posting a purchase. Initially purchasing/receipt drafts are
Owner/Admin work; Staff work is own sales drafts only (explicit safe assumption,
not a newly implemented assignment feature). Validate actual kind and state,
not route names. Staff cannot create adjustment/reversal or purchase drafts
through a generic draft endpoint.

**Viewer projection:** basic non-cost product fields, stock quantity by product,
and opaque order ID/status only by default. No contact identifiers/details,
free-text notes/contact-derived references, order lines, unit prices, totals,
cost snapshots, valuation, movements or audit data. Selling prices and order
dates are not included in the initial Viewer projection.

### Concrete work, field and membership defaults

- **Owner/Admin:** same-company operational products (including cost/valuation),
  contacts, orders/items and sales/purchase financials, stock quantities/history
  and redacted business audit. This never includes auth secrets, session/proof
  tables, raw invitation tokens or administrative credentials. Business data
  needed for duties does not mean arbitrary SQL or provider-admin access.
- **Staff work assignment assumption:** immutable creator identifies initial
  assigned sales work; no separate assignment/reassignment feature. Staff may
  view/edit own sales drafts and read the same limited sales projection after
  posting/cancellation, never edit posted/cancelled orders. Other creators'
  work, purchasing/supplier records and company-wide order aggregates deny.
- **Staff field allowlist:** product ID/SKU/name/unit/active state/selling price
  and available quantity; customer selection returns ID/display name only.
  For a customer linked to their own sales work, allow billing name/address,
  business invoice email/phone and tax/registration identifiers needed for that
  order. No full contact-directory detail, unrelated contacts, supplier/bank/
  internal notes or contact mutation. Customer lookup does not grant access
  to another creator's draft.
- **Own sales fields:** own order ID/status/date/customer reference, product/
  quantity/unit/selling price, bounded discount, tax classification/rate and
  calculated line/order totals. Only draft inputs are editable; totals are
  trusted calculations, never caller-written snapshots. Reject negative prices,
  discounts exceeding gross amount and arbitrary tax rates; use configured
  company tax/price rules. No purchase cost, inventory valuation, margin/profit,
  stock history or audit reads. New fields deny until explicitly allowlisted.
- **Membership ceiling:** Owner may invite/revoke/change Admin/Staff/Viewer.
  Admin may invite/revoke/change only Staff/Viewer, not Admin peers, Owner or
  itself. No self-role edits, Owner invitations/additional Owners, ownership
  transfer or last-Owner removal/demotion. Changing an existing member's role
  uses an explicit audited action, not invite acceptance/upsert.
- **Archive default:** Owner/Admin may mark products/contacts inactive, not
  hard-delete referenced records; Staff/Viewer cannot. Existing historical
  references remain intact and inactive records cannot be selected for new work.

### Cancellation contract

An eligible draft is an ordinary, not-yet-posted/non-reversed/non-cancelled
order with no stock effects or externally finalized obligation. Owner/Admin
may cancel such company drafts; Staff may cancel only their own sales drafts.
Require reason, verified actor and idempotency key; keep header/items/creator,
record terminal cancellation and atomic success audit. No hard deletion,
uncancel, reopening, stock adjustment or automatic reversal.

Serialize cancellation, editing and posting on the same parent lock and recheck
effective state/authorization. Same-key/same-payload retries return the original
authorized result, not a second audit; changed payload rejects. A cancelled
draft cannot be edited/posted. If posting won, draft cancellation rejects:
Owner/Admin must separately request the audited reversal workflow with all
stock/deferred checks. No generic posted-order DELETE/UPDATE/cancel shortcut.

The prepared core migration is unchanged and not assumed to support this
cancellation state. A future reviewed additive cancellation record/guard design
must block all posting/edit paths (including private-core access restrictions),
preserve deferred invariants and prove race behavior before release. No SQL is
prepared/applied by this document.

### Export dataset allowlist

Owner/Admin only: company business profile, product catalogue/valuation,
customer/supplier business contacts, orders and lines (including approved
financials), quantity balances, stock movement history and redacted business
audit events. Same-company predicates and normal dataset/field permissions
apply to every join/filter/aggregate and download. No raw database dumps,
membership/auth-directory export, sessions, JWTs, passwords, secrets, proofs,
invitation links/tokens, provider metadata, internal security events or
unrestricted audit payloads. Attachments/invoices/integrations not implemented
in this phase do not become export features. Audit exports use a fixed business
projection with no authentication identifiers or secret-bearing metadata.

### Remaining assumptions and release gates

The sales-only Staff scope, own-origin posted/cancelled read projection, precise
field allowlists, cancellation eligibility, archive-only deletion policy and
single-Owner model are conservative defaults selected for review, not claims
of implementation or pre-existing capabilities. Broader Staff purchasing/
assignment, Owner appointment/transfer, reopening and bulk deletion remain out
of scope. Tax configuration/rounding and allowed price/discount rules must be
specified before financial validation is implemented; deny unconfigured cases.
Provider signing/session-revocation details, invitation expiry/delivery,
onboarding initiator, recovery, retention, hosting and deployment topology still
need the release decisions below. No open permission cell grants broader access.

## 3. Implementation sequence and approval gates

### Step 1 — finalize contracts and risk decisions

Approve the complete matrix, field allowlists, first-owner identity rules,
onboarding initiator, invitation lifetime, session-revocation standard and
retention. Translate approved actions into a server/database permission catalogue.
Unknown actions and roles must deny. No deployment can compensate for an
unimplemented authorization boundary. Review the explicit defaults and
remaining operational assumptions before implementation approval.

### Step 2 — separate deployment, verification and business identities

Retain NOLOGIN owner/migrator roles for reviewed deployments. Propose separate
per-environment runtime and verifier LOGIN accounts with no superuser,
BYPASSRLS, CREATEROLE, database CREATE or privileged inherited memberships.
Each inherits only its reviewed capability role, without ADMIN/SET delegation.

The business role should be **EXECUTE-only**, with no raw inventory/security
table access. It calls approved read/mutation entry points. Separate NOLOGIN,
non-owner, NOBYPASSRLS reader/writer capability roles execute scoped queries
under mandatory policies; the runtime must not be their member or SET ROLE to
them. Reader roles are split by disclosure tier to protect columns as well as
rows. The verifier may
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

**Member changes:** Owner/Admin may manage same-company memberships through
authorized wrappers. Staff/Viewer cannot list other members or mutate them.
Owner manages Admin/Staff/Viewer; Admin manages Staff/Viewer only, never
Owner/Admin peers or itself. Owner grants/transfer and all self-role changes deny.
Expose only company business directory fields, not issuer/subject or auth data.
Never let a caller assign a role it cannot grant,
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

Review all seven original definers above and all eight prototype definers:
issue_context, verified_context, activate_context, can_read_company, authorize,
my_companies and the two API command wrappers. The verifier-only issuance helper
stays private to its credential. Context/policy helpers do not grant membership
or accept browser role claims. Replace the coarse read helper contract with
resource/action-aware checks and add session validation in a separately reviewed
implementation; do not deploy the old prototype unchanged.

Wrappers authorize company, current membership, session, resource, operation and
actual kind before privileged core calls, including idempotent results.
Owner/Admin-only posting, stock adjustment, reversal and membership operations
must have no direct runtime EXECUTE path to their private implementation.
Staff draft edits cannot set status, posted_at, posting_key, reversal linkage,
stock movement/balance or protected snapshots. Authorize each nested line ID.
Movement rows are immutable ledger effects of approved commands; even
Owner/Admin have no manual movement insert/edit/delete endpoint.

**RLS-enforced reads:** use separate NOLOGIN, non-owner/NOBYPASSRLS function
owners for safe basic reads versus sensitive operational reads. Give them only
required column SELECT rights; no login, runtime membership or arbitrary SQL
entry point. Safe readers have no contact/cost/audit/financial column rights.
Separate Viewer-safe readers, Staff sales/customer readers and Owner/Admin
business readers. Staff policies enforce own-origin sales scope, including its
read-only posted/cancelled projection; contact-detail reads require a linked
authorized own order, not just a caller-supplied customer ID. Selector-only
readers expose ID/name, not billing details. Fixed-purpose functions and column
ACLs keep these tiers distinct; never let a caller choose a stronger resource
or field tier by setting query context.
Resource-specific policies bind their queries to the current verified identity,
company and permission. Sensitive-reader policies must reject Viewer and every
unapproved role/resource combination. Reading products must not imply cost
permission; reading basic order status must not imply financial/body access.

**RLS-enforced ordinary writes:** dedicated non-owner write-function owners
receive only necessary DML/column privileges. Products INSERT/UPDATE policies
require same-company Owner/Admin product-write permission with both USING and
WITH CHECK protection. Draft policies require an authorized draft writer and
both old/new state remaining ordinary draft, with immutable company identity.
The Staff branch also requires sales kind and absence of terminal cancellation.
Cancellation has a separate guarded audited command, not a free-form state edit.
For Staff, SELECT/UPDATE policies and every database draft entry point require
the stored creator to equal the current verified identity. UPDATE USING
checks the old row; WITH CHECK validates the new row, while guards/column ACLs
prevent changing company or creator. Creation assigns the verified actor in
the trusted database function and validates that identity, not a browser claim.
Owner/Admin branches allow existing-draft reads/edits across creators only
inside the authorized company. Apply the same predicates to line operations
via the company-aware parent; authorizing a header alone is insufficient.
Use a separate Viewer basic-status projection, never full draft access.
Serialize draft edits with posting on the parent order and recheck its state
under lock: a draft fetched earlier cannot be edited once posting wins.
Check ownership before any idempotent response or existence-sensitive result.
No owner/creator mutation function or generic ownership-changing update exists.
Staff cannot select the posting policy by changing an input action string.
Existing guards plus explicit column whitelists prevent post/edit escalation.

New non-owner read/write definers are therefore subject to RLS even when an API
check is missing. Read projections and column grants additionally protect
hidden columns: RLS is row filtering, not column masking. Never use
SELECT * or default owner-bypass views to implement Viewer projections.

The seven core owner-context functions are a **documented RLS exception**:
table owners bypass RLS without FORCE. Existing posting/ledger/deferred code
remains unchanged/private and reachable only through audited database-side
authorization wrappers. API checks are not the boundary. Prove wrapper
authorization/company scoping under direct SQL calls; do not claim RLS filters
these owner bodies. If all privileged internals must themselves be subject to
RLS, stop for a separately approved redesign/forced-RLS proposal and full
regression tests. Do not silently FORCE RLS or weaken ledger checks.

The non-owner function-ownership/deployment topology is new work: review SET
authority, temporary schema CREATE, revocation and creator-specific global
function defaults for each new function owner. Preserve stockwise_owner's
no-parent-membership invariant and the existing migrator graph; do not edit the
prerequisite scripts to grant blanket authority.

Policies and helper checks must deny inactive companies, invalid/revoked
sessions and removed memberships. No blanket SELECT/DML, Viewer contact/audit
policy, or anon/authenticated/service_role/authenticator grant. Keep private
schemas out of Data API/GraphQL/Realtime exposure.

**Anti-inference contract:** Viewer endpoints, detail/line routes, joins,
search/filter/sort/group/count/summary queries, errors and exports must not
return or predicate on hidden contact/cost/financial/audit fields. Reject
unapproved fields before query execution; no cost-based filters, valuation/
margin aggregates, contact-derived labels or signed export links. Restrict
database functions/views and column ACLs too, not just response serialization.
Do not promise to prevent copying legitimately visible facts; prevent hidden
data and query-oracle disclosure.

All new definers need NOLOGIN ownership, fixed search_path, qualified references,
no unsafe dynamic SQL and explicit minimal EXECUTE grants. Recheck effective
privileges and caller search_path/temp-table attacks. Existing global owner
default hardening remains mandatory.

### Step 6A — company-scoped audit requirements

Audit product create/edit/archive, contact changes/archive, draft
create/edit/cancellation, posting, stock adjustments,
reversal, export authorization/outcome, invitations/acceptance/revocation,
membership add/remove and every role change. Store company, verified actor,
session/request correlation, action, target ID, timestamp, outcome and minimal
approved changed-field/before-after metadata. Never log JWTs, proofs, passwords,
invitation tokens/links or unrestricted request bodies.

Mutations and their success audit commit atomically: audit failure rolls back
product/draft/order/stock/membership/invitation effects. Keep core ledger audit
unchanged and add verified-human events; retries must not duplicate success
effects or erase the first actor. Use company-aware keys and append-only
constraints, including protection from ordinary UPDATE/DELETE/TRUNCATE.
Only trusted functions append; ordinary runtime cannot forge or alter events.

Viewer never reads audits; Staff has no approved audit-read permission.
Owner/Admin may read the redacted company business audit projection, not
authentication/security internals. RLS enforces company isolation for audit
readers; Staff and Viewer have no audit-read access.

Exports require Owner/Admin and current allowed dataset/column permissions at
request and delivery. Audit authorization before releasing any data; correlate
completed/failed/aborted outcomes to the same company/request. Do not claim
network delivery is atomic with a SQL transaction or roll back already sent
bytes. A stored export must stay private, be scoped to company/requester and
recheck current authorization on download; no reusable public URL. Export job
and audit creation can be atomic; generation/streaming failures need explicit
durable outcomes. Denied attempts use a separate safe security-event path that
does not commit a rejected business transaction or expose guessed IDs.

### Step 7 — implement backend contracts only after approval

Potential later CommonJS modules; no modules are created by this plan:

| Proposed module | Responsibility |
| --- | --- |
| server/security/config.cjs | Trusted provider/pool settings and fail-closed startup privilege checks |
| server/security/supabase-auth.cjs | Maintained JWT/provider validation adapter; no browser identity authority |
| server/security/session-status.cjs | Authoritative session checks, local tombstones, revocation/freshness contract |
| server/security/transaction.cjs | Separate pools, proof issuance/activation, deadlines, rollback/discard |
| server/security/permissions.cjs | Explicit action vocabulary and deny-unapproved behavior |
| server/security/read-contracts.cjs | Role/resource column allowlists and rejection of hidden-field predicates |
| server/security/audit.cjs | Verified company-scoped audit contract, atomic mutations and export outcomes |
| server/security/invitations.cjs | Verified recipient acceptance; no generic membership writes |
| server/workers/onboarding.cjs | Separately scoped trusted company/first-owner workflow |
| server/workers/invite-delivery.cjs | Outbox delivery without raw-token logging/storage |
| server/workers/proof-cleanup.cjs | Bounded expiry cleanup without deleting active revocation protection |
| server/routes/business.cjs | Input validation and per-operation authorization around narrow DB entry points |
| server/security/errors.cjs | Generic 401/403 and allowlisted errors; no token/parameter/DB URL leakage |

Future API contracts, not endpoints created now. Every row requires verified
session + active same-company membership + its action; database functions and
RLS enforce those checks independently of route visibility.

| Contract/resource | Required authorization |
| --- | --- |
| Own company/role context | Return minimal own context, not a company-member directory |
| Product read/list/detail | Owner/Admin business fields; Staff sales allowlist; Viewer nonfinancial basic fields only |
| Product create/edit | Owner/Admin; reject nested Staff updates, immutable company, atomic audit |
| Quantity read | All four roles, same company; costs/valuation only Owner/Admin, no history join leakage |
| Movement history read | Owner/Admin only |
| Contact read/search/write | Owner/Admin business management/archive; Staff customer selector + linked own-work read allowlist only; Viewer denied |
| Ordinary draft create | Owner/Admin ordinary drafts; Staff own sales drafts; verified immutable creator, field whitelist and atomic audit |
| Ordinary draft edit | Staff only their own sales drafts; Owner/Admin all company drafts; current ordinary-draft state, parent/line authorization, immutable company/creator, atomic audit |
| Whole-draft cancellation | Owner/Admin eligible company drafts; Staff eligible own sales drafts; terminal audited/idempotent command, no stock effects or hard delete |
| Draft list/detail/search/count/lines | Staff only their own sales drafts; Owner/Admin all company drafts; no foreign-company or other-creator leakage; permitted field projections only |
| Basic status / posted order read | Viewer ID/status only; Staff own-origin sales projection read-only after posting/cancellation; Owner/Admin company business projection |
| Draft reassignment / transfer / takeover | No route or database entry point; reject creator-changing payloads for every role |
| Post sale/purchase/receive | Owner/Admin only; real kind and ledger checked; Staff/Viewer denied |
| Adjustment / reversal | Owner/Admin only; no alternative draft route to bypass |
| Export request/generate/download | Owner/Admin + dataset/field permission + current membership; Staff/Viewer denied regardless of file/job ID |
| Membership list/invite/remove/role change | Owner manages Admin/Staff/Viewer; Admin manages Staff/Viewer only; no self-elevation, Owner changes or transfer; Staff/Viewer denied |
| Invitation accept | Verified intended recipient + valid token/issuer/expiry; cannot select company or granted role |
| Audit list/detail | Owner/Admin redacted company business events only; Staff/Viewer denied |
| Company / first Owner | Trusted onboarding channel only |

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
| company_memberships refinement | Company/identity composite key and FKs, Owner/Admin/Staff/Viewer only; Operator deprecated/denied, no automatic promotion; status/revoked_at/version checks |
| Immutable order-creator metadata | Future reviewed additive design: one creator per company/order, company-aware order FK and verified stable identity FK; no caller assignment, reassignment or automatic legacy backfill; child access inherits parent scope |
| Draft cancellation metadata / guards | Future additive design only: unique company/order cancellation, reason/actor/request, terminal state and immutable original records; shared parent locking prevents post/edit races; no change to core 0001 here |
| role_permissions | Reviewed role/resource/action and field-tier catalogue; unapproved access absent/denied; caller cannot edit it |
| company_security_state | One row per company FK, pending/active/suspended state, first-owner/recovery markers; avoids changing core 0001 |
| onboarding_requests | Trusted initiator, unique idempotency key and payload fingerprint, company FK, checked workflow state |
| company_invitations | Company-aware keys, recipient/issuer/role/purpose, unique token hash, expiry/revocation/acceptance fields, constrained first-owner pending uniqueness |
| invitation_outbox | Invitation/company FKs, delivery generation/idempotency, attempts/status; no raw token/link |
| verified_sessions | Issuer/session uniqueness, matching identity FK, expiry/revocation/version; tombstones cannot be reset by old JWT |
| request_proofs refinement | Required matching session+identity FK, PID/full-xid uniqueness, bounded expiry; no legacy proof path that omits session validation |
| security_events / command_audit | Append-only verified company/actor/session/request/action/target/outcome for every audited operation, protected payload, company-aware keys, idempotency; hidden from Viewer |
| export_requests | Company/requester and authorized dataset/projection, status/outcome and audit correlation; private delivery with fresh authorization |

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

- Explicit section 2 defaults resolve field scopes, new-draft creation,
  cancellation, role ceilings, exports and archive-only deletion for planning.
  Staff purchasing, broader assignments, additional Owners/transfer and reopening
  are excluded, not permissions waiting to become implicitly enabled.
  Financial configuration, eligibility checks and retention still need exact
  implementation contracts; implementation/deployment approval remains separate.
- Non-owner reader/writer ownership and RLS policy topology must be implemented
  and tested under separate approval; old owner-bypass read prototypes are not
  evidence that the new policy boundary works.
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

**Next gate:** review the explicit defaults, remaining operational assumptions
and lifecycle decisions, then explicitly authorize a bounded implementation/local
test scope. Any hosted resource, role/grant/secret change or persistent database
execution requires its own explicit target-specific approval. None is implied.
