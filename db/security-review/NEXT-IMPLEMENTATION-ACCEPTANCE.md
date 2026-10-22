# Runtime-security implementation acceptance specification

**Planning artifact only. No new tests executed.**
Companion: `NEXT-IMPLEMENTATION-PLAN.md`. Tests below are requirements for a
future explicitly approved implementation, not assertions about current code.

## Environment and evidence

1. Record hashes of 0001, prerequisite SQL and reviewed new files.
2. Use a fresh explicitly approved local PostgreSQL 17 cluster: private socket,
   no TCP, scrubbed environment, no DATABASE_URL, isolated roles/databases.
3. Use actual restricted runtime/verifier/worker LOGIN sessions. A superuser
   session followed by SET ROLE is not equivalent privilege evidence.
4. Seed synthetic A/B companies, pending and suspended companies, Owner/Admin/
   Staff/Viewer, removed/disabled identities, multi-company users, independent sessions
   and deliberately conflicting contacts/products/orders.
   Include two distinct Staff identities in company A, drafts created by each,
   an Owner/Admin-created draft, company B drafts, posted orders and a draft
   with missing/unverified creator metadata. Use synthetic fixtures only.
5. All future SQL, seeds and tests stay local unless hosted testing is separately
   authorized. Do not install services/resources or incur unapproved costs.
6. Re-run the original 58/40 suites and revised prototype tests where applicable.
   Update expected behavior for the new Viewer scope/no Operator/raw-table
   restrictions; report intentional changes, not fabricated compatibility.
7. Record actual PASS/FAIL/UNTESTED, expected/actual errors, final row counts and
   per-company ledger/audit invariants. Retain failure corrections and hashes.
8. Always stop/remove the cluster and all credentials/fixtures; keep only
   reviewed source and sanitized reports. Do not call the current health/db
   endpoint during local-only testing: it uses the existing Supabase connection.

## A. Authentication and sessions

| Case | Required result |
| --- | --- |
| Missing, malformed, unsigned or forged token | 401 before business connection/work; no effects |
| Wrong issuer/audience/algorithm, unknown key, malicious key URL | Deny; no attacker-controlled key fetch or fallback |
| Expired JWT, future nbf/iat, excessive lifetime, service-role token | Deny |
| Valid token with forged user_id/company_id/role metadata | Ignore those fields; derive actor from verified issuer/sub |
| Revoked provider session with unexpired valid JWT | Deny according to the approved authoritative-status contract |
| Locally revoked session/tombstone | Deny; presenting old JWT cannot re-register/reactivate it |
| Subject/session mismatch or cross-issuer session collision | Deny |
| Disabled user or issuer, session expiry after proof issuance | No subsequent protected operation |
| Unknown/rotating JWKS, required status source unavailable | Bounded refresh/fail closed, no admin fallback |
| Logout followed by replay; global versus single-session logout | Exactly the separately approved semantics; no untested immediate-revocation claim |

Offline crypto tests cannot establish hosted logout behavior. Keep this group
partially UNTESTED until separately approved provider tests demonstrate it.

## B. Tenant and role isolation

| Case | Required result |
| --- | --- |
| A member reads B products/inventory/orders, including direct ID URLs | No B rows/details; generic denial/not-found policy |
| A member passes A company with B contact/product/order/line ID | Deny; composite FKs and scoped command checks remain intact |
| List/search/count/filter/pagination join includes B rows | No cross-company content or counts |
| User belongs to both A and B | Each selected company's operation independently authorized |
| Browser/JWT metadata claims company/Owner/Admin | No authority; no membership/role creation |
| Viewer edits products, drafts, stock or memberships | Deny at API and database boundary |
| Viewer posts purchases/sales, adjusts stock or reverses | Deny with no ledger/order/audit side effects |
| Viewer reads contact/cost/financial/audit/movement data through alternate routes, joins, views or SELECT * | Deny; only basic products, quantities and order ID/status visible |
| Staff creates a new ordinary draft | Succeed within approved fields; immutable creator is verified actor, no stock movement/posting |
| Staff views/edits their own company draft, including its lines | Allow approved fields while still draft; atomic edit/audit, no stock effects |
| Staff views/edits another Staff member's draft in the same company | Deny detail/header/line access; list/search/count/status reveal no other-creator drafts |
| Staff views/edits an Owner/Admin-created draft | Deny; same company alone does not confer ownership |
| Staff accesses/edits a foreign-company draft | Deny even if its creator identity matches, or the user also belongs to that company but selected a different company |
| Staff passes their own header ID with another creator's or company's line ID | Deny the entire command; no partial header/line/audit effects |
| Owner/Admin views/manages drafts created by any member of their company | Allow permitted existing-draft reads/edits across creators; preserve original creator and field restrictions |
| Owner/Admin views/edits another company's draft | Deny; elevated role never bypasses company isolation |
| Viewer creates/edits any draft or reads full draft body/lines | Deny; allow only permitted company basic status |
| Any role requests draft reassignment/transfer/takeover | Deny; no route/function, including creator changes through nested/bulk updates |
| Browser supplies another creator or changes creator/company after creation | Reject caller-controlled creator changes; no spoofed assignment or ownership rewrite |
| Draft has missing/unverified creator metadata | Staff denied; no implicit claim, backfill or takeover |
| Staff tries product create/edit through direct or nested payload | Deny, including bulk/import/upsert aliases |
| Staff edits posted/reversed order or sets status/key/snapshots | Deny with all header/line/ledger values unchanged |
| Staff posts ordinary orders or calls purchase-receipt shortcuts | Deny, including calling SQL wrappers without API middleware |
| Staff adjusts stock, reverses, manages members or exports | Deny; no exception assumed |
| Owner/Admin product create/edit, posting, adjustment and reversal | Succeed within approved field scope for active authorized company; all effects/audits atomic |
| Unapproved action/unknown role/legacy Operator | Deny; no implicit migration to Admin |
| Owner/Admin export request/generation/download | Require dataset/read/field permission and fresh same-company membership; no raw public/signed-link bypass |
| Staff/Viewer export by guessed job ID, CSV route or alternate content type | Deny; no bytes, job payload or hidden-field metadata |
| Owner/Admin membership list/invite/remove/approved role change | Succeed for same-company permitted targets; approved management is not Owner-grant authority |
| Staff/Viewer membership records or management | Deny, except minimum own role/company context and intended-recipient invitation acceptance |
| Owner/Admin cross-company export/member/product actions | Deny despite their elevated role in a different company |
| Permissions changed/removed after token or proof issuance | Next operation uses current permissions, not cached claims |

For pending matrix cells, add positive tests only after approval; denial is the
initial required result. Test field/column exposure, not merely company filters.

Viewer-specific negative coverage must include hidden-field filters/sorts,
counts/aggregates, valuation/margins, order lines and nested JSON, free-text
notes/reference labels, GraphQL/RPC aliases, export metadata and error bodies.
Use hidden-value variants with identical authorized visible data and assert
responses/counts do not vary because a hidden predicate was evaluated.
Do not equate preventing hidden-data disclosure with preventing manual copying
of permitted fields.

Staff positives must prove create/edit of their own drafts only, while
malicious company/product/contact/line IDs, financial fields without permission,
adjustment/reversal kinds and posted-state changes are rejected at the database
boundary. Own-drafts-only is confirmed, not a pending scope decision.

Run the draft authorization cases at two independent boundaries in a future
approved test environment: authenticated backend requests and direct calls to
permitted database functions as the restricted runtime caller without API
middleware. Do not use a superuser as evidence. Verify row-level policies and
line-parent checks prevent other-creator access; no frontend hiding counts as
authorization. Confirm denial causes no business-state mutation or success
audit and does not disclose another draft's existence/content.

Test forged user/company/creator IDs, stale or revoked membership, role changes
and reused pooled connections. Being the original creator is insufficient
without current same-company permission. Owner/Admin changing roles must not
change creator metadata. Staff cannot regain authority over others' drafts by
changing request context, setting an action string or invoking a private core
function.

Race own-draft editing against Owner/Admin posting: lock and recheck the parent
state, accept only a valid serialized outcome, and prevent any edit after posting
commits. Staff posting and direct posted-header/line modification always fail,
including retries and low-level database attempts. Confirm balances, movements
and success audits are unchanged by rejected attempts.

## C. Membership, onboarding and invitations

| Case | Required result |
| --- | --- |
| Ordinary runtime caller tries to create company/first Owner | Deny |
| Trusted onboarding valid request | Pending company + one first-owner invite + outbox + audit atomically |
| Same onboarding key/same input versus changed input | Idempotent result versus rejection; no duplicate company |
| Pending/suspended company business operation | Deny |
| First Owner accepts as correct verified recipient | One active Owner, accepted invite and company activation atomically |
| Unverified/wrong email, wrong subject/issuer or anonymous recipient | Deny without granting membership |
| Expired, revoked, replaced, random or leaked invite token | Deny; generic response, no raw token leakage |
| Concurrent accept/accept and accept/revoke/resend | One serialized outcome; no duplicate membership or privilege promotion |
| Same-recipient acceptance retry | Idempotent result, no duplicate audit/membership |
| Existing lower role conflicts with invite role | No silent elevation; follow approved conflict rule |
| Owner/Admin tries to invite/promote beyond grantable role | Deny, including forged Owner purpose or company ID |
| Member tries to change its own role or restore removed membership | Deny |
| Last-owner removal/demotion and concurrent two-owner removal | Reject or approved atomic transfer; never active/ownerless |
| Emergency disable of only Owner | Disable identity safely, suspend company and require audited recovery |
| Removed member uses still-valid session or old command key | Deny subsequent reads/writes/retries |
| Membership revoke races authorized command | Document winner; command-first may finish, revoke-first prevents command |
| Mail delivery fails/crashes/retries | No activation, bounded retry, no persistent raw token; old generation invalid |

Test rate limiting, recipient enumeration, inbox-link leakage, expiry-boundary
times, verified-email changes and environment separation. Provider-specific
email behavior remains a hosted integration gate.

## D. Function, RLS and effective privilege checks

- Assert owner/migrator/runtime/verifier/worker flags, membership graph and
  effective privileges, not just SQL text. Runtime cannot SET owner/migrator,
  grant roles, alter permissions, create protected objects or disable RLS.
- New PUBLIC/API-role execution remains denied; private core helpers, proof
  issuance and membership tables cannot be called/read by ordinary runtime.
- Restrict runtime to explicitly approved entry points; direct base-table
  reads/writes deny. If any grants are deliberately fault-injected locally,
  RLS still prevents cross-company/unapproved-resource access.
- Every definer has intended NOLOGIN ownership, fixed search_path, explicit
  company/action checks, qualified references and minimal function ACL.
- Review the seven original and eight prototype definers plus every proposed
  read/write/member/adjustment/export wrapper. Private implementations remain
  inaccessible to runtime even when the API wrapper itself is callable.
- Search-path/temp-table spoofing cannot redirect helpers.
- Invoke new non-owner read/write definers directly, omitting API checks: RLS
  still blocks foreign companies, Staff posting, Viewer writes and unauthorized
  resources. Assert both USING and WITH CHECK and immutable company identities.
- Check the separate basic/sensitive reader owners have no BYPASSRLS, table
  ownership or runtime role membership. Basic readers lack hidden-column
  privileges; sensitive-reader policies deny Viewer. Default owner-bypass views
  and SELECT * cannot circumvent the projection boundary.
- Test that unchanged core table-owner functions bypass owner RLS, then prove
  database wrappers—not assumed RLS or API checks—enforce their scope.
- Each new function owner needs hardened global defaults and a narrowly reviewed
  deployment/ownership path; preserve the earlier owner/migrator invariants.
- Original deferred integrity functions still succeed at COMMIT under the
  restricted caller, and reject corrupted/partial final states.
- Global default function hardening remains effective; no schema-specific or
  named-role ACL unexpectedly restores broad execution.

## E. Pooling, transactions, concurrency and stock

- Two users repeatedly reuse one runtime pool connection; no prior identity,
  company, session, settings or permission cache grants access.
- Random/forged raw GUCs cannot authenticate. Proof from another backend,
  transaction, issuer/session or expired JWT cannot activate.
- Commit and rollback both invalidate proof reuse; no leaked transaction holds
  another request's context. Wrong isolation and shared-pool configuration deny.
- Issuer proof must commit before runtime visibility; timeouts, pool acquisition
  failure, status failure and rollback/reset failure fail closed.
- Posting/reversal authorization runs before core idempotent retry; revoked
  members cannot retrieve old results by operation key.
- Verify correct company/actor/session audit and stock quantities for multi-item
  and repeated-product orders, retries, reversal and insufficient stock.
- Force an exception after core mutation/before audit and an error at deferred
  COMMIT; ensure order, balance, movements, audit and invitation state roll back.
- Concurrent sales/reversals retain overselling/idempotency protection.
- Race permissions, company suspension, session/account revocation, invites,
  last-owner changes and commands; prove the documented lock ordering.
- Cleanup must not reactivate old sessions, delete needed tombstones, retain
  raw credentials or permit active-context reuse. Test bounded storage/load.

## E1. Audit integrity and delivery outcomes

- Assert company-scoped verified actor/session/request/action/target/time for
  product changes, draft edits, posting, adjustments, reversals, exports,
  invitation lifecycle, membership changes and all role changes.
- Mutations and success audit commit atomically. Inject audit failures and
  deferred COMMIT errors; no partial product/draft/order/stock/member/invite
  state or duplicate success event remains. Retrying records one logical effect.
- Staff cannot forge a posting/admin event through a generic audit call.
  Ordinary runtime cannot UPDATE/DELETE/TRUNCATE audit rows, spoof actor/company,
  remove prior role evidence or associate an event with another company's object.
- Viewer cannot read audit rows, event counts, joins, downloads or event metadata.
  Staff audit reads remain denied pending approval. Any approved audit reader
  is subject to company policies, including Owner/Admin cross-company denial.
- Exports have a durable authorization event before data release plus correlated
  completion/failure/abort outcomes. Denied requests release no bytes. Confirm
  revocation before later download denies even if a private artifact exists.
- Failed streaming is not a successfully delivered file; already released bytes
  cannot be rolled back. Never claim exactly-once network delivery.
- Logs/audit payloads contain no JWT, proof, credential, raw invitation token,
  secret-bearing URL or uncontrolled request body. Denial logging must not
  accidentally commit a rolled-back business operation.

## F. Separately approved hosted tests and release gates

Require approval identifying disposable project, costs, exact credentials,
role/DDL/data scope, allowed external calls, backups and cleanup.

Verify actual Supabase signing/JWKS/session revocation, email invitation flow,
managed-auth lookup permissions (if chosen), pooler custom roles/affinity,
PostgreSQL version, TLS/CA, role inheritance/default ACL/event triggers and
Data API/GraphQL/Realtime exclusion. Never broaden grants to make a test pass.

Verify administrative/provider-admin credentials are absent from public web
processes, including health-check handling. Validate startup denial on missing
restricted secrets or an unexpected privileged connection.

Release requires approved matrix/lifecycle, completed local and hosted tests,
documented unresolved risks, security review and explicit deployment approval.
Passing static checks or earlier test reports cannot substitute for these gates.
