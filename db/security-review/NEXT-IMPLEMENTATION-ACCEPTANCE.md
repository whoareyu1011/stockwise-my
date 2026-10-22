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
   Viewer, removed/disabled identities, multi-company users, independent sessions
   and deliberately conflicting contacts/products/orders.
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
| Viewer reads contacts/tax/audit data through joins or SELECT * | No access beyond approved projection |
| Owner/Admin adjustment and reversal | Succeed only for active authorized company and valid ledger operation |
| Unapproved action/unknown role/legacy Operator | Deny; no implicit migration to Admin |
| Exports and member-management actions | Deny unless the matrix cell was separately approved |
| Permissions changed/removed after token or proof issuance | Next operation uses current permissions, not cached claims |

For pending matrix cells, add positive tests only after approval; denial is the
initial required result. Test field/column exposure, not merely company filters.

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
- Search-path/temp-table spoofing cannot redirect helpers.
- Test that table-owner functions bypass owner RLS, then prove wrappers—not
  assumed RLS—enforce scope. New read functions return only allowed columns.
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
