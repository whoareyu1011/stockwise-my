# StockWise MY runtime security — review only

**Not deployed or connected to Supabase. No authentication or tenant isolation
has been implemented in the existing application.** This directory contains an
isolated prototype and its test results, not an approved next migration.

**Current planning authority:** `NEXT-IMPLEMENTATION-PLAN.md` and
`NEXT-IMPLEMENTATION-ACCEPTANCE.md` contain the confirmed Owner/Admin/Staff/Viewer
rules. The SQL and tests described below are historical prototypes, not current
permission approval. Operator is deprecated and excluded from authorization.
Broad Viewer reads in the prototype are superseded, not authorized for rollout.

## 1. Proposed authentication choice

**Supabase Auth is confirmed for planning.** The reference prototype uses
asymmetric ES256 access tokens; exact signing-mode settings still need
confirmation. The actual project's signing settings were not inspected or
changed.

The provider handles sign-in, passwords, password recovery and MFA. StockWise
stores only an immutable external `(issuer, subject)` identity mapping, account
status and company memberships, not passwords or provider/database credentials.
Do not identify users by a browser user ID, email address or editable profile.

The future Node authentication boundary must validate:

- Signature against a trusted provider key; exact configured issuer and audience.
- An explicit permitted algorithm/key type and key ID.
- Expiry, not-before, issued-at and permitted token lifetime.
- User-token class (`role=authenticated` for this reference), not service tokens.
- Appropriate provider/session revocation rules, separately verified with the
  actual provider before release.

`verify-jwt.reference.cjs` demonstrates that contract offline with ES256. It
uses locally generated test public keys; it does not implement sign-in, fetch
JWKS, configure Supabase or install an authentication SDK. Production should
use a maintained provider/JWT library with the same tested contract.

The JWKS address must be pinned in trusted server configuration. Never fetch
keys from JWT `iss`, `jku`, `x5u` or an embedded key. Unknown `kid` may trigger one
bounded refresh from the configured endpoint, never accept an unknown key.
Use a bounded cache, rotation handling, timeouts and fail-closed behavior.
Those live network/rotation paths remain untested.

Legacy HS256 and other signing algorithms are deliberately rejected by this
prototype. Do not rotate keys or enable another algorithm without a separately
approved provider integration and tests.

## 2. Why user-ID session settings alone are insufficient

A direct PostgreSQL runtime caller can set custom settings such as
`request.jwt.claims` or `stockwise.user_id`. A policy trusting those values
would let an SQL injection impersonate another user. Parameterized SQL is
required, but the database boundary should also reject forged identity context.

The prototype therefore uses a **server-internal random proof**:

1. Node verifies the bearer JWT before borrowing a business connection.
2. Node begins READ COMMITTED on one checked-out runtime connection.
3. That connection returns its own backend PID and full transaction ID (`xid8`).
4. A separate trusted verification component uses its separate restricted
   verifier connection to issue a proof for the verified issuer/subject and
   that PID/transaction. Browser-supplied IDs are never used for this step.
5. Proof issuance commits on the verifier connection before the runtime's next
   statement. It stores only a SHA-256 hash, identity, request ID, PID,
   transaction ID and expiry.
6. The runtime connection activates the returned random proof using SET LOCAL.
   Its expiry is the earlier of JWT expiry or 60 seconds.
7. Policies/helpers require a matching private proof row, current PID and full
   transaction ID, a live expiry, enabled issuer and active account.
8. Membership queries use that verified identity. A requested company UUID is
   only a selector; it never establishes permission.
9. COMMIT/ROLLBACK ends the transaction. The proof cannot work on a later
   transaction, even if a caller poisons a session setting or reuses a backend.

The proof contains about 244 bits of randomness from two core random UUIDs.
It is never returned to the browser, put in a URL or logged. The private table
does not store the raw proof/JWT. An expired-proof cleanup process, capacity
limits and retention policy must be approved before release; none is scheduled.

This is an additional trusted-component boundary, not magic protection against
a compromised backend. The verifier can issue proofs for existing identities.
Its credential is therefore sensitive, despite lacking business-table access.
Isolating the verifier in a small service with its own secret scope is preferred.
If both low-privilege credentials share one Node process, complete process
compromise can impersonate users. The reference code does not claim otherwise.

## 3. Connection/credential separation

| Identity | Allowed purpose | Explicit exclusions |
| --- | --- | --- |
| Administrative operator | Approved offline deployment/provisioning | Never ordinary web requests |
| stockwise_owner | NOLOGIN object/function owner | No runtime membership or login |
| stockwise_migrator | NOLOGIN deployment role | No runtime membership or login |
| stockwise_runtime | Historical prototype: RLS SELECT plus five helper/entry-point functions; current plan replaces this with EXECUTE-only access | No DML, auth-table access, proof issuance, owner/migrator membership, CREATE or BYPASSRLS |
| stockwise_verifier | NOLOGIN capability role: issue_context only | No business SELECT, commands, membership editing or deployment rights |

Here “public-to-runtime” means explicitly granted to that restricted role,
**not PostgreSQL PUBLIC or an unauthenticated internet endpoint**.

Future per-environment LOGIN accounts would inherit exactly one capability
role, without ADMIN/SET privilege on that grant or other privileged memberships.
The draft creates neither login account nor password. Local LOGIN test
accounts exist only inside the disposable cluster.

Use separate TLS-verified runtime and verifier pool configurations, with the
existing trusted CA and hostname verification. They must never fall back to
`DATABASE_URL`. Fail startup if a required restricted configuration is missing,
the pools share an identity, or role/ownership/privilege checks fail.
Suggested future secret names are `STOCKWISE_RUNTIME_DATABASE_URL` and
`STOCKWISE_VERIFIER_DATABASE_URL`; they have **not** been created.

The existing `server.js` still uses the administrative DATABASE_URL for its
lazy health-check pool. The previous review identified that connection as
postgres with BYPASSRLS and inherited pg_read_all_data. This task did not
reinspect its live role.

**Release blocker:** before introducing real records or business APIs, move
administrative credentials out of every internet-facing application process,
not merely avoid using its pool in new handlers. Keep them only in an approved
deployment operator/job scope. A later approved change must keep health checks
working through a restricted SELECT NOW() connection. This conflicts with
changing nothing today, so it is a required future change, not something done
in this preparation step.

## 4. Identity and membership tables

All five proposed security tables are owned by stockwise_owner, have RLS
enabled without runtime policies, and have no direct runtime/verifier grants.

| Table | Purpose and important constraints |
| --- | --- |
| issuers | Administrator-approved exact HTTPS issuers; enabled switch |
| identities | UUID internal identity; UNIQUE(issuer,subject), issuer FK, active switch, creation timestamp |
| company_memberships | PRIMARY KEY(company_id,identity_id), FKs to company/identity, checked role and active switch, identity-first lookup index |
| request_proofs | Hash PK; identity FK; UNIQUE(backend_pid,transaction_id); indexed expiry; generated request UUID |
| command_audit | Append-only verified human actor/request for post/reverse; company-aware order FK; UNIQUE(company_id,action,operation_key) |

The eight inventory tables and their composite company foreign keys remain
unchanged. They prevent inconsistent links, not unauthorized access. Global
identity mappings allow one person to belong legitimately to several companies.

There is **no self-service membership write path**. First-company ownership,
invitations, provisioning, role changes and last-owner protection need a
separate workflow. Proposed bootstrap: a trusted administrator verifies the
provider identity and provisions the first owner; later invitations must be
bound server-side to a verified recipient and authorized company administrator.
Never accept browser `is_admin`, company claims, metadata roles or user IDs
as evidence. This lifecycle is not implemented by the prototype.

Review exact, deterministic comparison/collation requirements for opaque
issuer/subject strings on the eventual hosted target. The local tests used
the fresh cluster's deterministic locale.

## 5. Current confirmed operation permissions

| Operation | Owner | Admin | Staff | Viewer |
| --- | --- | --- | --- | --- |
| Create/edit products | Yes | Yes | No | No |
| Create/edit ordinary drafts | Pending | Pending | Yes, scoped | No |
| Post ordinary orders | Yes | Yes | No | No |
| Adjust stock / reverse orders | Yes | Yes | No | No |
| Export permitted data | Yes, scoped | Yes, scoped | No | No |
| Manage same-company members | Yes, scoped | Yes, scoped | No | No |
| Basic products / quantities / order status | Other read scopes pending | Other read scopes pending | Draft workflow scope; other reads pending | Yes, no contacts/costs/audit |
| Direct business DML / audit modification | No | No | No | No |

The detailed resource/field matrix, pending financial/contact/movement/audit
read permissions and role-assignment ceilings are in NEXT-IMPLEMENTATION-PLAN.
“Owner” is a company role, never a database owner. Operator is deprecated,
excluded and not automatically mapped to Staff. The old all-eight-table Viewer
projection and Operator posting path remain only in unmodified historical test
sources; they are not approved permissions.

Runtime users enumerate companies through `stockwise_api.my_companies()`,
which derives results from the verified identity and current active memberships.
The browser can select one returned company, but every later database operation
must independently authorize it.

## 6. Privileged functions and posting/reversal

The seven existing SECURITY DEFINER functions remain untouched:

| Existing functions | Assessment / restriction |
| --- | --- |
| initialize_balance, audit_catalogue_change | Trusted trigger helpers; no direct runtime execution |
| apply_movement | Updates stock through the guarded ledger path; no direct runtime execution |
| check_balance_integrity, check_order_integrity | Deferred owner-context validators; keep their existing permissions so COMMIT can validate |
| post_order, reverse_order | Privileged internal commands; remain private, not directly granted to runtime |

All remain owned by the NOLOGIN stockwise_owner with their fixed search paths.
Owner functions bypass owner RLS even though the role has NOBYPASSRLS. Do not
assume enabling RLS makes their bodies safe.

Two new proposed wrappers provide the authorization boundary:

The following describes the historical tested prototype, not the current
four-role contract. Future posting must be Owner/Admin only; adjustments and
membership management also need private authorized entry points, and new
read/write definers need the non-owner policy design in the implementation plan.

- `stockwise_api.post_order`: verifies proof, locks active account/issuer/
  membership, checks the company role, locks/scopes the order, checks operator
  order-kind restrictions, then invokes the unchanged core command.
- `stockwise_api.reverse_order`: checks the same trusted context, requires
  admin/owner membership, then invokes the unchanged reversal.

Authorization occurs **before idempotent retries**. A revoked member cannot
retrieve a previous command result merely by supplying its old operation key.
Core stock locks, operation keys and deferred checks remain authoritative.
The added verified-actor audit commits/rolls back with the command and preserves
the first successful actor on retries. Original core audit rows remain intact.

Authorization takes FOR SHARE locks on membership, identity and issuer rows.
Revocation that commits first causes denial. A command that locks first may
finish while revocation waits. That is the explicit serial ordering, not a
claim that revocation cancels already authorized in-flight work.
Ordinary SELECT policies see statement-level READ COMMITTED membership state;
they do not retroactively cancel a query whose snapshot predates revocation.

Every new definer has a fixed `pg_catalog,pg_temp` path and qualified object
references, no dynamic SQL and explicit narrow EXECUTE grants. The owner-global
function default hardening remains mandatory. Do not FORCE RLS on the existing
owner-dependent command chain without redesigning and retesting it.

## 7. Proposed RLS and direct-write defense

**Historical prototype only:** the broad eight-table SELECT policies below
must not be deployed as the current Viewer design. The current plan requires
EXECUTE-only runtime, non-owner policy-enforced readers/writers, disclosure-tier
column grants and anti-inference tests. The old SQL/test report is preserved
as evidence, not silently changed to claim those new controls were tested.

Eight SELECT policies apply only to stockwise_runtime:

- companies: `can_read_company(id)`;
- products, contacts, orders, order_items, stock_balances, stock_movements,
  audit_logs: `can_read_company(company_id)`.

The helper uses only verified transaction context and active memberships. The
auth tables have no runtime policies/grants. There are no INSERT/UPDATE/DELETE
policies or grants on inventory tables. Even an accidental direct DML grant
still encounters default-deny write RLS, as tested locally.

New catalogue/draft editing APIs are deliberately not provided. They need
separately reviewed authorization-aware entry points and tests before release.
Do not broaden table grants to make future routes work.

Keep stockwise, stockwise_auth and stockwise_api out of Supabase Data API,
GraphQL and Realtime exposure in this direct-Node architecture. No anon,
authenticated, service_role or authenticator grant is included.

## 8. Pools, transactions, failures and operating limits

- One checked-out runtime client for BEGIN through COMMIT/ROLLBACK.
- Explicit READ COMMITTED; stronger snapshot modes fail closed. They cannot
  see a proof committed after their first snapshot.
- Separate verifier pool/autocommit; shared pools are rejected by the reference.
- Parameterized, unnamed queries; no session-level identity or client SET ROLE.
- SET LOCAL proof and timeouts. PID+xid checks make security independent of
  cleanup reaching a particular backend.
- On request error: rollback. On rollback/reset failure: discard the connection.
- PostgreSQL transaction pooling should retain a backend for the transaction,
  but actual Supabase pooler/custom-login compatibility remains untested.
- Proof issuance adds a committed database write even for reads. Size pools,
  cap request rates, purge expired hashes safely and budget storage/latency.
  Issuer pool exhaustion, full storage or missing proof causes failure, not an
  unauthenticated fallback. Production pool acquisition/wall-clock deadlines
  and cleanup must still be implemented and tested.
- JWT/proof expiry is checked on activation and each authorization/read. It
  is not a promise to cancel an already running command at an expiry instant.
- Do not log JWTs, proofs, credentials, bound SQL parameters or raw database
  error context. Return generic 401 for invalid/absent JWTs, 403 for denied
  authorization and allowlisted business errors only to authorized members.

The Node reference is not an HTTP server and provides no endpoints or startup
hook. The frontend remains its existing unauthenticated browser-data prototype.

## 9. Manual decisions and release gates

1. Supabase Auth is confirmed; approve signing mode, exact issuer/audience, token lifetime,
   session revocation expectations and client token storage/CSRF strategy.
2. Approve the two-restricted-connection proof architecture and verifier
   isolation, or request an alternative design using a trusted JWT gateway
   instead of direct PostgreSQL request connections. That alternative has not
   been implemented or tested here.
3. Use the confirmed four-role matrix; resolve its marked field/target-role
   decisions, first-owner bootstrap, invitations, account disabling, last-owner
   safeguards and audit retention.
4. Approve future credential separation and removal of admin credentials from
   internet-facing processes; no configuration/secrets were changed today.
5. Decide proof retention/cleanup, rate limits, pool sizes, timeout budgets and
   monitoring. Never expose an unverified proof-minting endpoint.
6. Recheck hosted role/default ACL/event trigger behavior, collations, Data API,
   GraphQL/Realtime exclusion, pooler login format and TLS under separate
   explicit approval. No Supabase contact occurred in this task.
7. Obtain a separate security review and provider/pooler integration tests.
   The local prototype is not a production security guarantee.
8. Approve exact future migration contents and target before any persistent
   database change. The file here is not in the migration/startup path.

Read `TEST-REPORT.md` for actual results and limitations. None of these files
authorize deployment, create live roles or grant application access.
