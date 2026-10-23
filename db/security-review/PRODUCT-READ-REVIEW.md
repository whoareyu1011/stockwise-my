# Product-read proposal correction review

**Status: review-only. No SQL was executed or tested.** The two SQL files below
are proposals, not installed database state. This document reports source
changes and static reasoning only; it does not attest that PostgreSQL accepts
the SQL or that the proposed checks pass in Supabase.

## Finding-by-finding remediation

| # | Review finding | Source correction | Status / remaining limitation |
| --- | --- | --- | --- |
| 1 | Effective privileges and role-membership closure | The product proposal checks transitive API-role reachability and effective object privileges for the four standard API roles. Both proposals now inspect direct `pg_auth_members` rows, including grantor and option fields, rather than assuming one row per `(roleid, member)` pair. | Partially addressed in source. The checks are unexecuted, custom Data API roles/exposed schemas remain outside the SQL-visible scope, and the target's exact grantor/options rows must match the fail-closed expectations. |
| 2 | Privileged deployment roles | Both proposals state that the migrator can `SET ROLE` into function owners and that the role-creating operator can administer memberships. The migrator/operator are trusted privileged identities, not an RPC-only boundary. | Explicitly documented, not technically prevented. Keep those credentials out of application requests; actual grants and credential handling remain target-specific and unverified. |
| 3 | Membership-owner RLS bypass and administration | Membership operations are not exposed through the API and remain blocked until an approved audit control or independently verified privileged operational procedure exists. | Unresolved. This is an operational stop condition, not a database-enforced audit trail. A trusted operator/migrator can still change or delete rows; no membership write or first-Owner procedure is approved here. |
| 4 | Permissive RLS policy composition | Each protected table gets a permissive reader policy plus a restrictive company-membership guard. Both the RPC and policies call the same active-membership helper and the RPC rejects roles outside Owner/Admin/Staff/Viewer. | Company checks are repeated at separate call sites but share one trust point; they are not independent implementations. Later policy/DDL changes could still remove or alter the restrictive guard. |
| 5 | Existing ACL drift | The product proposal checks current effective privileges and fails closed before the DDL instead of broadly revoking unknown grants from existing `stockwise` objects. New schemas receive explicit revocations; postflight verifies the intended API surface. | Addressed in source. The effective ACL catalog checks have not been run, and unmodeled managed objects/privileges may require revision. |
| 6 | Owner default function privileges | The product proposal requires explicit global function-default hardening for all three function-owner roles, rejects PUBLIC or named-role EXECUTE defaults, grants by exact signatures, and postflights owners, `SECURITY DEFINER`, fixed `search_path`, and PUBLIC ACLs. | Addressed in source. The prerequisite's actual application and resulting defaults/ACLs are unknown until inspected in the intended database. |
| 7 | Provisioning roles and Supabase prerequisites | Added a separate review-only SQL proposal for `stockwise_auth_owner` and `stockwise_product_reader`, including restricted role attributes, exact direct membership checks, and narrowly described grants. | Partially addressed as a proposal only. PostgreSQL version, automatic creator-membership behavior/options, Auth schema ACLs, and grant authority must be verified on the intended target. The postflight aborts on an unexpected membership graph; it does not normalize one. |
| 8 | Unexpected membership roles | The RPC rejects null or unexpected membership roles before returning rows; the authorization branch no longer treats unknown roles as Viewer. | Addressed in source. Database execution and negative tests remain outstanding. |

## Latest independent-review remediation

| Finding | Source location | Correction/status |
| --- | --- | --- |
| Required database/schema authority was not explicit | `PRODUCT-READ-PROPOSAL.sql:119–145, 175–190, 870`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:129–140, 285–291, 365–378` | Added fail-closed checks for target-database CREATE on `stockwise_migrator`, absence of that privilege on protected/API roles, and grant authority for `stockwise` schema USAGE. These do not grant privileges. Target values remain unknown. |
| Role-attribute checks omitted REPLICATION/API administration flags | `PRODUCT-READ-PROPOSAL.sql:148–180, 833–853`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:119–127, 268–291, 339–363` | Added REPLICATION checks for StockWise roles and rejected SUPERUSER, CREATEROLE, CREATEDB, and REPLICATION on standard API roles. `service_role` may retain BYPASSRLS; `anon`, `authenticated`, and `authenticator` may not. `authenticator` may be LOGIN; the other three API roles may not. Not executed. |
| RPC/RLS use one shared membership helper | `PRODUCT-READ-PROPOSAL.sql:652–737, 739–809`; this review's “Static review and limitations” section | Clarified that multiple enforcement call sites share one authorization trust point. Focused review and negative tests remain required. |
| Membership lifecycle lacked a database audit control | `PRODUCT-READ-PROPOSAL.sql:45–49, 652–671`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:31–36`; this review's “Latest correction” section | Explicitly blocks membership creation, role changes, deactivation, deletion, and first-Owner provisioning until an approved audit control or independently verified privileged process exists. There is no membership-write endpoint. Privileged operators can still mutate the table; the block is operational, not enforced by this SQL. |
| Privileged operator/migrator path | `PRODUCT-READ-PROPOSAL.sql:18–33, 119–145, 739–809`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:7–36` | Explicitly states that trusted provisioning/migration operators can exercise privileged access outside the product RPC. No claim is made that the RPC technically prevents that access. |
| Actual Data API exposure and callable roles were not established | `PRODUCT-READ-PROPOSAL.sql:39–54`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:37–39`; this review's “Remaining assumptions and blockers” section | Requires independent target evidence for exposed schemas, callable roles, membership closure, and effective grants. The Dashboard configuration is not inspectable by these SQL files. |
| PostgreSQL/Auth/Data API behavior remains unverified | `PRODUCT-READ-PROPOSAL.sql:51–77`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:58–73`; historical artifacts cited below | Version, Supabase Auth grants/identity propagation, catalog behavior, and Data API behavior remain assumptions until verified in an approved isolated or hosted target. |
| Explicit global function-default hardening must cover each function owner | `PRODUCT-READ-PROPOSAL.sql:478–510`; `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:323–329, 708–722` | The product preflight now requires explicit hardening for the existing owner and both new function owners; the provisioning postflight checks the new owners. Effective target ACLs remain unverified. |
| Helper overload and PUBLIC EXECUTE checks were incomplete | `PRODUCT-READ-PROPOSAL.sql:1010–1069` | Added an exact one-function count and signature-resolution check for the private membership helper, and a catalog ACL check rejecting PUBLIC EXECUTE on either security function. Effective named-role access checks remain in place. Not executed. |
| Provisioning preflight/postflight assumed membership-pair uniqueness and did not verify the complete role-membership graph | `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:99–103, 167–246, 381–571`; `PRODUCT-READ-PROPOSAL.sql:141–390` | Revised both proposals to check grantor-specific `pg_auth_members` rows and `ADMIN`/`INHERIT`/`SET` options. The new role postflight checks the migrator's complete incoming set, rejects any membership granted by the migrator, verifies operator memberships, validates incoming edges to both new owner roles, and rejects outgoing/grantor edges involving them. These source checks are not executed. |

## Latest correction: role-membership catalog review

The source now distinguishes direct catalog membership edges from effective,
possibly transitive membership:

| Invariant | Source check | Limitation |
| --- | --- | --- |
| `stockwise_migrator` has exactly the three expected direct role memberships, each with `ADMIN=false`, `INHERIT=false`, `SET=true`, and the reviewed grantor; it grants no role memberships | `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:381–418, 505–510`; `PRODUCT-READ-PROPOSAL.sql:295–331, 205–210` | The checks reject extra roles, grantors, or option combinations and any row with `stockwise_migrator` as grantor. They have not been run against a database. |
| The non-superuser operator-to-migrator relation preserves both grantor-specific rows: automatic creator `ADMIN` only, and the explicit operator-granted `SET` only edge | `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:167–246, 513–571`; `PRODUCT-READ-PROPOSAL.sql:334–390` | The automatic row is correlated to the existing `stockwise_owner` creator row. The source does not identify or prove trust in that common grantor; target grantor identity/options remain unknown. |
| Each function-owner role has only the migrator's explicit `SET` edge and the creator's automatic `ADMIN`-only edge; neither protected role is a member or grantor for another role | `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:421–510` | The code correlates the creator row to the existing `stockwise_owner` creator grantor and aborts on other edges/options. This does not establish that the grantor is trusted; the new roles have not been tested on PostgreSQL. |

The proposals require PostgreSQL major version 17 and use its catalog fields
and membership options (`PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:68–75`;
`PRODUCT-READ-PROPOSAL.sql:66–70`). They accept any 17.x minor version; the
retained local report was from PostgreSQL 17.6. No current Supabase version was
checked.
`pg_auth_members` may contain multiple rows for the same `(roleid, member)` pair
when the grantors differ; the checks retain and validate grantor-specific rows.
`pg_has_role` is supplementary and does not establish the exact edge set. The
retained historical report documents two rows for the operator's membership in
`stockwise_migrator`, with different grantors and different options
(`db/deployment/README.md:72–99`;
`db/test-reports/prerequisites-postgresql17.md:103–118`). That historical run
covered the earlier deployment-role setup, not these modified proposals or the
current Supabase target. The new-role checks require creator rows to share the
grantor from the existing `stockwise_owner` creator edge and fail closed if they
differ. The source does not establish that this grantor is a trusted bootstrap
principal; its actual role identity and authority require independent review.
No membership behavior was verified in this task.

Membership creation, role changes, deactivation, deletion, and first-Owner
provisioning remain process-blocked only. The SQL does not install an audit
trigger or prevent a trusted owner/migrator from changing membership records;
see `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql:31–36` and
`PRODUCT-READ-PROPOSAL.sql:45–49`.

## Precision follow-up for the API projection

The read RPC proposal now serializes `NUMERIC` prices and `BIGINT` stock/
threshold quantities as decimal strings in its JSON response. This is needed
because ordinary JavaScript JSON numbers cannot represent every PostgreSQL
value exactly. The product service rejects money returned as a JSON number
rather than silently accepting a rounded value. These are source changes only;
the SQL has not been compiled or exercised on PostgreSQL.

## Source files

- `db/security-review/PRODUCT-READ-PROPOSAL.sql` — revised read-only product RPC
  proposal with role-closure/effective-ACL checks, restrictive RLS guards,
  unexpected-role rejection, default-privilege prerequisites, and postflight
  ownership/grant/policy checks.
- `db/security-review/PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql` — separate
  review-only provisioning proposal for the two additional non-login roles.
- `db/security-review/PRODUCT-READ-REVIEW.md` — this finding-by-finding report
  and the unresolved assumptions.

The inventory migration, existing deployment SQL, application code,
configuration, and secrets were not changed for this correction.

## Static review and limitations

Static review of the proposal source confirmed:

- The product RPC has one explicit four-argument signature and is granted to
  `authenticated` by that exact signature. The private helper is also checked
  for exactly one function/signature; the postflight rejects PUBLIC EXECUTE on
  either security function.
- The proposals now check database CREATE on the migrator, schema-USAGE grant
  authority for `stockwise_owner`, the required grant path for Auth references,
  explicit global function-default hardening for each function owner, and
  relevant owner/migrator/API role attributes including REPLICATION.
- `service_role` is the documented BYPASSRLS exception; it remains denied the
  proposed API/private schemas and RPC. `authenticator` may be LOGIN as the
  Data API connection role.
- The RPC and membership helper specify `SECURITY DEFINER` and the fixed path
  `pg_catalog, pg_temp`; referenced business/Auth objects are schema-qualified.
- The membership helper derives the identity from `auth.uid()` and requires an
  active company membership. The supplied company ID is only a selector. The
  RPC and RLS policies share this helper, so helper review is a critical
  authorization requirement rather than an independent second implementation.
- Product and balance rows are both constrained by `company_id`; the composite
  join matches both company and product IDs.
- Owner/Admin, Staff, and Viewer projections preserve the approved field
  matrix. Unknown roles are rejected.
- The four standard Supabase API roles receive no proposed direct access to
  membership internals or base product tables; only `authenticated` receives
  the exact RPC permission. Custom Data API roles and exposed schemas remain a
  target-environment check.
- The provisioning proposal does not grant API/runtime membership, login,
  `BYPASSRLS`, or product table access to the new roles.
- The provisioning postflight checks the full direct membership set of
  `stockwise_migrator`, rejects memberships granted by it, checks the direct
  operator edge/options, validates incoming membership edges to the new
  function-owner roles, and disallows those owner roles from being members or
  grantors. Creator rows are correlated to the existing owner-role creator
  grantor; trust in that principal remains an external review requirement.
  These are checks in source only.
- The privileged operator/migrator boundary remains explicit. Membership
  lifecycle changes and first-Owner provisioning are blocked by process until
  approved audit controls or independently verified privileged procedures exist.

These are properties of the written source, not results of SQL compilation,
PostgreSQL execution, or Supabase verification. The postflight blocks are
proposed database checks and have not been run.

## Remaining assumptions and blockers

Before any isolated database test or hosted execution:

1. Confirm the target server is PostgreSQL 17 and supports the explicit
   membership options. The preflights accept any 17.x minor, while the retained
   isolated report is specifically from 17.6; the hosted target version is
   unknown.
2. Verify that migration 0001 is installed exactly as expected: required tables,
   RLS enabled, expected ownership, and no unexpected existing policies.
3. Inspect the full target role graph, creator memberships/options, role
   attributes, effective grants, function ACLs, and default ACLs. Include every
   role that can be selected by the Data API, not only the four standard names.
   The proposal intentionally aborts rather than repairing unknown access.
   Independently verify every grantor-specific `pg_auth_members` row and option.
   Confirm that the common creator grantor is the approved trusted system role;
   the SQL correlates it across rows but does not prove its trust.
4. Verify the approved operator can assume `stockwise_migrator`, and that the
   migrator has exactly SET-only memberships in all three object-owner roles;
   verify its target-database CREATE and `stockwise_owner`'s schema-USAGE grant
   authority. The operator remains trusted and may administer role membership.
5. Verify `auth.users`, `auth.uid()`, Auth schema USAGE/REFERENCES/EXECUTE grant
   authority, and all effective Auth function ACLs. The role proposal aborts if
   the membership owner could execute additional functions in `auth`; do not
   silently revoke Supabase-managed privileges.
6. Review the membership-owner table's RLS bypass. Membership creation, role
   changes, deactivation, deletion, and first-Owner provisioning remain blocked
   until an approved audit control or independently verified privileged
   operational procedure exists. No application membership-write endpoint is
   authorized by this proposal.
7. Confirm Supabase Data API exposure separately: expose only `stockwise_api`;
   do not expose `stockwise` or `stockwise_private`. The SQL cannot prove or set
   the Dashboard's exposed-schema configuration. Independently inspect every
   currently exposed schema for views or functions that could reveal
   `stockwise` data; this proposal does not attempt to prove the absence of
   dynamic-SQL or cross-schema wrappers. Enumerate all callable roles, their
   role-membership closure, and effective grants, including custom JWT role
   claims, before deployment. The SQL proposals cannot verify these Dashboard
   settings or prove which custom roles can be selected by hosted requests.
8. Do not insert any membership, including the first Owner, until the audit
   control or privileged operational procedure has been approved and verified.
9. Obtain independent review of the final SQL and target-specific role, Auth,
   RLS, and Data API behavior before any real database changes.

No database tests, SQL execution, application tests, service restarts, network
requests, or Supabase access were performed for this revision.

## Source-verifiable findings versus target checks

**Source-verifiable:** the exact signatures, proposed function owners and
`SECURITY DEFINER` declarations, fixed search paths, explicit grant/revoke
statements, membership helper logic, company-filtered join, role-specific field
projection, direct `pg_auth_members` predicates, and the explicit operational
block on membership lifecycle changes.

**Not established from source:** current Data API exposed schemas; all callable
roles and custom JWT role claims; actual/transitive effective privileges and
ACLs; deployed PostgreSQL version and catalog rows; Supabase Auth object
ownership/grants and `auth.uid()` behavior; validation and propagation of the
same user JWT to the Data API; or whether hosted RLS sees the intended identity.
Those require an approved target-specific review and controlled evidence.

The product-read boundary remains RPC-only in the proposal: `authenticated`
receives the exact `list_products` function grant, while the function owner has
the underlying column access. Viewer field omission is performed by the RPC
projection, not by role-specific RLS. This remains safe only if target exposure
and grants prevent alternate base-table/view/function paths; that target
condition is unresolved.

## Required later checks (NOT RUN)

Only in a separately approved, genuinely isolated PostgreSQL 17 environment;
all cases below are **NOT RUN**:

- Verify role-creation automatic memberships and every direct
  `(roleid, member, grantor)` row and `ADMIN`/`INHERIT`/`SET` option. Include
  negative cases for an extra membership, an extra grantor row, changed options,
  mismatched creator grantors, membership granted by a protected function owner
  or migrator, and an unexpected role member; each must abort and roll back.
  Independently identify and approve the common creator grantor. Verify role
  attributes, the operator boundary, database CREATE, schema grant authority,
  and all target Data API role closures.
- Seed harmless synthetic companies, users, memberships, and products; test
  valid/forged/missing `auth.uid()` identity, same-company reads, cross-company
  denial, forged company selectors, pending/inactive/missing memberships, and
  rejection of unknown roles/statuses.
- Check Owner/Admin, Staff, and Viewer field projections and confirm sensitive
  product columns are absent where not permitted.
- Confirm `anon`, `service_role`, and `authenticator` cannot execute the RPC;
  `authenticated` can execute only the exact signature and has no direct base
  table, column, membership-table, helper-function, or private-schema access.
- Check every configured custom Data API role and exposed schema for inherited
  RPC access, direct privileges, views, or functions that could expose base data.
- Verify restrictive RLS still blocks rows if a future permissive policy is
  added, and confirm the RPC and RLS call the shared authorization helper with
  the intended identity/company scope.
- Verify SECURITY DEFINER owners, exact signatures/no overloads, `search_path`,
  owner function defaults, effective ACLs (including PUBLIC), and rollback on
  every failed preflight/postflight.
- Confirm trusted migration/provisioning access is isolated from request
  handling; test that ordinary API roles cannot assume deployment or owner roles.
- Confirm the target's Auth function ACLs and `auth.uid()` identity behavior.
  This requires an approved Supabase-like identity-aware test environment;
  local catalog checks alone cannot establish hosted JWT propagation.

These are proposed cases, not executable results. A passing local test would
not establish Dashboard Data API exposure settings or hosted Supabase behavior.

## Decision

**NOT READY FOR CONTROLLED-TEST PLANNING.** The revised source has not received
independent review or PostgreSQL execution. Target-specific role/catalog
semantics, Data API exposed schemas and callable roles, effective privileges,
Supabase Auth behavior, and JWT identity propagation remain unresolved.
Membership lifecycle changes and first-Owner provisioning also remain blocked
until an approved audit control or independently verified privileged process
exists. These source corrections and static inspection do not establish
readiness or authorize SQL execution, database setup, deployment, business-data
access, or endpoint implementation.
