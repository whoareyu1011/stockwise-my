# Product-read proposal correction review

**Status: review-only. No SQL was executed or tested.** The two SQL files below
are proposals, not installed database state. This document reports source
changes and static reasoning only; it does not attest that PostgreSQL accepts
the SQL or that the proposed checks pass in Supabase.

## Finding-by-finding remediation

| # | Review finding | Source correction | Status / remaining limitation |
| --- | --- | --- | --- |
| 1 | Effective privileges and role-membership closure | The product proposal computes transitive API-role membership and checks effective schema, relation, column, sequence, and function privileges before changes. It rejects protected-role reachability and verifies the intended grants afterward. | Addressed in source; target role graph and ACLs are unverified until the preflight/postflight are run in an approved isolated database. |
| 2 | Privileged deployment roles | Both proposals state that the migrator can `SET ROLE` into function owners and that the role-creating operator can administer memberships. The migrator/operator are trusted privileged identities, not an RPC-only boundary. | Explicitly documented, not technically prevented. Keep those credentials out of application requests; actual grants and credential handling remain target-specific and unverified. |
| 3 | Membership-owner RLS bypass and administration | Membership operations are not exposed through the API and are explicitly blocked until an approved audit control or independently verified privileged operational procedure exists. | The block is a process requirement, not a database-enforced audit trail. A trusted operator/migrator can still change or delete rows; no membership write or first-Owner procedure is approved here. |
| 4 | Permissive RLS policy composition | Each protected table gets a permissive reader policy plus a restrictive company-membership guard. Both the RPC and policies call the same active-membership helper and the RPC rejects roles outside Owner/Admin/Staff/Viewer. | Company checks are repeated at separate call sites but share one trust point; they are not independent implementations. Later policy/DDL changes could still remove or alter the restrictive guard. |
| 5 | Existing ACL drift | The product proposal checks current effective privileges and fails closed before the DDL instead of broadly revoking unknown grants from existing `stockwise` objects. New schemas receive explicit revocations; postflight verifies the intended API surface. | Addressed in source. The effective ACL catalog checks have not been run, and unmodeled managed objects/privileges may require revision. |
| 6 | Owner default function privileges | The product proposal requires the existing owner-default hardening prerequisite and rejects PUBLIC or named-role function EXECUTE defaults. Function grants use the exact RPC signature; postflight checks owners, `SECURITY DEFINER`, and fixed `search_path`. | Addressed in source. The prerequisite's actual application and the resulting defaults are unknown until inspected in the intended database. |
| 7 | Provisioning roles and Supabase prerequisites | Added a separate review-only SQL proposal for `stockwise_auth_owner` and `stockwise_product_reader`, including restricted role attributes, SET-only migrator memberships, and narrowly described grants. | Addressed as a proposal only. PostgreSQL version, role-creation behavior, Auth schema ACLs, and grant authority must be verified on the intended target. |
| 8 | Unexpected membership roles | The RPC rejects null or unexpected membership roles before returning rows; the authorization branch no longer treats unknown roles as Viewer. | Addressed in source. Database execution and negative tests remain outstanding. |

## Latest independent-review remediation

| Finding | Source location | Correction/status |
| --- | --- | --- |
| Required database/schema authority was not explicit | `PRODUCT-READ-PROPOSAL.sql` preflight and `PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql` preflight/postflight | Added fail-closed checks for target-database CREATE on `stockwise_migrator` and grant authority for `stockwise` schema USAGE. These do not grant privileges. The target values remain unknown. |
| Role-attribute checks omitted REPLICATION/API administration flags | Both SQL proposals' preflight/postflight role checks | Added REPLICATION checks for StockWise roles and rejected SUPERUSER, CREATEROLE, CREATEDB, and REPLICATION on the standard API roles. `service_role` may retain BYPASSRLS; `anon`, `authenticated`, and `authenticator` may not. Not executed. |
| RPC/RLS use one shared membership helper | Product proposal helper, RPC, and restrictive policies; this document's trust-point explanation | Corrected the description: multiple enforcement call sites share one authorization trust point. Focused independent review and negative tests remain required. |
| Membership lifecycle lacked a database audit control | Product proposal and role-provisioning comments; membership table | Explicitly blocks membership creation, role changes, deactivation, deletion, and first-Owner provisioning until an approved audit control or independently verified privileged process exists. There is no membership-write endpoint. Privileged operators can still mutate the table; the block is operational, not enforced by this SQL. |
| Privileged operator/migrator path | Both proposals' trust-boundary comments | Explicitly states that trusted provisioning/migration operators can exercise privileged access outside the product RPC. No claim is made that the RPC technically prevents that access. |
| Actual Data API exposure and callable roles were not established | Both proposal headers; target prerequisites below | Requires independent target evidence for exposed schemas, callable roles, membership closure, and effective grants. The Dashboard configuration is not inspectable by these SQL files. |
| PostgreSQL/Auth/Data API behavior remains unverified | Both proposals' version/Auth preflights and this document's target checklist | Version, Supabase Auth grants/identity propagation, catalog behavior, and Data API behavior remain assumptions until verified in an approved isolated or hosted target. |

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
  `authenticated` by that exact signature.
- The proposals now check database CREATE on the migrator, schema-USAGE grant
  authority for `stockwise_owner`, the required grant path for Auth references,
  and relevant owner/migrator/API role attributes including REPLICATION.
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
- The privileged operator/migrator boundary remains explicit. Membership
  lifecycle changes and first-Owner provisioning are blocked by process until
  approved audit controls or independently verified privileged procedures exist.

These are properties of the written source, not results of SQL compilation,
PostgreSQL execution, or Supabase verification. The postflight blocks are
proposed database checks and have not been run.

## Remaining assumptions and blockers

Before any isolated database test or hosted execution:

1. Confirm the target server is the reviewed PostgreSQL 17 version and supports
   the explicit role-membership options used by the role proposal.
2. Verify that migration 0001 is installed exactly as expected: required tables,
   RLS enabled, expected ownership, and no unexpected existing policies.
3. Inspect the full target role graph, creator memberships/options, role
   attributes, effective grants, function ACLs, and default ACLs. Include every
   role that can be selected by the Data API, not only the four standard names.
   The proposal intentionally aborts rather than repairing unknown access.
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
   claims, before deployment.
8. Do not insert any membership, including the first Owner, until the audit
   control or privileged operational procedure has been approved and verified.
9. Obtain independent review of the final SQL and target-specific role, Auth,
   RLS, and Data API behavior before any real database changes.

No database tests, SQL execution, application tests, service restarts, network
requests, or Supabase access were performed for this revision.

## Required later checks (NOT RUN)

Only in a separately approved, genuinely isolated PostgreSQL 17 environment;
all cases below are **NOT RUN**:

- Verify role-creation automatic memberships and all direct/transitive
  membership options; verify role attributes, the operator boundary, database
  CREATE, schema grant authority, and all target Data API role closures.
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
  owner function defaults, effective ACLs, and rollback on every failed
  preflight/postflight.
- Confirm trusted migration/provisioning access is isolated from request
  handling; test that ordinary API roles cannot assume deployment or owner roles.
- Confirm the target's Auth function ACLs and `auth.uid()` identity behavior.
  This requires an approved Supabase-like identity-aware test environment;
  local catalog checks alone cannot establish hosted JWT propagation.

These are proposed cases, not executable results. A passing local test would
not establish Dashboard Data API exposure settings or hosted Supabase behavior.
