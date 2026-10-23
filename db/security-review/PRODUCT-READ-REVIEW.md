# Product-read proposal correction review

**Status: review-only. No SQL was executed.** The two SQL files below are
proposals, not installed database state. This document reports source changes
and static reasoning only; it does not attest that PostgreSQL accepts the SQL
or that the proposed checks pass in Supabase.

## Finding-by-finding remediation

| # | Review finding | Source correction | Status / remaining limitation |
| --- | --- | --- | --- |
| 1 | Effective privileges and role-membership closure | The product proposal computes transitive API-role membership and checks effective schema, relation, column, sequence, and function privileges before changes. It rejects protected-role reachability and verifies the intended grants afterward. | Addressed in source; target role graph and ACLs are unverified until the preflight/postflight are run in an approved isolated database. |
| 2 | Privileged deployment roles | Both proposals state that the migrator can `SET ROLE` into function owners and that the role-creating operator can administer memberships. The migrator/operator are trusted privileged identities, not an RPC-only boundary. | Addressed in documentation and preflight design. Their actual grants and credential handling remain target-specific and unverified. |
| 3 | Membership-owner RLS bypass and administration | The membership table remains private and has no API writes. A proposed manual membership change process requires verified identity/company, an approved change record, captured before/after state and operator evidence, and independent second-person verification. No first-owner self-service is proposed. | Partially addressed: this is an operational proposal, not a database-enforced audit trail. Membership writes must remain blocked until an independently approved, tamper-resistant audit mechanism is chosen. |
| 4 | Permissive RLS policy composition | Each protected table gets a permissive reader policy plus a restrictive company-membership guard. The RPC independently checks the active membership and rejects roles outside Owner/Admin/Staff/Viewer. | Addressed in source. Later policy/DDL changes could still remove or alter the restrictive guard; ongoing drift monitoring and review are not implemented. |
| 5 | Existing ACL drift | The product proposal checks current effective privileges and fails closed before the DDL instead of broadly revoking unknown grants from existing `stockwise` objects. New schemas receive explicit revocations; postflight verifies the intended API surface. | Addressed in source. The effective ACL catalog checks have not been run, and unmodeled managed objects/privileges may require revision. |
| 6 | Owner default function privileges | The product proposal requires the existing owner-default hardening prerequisite and rejects PUBLIC or named-role function EXECUTE defaults. Function grants use the exact RPC signature; postflight checks owners, `SECURITY DEFINER`, and fixed `search_path`. | Addressed in source. The prerequisite's actual application and the resulting defaults are unknown until inspected in the intended database. |
| 7 | Provisioning roles and Supabase prerequisites | Added a separate review-only SQL proposal for `stockwise_auth_owner` and `stockwise_product_reader`, including restricted role attributes, SET-only migrator memberships, and narrowly described grants. | Addressed as a proposal only. PostgreSQL version, role-creation behavior, Auth schema ACLs, and grant authority must be verified on the intended target. |
| 8 | Unexpected membership roles | The RPC rejects null or unexpected membership roles before returning rows; the authorization branch no longer treats unknown roles as Viewer. | Addressed in source. Database execution and negative tests remain outstanding. |

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
- The RPC and membership helper specify `SECURITY DEFINER` and the fixed path
  `pg_catalog, pg_temp`; referenced business/Auth objects are schema-qualified.
- The membership helper derives the identity from `auth.uid()` and requires an
  active company membership. The supplied company ID is only a selector; the
  helper and RLS policies independently authorize it.
- Product and balance rows are both constrained by `company_id`; the composite
  join matches both company and product IDs.
- Owner/Admin, Staff, and Viewer projections preserve the approved field
  matrix. Unknown roles are rejected.
- API roles receive no proposed direct access to membership internals or base
  product tables; only `authenticated` receives the exact RPC permission.
- The provisioning proposal does not grant API/runtime membership, login,
  `BYPASSRLS`, or product table access to the new roles.

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
   attributes, effective grants, function ACLs, and default ACLs. The proposal
   intentionally aborts rather than repairing unknown access.
4. Verify the approved operator can assume `stockwise_migrator`, and that the
   migrator has exactly SET-only memberships in all three object-owner roles.
   The operator remains trusted and may administer role membership.
5. Verify `auth.users`, `auth.uid()`, Auth schema USAGE/REFERENCES/EXECUTE grant
   authority, and all effective Auth function ACLs. The role proposal aborts if
   the membership owner could execute additional functions in `auth`; do not
   silently revoke Supabase-managed privileges.
6. Review the membership-owner table's RLS bypass. The proposed second-person
   procedure is not an enforced database audit mechanism, so membership writes
   must not be exposed until a tamper-resistant audit process is approved.
7. Confirm Supabase Data API exposure separately: expose only `stockwise_api`;
   do not expose `stockwise` or `stockwise_private`. The SQL cannot prove or set
   the Dashboard's exposed-schema configuration. Independently inspect every
   currently exposed schema for views or functions that could reveal
   `stockwise` data; this proposal does not attempt to prove the absence of
   dynamic-SQL or cross-schema wrappers.
8. Approve the first-owner provisioning procedure and the handling of role
   changes/deactivation before inserting any membership.
9. Obtain independent review of the final SQL and the target-specific role,
   Auth, RLS, and Data API behavior before any real database changes.

No database tests, SQL execution, application tests, service restarts, network
requests, or Supabase access were performed for this revision.

## Required later checks (NOT RUN)

Only in a separately approved, genuinely isolated PostgreSQL 17 environment:

- Verify role-creation automatic memberships and all direct/transitive
  membership options; confirm only the migrator can `SET` to the three
  object-owner roles, apart from the documented administrator boundary.
- Seed harmless synthetic companies, users, memberships, and products; test
  same-company reads, cross-company denial, forged company selectors, pending
  and inactive membership denial, and rejection of unknown roles.
- Check Owner/Admin, Staff, and Viewer field projections and confirm sensitive
  product columns are absent where not permitted.
- Confirm `anon`, `service_role`, and `authenticator` cannot execute the RPC;
  `authenticated` can execute only the exact signature and has no direct base
  table, column, membership-table, helper-function, or private-schema access.
- Verify restrictive RLS still blocks rows if a future permissive policy is
  added, while the RPC's independent membership check continues to deny
  cross-company access.
- Verify SECURITY DEFINER owners, exact signatures/no overloads, `search_path`,
  owner function defaults, effective ACLs, and rollback on every failed
  preflight/postflight.
- Confirm the target's Auth function ACLs and `auth.uid()` identity behavior.
  This requires an approved Supabase-like identity-aware test environment;
  local catalog checks alone cannot establish hosted JWT propagation.

These are proposed cases, not executable results. A passing local test would
not establish Dashboard Data API exposure settings or hosted Supabase behavior.
