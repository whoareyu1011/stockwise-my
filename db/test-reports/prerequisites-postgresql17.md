# StockWise prerequisite SQL — actual local PostgreSQL test report

## Final outcome

**40 grouped checks passed; 0 failed on the corrected fresh-cluster run.**
All three new SQL files and the unchanged inventory migration were executed
against a fresh disposable PostgreSQL **17.6** cluster only.

The initial draft failed one real PostgreSQL permission test after twelve
passes. Its exact error and correction are disclosed below. The final results
are not static checks and are not Supabase deployment results.

## Source identity

| Tested file | SHA-256 |
| --- | --- |
| `db/deployment/01_create_roles.sql` | `a6e3dc5f5808c77272211a772c66291c9f2c29d26697789c95c06af3ee176ff9` |
| `db/deployment/02_grant_migration_access.sql` | `7d1552d4cb9905f2207eb0cb5e7e0b8f71bdfc29abb2bf120c45c8b1a1f725d6` |
| `db/deployment/03_harden_owner_function_defaults.sql` | `f8ce56ff614a6e5e6087cec8790d69dfd19b6a71075834ec20874576d5f58bd2` |
| `db/migrations/0001_inventory.sql` — unchanged | `b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0` |

## Environment and boundaries

- Date: 2026-10-22 UTC / 2026-10-23 Asia/Kuala_Lumpur.
- Existing PostgreSQL 17.6 binaries; no installation or paid/external resource.
- Final fresh cluster: `/tmp/stockwise-prereq-uDzzKzPX`.
- Private Unix socket only; empty listen_addresses, no TCP/public listener.
  The root/socket directories and socket had 0700 permissions.
- Temporary local trust authentication enabled actual test LOGIN sessions
  without passwords. This was confined to the private disposable cluster,
  not the application or Supabase TLS configuration.
- The provisioning client had actual session_user/current_user `sw_provisioner`,
  CREATEROLE and database ownership, but no superuser, BYPASSRLS, CREATEDB or
  inherited privileges. This verified permissions rather than masking them with
  a superuser session's unrestricted SET ROLE capability.
- The private harness was run under `env -i` and used explicit local socket,
  database and user settings. No DATABASE_URL or Supabase connection was used.
- No business records were inserted. Probe functions returned constants and
  were rolled back. Every application table remained empty.
- Existing local test-role flags were unchanged; expected temporary adversarial
  role/default-grant fixtures were rolled back. No application/runtime grants
  or application credentials were introduced.

## Passed checks

| ID | Check |
| --- | --- |
| T01 | Actual non-superuser/non-BYPASSRLS provisioning session |
| T02 | Permission script before roles exist fails closed |
| T03 | Original migration before owner creation fails preflight |
| T04 | Unprivileged role cannot provision roles |
| T05 | Existing role names rejected, not overwritten |
| T06 | Existing schema rejected |
| T07 | Both new roles have all seven restricted privilege/login/inheritance flags |
| T08 | Role-creation reapplication rejected |
| T09 | Creator cannot SET either new role before explicit switching grants |
| T10 | Changed owner LOGIN flag blocks permission setup |
| T11 | Unexpected owner membership blocks permission setup |
| T12 | Unexpected creator inheritance option blocks permission setup |
| T13 | Exact four membership rows and only migrator database CREATE verified |
| T14 | Permission setup safely repeatable before schema installation |
| T15 | Actual operator-to-migrator-to-owner switching succeeds |
| T16 | Actual unprivileged session cannot SET deployment roles |
| T17 | Owner and migrator direct logins denied |
| T18 | Post-migration hardening before 0001 rejected |
| T19 | Unprivileged caller cannot run hardening |
| T20 | Original migration rejects unsafe owner flags |
| T21 | Original migration rejects owner membership in any parent role |
| T22 | Original migration rejects API role membership in owner |
| T23 | Original migration rejects missing target-database CREATE |
| T24 | Early global default hardening triggers original clean-default preflight rejection |
| T25 | Original migration rejects missing owner membership |
| T26 | Exact unchanged migration executes under actual non-superuser migrator |
| T27 | Original migration rejects existing schema on reapplication |
| T28 | Permission script refuses to rewrite memberships after installation |
| T29 | Schema-specific PUBLIC function default grant blocks global-only hardening |
| T30 | Named-role function default grant blocks global-only hardening |
| T31 | Hardening creates owner-only global function default; other defaults and existing function ACLs unchanged |
| T32 | Hardening safely repeatable |
| T33 | Eight owner tables, fourteen owner functions, seven intended definers, fixed search paths, RLS enabled/not forced and zero policies |
| T34 | PUBLIC EXECUTE absent; five API/observer roles have no StockWise schema/table/function access or deployment memberships |
| T35 | Real unprivileged SELECT and command invocation denied |
| T36 | New owner-created SECURITY DEFINER function has no PUBLIC/API/observer execution access; owner can execute |
| T37 | Owner-global default also applies in a second private test schema |
| T38 | Other creator's built-in PUBLIC function default remains unchanged |
| T39 | Existing role flags and other creators' default privileges unchanged |
| T40 | All eight business tables empty; no probe function/schema retained |

All original migration preflight requirements were exercised: missing/unsafe
owner, owner-parent membership, API membership, missing operator membership,
missing database CREATE, custom owner defaults and existing schema.

## Failure found, exact error and correction

Initial run: **12 PASS, 1 FAIL**, stopping at T13. File 02 initially tried to
re-grant ADMIN to the role creator itself.

```text
SQLSTATE: 0LP01
ADMIN option cannot be granted back to your own grantor
```

PostgreSQL 17 had already created administrative creator memberships, granted
by the cluster bootstrap role. Trying to add an ADMIN self-grant was invalid.

Correction to the new draft only:

- Preserve the automatic creator ADMIN memberships with INHERIT/SET false.
- Do not re-grant ADMIN to the creator.
- Add a separate **ADMIN false, INHERIT false, SET true** migrator-to-operator
  membership, plus the same non-admin owner-to-migrator switching link.
- Validate membership rows by grantor/options rather than assuming there can
  only be one row for a role/member pair.

A local rollback-only probe established that exact correction and role switches.
The first cluster was stopped and removed. The entire forty-check suite then
ran from scratch in a second freshly initialized cluster and passed.
No change to 0001, a Supabase role or an application file was needed.

## Expected database rejections

Representative exact errors from successful negative checks:

| Code | Message |
| --- | --- |
| 42501 | permission denied to set role "stockwise_owner" |
| 42501 | permission denied to set role "stockwise_migrator" |
| 28000 | role "stockwise_owner" is not permitted to log in |
| 28000 | role "stockwise_migrator" is not permitted to log in |
| 42501 | permission denied for schema stockwise |
| P0001 | StockWise role name already exists; inspect, do not overwrite |
| P0001 | Unexpected deployment membership options; review explicit SET/INHERIT/ADMIN flags |
| P0001 | Verified migration 0001 must be installed before owner-default hardening |
| P0001 | Use a clean owner with no custom default privileges; review defaults separately |
| P0001 | Unexpected positive owner function defaults; review schema-specific or named-role grants |

Negative tests passing means PostgreSQL rejected the unsafe operation as
expected, not that the rejected statement succeeded.

## Untested and unresolved Supabase-specific requirements

- No connection to hosted PostgreSQL 17.11 was made. Managed restrictions,
  role-creation self-grant settings, bootstrap grantors and provisioning
  authority must be checked on the approved target.
- Managed event triggers/default ACLs and Data API/GraphQL exposure were not
  reproduced in this fresh plain PostgreSQL cluster.
- Confirm project identity, backups/recovery, Data API schema exclusion and
  Realtime publication scope before any separately authorized deployment.
- The previously observed app connection uses postgres with BYPASSRLS and
  pg_read_all_data. It was not changed and remains unsuitable for business-data
  runtime use, even when these private-schema grants are closed.
- Authentication, company membership authorization, RLS access policies and
  runtime credentials are not implemented or tested by this work. Tenant
  isolation must not be claimed as implemented.
- The earlier fifty-eight inventory/concurrency checks were not rerun here.
  Their unchanged-migration results remain in `local-postgresql17.md`; this
  report covers the new provisioning/default-permissions integration suite.
- Not every individual flag/ownership/version mismatch branch of the new
  preflight guards was tested. Roles were verified restricted; representative
  unsafe configurations were rejected.
- Tests do not authorize or establish production deployment readiness.

## Preservation, cleanup and manual next steps

Checksums verified the original frontend, both servers, startup/dependency
files, TLS certificate, existing database README/report and 0001 were unchanged.
No existing secrets or external roles/grants/objects were accessed or changed.

Both temporary clusters were stopped and removed. For the final cluster,
`pg_ctl -m fast -w stop` completed and the server log confirmed
`database system is shut down`; directory absence and no remaining PostgreSQL
process were verified after removal. Temporary test databases, role catalogs,
socket files, records and logs were discarded.

The retained files are the three draft SQL files, their deployment README,
the local-only test harness and this report. Review them first. Any Supabase
execution requires separate approval of the exact target and scripts; follow
the manual sequence in `db/deployment/README.md`, not application startup.
