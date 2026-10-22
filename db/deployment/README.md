# StockWise deployment prerequisites — prepared only

**No Supabase execution is authorized. These files are not loaded by the
application or startup scripts.** Only disposable local testing has occurred.

## Files and required order

| Order | File | Purpose |
| --- | --- | --- |
| 1 | `01_create_roles.sql` | Create two fresh, restricted, non-login roles atomically; reject existing names instead of changing them |
| 2 | `02_grant_migration_access.sql` | Give the migrator only target-database CREATE and non-admin SET access to the owner; allow the same approved operator to assume the migrator |
| 3 | `../migrations/0001_inventory.sql` | The unchanged, separately reviewed eight-table inventory migration |
| 4 | `03_harden_owner_function_defaults.sql` | Remove global default PUBLIC function EXECUTE for the dedicated owner, after 0001 has committed |

All three new SQL files target PostgreSQL 17 and have explicit transactions,
timeouts and fail-closed checks. No passwords, login credentials, runtime roles,
business API grants, extensions, managed-schema changes or data imports are
included.

## Approval and target checks before any external execution

1. Obtain explicit approval for the exact project, database, scripts/hashes,
   operator and changes. The current request approved local testing only.
2. Confirm backup/recovery availability and the recovery procedure.
3. Check the project Dashboard's Data API settings: `stockwise` must not be an
   exposed schema. Do not infer that setting from an empty SQL catalog result.
4. Reinspect only target metadata for drift: roles, membership grantors/options,
   default ACLs, event triggers, schema names and Realtime publication coverage.
5. Confirm the approved provisioning operator has CREATEROLE, administrative
   authority on the roles it creates, and database CREATE grant authority.
   These roles do not need superuser or BYPASSRLS.
6. Confirm PostgreSQL's role-creation self-grant settings produce the reviewed
   non-inheriting creator memberships. Unexpected options make file 02 stop.
   Do not alter managed settings or widen privileges to force it through.
7. Review Supabase-specific behavior on an explicitly approved hosted staging
   environment if required; no hosted staging was created or contacted here.
8. Use a verified administrator-controlled connection, with the existing TLS
   verification requirements. Never put credentials in these SQL files or chat.

These files contain no connection string. They operate on the current SQL
session's role/database. That does not itself verify the correct project:
project identity must be confirmed outside the scripts before execution.

## Proposed manual procedure, not permission to execute

Use the **same administrative current_user** for files 01 and 02. In an approved
manual SQL client, stop at the first error:

1. Review current user/database identity and the approved target.
2. Execute file 01.
3. Execute file 02.
4. Explicitly `SET ROLE stockwise_migrator`.
5. Execute the unchanged migration 0001. Its SET LOCAL ROLE creates application
   objects as `stockwise_owner`; COMMIT returns to the migrator.
6. Execute file 03. It uses transaction-local migrator/owner role switches.
7. `RESET ROLE` when done and verify catalog ownership, grants and defaults.

Each file owns its transaction: do not wrap this sequence in an outer BEGIN.
For psql use `-X` and `ON_ERROR_STOP=1`; connection details must be separately
reviewed and supplied securely. Do not use the application's admin credential
as the future business-data runtime identity.

File 01 and 0001 deliberately reject reapplication. File 02 is repeatable only
before the schema exists. File 03 is repeatable after a valid installation.
Global owner-default hardening must not run before 0001: its clean-owner-default
preflight would reject that state.

Files 01, 02 and 0001 commit separately. If a later step fails, earlier role
provisioning may remain. Stop and inspect; do not automatically DROP roles,
drop schemas, cascade cleanup or retry against another target.

## PostgreSQL 17 membership details

The tests used a real LOGIN provisioning session with CREATEROLE and database
ownership, but **without superuser or BYPASSRLS**. They did not merely SET ROLE
under a superuser session, which could mask role-switching permission failures.

For that non-superuser provisioning operator:

| Role granted | Member | ADMIN | INHERIT | SET | Origin |
| --- | --- | --- | --- | --- | --- |
| stockwise_owner | provisioning operator | true | false | false | PostgreSQL automatic creator grant |
| stockwise_migrator | provisioning operator | true | false | false | PostgreSQL automatic creator grant |
| stockwise_owner | stockwise_migrator | false | false | true | File 02 |
| stockwise_migrator | provisioning operator | false | false | true | File 02 |

The two migrator-to-operator rows have different grantors. This is normal in
PostgreSQL 17; do not collapse them in a security audit.

The creator's automatic ADMIN memberships remain because its dependent role
grants rely on that administrative authority. File 02 does not grant new ADMIN
authority to the operator or migrator. An initial draft trying to re-grant
ADMIN to the creator failed with SQLSTATE 0LP01 and was corrected before the
successful fresh-cluster run.

The migrator has no automatic inheritance, no login and no ADMIN option on the
owner. It must explicitly SET ROLE to create objects as the owner. It remains
a powerful deployment identity, not an application account. No API/runtime
role may be a member of either deployment role.

## Why file 03 has global scope

PostgreSQL's built-in global function default grants EXECUTE to PUBLIC.
`ALTER DEFAULT PRIVILEGES IN SCHEMA ... REVOKE` cannot subtract a global grant.
File 0001 still closes existing functions through its final explicit revokes.

File 03 changes only the function defaults of `stockwise_owner`. Its global
scope means that owner's future functions in **any** schema start private.
That owner must remain dedicated to StockWise. No other creator's defaults or
existing function ACLs are changed.

Positive schema-specific PUBLIC defaults or named-role function defaults could
defeat a global-only PUBLIC revoke. File 03 detects and rejects those instead
of claiming success or silently removing unrelated grants. Future privileged
migrations must still SET ROLE to the dedicated owner and audit every grant.

## Runtime security remains out of scope

These scripts do not authenticate users or authorize company memberships.
Composite foreign keys are consistency checks, not access-control policies.
The seven owner SECURITY DEFINER functions can bypass owner RLS and remain
private. Do not grant the current posting/reversal functions to runtime callers
without a separately designed and tested authorization boundary.

The previously inspected Supabase `postgres` application connection has
BYPASSRLS and inherited pg_read_all_data. Schema/function revocations do not
turn that connection into a safe runtime role. A separate, approved credential
and authorization design is required before real business data/APIs are used.
This work neither changes that secret nor removes that existing risk.

## Local test reproduction

Read `../test-reports/prerequisites-postgresql17.md` first. Reproduction creates
roles and databases and requires explicit approval for a fresh disposable
cluster; never run the harness against an existing server.

The retained harness is `../tests/prerequisites.local.cjs`. It takes exactly an
approved `/tmp/stockwise-prereq-<random>` directory argument, checks its data
directory and PostgreSQL version, and uses only its private Unix socket.
It has no URL/environment-based target fallback and enforces the original
0001 checksum.

Use existing PostgreSQL 17 tools to initialize that fresh cluster with bootstrap
user `runner`, a 0700 root/socket directory, empty listen_addresses, socket
permissions 0700 and port 6543. Test-only local trust authentication permits
actual non-superuser LOGIN test sessions without passwords; TCP is disabled.
This is not a recommendation for hosted/network authentication.

Start the cluster, run the harness under an environment scrubbed with `env -i`,
and guarantee `pg_ctl -m fast -w stop` in the same shell invocation. Preserve the
test report, verify shutdown and remove that exact temporary directory.
Do not change application workflows or install a permanent PostgreSQL service.
