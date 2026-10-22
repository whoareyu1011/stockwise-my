# Runtime security prototype — actual isolated test report

## Outcome and boundaries

**Final fresh PostgreSQL 17.6 run: 51 grouped PASS, 0 FAIL.**
The new SQL compiled/committed and was exercised with real restricted LOGIN
sessions, synthetic identities and two synthetic companies. Nothing was
deployed and no Supabase connection, DATABASE_URL, real identity, business
record or provider service was used.

The unchanged prerequisite package and migration were installed first under
the same non-superuser/non-BYPASSRLS provisioner used in the preceding role
tests. The proposed runtime/verifier roles and grants existed **only inside
this disposable cluster**, with test-only login members. The existing
application has no authentication or tenant authorization implementation.

Source review included the unchanged inventory migration, three deployment
SQL files, deployment guide, server's current credential usage and both retained
reports: `db/test-reports/local-postgresql17.md` and
`db/test-reports/prerequisites-postgresql17.md`.

## Tested source hashes

| File | SHA-256 |
| --- | --- |
| runtime-boundary.sql | `485bc60de69c53f39815bab8e70dc95513de6f2631361351a82f02443b28315a` |
| verify-jwt.reference.cjs | `af9451311af4b29d8bf278702212ac8c595022ba545e177f167b34c1b07edc31` |
| transaction.reference.cjs | `c93f8a525557c9fc3326bb1dd01075a18bc217f6eee3e58b8963285fbb21a29d` |
| test-local.cjs | `2e4ba2b82284d6f196003ba3bc8919da07e8ebda64f83876320dc3d7f255eaf5` |
| unchanged 0001_inventory.sql | `b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0` |

## Environment

- 2026-10-22 UTC / 2026-10-23 Asia/Kuala_Lumpur.
- Existing PostgreSQL 17.6 and Node binaries; existing pg dependency. No install.
- Final fresh cluster `/tmp/stockwise-security-8D8Sm8hJ`, private Unix socket
  on port 6543; empty listen_addresses and no network database listener.
- Root/socket directories and socket permissions 0700. Local trust was confined
  to this private test cluster; host authentication rejected network clients.
  It is not the production authentication/TLS design.
- Database tools/Node test process used `env -i` and explicit local targets.
- JWT tests used process-local generated ES256 keys, not a live provider.
- Synthetic business data was written only inside the disposable cluster.
- Server was stopped after each run; all four cluster directories were removed.
  Final shutdown log confirmed `database system is shut down` before removal.
  No PostgreSQL test process remained afterward.

## Actual checks

| ID | Passed check |
| --- | --- |
| 01 | Original prerequisites and exact original migration install |
| 02 | Proposed security SQL compiles/commits |
| 03 | Synthetic two-company, identity and membership fixtures |
| 04 | Actual runtime/verifier sessions have no admin/BYPASSRLS flags |
| 05 | Anonymous runtime SELECT returns no rows; commands denied |
| 06 | Forged actor/company/JWT-claims GUCs cannot authenticate |
| 07 | Runtime cannot read auth tables, mint proofs or invoke internal authorization |
| 08 | Verifier cannot read business data or invoke business commands |
| 09 | Core helper execution, owner/migrator/verifier switching, schema CREATE and RLS-off escalation denied |
| 10 | Membership-derived enumeration and legitimate multi-company membership |
| 11 | Foreign company and mismatched order/company commands denied |
| 12 | Viewer posting denied; operator adjustment/reversal denied |
| 13 | Direct balance/order/product/ledger/membership writes denied |
| 14 | Multi-item posting, verified human actor audit and idempotent retry |
| 15 | All eight original tables RLS-filter cross-company rows |
| 16 | Old proof cannot replay after COMMIT or session-setting poisoning |
| 17 | Proof rejected on different backend |
| 18 | Expired proof removes read access and denies commands |
| 19 | REPEATABLE READ context fails closed |
| 20 | Membership revoked after proof issuance blocks reads, enumeration and retries |
| 21 | Identity/issuer disable invalidates existing context |
| 22 | Insufficient stock rolls back balance, ledger and command audit |
| 23 | Authorized reversal/retry commits with deferred constraints and audit |
| 24 | Admin adjustment; rollback undoes command/audit and proof cannot replay |
| 25 | Company-aware contact/product FKs reject cross-company links |
| 26 | Real concurrent revocation waits on command membership lock; later revocation blocks the next command |
| 27 | Repeated reuse of a one-client pool changes actors without tenant leakage |
| 28 | Ledger sums match balances, other company unchanged, verified audit immutable |
| 29 | Fake Supabase API roles receive no new schema access/membership |
| 30 | Eight new functions owner-owned/definer/fixed path; eight SELECT policies and thirteen RLS tables |
| 31 | Valid ES256 JWT produces only verified issuer/subject/expiry |
| 32–44 | JWT rejects wrong issuer/audience, expiry, future nbf/iat, excessive lifetime, service-role token, missing subject, none/HS256 confusion, unknown kid, attacker key URL and embedded key |
| 45 | Modified payload/forged signature rejected |
| 46 | Invalid/absent JWT never checks out a business connection |
| 47 | Complete Node JWT → proof → RLS reference ignores forged browser user/company fields |
| 48 | Node request error rolls back posting; next pooled actor isolated |
| 49 | After deliberate test-only DML grants, default-deny write RLS still prevents own-company and cross-company writes; grants revoked afterward |
| 50 | Proof expiry capped by JWT expiry, hash-only storage, unique identity binding per transaction |
| 51 | Shared verifier/runtime pool rejected before checkout |

Negative checks were successful because PostgreSQL rejected the operation, not
because the forbidden operation succeeded.

## Initial harness failures and corrections

Two early runs stopped at test-fixture errors:

1. **2 PASS, 1 FAIL**, SQLSTATE `42P08`:
   `inconsistent types deduced for parameter $1`.
   The fixture reused an untyped parameter as UUID and text in the same INSERT.
   Corrected the fixture to use `$1::uuid` and `($1::uuid)::text`.
2. **6 PASS, 1 FAIL**, SQLSTATE `42846`:
   `cannot cast type integer to xid8`.
   A negative permission probe used `1::xid8`, so parsing failed before ACL
   authorization. Corrected the test to use `'1'::xid8`, then observed the
   intended `42501` permission denial.

No security SQL or existing migration was weakened or changed to bypass either
error. Each failed cluster was stopped/removed. A fresh run then passed 48
checks. Three additional defense-in-depth checks and a shared-pool configuration
guard were added; the **final fresh full run passed all 51**.

Representative expected error codes:

- `AUTH_INVALID`: offline JWT validation denied.
- `42501`: denied permission or unavailable/unauthorized company context.
- `25001`: unsupported transaction isolation, deliberately fail closed.
- `23503`: invalid company-aware foreign key.
- `23505`: duplicate proof for the same backend/full transaction ID.
- `55P03`: concurrent membership revocation lock timeout, proving lock conflict.
- `P0001`: core insufficient-stock error / append-only audit guard.
- `SECURITY_CONFIGURATION`: deliberately shared connection pools rejected.

## Scope limits and unresolved risks

1. These are real local PostgreSQL/Node tests, **not** hosted Supabase, TLS or
   provider integration tests. Managed event triggers/default ACLs, exposed
   schemas, Realtime, hosted signing settings, custom login/pooler behavior and
   PostgreSQL 17.11 remain unverified.
2. No auth SDK, sign-in, refresh, invitation, account provisioning, actual JWKS
   rotation/network outage or provider session revocation was implemented.
   Offline JWT signature checks alone do not provide immediate provider logout
   revocation. Local company revocation is tested separately.
3. No HTTP routes or frontend changes. HTTP error mapping, cookie/CSRF handling,
   browser token storage, CORS, rate limiting and real middleware integration
   remain design requirements.
4. The existing web server still holds the administrative connection setting.
   It was not used or changed. Credential removal from internet-facing
   processes is mandatory before business data/APIs.
5. The trusted verifier can impersonate mapped users if compromised. Physical
   service/secret isolation is recommended; two pools in one compromised
   process do not solve that threat.
6. READ COMMITTED only. The proof uses a separately committed row, so repeatable
   snapshots are intentionally unsupported.
7. No unbounded stress/load, long-running transaction, crash/failover, proof
   cleanup or production pool-exhaustion tests. Proof issuance adds a write per
   request; operational limits and safe cleanup are required.
8. Concurrent revocation ordering was tested through two sessions and a lock
   timeout. Exhaustive concurrent role-change, order-kind races and all lock
   ordering combinations were not tested.
9. Existing seven definers remain owner-RLS bypasses and trusted internal code;
   their EXECUTE permissions must remain private. New direct editing/invite
   commands are not provided. Do not add blanket DML or helper grants.
10. The previous 58 inventory and 40 prerequisite suites were reviewed, not
    rerun in full. This suite reinstalls the unchanged package and tests the
    security/wrapper integration, including posting, reversal, rollback and
    actual deferred COMMIT checks.
11. The local prototype does not establish complete production tenant isolation.
    It must be separately reviewed, integrated and tested before that claim.

## Retained files and reproduction

All six new files are confined to `db/security-review/`:

- `DESIGN.md`
- `runtime-boundary.sql`
- `verify-jwt.reference.cjs`
- `transaction.reference.cjs`
- `test-local.cjs`
- `TEST-REPORT.md`

Original frontend/server, startup/dependency files, TLS certificate, migration,
deployment files and both retained reports were checksum-verified unchanged.
No existing Replit secrets were accessed, altered or added; no existing browser data was used.

For a separately approved reproduction, initialize a fresh PostgreSQL 17 cluster
with bootstrap user runner in a 0700 `/tmp/stockwise-security-<random>` directory,
its own data/socket directories, private local socket and no TCP listener.
Run `node db/security-review/test-local.cjs <that-directory>` under a scrubbed
environment while that cluster is running. The harness verifies the local
data directory, version, disabled network listener and original migration hash;
it has no DATABASE_URL fallback. Guarantee pg_ctl shutdown in the same shell,
retain sanitized results, then remove only that exact disposable directory.
Never run it against an existing or hosted database.

No startup hook or migration runner references these files. **Stop here for
review; exact target approval is required before any persistent deployment.**
