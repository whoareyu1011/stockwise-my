# Phase 1 — offline, unmounted security foundation

## Status and boundaries

Implemented JavaScript security modules and synthetic tests only. **Not mounted,
not deployed, not connected to PostgreSQL or Supabase.** Authentication is not
enabled in the existing application. No live business-data API exists.

The only authorized external access was npm registry access to install official
`jose` **6.2.13**, pinned exactly in package.json/package-lock.json. It has **zero
runtime dependencies** and its published package has no lifecycle scripts.
Installation explicitly disabled scripts, audit and funding requests.
No custom JWT signature verification was written.

Existing frontend, server.js/server.py, routes, health-check behavior, startup,
TLS certificate, migrations, deployment SQL, planning documents and secrets
remain unchanged. The health endpoint was not called: it would contact Supabase.
No SQL was executed, including tests, preflight queries or role inspection.

## Files

Modified:

- `package.json`: exact jose dependency and `test:security:offline` script;
  existing `start` command unchanged.
- `package-lock.json`: jose package/integrity entry and root dependency only.

Added:

| File | Responsibility |
| --- | --- |
| server/security/errors.cjs | Fixed sanitized errors; no raw token/driver error propagation |
| server/security/config.cjs | Explicit trusted HTTPS issuer/audience/JWKS/algorithm configuration |
| server/security/verify-token.cjs | jose verification with trusted local public JWKS, minimal branded principal |
| server/security/session-status.cjs | Required trusted status adapter; missing/unavailable/expired/revoked status denies |
| server/security/permissions.cjs | Fixed four-role action predicates and own-sales-work restrictions |
| server/security/authorize.cjs | Fresh membership/resource checks, role ceilings and branded authorization context |
| server/security/pools.cjs | Distinct injected pool interfaces, no administrative fallback, bounded acquisition |
| server/security/transaction.cjs | Semantic transaction/proof/DB-authorization contract; no SQL implementation |
| tests/security/fixtures.cjs | Explicitly synthetic keys, tokens, statuses, memberships and transaction doubles |
| tests/security/security.test.cjs | Offline cryptographic, authorization, network-block and mock-transaction cases |
| tests/security/run-offline.py | Fail-closed Linux seccomp launcher, scrubbed child environment |
| db/security-review/PHASE-1.md | This implementation/limitations/test report |

No application module imports the new foundation. Test fixtures are never
imported by server/security modules. Importing the foundation does not construct
a database pool, read environment variables, start listeners or fetch keys.

## Verification and trust boundaries

### Tokens and keys

`createTokenVerifier` uses jose's jwtVerify and createLocalJWKSet. Trusted
startup configuration supplies issuer, audience, ES256 and/or RS256, and a
public JWKS. Default algorithm is ES256. Private JWK material, symmetric
algorithms, duplicate/unknown key IDs and missing trust configuration reject.
JWKS URL configuration is HTTPS, credential/query/fragment-free, same-origin
with issuer and on its standard JWKS path. **The URL is validated but never
fetched in Phase 1.** No token-supplied jku/x5u/jwk/crit is accepted.

Require signature, issuer/audience, authenticated token class, UUID subject and
session_id, integer exp/iat, valid nbf, non-future iat and bounded lifetime.
Anonymous/service-role tokens reject. Browser company/user/member-role/session
metadata is not authority. Returned principal contains only verified
issuer/subject/session ID/issue/expiry times and has an internal object brand;
JSON-shaped copies are not verified principals.

### Session status

No live status lookup is supplied. The default denies with SESSION_UNAVAILABLE.
An injected, trusted adapter must match issuer/subject/session, report active
and not revoked, and provide valid expiry/freshness timestamps. Attestations
are internally bound to the verified principal and expire no later than the
token/source/freshness boundary (maximum 30 seconds).

Synthetic fixture adapters are test doubles, **not** a provider or an active
session implementation. The generic adapter interface cannot itself prove that
a lookup is authoritative. A real source and its freshness/logout semantics
require separate design, implementation and hosted verification. **No real
Supabase session-status or immediate-revocation support is claimed.**

### Membership, roles and fields

Each authorization call rereads current membership using verified issuer/sub
and the requested company selector. Require exact company/identity mapping and
active identity/company/membership. Do not cache JWT membership claims.
Current resource ownership/kind/state comes from a trusted repository, not
browser-supplied order/creator/state objects. Missing repositories or failed
lookups deny; there is no default in-memory membership provider.

Owner/Admin may manage company drafts; Staff initially handles own-origin sales
work only, cannot post/modify posted orders, and has no product writes,
cost/history/audit/export/member-management privilege. Viewer has basic product/
quantity/status scope only. Owner can change existing Admin/Staff/Viewer
members; Admin only existing Staff/Viewer, not peers/Owner/itself. New membership
invitation/onboarding handlers are not implemented. Additional Owner/transfer/
reassignment actions deny. These are predicate tests, not business operations.

The returned projection label is **not a serializer, SQL column policy or
field-masking implementation**. Actual column allowlists, contact-link joins,
totals validation, line-parent integrity, cancellation execution, audit writing
and business APIs remain outside Phase 1. No existing database prototype has
been upgraded to these permissions.

### Database and pooling

Pools are injected interfaces, not pg constructors. No DATABASE_URL reference,
administrative credential lookup or fallback exists in the security modules.
Distinct pool objects and clients are checked; object separation is not proof
of actual PostgreSQL login privileges.

The runner requires all semantic adapter operations; none has a production
implementation here:

1. Verify token and current session before acquisition.
2. Begin READ COMMITTED with future server-side timeouts; obtain actual PID/full
   transaction ID from that connection.
3. Separate verifier autocommit issues a proof bound to identity/session/PID/xid
   and short expiry; activate it transaction-locally on runtime connection.
4. Read current authorization through a transaction-bound repository.
5. Require independent database authorization matching identity, company,
   session, role, action, resource/kind/target, PID and xid before invoking work.
6. Commit or roll back, reset context and release; discard broken connections.
   Pool acquisition times out and destroys late arrivals. Commit uncertainty
   raises COMMIT_UNCERTAIN without automatic retry.

Mock adapters echo/check contract data only. Their success is **not evidence
that PostgreSQL verified anything**. A real implementation must enforce current
authorization inside every privileged SQL entry point, not simply echo Node's
context or trust user-ID GUCs. It must implement actual transaction-local proofs,
timeouts, cancellation, concurrency and cleanup under restricted login sessions.
Only acquisition timeout is implemented here; full query/request deadlines and
cancellation remain an integration requirement.

The live health pool still uses administrative DATABASE_URL. It was untouched,
not reused or tested. Actual credential/process separation is **not achieved**
by these modules: before live wiring, remove administrative credentials from
internet-facing request processes using a separately approved health-check/
deployment-process arrangement.

## Actual commands and results

The package helper rejected the --ignore-scripts token before installation.
The explicit npm command below was then used to preserve the approved safety
flags; no lifecycle scripts were run:

```sh
npm install --ignore-scripts --registry=https://registry.npmjs.org --no-audit --no-fund --save-exact jose@latest
```

Result: `added 1 package`; jose 6.2.13, zero additional dependencies.
Existing locked dependencies were not changed. No audit/network scan was run.

Commands used for offline testing/verification:

```sh
npm run test:security:offline
python3 tests/security/run-offline.py
for file in server/security/*.cjs tests/security/*.cjs; do node --check "$file" || exit 1; done
git diff --check
```

The final combined syntax/test command ran the syntax loop followed by the
Python launcher. Node.js version: 20.20.0.

| Run | Actual result |
| --- | --- |
| Initial guarded suite | 189 PASS, 2 FAIL out of 191 including parent groups: UDP denial emitted uncaught `Error: bind EPERM 0.0.0.0`, also failing its parent group |
| Following harness edit | Parse failure: `SyntaxError: Unexpected identifier 'f'` from await inside a non-async test callback; 0 PASS, 1 FAIL |
| Final corrected syntax + guarded suite | **196 tests/subtests PASS, 0 FAIL, 0 skipped/cancelled/todo**; includes parent group tests; 424.234821 ms reported test duration |

Both failures were test-harness defects. The UDP listener now captures the
expected EPERM event; the callback is async. The network filter/security checks
were not relaxed. Original results are disclosed, not described as passes.

Test coverage: ES256/RS256 jose signatures; invalid issuer/audience/time/session/
class/key/token headers; minimum branded identities; unavailable/stale/revoked/
mismatched synthetic statuses; forged company/role claims; fresh memberships;
role changes/revocation; four-role predicates; own/other-company/other-creator
drafts; read-only posted work; membership ceilings; no administrative fallback;
mock proof ordering/binding; independent mock DB denial; rollback/reset/
uncertain commit and pool timeout/late-release behavior.

### Network isolation

Linux network namespaces were unavailable (`unshare -n`: Operation not
permitted). Tests instead ran beneath a libseccomp kernel filter, installed
before Node starts and inherited by descendants. It blocks socket creation,
connect/bind/listen/accept, network send syscalls and io_uring setup. If the
filter cannot load, the launcher exits without running tests.

Tests observed EPERM for TCP/TLS/UDP/fetch attempts to numeric loopback targets;
a child process inherited the block. No remote destination was needed to test
denial. Inherited descriptors above stderr are closed and the Node child gets
only explicit PATH/TZ, not copied workspace secrets.

This filter applies to the test process tree, not the live server or entire
workspace. It is not a filesystem sandbox. Test code uses synthetic data only.

## Still blocked / untested

- Actual project signing configuration, trusted keys/rotation and hosted JWTs.
- Authoritative session status, real logout/revocation and recovery semantics.
- PostgreSQL schema, RLS, column/EXECUTE grants, function ownership/default ACLs,
  restricted LOGIN credentials and pooler behavior. No database test ran.
- Revised security SQL must be prepared/reviewed separately; never deploy the
  historical broad SELECT/Operator runtime prototype unchanged.
- Non-owner disclosure-tier readers/writers and private owner-definer exceptions
  require actual least-privilege and direct-SQL negative tests.
- Database proofs, membership/resource joins, lock races, ledger/deferred
  integrity, real rollback and server-side deadlines. Mock tests prove no SQL.
- Production credential/process isolation and replacement/separation of the
  administrative health-check pool.
- Request parsing, HTTP middleware/routes, login UI, CORS/CSRF/rate limits,
  data-field projection, onboarding, audit persistence and all business APIs.

No endpoint, login flow, schema or environment value was added. Do not infer
production tenant isolation from these tests. **Stop after Phase 1.** Database
setup/tests, real adapters, provider access, live wiring and deployment each
require separately scoped explicit approval.
