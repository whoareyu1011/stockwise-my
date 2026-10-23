-- REVIEW-ONLY PROPOSAL. DO NOT EXECUTE.
--
-- Separate prerequisite proposal for PRODUCT-READ-PROPOSAL.sql.
-- This is not part of the existing deployment scripts and must not be run
-- against Supabase until independently reviewed and explicitly approved.
--
-- Intended order:
--   1. 0001_inventory.sql has been independently applied.
--   2. Existing deployment role prerequisites, including owner function
--      default-privilege hardening, have been approved and verified.
--   3. This proposal is separately reviewed and approved.
--   4. This is applied by a trusted provisioner.
--   5. PRODUCT-READ-PROPOSAL.sql is independently reviewed and separately
--      approved; it is not executed by application startup.
--
-- Trust boundary:
--   * stockwise_auth_owner owns the private membership table and SECURITY
--     DEFINER membership helper. As table owner it bypasses ordinary RLS.
--   * stockwise_product_reader owns the SECURITY DEFINER product RPC.
--   * stockwise_migrator is granted explicit SET-only membership in both
--     function-owner roles. The role-creating operator is an administrator who
--     may be able to change memberships; PostgreSQL's automatic creator
--     membership is target-version dependent and must be inspected. These
--     deployment identities are trusted and may access business data or
--     membership state; the RPC-only claim is not an effective isolation
--     boundary against them.
--   * Neither role is a login, neither has BYPASSRLS, and no Supabase API role
--     is granted membership in either role. No runtime credential is created.
--   * The provisioning operator and migrator remain privileged identities;
--     their access is not technically prevented by the RPC design.
--   * Membership creation, role changes, deactivation, deletion, and first-
--     Owner provisioning remain blocked until an approved audit control or
--     independently verified privileged operational procedure exists. No
--     application membership-write endpoint is in scope. This is an
--     operational stop condition, not a database-enforced block: the trusted
--     owner/migrator roles can still change membership rows.
--   * Before deployment, independently enumerate all exposed Data API schemas,
--     callable roles, their membership closures, and effective grants. The
--     Dashboard's exposed-schema setting cannot be verified by this SQL.
--
-- Exact role grants proposed here:
--   stockwise_migrator -> each owner role, SET only (no INHERIT, no ADMIN).
--   stockwise_auth_owner -> USAGE on stockwise/auth schemas; REFERENCES on
--     companies.id and auth.users.id; EXECUTE on auth.uid().
--   stockwise_product_reader -> no table grants here. The separate product
--     proposal grants only required SELECT columns and function/schema rights.
--   No grant is made to anon, authenticated, service_role, or authenticator.
--   The existing deployment file 02 must already grant stockwise_migrator
--     CREATE on the target database. This proposal verifies that prerequisite;
--     it does not grant it. Database CREATE allows schema creation throughout
--     the database, so the NOLOGIN migrator remains a privileged deployment role.
--     stockwise_owner and the API/object-owner roles do not need database CREATE.
--
-- Supabase API-role attribute assumptions checked below:
--   * No API role may be SUPERUSER, CREATEROLE, CREATEDB, or REPLICATION.
--   * service_role may have BYPASSRLS as Supabase's managed service role;
--     it is still denied the proposed schemas and RPC.
--   * anon, authenticated, and authenticator must not have BYPASSRLS.
--   * authenticator may be LOGIN because it is the Data API connection role.
--   * anon, authenticated, and service_role must not be LOGIN roles.
--
-- PostgreSQL version is a target prerequisite: membership option syntax below
-- requires a server supporting explicit SET/INHERIT role-membership options.
-- This proposal requires PostgreSQL 17 and inspects direct pg_auth_members rows
-- (roleid, member, grantor, admin_option, inherit_option, set_option). Effective
-- pg_has_role checks are supplementary; they do not replace exact edge checks.
-- Automatic creator-membership behavior/options remain target-dependent; the
-- postflight rejects any edge set/options other than those explicitly expected.
-- Supabase server version and managed Auth ACL behavior have not been checked.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
BEGIN
  IF current_user <> session_user THEN
    RAISE EXCEPTION 'Use the same directly authenticated operator for role creation and migration setup';
  END IF;
  IF current_user IN (
    'anon','authenticated','service_role','authenticator',
    'stockwise_owner','stockwise_migrator',
    'stockwise_auth_owner','stockwise_product_reader'
  ) OR session_user IN (
    'anon','authenticated','service_role','authenticator',
    'stockwise_owner','stockwise_migrator',
    'stockwise_auth_owner','stockwise_product_reader'
  ) THEN
    RAISE EXCEPTION 'Use a separately approved privileged provisioning identity';
  END IF;
  IF pg_catalog.current_setting('server_version_num')::integer / 10000 <> 17 THEN
    RAISE EXCEPTION 'This proposal requires an independently reviewed PostgreSQL 17 target';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = current_user AND (rolsuper OR rolcreaterole)
  ) THEN
    RAISE EXCEPTION 'Provisioner needs approved CREATEROLE authority';
  END IF;

  IF pg_catalog.to_regrole('stockwise_owner') IS NULL
     OR pg_catalog.to_regrole('stockwise_migrator') IS NULL
     OR pg_catalog.to_regclass('stockwise.companies') IS NULL
     OR pg_catalog.to_regclass('auth.users') IS NULL
     OR pg_catalog.to_regprocedure('auth.uid()') IS NULL THEN
    RAISE EXCEPTION 'Base migration and required Supabase Auth objects must exist';
  END IF;

  IF pg_catalog.to_regrole('stockwise_auth_owner') IS NOT NULL
     OR pg_catalog.to_regrole('stockwise_product_reader') IS NOT NULL THEN
    RAISE EXCEPTION 'A proposed role already exists; inspect rather than overwrite';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname IN ('stockwise_owner','stockwise_migrator')
      AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls
           OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit
           OR r.rolreplication)
  ) THEN
    RAISE EXCEPTION 'Existing StockWise roles do not match their restricted design';
  END IF;

  IF NOT pg_catalog.has_database_privilege(
       'stockwise_migrator',pg_catalog.current_database(),'CREATE') THEN
    RAISE EXCEPTION 'Existing deployment setup must grant target-database CREATE to stockwise_migrator';
  END IF;
  IF pg_catalog.has_database_privilege(
       'stockwise_owner',pg_catalog.current_database(),'CREATE') THEN
    RAISE EXCEPTION 'stockwise_owner must not have target-database CREATE';
  END IF;
  IF NOT pg_catalog.has_schema_privilege(
       'stockwise_owner','stockwise','USAGE WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'stockwise_owner must be able to grant stockwise schema USAGE';
  END IF;

  IF NOT pg_catalog.pg_has_role(session_user,'stockwise_owner','SET')
     OR NOT pg_catalog.pg_has_role(session_user,'stockwise_migrator','SET')
     OR NOT pg_catalog.pg_has_role('stockwise_migrator','stockwise_owner','SET') THEN
    RAISE EXCEPTION 'Provisioner and migrator must have the reviewed owner SET path';
  END IF;
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
  ) <> 1 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND (
        m.roleid <> pg_catalog.to_regrole('stockwise_owner')
        OR m.admin_option OR m.inherit_option OR NOT m.set_option
      )
  ) THEN
    RAISE EXCEPTION 'Existing migrator membership must be only SET access to stockwise_owner';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member <> pg_catalog.to_regrole(current_user)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member = pg_catalog.to_regrole(current_user)
      AND (NOT m.admin_option OR m.inherit_option OR NOT m.set_option)
  ) OR (
    NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = current_user AND rolsuper
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_auth_members AS m
      WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
        AND m.member = pg_catalog.to_regrole(current_user)
        AND m.admin_option
        AND NOT m.inherit_option
        AND m.set_option
    )
  ) THEN
    RAISE EXCEPTION 'Provisioner must be the sole approved migrator member with ADMIN, SET, and no INHERIT';
  END IF;

  IF NOT pg_catalog.has_table_privilege(
       'stockwise_owner','stockwise.companies','REFERENCES WITH GRANT OPTION')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_owner','stockwise','USAGE WITH GRANT OPTION')
     OR NOT pg_catalog.has_schema_privilege(
       current_user,'auth','USAGE WITH GRANT OPTION')
     OR NOT pg_catalog.has_table_privilege(
       current_user,'auth.users','REFERENCES WITH GRANT OPTION')
     OR NOT pg_catalog.has_function_privilege(
       current_user,'auth.uid()','EXECUTE WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'Provisioner lacks required grant authority; review target privileges';
  END IF;

  IF (
    SELECT count(*) FROM pg_catalog.pg_roles
    WHERE rolname IN ('anon','authenticated','service_role','authenticator')
  ) <> 4 THEN
    RAISE EXCEPTION 'Supabase API roles are missing; verify the target environment';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND (api.rolsuper OR api.rolcreaterole OR api.rolcreatedb
           OR api.rolreplication
           OR (api.rolname IN ('anon','authenticated','service_role')
               AND api.rolcanlogin))
  ) THEN
    RAISE EXCEPTION 'A Supabase API role has an unapproved administrative attribute';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS api
    WHERE api.rolname IN ('anon','authenticated','authenticator')
      AND api.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'Only the expected service_role may have BYPASSRLS';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND pg_catalog.has_database_privilege(
        api.oid,pg_catalog.current_database(),'CREATE')
  ) THEN
    RAISE EXCEPTION 'A Supabase API role has target-database CREATE';
  END IF;
END
$preflight$;

CREATE ROLE stockwise_auth_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE stockwise_product_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;

-- The creator's PostgreSQL role-creation membership is intentionally not
-- revoked. Its exact grantor/options are target-version dependent and must be
-- inspected. The creator is a trusted role administrator, not a runtime role.
GRANT stockwise_auth_owner TO stockwise_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT stockwise_product_reader TO stockwise_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

SET LOCAL ROLE stockwise_owner;
GRANT USAGE ON SCHEMA stockwise TO stockwise_auth_owner;
GRANT REFERENCES (id) ON TABLE stockwise.companies TO stockwise_auth_owner;
RESET ROLE;

GRANT USAGE ON SCHEMA auth TO stockwise_auth_owner;
GRANT REFERENCES (id) ON TABLE auth.users TO stockwise_auth_owner;
GRANT EXECUTE ON FUNCTION auth.uid() TO stockwise_auth_owner;

SET LOCAL ROLE stockwise_auth_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
RESET ROLE;

SET LOCAL ROLE stockwise_product_reader;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
RESET ROLE;

DO $postflight$
DECLARE
  v_object record;
  v_column record;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls
           OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit
           OR r.rolreplication)
  ) THEN
    RAISE EXCEPTION 'New owner roles have unexpected attributes';
  END IF;
  IF NOT pg_catalog.has_database_privilege(
       'stockwise_migrator',pg_catalog.current_database(),'CREATE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_owner','stockwise','USAGE WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'Postflight lost required migration or schema-grant authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND (api.rolsuper OR api.rolcreaterole OR api.rolcreatedb
           OR api.rolreplication
           OR (api.rolname IN ('anon','authenticated','service_role')
               AND api.rolcanlogin))
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS api
    WHERE api.rolname IN ('anon','authenticated','authenticator')
      AND api.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'Postflight found unapproved Supabase API role attributes';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname IN (
      'stockwise_owner','stockwise_auth_owner','stockwise_product_reader'
    )
      AND pg_catalog.has_database_privilege(
        r.oid,pg_catalog.current_database(),'CREATE')
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND pg_catalog.has_database_privilege(
        api.oid,pg_catalog.current_database(),'CREATE')
  ) THEN
    RAISE EXCEPTION 'Postflight found target-database CREATE on an owner or API role';
  END IF;

  -- Validate direct catalog edges, not merely transitive pg_has_role results.
  -- For PostgreSQL 17, pg_auth_members has one row per direct (member, roleid)
  -- edge and explicit ADMIN/INHERIT/SET options. The expected memberships
  -- granted to stockwise_migrator are exactly stockwise_owner,
  -- stockwise_auth_owner, and stockwise_product_reader, all SET-only.
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
  ) <> 3 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND m.roleid NOT IN (
        pg_catalog.to_regrole('stockwise_owner'),
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND (m.admin_option OR m.inherit_option OR NOT m.set_option)
  ) THEN
    RAISE EXCEPTION 'Migrator must have exactly three direct SET-only memberships and no others';
  END IF;

  -- Memberships granted TO the two new owner roles must consist only of the
  -- migrator's SET-only edge and, for a non-superuser creator, PostgreSQL's
  -- expected ADMIN-only creator edge. Any other member or option combination
  -- aborts. Superusers need no automatic creator membership.
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid IN (
      pg_catalog.to_regrole('stockwise_auth_owner'),
      pg_catalog.to_regrole('stockwise_product_reader')
    )
  ) <> 2 + CASE
       WHEN EXISTS (
         SELECT 1 FROM pg_catalog.pg_roles AS r
         WHERE r.rolname = session_user AND r.rolsuper
       ) THEN 0 ELSE 2 END
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.pg_auth_members AS m
       WHERE m.roleid IN (
         pg_catalog.to_regrole('stockwise_auth_owner'),
         pg_catalog.to_regrole('stockwise_product_reader')
       )
         AND NOT (
           (m.member = pg_catalog.to_regrole('stockwise_migrator')
            AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
           OR
           (m.member = pg_catalog.to_regrole(session_user)
            AND EXISTS (
              SELECT 1 FROM pg_catalog.pg_roles AS r
              WHERE r.rolname = session_user AND NOT r.rolsuper
            )
            AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
         )
     ) THEN
    RAISE EXCEPTION 'Unexpected direct membership granted to a function-owner role';
  END IF;

  -- A protected owner must not itself be a member of another role or grant
  -- role membership to anyone. Check both pg_auth_members directions and the
  -- grantor field; pg_has_role alone cannot prove these direct-edge invariants.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member IN (
      pg_catalog.to_regrole('stockwise_auth_owner'),
      pg_catalog.to_regrole('stockwise_product_reader')
    )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.grantor IN (
      pg_catalog.to_regrole('stockwise_auth_owner'),
      pg_catalog.to_regrole('stockwise_product_reader')
    )
  ) THEN
    RAISE EXCEPTION 'A function-owner role has an outgoing membership or is a membership grantor';
  END IF;

  -- Only the approved operator may be a direct member of the migrator role.
  -- A non-superuser operator must have exact ADMIN+SET, non-INHERIT options;
  -- a superuser may have no membership edge because superusers can assume it.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member <> pg_catalog.to_regrole(session_user)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member = pg_catalog.to_regrole(session_user)
      AND (NOT m.admin_option OR m.inherit_option OR NOT m.set_option)
  ) OR (
    NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles AS r
      WHERE r.rolname = session_user AND r.rolsuper
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_auth_members AS m
      WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
        AND m.member = pg_catalog.to_regrole(session_user)
        AND m.admin_option AND NOT m.inherit_option AND m.set_option
    )
  ) OR NOT pg_catalog.pg_has_role(
       session_user,'stockwise_migrator','SET') THEN
    RAISE EXCEPTION 'Migrator membership is not limited to the approved operator path';
  END IF;

  IF NOT pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','stockwise','USAGE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','auth','USAGE')
     OR NOT pg_catalog.has_column_privilege(
       'stockwise_auth_owner','stockwise.companies','id','REFERENCES')
     OR NOT pg_catalog.has_column_privilege(
       'stockwise_auth_owner','auth.users','id','REFERENCES')
     OR NOT pg_catalog.has_function_privilege(
       'stockwise_auth_owner','auth.uid()','EXECUTE') THEN
    RAISE EXCEPTION 'Required membership-helper privileges are missing';
  END IF;

  IF pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','auth.users','SELECT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','auth.users','SELECT')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','stockwise.companies','SELECT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','SELECT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.products','SELECT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.stock_balances','SELECT') THEN
    RAISE EXCEPTION 'Membership owner unexpectedly has business/Auth row read access';
  END IF;
  IF pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','INSERT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','UPDATE')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','DELETE')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','TRUNCATE')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','TRIGGER')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','stockwise.companies','INSERT')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','stockwise.companies','UPDATE')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','auth.users','INSERT')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','auth.users','UPDATE')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','auth.users','INSERT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','auth.users','UPDATE')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','auth.users','DELETE') THEN
    RAISE EXCEPTION 'Membership owner unexpectedly has data mutation privileges';
  END IF;

  -- Check effective access from direct grants, inherited memberships, and
  -- PUBLIC across both managed schemas. Only REFERENCES on the two FK target
  -- id columns is permitted; no row data access is intended.
  FOR v_object IN
    SELECT c.oid, c.relkind, n.nspname, c.relname
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname IN ('stockwise','auth')
  LOOP
    IF v_object.relkind = 'S' THEN
      IF pg_catalog.has_sequence_privilege(
           'stockwise_auth_owner',v_object.oid,'USAGE')
         OR pg_catalog.has_sequence_privilege(
           'stockwise_auth_owner',v_object.oid,'SELECT')
         OR pg_catalog.has_sequence_privilege(
           'stockwise_auth_owner',v_object.oid,'UPDATE') THEN
        RAISE EXCEPTION 'Unexpected membership-owner sequence access on %.%',
          v_object.nspname,v_object.relname;
      END IF;
    ELSIF v_object.relkind IN ('r','p','v','m','f') THEN
      IF pg_catalog.has_table_privilege(
           'stockwise_auth_owner',v_object.oid,'SELECT')
         OR pg_catalog.has_table_privilege(
           'stockwise_auth_owner',v_object.oid,'INSERT')
         OR pg_catalog.has_table_privilege(
           'stockwise_auth_owner',v_object.oid,'UPDATE')
         OR pg_catalog.has_table_privilege(
           'stockwise_auth_owner',v_object.oid,'DELETE')
         OR pg_catalog.has_table_privilege(
           'stockwise_auth_owner',v_object.oid,'TRUNCATE')
         OR pg_catalog.has_table_privilege(
           'stockwise_auth_owner',v_object.oid,'TRIGGER') THEN
        RAISE EXCEPTION 'Unexpected membership-owner relation access on %.%',
          v_object.nspname,v_object.relname;
      END IF;
      FOR v_column IN
        SELECT a.attname
        FROM pg_catalog.pg_attribute AS a
        WHERE a.attrelid = v_object.oid
          AND a.attnum > 0 AND NOT a.attisdropped
      LOOP
        IF pg_catalog.has_column_privilege(
             'stockwise_auth_owner',v_object.oid,v_column.attname,'SELECT')
           OR pg_catalog.has_column_privilege(
             'stockwise_auth_owner',v_object.oid,v_column.attname,'INSERT')
           OR pg_catalog.has_column_privilege(
             'stockwise_auth_owner',v_object.oid,v_column.attname,'UPDATE') THEN
          RAISE EXCEPTION 'Unexpected membership-owner column access on %.%.%',
            v_object.nspname,v_object.relname,v_column.attname;
        END IF;
        IF pg_catalog.has_column_privilege(
             'stockwise_auth_owner',v_object.oid,v_column.attname,'REFERENCES')
           AND NOT (
             v_column.attname = 'id'
             AND ((v_object.nspname = 'stockwise'
                   AND v_object.relname = 'companies')
                  OR (v_object.nspname = 'auth'
                      AND v_object.relname = 'users'))
           ) THEN
          RAISE EXCEPTION 'Unexpected membership-owner REFERENCES access on %.%.%',
            v_object.nspname,v_object.relname,v_column.attname;
        END IF;
      END LOOP;
    END IF;
  END LOOP;

  -- Schema USAGE can make every PUBLIC-executable auth function callable.
  -- Do not silently revoke Supabase-managed ACLs; abort for independent review.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname = 'auth'
      AND p.oid <> pg_catalog.to_regprocedure('auth.uid()')
      AND pg_catalog.has_function_privilege(
        'stockwise_auth_owner',p.oid,'EXECUTE')
  ) THEN
    RAISE EXCEPTION 'Auth owner can execute additional auth functions; review managed ACLs';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = m.roleid
    JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = m.member
    WHERE granted.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND member_role.rolname IN ('anon','authenticated','service_role','authenticator')
  ) THEN
    RAISE EXCEPTION 'A Supabase API role can assume a proposed owner role';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = m.roleid
    JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = m.member
    WHERE granted.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND member_role.rolname <> 'stockwise_migrator'
      AND (m.inherit_option OR m.set_option)
  ) THEN
    RAISE EXCEPTION 'Unexpected non-migrator role inherits or can SET an object-owner role';
  END IF;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND m.roleid IN (
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
  ) <> 2 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND m.roleid IN (
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
      AND (m.admin_option OR m.inherit_option OR NOT m.set_option)
  ) THEN
    RAISE EXCEPTION 'Migrator must have exactly the two proposed SET-only role edges';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = m.roleid
    JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = m.member
    WHERE granted.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND member_role.rolname <> 'stockwise_migrator'
      AND member_role.rolname <> session_user::text
  ) THEN
    RAISE EXCEPTION 'Unexpected role is a member of a proposed owner role';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = m.roleid
    WHERE granted.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND m.member = pg_catalog.to_regrole(session_user)
      AND (NOT m.admin_option OR m.inherit_option OR m.set_option)
  ) THEN
    RAISE EXCEPTION 'Operator creator membership differs from expected ADMIN-only behavior';
  END IF;

  IF EXISTS (
    SELECT required.role_oid
    FROM (VALUES
      (pg_catalog.to_regrole('stockwise_auth_owner')),
      (pg_catalog.to_regrole('stockwise_product_reader'))
    ) AS required(role_oid)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_default_acl AS d
      WHERE d.defaclrole = required.role_oid
        AND d.defaclnamespace = 0
        AND d.defaclobjtype = 'f'
    )
  ) THEN
    RAISE EXCEPTION 'Owner roles lack explicit global function-default hardening';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS d
    CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) AS a
    WHERE d.defaclrole IN (
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
      AND d.defaclobjtype = 'f'
      AND a.privilege_type = 'EXECUTE'
      AND a.grantee <> d.defaclrole
  ) THEN
    RAISE EXCEPTION 'Owner roles retain a PUBLIC or named-role function EXECUTE default';
  END IF;
END
$postflight$;

COMMIT;
