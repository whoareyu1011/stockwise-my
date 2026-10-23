-- REVIEW-ONLY PROPOSAL. DO NOT EXECUTE.
--
-- Purpose:
--   Add company membership and a read-only, role-aware product RPC for the
--   Supabase Data API. This is separate from 0001_inventory.sql and is not
--   loaded by application startup or deployment scripts.
--
-- Intended request path:
--   Supabase Auth JWT -> Express verification -> request-scoped Data API client
--   forwarding the same JWT -> this RPC -> current membership + RLS.
--
-- This draft assumes 0001_inventory.sql was separately reviewed and applied.
-- It deliberately does not create login roles, set Data API exposure, provision
-- the first Owner, implement invitations, or configure authentication.
-- It does not provision or authorize any application credential. Do not use
-- the existing administrative DATABASE_URL as a business-request fallback.
--
-- Required separately approved prerequisites:
--   * NOLOGIN, NOBYPASSRLS roles stockwise_auth_owner and
--     stockwise_product_reader. Only stockwise_migrator is granted an explicit
--     SET path into them; the provisioning operator remains a trusted role
--     administrator who may be able to change role membership.
--   * Run this transaction with current_user set to stockwise_migrator, after
--     the separately approved operator explicitly SET ROLE stockwise_migrator.
--   * stockwise_auth_owner has only the approved REFERENCES/EXECUTE access
--     required for stockwise.companies, auth.users, and auth.uid().
--   * Neither function-owner role has login, BYPASSRLS, or membership in any
--     other role. The provisioner/migrator can SET into these roles and is
--     therefore a trusted database administrator with potential access to
--     business data and membership records. These roles are not RPC-only.
--   * stockwise_migrator must have CREATE on the target database to create the
--     two schemas. stockwise_owner must be able to grant USAGE on stockwise.
--     These broad deployment capabilities are not business-request privileges.
--   * API roles may not be SUPERUSER, CREATEROLE, CREATEDB, or REPLICATION.
--     Supabase service_role may retain its managed BYPASSRLS attribute, but is
--     denied the proposed schemas and function; other API roles must not bypass RLS.
--     authenticator may be LOGIN as the Data API connection role.
--     anon, authenticated, and service_role must be NOLOGIN.
--   * Require Dashboard configuration to expose only stockwise_api; this is
--     not verifiable from this SQL session and remains an unverified prerequisite.
--   * Independently enumerate every exposed Data API schema, callable role,
--     role-membership path, and effective grant. The Dashboard configuration
--     and custom claimable roles cannot be proven from this SQL session alone.
--
-- Membership writes are not exposed through the API. Membership creation,
-- role changes, deactivation, deletion, and first-Owner provisioning remain
-- blocked until an approved audit control or independently verified privileged
-- operational procedure exists. No membership-write API is proposed.
-- "Never DELETE" is a process restriction only; this SQL does not enforce it.
--
-- Static source review can inspect the SQL text and signatures only. Current
-- role closure, effective ACLs/default ACLs, object ownership, policy catalogs,
-- Supabase Auth behavior, and Data API exposed-schema settings require
-- inspection of the intended database; none is established by this proposal.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
DECLARE
  v_role text;
  v_api_role record;
  v_object record;
  v_column record;
BEGIN
  IF pg_catalog.current_setting('server_version_num')::integer / 10000 <> 17 THEN
    RAISE EXCEPTION 'This review-only proposal requires a separately verified PostgreSQL 17 target';
  END IF;
  IF pg_catalog.to_regclass('stockwise.companies') IS NULL
     OR pg_catalog.to_regclass('stockwise.products') IS NULL
     OR pg_catalog.to_regclass('stockwise.stock_balances') IS NULL THEN
    RAISE EXCEPTION '0001 inventory tables are required; inspect migration state';
  END IF;
  IF pg_catalog.to_regclass('auth.users') IS NULL
     OR pg_catalog.to_regprocedure('auth.uid()') IS NULL THEN
    RAISE EXCEPTION 'Supabase Auth users and auth.uid() are required';
  END IF;
  IF pg_catalog.to_regnamespace('stockwise_private') IS NOT NULL
     OR pg_catalog.to_regnamespace('stockwise_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Proposed schemas already exist; inspect state, do not overwrite';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    WHERE c.oid = pg_catalog.to_regclass('stockwise.products')
      AND c.relrowsecurity
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    WHERE c.oid = pg_catalog.to_regclass('stockwise.stock_balances')
      AND c.relrowsecurity
  ) THEN
    RAISE EXCEPTION 'RLS must already be enabled on products and stock_balances';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_policy p
    WHERE p.polrelid IN (
      pg_catalog.to_regclass('stockwise.products'),
      pg_catalog.to_regclass('stockwise.stock_balances')
    )
  ) THEN
    RAISE EXCEPTION 'Existing product/balance policies require independent review';
  END IF;

  FOREACH v_role IN ARRAY ARRAY[
    'stockwise_migrator',
    'stockwise_owner',
    'stockwise_auth_owner',
    'stockwise_product_reader',
    'anon',
    'authenticated',
    'service_role',
    'authenticator'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      RAISE EXCEPTION 'Required role % is missing', v_role;
    END IF;
  END LOOP;

  IF current_user <> 'stockwise_migrator'
     OR NOT pg_catalog.pg_has_role(current_user, 'stockwise_owner', 'SET')
     OR NOT pg_catalog.pg_has_role(current_user, 'stockwise_auth_owner', 'SET')
     OR NOT pg_catalog.pg_has_role(current_user, 'stockwise_product_reader', 'SET')
     OR NOT pg_catalog.pg_has_role(session_user, 'stockwise_owner', 'SET')
     OR NOT pg_catalog.pg_has_role(session_user, 'stockwise_auth_owner', 'SET')
     OR NOT pg_catalog.pg_has_role(session_user, 'stockwise_product_reader', 'SET') THEN
    RAISE EXCEPTION 'Run as stockwise_migrator with the reviewed SET paths';
  END IF;
  IF NOT pg_catalog.has_database_privilege(
       current_user,pg_catalog.current_database(),'CREATE') THEN
    RAISE EXCEPTION 'stockwise_migrator needs approved CREATE on the target database';
  END IF;
  IF NOT pg_catalog.has_schema_privilege(
       'stockwise_owner','stockwise','USAGE WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'stockwise_owner must be able to grant stockwise schema USAGE';
  END IF;
  IF session_user IN ('anon','authenticated','service_role','authenticator',
                      'stockwise_owner','stockwise_migrator',
                      'stockwise_auth_owner','stockwise_product_reader') THEN
    RAISE EXCEPTION 'Use the separately approved privileged deployment identity, not an API or object-owner role';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS operator_role
    WHERE operator_role.rolname = session_user AND operator_role.rolsuper
  ) THEN
    RAISE EXCEPTION 'Use the reviewed non-superuser deployment operator';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles r
    WHERE r.rolname IN ('stockwise_owner','stockwise_auth_owner','stockwise_product_reader')
      AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb
           OR r.rolcreaterole OR r.rolinherit OR r.rolreplication)
  ) THEN
    RAISE EXCEPTION 'Object-owner roles must be restricted NOLOGIN/NOBYPASS roles';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles r
    WHERE r.rolname = 'stockwise_migrator'
      AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb
           OR r.rolcreaterole OR r.rolinherit OR r.rolreplication)
  ) THEN
    RAISE EXCEPTION 'stockwise_migrator must remain a restricted NOLOGIN role';
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
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname IN (
      'stockwise_owner','stockwise_auth_owner','stockwise_product_reader',
      'anon','authenticated','service_role','authenticator'
    )
      AND pg_catalog.has_database_privilege(
        r.oid,pg_catalog.current_database(),'CREATE')
  ) THEN
    RAISE EXCEPTION 'A protected or API role has unexpected target-database CREATE';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles target ON target.oid = m.member
    WHERE target.rolname IN ('stockwise_owner','stockwise_auth_owner','stockwise_product_reader')
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles grantor ON grantor.oid = m.grantor
    WHERE grantor.rolname IN ('stockwise_owner','stockwise_auth_owner','stockwise_product_reader')
  ) THEN
    RAISE EXCEPTION 'Object-owner roles must not be members or membership grantors';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.grantor = pg_catalog.to_regrole('stockwise_migrator')
  ) THEN
    RAISE EXCEPTION 'stockwise_migrator must not grant memberships to other roles';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
    JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
    WHERE granted.rolname IN ('stockwise_owner','stockwise_auth_owner','stockwise_product_reader')
      AND member_role.rolname IN ('anon','authenticated','service_role','authenticator')
  ) THEN
    RAISE EXCEPTION 'Supabase API roles must not be members of object-owner roles';
  END IF;
  -- PostgreSQL 17 pg_auth_members can contain several rows for a
  -- (roleid, member) pair when grantors differ. Validate the grantor and each
  -- option tuple explicitly rather than counting only distinct role pairs.
  -- Each protected role must have exactly the migrator SET edge granted by
  -- session_user and the creator ADMIN edge from the same non-operator grantor
  -- recorded on stockwise_owner's existing creator membership.
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid IN (
      pg_catalog.to_regrole('stockwise_owner'),
      pg_catalog.to_regrole('stockwise_auth_owner'),
      pg_catalog.to_regrole('stockwise_product_reader')
    )
  ) <> 6 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid IN (
      pg_catalog.to_regrole('stockwise_owner'),
      pg_catalog.to_regrole('stockwise_auth_owner'),
      pg_catalog.to_regrole('stockwise_product_reader')
    )
      AND NOT (
        (m.member = pg_catalog.to_regrole('stockwise_migrator')
         AND m.grantor = pg_catalog.to_regrole(session_user)
         AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
        OR
        (m.member = pg_catalog.to_regrole(session_user)
         AND m.grantor = (
           SELECT base.grantor
           FROM pg_catalog.pg_auth_members AS base
           WHERE base.roleid = pg_catalog.to_regrole('stockwise_owner')
             AND base.member = pg_catalog.to_regrole(session_user)
             AND base.admin_option
             AND NOT base.inherit_option
             AND NOT base.set_option
         )
         AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
      )
  ) OR EXISTS (
    SELECT 1
    FROM (VALUES
      (pg_catalog.to_regrole('stockwise_owner')),
      (pg_catalog.to_regrole('stockwise_auth_owner')),
      (pg_catalog.to_regrole('stockwise_product_reader'))
    ) AS expected(role_oid)
    WHERE (
      SELECT count(*)
      FROM pg_catalog.pg_auth_members AS m
      WHERE m.roleid = expected.role_oid
        AND m.member = pg_catalog.to_regrole('stockwise_migrator')
        AND m.grantor = pg_catalog.to_regrole(session_user)
        AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
    ) <> 1 OR (
      SELECT count(*)
      FROM pg_catalog.pg_auth_members AS m
      WHERE m.roleid = expected.role_oid
        AND m.member = pg_catalog.to_regrole(session_user)
        AND m.grantor = (
          SELECT base.grantor
          FROM pg_catalog.pg_auth_members AS base
          WHERE base.roleid = pg_catalog.to_regrole('stockwise_owner')
            AND base.member = pg_catalog.to_regrole(session_user)
            AND base.admin_option
            AND NOT base.inherit_option
            AND NOT base.set_option
        )
        AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
    ) <> 1
  ) THEN
    RAISE EXCEPTION 'Protected-role membership edges/grantors/options differ from the reviewed PostgreSQL 17 setup';
  END IF;

  -- Migrator must be a member of exactly the three protected roles, with the
  -- approved grantor and SET-only options; test distinct roles, not assumed
  -- uniqueness of (roleid, member) alone.
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND m.grantor = pg_catalog.to_regrole(session_user)
      AND m.roleid IN (
        pg_catalog.to_regrole('stockwise_owner'),
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
  ) <> 3 OR (
    SELECT count(DISTINCT m.roleid)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND m.grantor = pg_catalog.to_regrole(session_user)
      AND m.roleid IN (
        pg_catalog.to_regrole('stockwise_owner'),
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
  ) <> 3 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.member = pg_catalog.to_regrole('stockwise_migrator')
      AND (m.grantor <> pg_catalog.to_regrole(session_user)
           OR m.roleid NOT IN (
             pg_catalog.to_regrole('stockwise_owner'),
             pg_catalog.to_regrole('stockwise_auth_owner'),
             pg_catalog.to_regrole('stockwise_product_reader')
           )
           OR m.admin_option OR m.inherit_option OR NOT m.set_option)
  ) THEN
    RAISE EXCEPTION 'Migrator must have exactly three reviewed grantor/options memberships';
  END IF;

  -- The provisioner's automatic ADMIN edge and explicit SET edge into
  -- stockwise_migrator have different grantors and must both be present. The
  -- creator edge must use the same non-operator grantor as the existing
  -- stockwise_owner creator edge.
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member = pg_catalog.to_regrole(session_user)
  ) <> 2 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member <> pg_catalog.to_regrole(session_user)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member = pg_catalog.to_regrole(session_user)
      AND NOT (
        (m.grantor = pg_catalog.to_regrole(session_user)
         AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
        OR (m.grantor = (
              SELECT base.grantor
              FROM pg_catalog.pg_auth_members AS base
              WHERE base.roleid = pg_catalog.to_regrole('stockwise_owner')
                AND base.member = pg_catalog.to_regrole(session_user)
                AND base.admin_option
                AND NOT base.inherit_option
                AND NOT base.set_option
            )
            AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)
      )
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member = pg_catalog.to_regrole(session_user)
      AND m.grantor = pg_catalog.to_regrole(session_user)
      AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS m
    WHERE m.roleid = pg_catalog.to_regrole('stockwise_migrator')
      AND m.member = pg_catalog.to_regrole(session_user)
      AND m.grantor = (
        SELECT base.grantor
        FROM pg_catalog.pg_auth_members AS base
        WHERE base.roleid = pg_catalog.to_regrole('stockwise_owner')
          AND base.member = pg_catalog.to_regrole(session_user)
          AND base.admin_option
          AND NOT base.inherit_option
          AND NOT base.set_option
      )
      AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
  ) THEN
    RAISE EXCEPTION 'Provisioner/migrator role edges differ from the reviewed PostgreSQL 17 grantor/options setup';
  END IF;

  -- pg_has_role checks effective membership, including transitive memberships.
  -- The approved session_user is a privileged deployment exception; API roles
  -- must not be able to reach any migration or function-owner role.
  IF EXISTS (
    WITH RECURSIVE role_closure(api_role_oid, reachable_role_oid) AS (
      SELECT r.oid, r.oid
      FROM pg_catalog.pg_roles AS r
      WHERE r.rolname IN ('anon','authenticated','service_role','authenticator')
      UNION
      SELECT rc.api_role_oid, m.roleid
      FROM role_closure AS rc
      JOIN pg_catalog.pg_auth_members AS m ON m.member = rc.reachable_role_oid
    )
    SELECT 1
    FROM role_closure AS rc
    JOIN pg_catalog.pg_roles AS reachable ON reachable.oid = rc.reachable_role_oid
    WHERE reachable.rolname IN (
      'stockwise_owner','stockwise_migrator',
      'stockwise_auth_owner','stockwise_product_reader'
    )
  ) THEN
    RAISE EXCEPTION 'An API role inherits membership in a protected StockWise role';
  END IF;

  -- Effective privilege checks include direct, inherited, and PUBLIC ACLs.
  -- The reader is checked before its intentionally narrow grants are added.
  -- Do not use blanket REVOKE to silently repair unexpected existing grants.
  FOR v_api_role IN
    SELECT oid, rolname
    FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'anon','authenticated','service_role','authenticator',
      'stockwise_product_reader'
    )
  LOOP
    IF pg_catalog.has_schema_privilege(v_api_role.oid,'stockwise','USAGE')
       OR pg_catalog.has_schema_privilege(v_api_role.oid,'stockwise','CREATE') THEN
      RAISE EXCEPTION 'Unexpected effective stockwise schema access for %',v_api_role.rolname;
    END IF;
    FOR v_object IN
      SELECT c.oid, c.relkind, n.nspname, c.relname
      FROM pg_catalog.pg_class AS c
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'stockwise'
    LOOP
      IF v_object.relkind = 'S' THEN
        IF pg_catalog.has_sequence_privilege(v_api_role.oid,v_object.oid,'USAGE')
           OR pg_catalog.has_sequence_privilege(v_api_role.oid,v_object.oid,'SELECT')
           OR pg_catalog.has_sequence_privilege(v_api_role.oid,v_object.oid,'UPDATE') THEN
          RAISE EXCEPTION 'Unexpected effective sequence access for % on %.%',
            v_api_role.rolname,v_object.nspname,v_object.relname;
        END IF;
      ELSIF v_object.relkind IN ('r','p','v','m','f') THEN
        IF pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'SELECT')
           OR pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'INSERT')
           OR pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'UPDATE')
           OR pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'DELETE')
           OR pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'TRUNCATE')
           OR pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'REFERENCES')
           OR pg_catalog.has_table_privilege(v_api_role.oid,v_object.oid,'TRIGGER') THEN
          RAISE EXCEPTION 'Unexpected effective relation access for % on %.%',
            v_api_role.rolname,v_object.nspname,v_object.relname;
        END IF;
        IF pg_catalog.has_any_column_privilege(v_api_role.oid,v_object.oid,'SELECT')
           OR pg_catalog.has_any_column_privilege(v_api_role.oid,v_object.oid,'INSERT')
           OR pg_catalog.has_any_column_privilege(v_api_role.oid,v_object.oid,'UPDATE')
           OR pg_catalog.has_any_column_privilege(v_api_role.oid,v_object.oid,'REFERENCES') THEN
          RAISE EXCEPTION 'Unexpected effective column access for % on %.%',
            v_api_role.rolname,v_object.nspname,v_object.relname;
        END IF;
      END IF;
    END LOOP;
    FOR v_object IN
      SELECT p.oid, n.nspname, p.proname
      FROM pg_catalog.pg_proc AS p
      JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
      WHERE n.nspname = 'stockwise'
    LOOP
      IF pg_catalog.has_function_privilege(v_api_role.oid,v_object.oid,'EXECUTE') THEN
        RAISE EXCEPTION 'Unexpected effective function access for % on %.%',
          v_api_role.rolname,v_object.nspname,v_object.proname;
      END IF;
    END LOOP;
  END LOOP;

  -- Require the owner-default hardening from deployment step 03. Reject
  -- PUBLIC or named-role EXECUTE defaults; do not silently repair ACL drift.
  IF EXISTS (
    SELECT required.role_oid
    FROM (VALUES
      (pg_catalog.to_regrole('stockwise_owner')),
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
    RAISE EXCEPTION 'StockWise function-owner roles lack explicit global function-default hardening';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS d
    CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) AS a
    WHERE d.defaclrole IN (
        pg_catalog.to_regrole('stockwise_owner'),
        pg_catalog.to_regrole('stockwise_auth_owner'),
        pg_catalog.to_regrole('stockwise_product_reader')
      )
      AND d.defaclobjtype = 'f'
      AND a.privilege_type = 'EXECUTE'
      AND a.grantee <> d.defaclrole
  ) THEN
    RAISE EXCEPTION 'Unreviewed function default EXECUTE grants exist for a StockWise owner';
  END IF;

  IF NOT pg_catalog.has_column_privilege(
       'stockwise_auth_owner','stockwise.companies','id','REFERENCES')
     OR NOT pg_catalog.has_column_privilege(
       'stockwise_auth_owner','auth.users','id','REFERENCES')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','stockwise','USAGE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','auth','USAGE')
     OR NOT pg_catalog.has_function_privilege(
       'stockwise_auth_owner','auth.uid()','EXECUTE') THEN
    RAISE EXCEPTION 'Auth-owner REFERENCES/uid privileges require separate review';
  END IF;
  IF pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','stockwise.companies','SELECT')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_auth_owner','auth.users','SELECT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.products','SELECT')
     OR pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.stock_balances','SELECT') THEN
    RAISE EXCEPTION 'Auth-owner has unexpected business-data or Auth-user read access';
  END IF;
  IF pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','stockwise','CREATE')
     OR pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','auth','CREATE') THEN
    RAISE EXCEPTION 'Auth-owner must not create objects in managed schemas';
  END IF;

  -- Recheck the membership owner's effective grants in every existing
  -- stockwise/Auth relation. Its only REFERENCES rights are the two FK id
  -- columns; it must not inherit row reads or mutation privileges.
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
        RAISE EXCEPTION 'Unexpected auth-owner sequence access on %.%',
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
        RAISE EXCEPTION 'Unexpected auth-owner relation access on %.%',
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
          RAISE EXCEPTION 'Unexpected auth-owner column access on %.%.%',
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
          RAISE EXCEPTION 'Unexpected auth-owner REFERENCES access on %.%.%',
            v_object.nspname,v_object.relname,v_column.attname;
        END IF;
      END LOOP;
    END IF;
  END LOOP;

  FOR v_object IN
    SELECT p.oid, n.nspname, p.proname
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('stockwise','auth')
      AND NOT (n.nspname = 'auth'
               AND p.oid = pg_catalog.to_regprocedure('auth.uid()'))
  LOOP
    IF pg_catalog.has_function_privilege(
         'stockwise_auth_owner',v_object.oid,'EXECUTE') THEN
      RAISE EXCEPTION 'Unexpected auth-owner function access on %.%',
        v_object.nspname,v_object.proname;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'stockwise'
      AND c.relname IN ('companies','products','stock_balances')
      AND pg_catalog.pg_get_userbyid(c.relowner) <> 'stockwise_owner'
  ) THEN
    RAISE EXCEPTION 'Expected stockwise_owner ownership differs; inspect before proceeding';
  END IF;
END
$preflight$;

-- The caller is already required to be stockwise_migrator by preflight. It
-- creates schemas for their intended NOLOGIN owners using its approved
-- database CREATE and SET membership; do not RESET to session_user here.
CREATE SCHEMA stockwise_private AUTHORIZATION stockwise_auth_owner;
CREATE SCHEMA stockwise_api AUTHORIZATION stockwise_owner;

SET LOCAL ROLE stockwise_auth_owner;
REVOKE ALL ON SCHEMA stockwise_private
  FROM PUBLIC, anon, authenticated, service_role, authenticator,
       stockwise_product_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA stockwise_private
  FROM PUBLIC, anon, authenticated, service_role, authenticator,
       stockwise_product_reader;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise_private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE stockwise_private.company_memberships (
  company_id uuid NOT NULL
    REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  auth_user_id uuid NOT NULL
    REFERENCES auth.users(id) ON DELETE RESTRICT,
  role text NOT NULL CHECK (role IN ('Owner','Admin','Staff','Viewer')),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','active','inactive')),
  created_by uuid REFERENCES auth.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (company_id, auth_user_id)
);
CREATE INDEX company_memberships_user_status_idx
  ON stockwise_private.company_memberships (auth_user_id, status, company_id);
ALTER TABLE stockwise_private.company_memberships ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON stockwise_private.company_memberships
  FROM PUBLIC, anon, authenticated, service_role, authenticator,
       stockwise_product_reader;

CREATE FUNCTION stockwise_private.current_company_role(p_company_id uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
  SELECT m.role
  FROM stockwise_private.company_memberships AS m
  WHERE m.company_id = p_company_id
    AND m.auth_user_id = auth.uid()
    AND m.status = 'active'
  LIMIT 1
$function$;
-- Shared authorization trust point: the product RPC and both restrictive RLS
-- policies invoke this same helper. They are multiple enforcement call sites,
-- not independent authorization implementations. Review and test this helper's
-- identity, membership, status, and company-scope semantics directly.
REVOKE ALL ON FUNCTION stockwise_private.current_company_role(uuid)
  FROM PUBLIC, anon, authenticated, service_role, authenticator,
       stockwise_product_reader;
GRANT USAGE ON SCHEMA stockwise_private TO stockwise_product_reader;
GRANT EXECUTE ON FUNCTION stockwise_private.current_company_role(uuid)
  TO stockwise_product_reader;
RESET ROLE;

SET LOCAL ROLE stockwise_owner;
REVOKE ALL ON SCHEMA stockwise_api FROM PUBLIC, anon, authenticated, service_role, authenticator;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise_api
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT USAGE ON SCHEMA stockwise TO stockwise_product_reader;
GRANT SELECT (
  id, company_id, sku, name, category, unit_code, classification_code,
  unit_cost, selling_price, low_stock_threshold, is_active
) ON stockwise.products TO stockwise_product_reader;
GRANT SELECT (company_id, product_id, quantity)
  ON stockwise.stock_balances TO stockwise_product_reader;

CREATE POLICY products_reader_allow
  ON stockwise.products
  AS PERMISSIVE
  FOR SELECT TO stockwise_product_reader
  USING (true);
CREATE POLICY products_company_scope
  ON stockwise.products
  AS RESTRICTIVE
  FOR SELECT TO stockwise_product_reader
  USING (stockwise_private.current_company_role(company_id) IS NOT NULL);
CREATE POLICY balances_reader_allow
  ON stockwise.stock_balances
  AS PERMISSIVE
  FOR SELECT TO stockwise_product_reader
  USING (true);
CREATE POLICY balances_company_scope
  ON stockwise.stock_balances
  AS RESTRICTIVE
  FOR SELECT TO stockwise_product_reader
  USING (stockwise_private.current_company_role(company_id) IS NOT NULL);

GRANT USAGE, CREATE ON SCHEMA stockwise_api TO stockwise_product_reader;
GRANT USAGE ON SCHEMA stockwise_api TO authenticated;
RESET ROLE;

SET LOCAL ROLE stockwise_product_reader;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise_api
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE FUNCTION stockwise_api.list_products(
  p_company_id uuid,
  p_limit integer DEFAULT 100,
  p_after_sku text DEFAULT NULL,
  p_after_id uuid DEFAULT NULL
)
RETURNS SETOF jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role text;
BEGIN
  IF p_company_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid page size';
  END IF;
  IF (p_after_sku IS NULL) <> (p_after_id IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid cursor';
  END IF;

  v_role := stockwise_private.current_company_role(p_company_id);
  IF v_role IS NULL OR v_role NOT IN ('Owner','Admin','Staff','Viewer') THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'not authorized';
  END IF;

  RETURN QUERY
  SELECT
    pg_catalog.jsonb_build_object(
      'id', p.id,
      'sku', p.sku,
      'name', p.name,
      'category', p.category,
      'unit_code', p.unit_code,
      'is_active', p.is_active,
      'stock_quantity', b.quantity
    )
    ||
    CASE
      WHEN v_role IN ('Owner','Admin') THEN pg_catalog.jsonb_build_object(
        'selling_price', p.selling_price,
        'cost_price', p.unit_cost,
        'low_stock_threshold', p.low_stock_threshold,
        'classification_code', p.classification_code
      )
      WHEN v_role = 'Staff' THEN pg_catalog.jsonb_build_object(
        'selling_price', p.selling_price,
        'low_stock_threshold', p.low_stock_threshold
      )
      ELSE '{}'::jsonb
    END
  FROM stockwise.products AS p
  JOIN stockwise.stock_balances AS b
    ON b.company_id = p.company_id
   AND b.product_id = p.id
  WHERE p.company_id = p_company_id
    AND (
      p_after_sku IS NULL
      OR (p.sku, p.id) > (p_after_sku, p_after_id)
    )
  ORDER BY p.sku, p.id
  LIMIT p_limit;
END
$function$;
REVOKE ALL ON FUNCTION stockwise_api.list_products(uuid,integer,text,uuid)
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
GRANT EXECUTE ON FUNCTION stockwise_api.list_products(uuid,integer,text,uuid)
  TO authenticated;
RESET ROLE;

SET LOCAL ROLE stockwise_owner;
REVOKE CREATE ON SCHEMA stockwise_api FROM stockwise_product_reader;
RESET ROLE;

-- The base schema and membership internals are not client API surfaces. Only
-- the exact RPC signature above is granted to authenticated; anon and
-- service_role remain denied. The trusted provisioner can administer role
-- memberships and the migrator can SET into object-owner roles, so these
-- deployment identities are privileged and may access business data.
-- Dashboard Data API schema exposure still needs separate review and must
-- expose stockwise_api without exposing stockwise or stockwise_private.

DO $postflight$
DECLARE
  v_role record;
  v_proc record;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname IN (
      'stockwise_owner','stockwise_migrator',
      'stockwise_auth_owner','stockwise_product_reader'
    )
      AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb
           OR r.rolcreaterole OR r.rolinherit OR r.rolreplication)
  ) THEN
    RAISE EXCEPTION 'Postflight found an unapproved StockWise role attribute';
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
  IF NOT pg_catalog.has_database_privilege(
       'stockwise_migrator',pg_catalog.current_database(),'CREATE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_owner','stockwise','USAGE WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'Postflight lost required database or schema authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS r
    WHERE r.rolname IN (
      'stockwise_owner','stockwise_auth_owner','stockwise_product_reader',
      'anon','authenticated','service_role','authenticator'
    )
      AND pg_catalog.has_database_privilege(
        r.oid,pg_catalog.current_database(),'CREATE')
  ) THEN
    RAISE EXCEPTION 'Postflight found target-database CREATE on a protected or API role';
  END IF;

  IF EXISTS (
    WITH RECURSIVE role_closure(api_role_oid, reachable_role_oid) AS (
      SELECT r.oid, r.oid
      FROM pg_catalog.pg_roles AS r
      WHERE r.rolname IN ('anon','authenticated','service_role','authenticator')
      UNION
      SELECT rc.api_role_oid, m.roleid
      FROM role_closure AS rc
      JOIN pg_catalog.pg_auth_members AS m ON m.member = rc.reachable_role_oid
    )
    SELECT 1
    FROM role_closure AS rc
    JOIN pg_catalog.pg_roles AS reachable ON reachable.oid = rc.reachable_role_oid
    WHERE reachable.rolname IN (
      'stockwise_owner','stockwise_migrator',
      'stockwise_auth_owner','stockwise_product_reader'
    )
  ) THEN
    RAISE EXCEPTION 'Postflight found an API role in a protected role-membership closure';
  END IF;

  IF NOT pg_catalog.has_schema_privilege('authenticated','stockwise_api','USAGE')
     OR NOT pg_catalog.has_function_privilege(
       'authenticated','stockwise_api.list_products(uuid,integer,text,uuid)','EXECUTE') THEN
    RAISE EXCEPTION 'authenticated is missing the exact approved product RPC access';
  END IF;

  FOR v_role IN
    SELECT rolname FROM pg_catalog.pg_roles
    WHERE rolname IN ('anon','service_role','authenticator')
  LOOP
    IF pg_catalog.has_schema_privilege(v_role.rolname,'stockwise_api','USAGE')
       OR pg_catalog.has_function_privilege(
         v_role.rolname,'stockwise_api.list_products(uuid,integer,text,uuid)','EXECUTE')
       OR pg_catalog.has_schema_privilege(v_role.rolname,'stockwise_private','USAGE')
       OR pg_catalog.has_function_privilege(
         v_role.rolname,'stockwise_private.current_company_role(uuid)','EXECUTE') THEN
      RAISE EXCEPTION 'Unexpected API schema or RPC access for %',v_role.rolname;
    END IF;
  END LOOP;

  IF pg_catalog.has_schema_privilege('authenticated','stockwise','USAGE')
     OR pg_catalog.has_schema_privilege('authenticated','stockwise_private','USAGE')
     OR pg_catalog.has_function_privilege(
       'authenticated','stockwise_private.current_company_role(uuid)','EXECUTE')
     OR pg_catalog.has_table_privilege(
       'authenticated','stockwise_private.company_memberships','SELECT')
     OR pg_catalog.has_table_privilege(
       'authenticated','stockwise.products','SELECT')
     OR pg_catalog.has_table_privilege(
       'authenticated','stockwise.stock_balances','SELECT')
     OR pg_catalog.has_any_column_privilege(
       'authenticated','stockwise.products','SELECT')
     OR pg_catalog.has_any_column_privilege(
       'authenticated','stockwise.stock_balances','SELECT')
     OR pg_catalog.has_any_column_privilege(
       'authenticated','stockwise_private.company_memberships','SELECT') THEN
    RAISE EXCEPTION 'authenticated has direct access to a private or base data object';
  END IF;

  IF NOT pg_catalog.has_schema_privilege('stockwise_product_reader','stockwise','USAGE')
     OR pg_catalog.has_schema_privilege('stockwise_product_reader','stockwise','CREATE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_product_reader','stockwise_private','USAGE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_product_reader','stockwise_api','USAGE')
     OR pg_catalog.has_table_privilege(
       'stockwise_product_reader','stockwise_private.company_memberships','SELECT')
     OR pg_catalog.has_any_column_privilege(
       'stockwise_product_reader','stockwise_private.company_memberships','SELECT')
     OR NOT pg_catalog.has_function_privilege(
       'stockwise_product_reader','stockwise_private.current_company_role(uuid)','EXECUTE')
     OR pg_catalog.has_schema_privilege(
       'stockwise_product_reader','stockwise_api','CREATE') THEN
    RAISE EXCEPTION 'Reader grants do not match the reviewed minimum';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute AS a
    WHERE a.attrelid = pg_catalog.to_regclass('stockwise.products')
      AND a.attnum > 0 AND NOT a.attisdropped
      AND pg_catalog.has_column_privilege(
        'stockwise_product_reader',a.attrelid,a.attname,'SELECT')
      AND a.attname NOT IN (
        'id','company_id','sku','name','category','unit_code',
        'classification_code','unit_cost','selling_price',
        'low_stock_threshold','is_active'
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute AS a
    WHERE a.attrelid = pg_catalog.to_regclass('stockwise.stock_balances')
      AND a.attnum > 0 AND NOT a.attisdropped
      AND pg_catalog.has_column_privilege(
        'stockwise_product_reader',a.attrelid,a.attname,'SELECT')
      AND a.attname NOT IN ('company_id','product_id','quantity')
  ) OR NOT (
    pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','id','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','company_id','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','sku','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','name','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','category','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','unit_code','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','classification_code','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','unit_cost','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','selling_price','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','low_stock_threshold','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.products','is_active','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.stock_balances','company_id','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.stock_balances','product_id','SELECT')
    AND pg_catalog.has_column_privilege('stockwise_product_reader','stockwise.stock_balances','quantity','SELECT')
  ) THEN
    RAISE EXCEPTION 'Reader column privileges do not match the reviewed projection';
  END IF;
  IF pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.products','INSERT')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.products','UPDATE')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.products','DELETE')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.products','TRUNCATE')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.products','REFERENCES')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.products','TRIGGER')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.stock_balances','INSERT')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.stock_balances','UPDATE')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.stock_balances','DELETE')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.stock_balances','TRUNCATE')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.stock_balances','REFERENCES')
     OR pg_catalog.has_table_privilege('stockwise_product_reader','stockwise.stock_balances','TRIGGER')
     OR pg_catalog.has_any_column_privilege('stockwise_product_reader','stockwise.products','INSERT')
     OR pg_catalog.has_any_column_privilege('stockwise_product_reader','stockwise.products','UPDATE')
     OR pg_catalog.has_any_column_privilege('stockwise_product_reader','stockwise.products','REFERENCES')
     OR pg_catalog.has_any_column_privilege('stockwise_product_reader','stockwise.stock_balances','INSERT')
     OR pg_catalog.has_any_column_privilege('stockwise_product_reader','stockwise.stock_balances','UPDATE')
     OR pg_catalog.has_any_column_privilege('stockwise_product_reader','stockwise.stock_balances','REFERENCES') THEN
    RAISE EXCEPTION 'Product reader unexpectedly has write or reference privileges';
  END IF;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname = 'stockwise_api'
  ) <> 1 OR pg_catalog.to_regprocedure(
       'stockwise_api.list_products(uuid,integer,text,uuid)') IS NULL THEN
    RAISE EXCEPTION 'The product RPC is missing, duplicated, or has an unexpected overload';
  END IF;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname = 'stockwise_private'
  ) <> 1 OR pg_catalog.to_regprocedure(
       'stockwise_private.current_company_role(uuid)') IS NULL THEN
    RAISE EXCEPTION 'The membership helper is missing, duplicated, or has an unexpected overload';
  END IF;

  SELECT p.proowner, p.prosecdef, p.proconfig
  INTO v_proc
  FROM pg_catalog.pg_proc AS p
  WHERE p.oid = pg_catalog.to_regprocedure(
    'stockwise_api.list_products(uuid,integer,text,uuid)');
  IF v_proc.proowner <> pg_catalog.to_regrole('stockwise_product_reader')
     OR NOT v_proc.prosecdef
     OR NOT COALESCE(
       'search_path=pg_catalog, pg_temp' = ANY(v_proc.proconfig), false
     ) THEN
    RAISE EXCEPTION 'Product RPC owner, SECURITY DEFINER status, or fixed search_path differs';
  END IF;

  SELECT p.proowner, p.prosecdef, p.proconfig
  INTO v_proc
  FROM pg_catalog.pg_proc AS p
  WHERE p.oid = pg_catalog.to_regprocedure(
    'stockwise_private.current_company_role(uuid)');
  IF v_proc.proowner <> pg_catalog.to_regrole('stockwise_auth_owner')
     OR NOT v_proc.prosecdef
     OR NOT COALESCE(
       'search_path=pg_catalog, pg_temp' = ANY(v_proc.proconfig), false
     ) THEN
    RAISE EXCEPTION 'Membership helper owner, SECURITY DEFINER status, or fixed search_path differs';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS p
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))
    ) AS acl
    WHERE p.oid IN (
      pg_catalog.to_regprocedure(
        'stockwise_api.list_products(uuid,integer,text,uuid)'),
      pg_catalog.to_regprocedure(
        'stockwise_private.current_company_role(uuid)')
    )
      AND acl.grantee = 0
      AND acl.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC has EXECUTE on a proposed security function';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_policy
    WHERE polrelid = pg_catalog.to_regclass('stockwise.products')
      AND polname = 'products_company_scope'
      AND NOT polpermissive AND polcmd = 'r'
      AND polroles = ARRAY[
        pg_catalog.to_regrole('stockwise_product_reader')
      ]::oid[]
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_policy
    WHERE polrelid = pg_catalog.to_regclass('stockwise.stock_balances')
      AND polname = 'balances_company_scope'
      AND NOT polpermissive AND polcmd = 'r'
      AND polroles = ARRAY[
        pg_catalog.to_regrole('stockwise_product_reader')
      ]::oid[]
  ) THEN
    RAISE EXCEPTION 'Required restrictive company policies are missing';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class AS c
    WHERE c.oid IN (
      pg_catalog.to_regclass('stockwise.products'),
      pg_catalog.to_regclass('stockwise.stock_balances')
    )
      AND (NOT c.relrowsecurity
           OR c.relowner = pg_catalog.to_regrole('stockwise_product_reader'))
  ) THEN
    RAISE EXCEPTION 'RLS is disabled or reader unexpectedly owns a protected table';
  END IF;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_policy
    WHERE polrelid IN (
      pg_catalog.to_regclass('stockwise.products'),
      pg_catalog.to_regclass('stockwise.stock_balances')
    )
  ) <> 4
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_policy
       WHERE polrelid = pg_catalog.to_regclass('stockwise.products')
         AND polname = 'products_reader_allow'
         AND polpermissive AND polcmd = 'r'
         AND polroles = ARRAY[
           pg_catalog.to_regrole('stockwise_product_reader')
         ]::oid[]
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_policy
       WHERE polrelid = pg_catalog.to_regclass('stockwise.stock_balances')
         AND polname = 'balances_reader_allow'
         AND polpermissive AND polcmd = 'r'
         AND polroles = ARRAY[
           pg_catalog.to_regrole('stockwise_product_reader')
         ]::oid[]
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_policy
       WHERE polrelid = pg_catalog.to_regclass('stockwise.products')
         AND polname = 'products_company_scope'
         AND NOT polpermissive AND polcmd = 'r'
         AND polroles = ARRAY[
           pg_catalog.to_regrole('stockwise_product_reader')
         ]::oid[]
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_policy
       WHERE polrelid = pg_catalog.to_regclass('stockwise.stock_balances')
         AND polname = 'balances_company_scope'
         AND NOT polpermissive AND polcmd = 'r'
         AND polroles = ARRAY[
           pg_catalog.to_regrole('stockwise_product_reader')
         ]::oid[]
     ) THEN
    RAISE EXCEPTION 'Product RLS policy composition differs from the reviewed design';
  END IF;
END
$postflight$;

COMMIT;
