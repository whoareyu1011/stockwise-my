-- PREPARED FOR REVIEW ONLY. Run after 01, before unchanged migration 0001.
-- Same administrative current_user as 01; current_database is the target.
-- Does not modify role flags, managed schemas, existing project defaults,
-- API roles or runtime accounts. Memberships are only for deployment.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
DECLARE
  v_owner oid := pg_catalog.to_regrole('stockwise_owner');
  v_migrator oid := pg_catalog.to_regrole('stockwise_migrator');
  v_operator oid;
BEGIN
  IF pg_catalog.current_setting('server_version_num')::integer / 10000 <> 17 THEN
    RAISE EXCEPTION 'This provisioning package requires reviewed PostgreSQL 17';
  END IF;
  SELECT oid INTO v_operator FROM pg_catalog.pg_roles WHERE rolname=current_user;
  IF current_user IN ('anon','authenticated','service_role','authenticator',
                      'stockwise_owner','stockwise_migrator') THEN
    RAISE EXCEPTION 'Use the approved administrative role that ran file 01';
  END IF;
  IF v_owner IS NULL OR v_migrator IS NULL THEN
    RAISE EXCEPTION 'Both reviewed StockWise roles must be created by file 01 first';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_roles
      WHERE oid IN (v_owner,v_migrator) AND NOT rolcanlogin AND NOT rolsuper
        AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb
        AND NOT rolinherit AND NOT rolreplication) <> 2 THEN
    RAISE EXCEPTION 'StockWise role flags differ from the approved restricted configuration';
  END IF;
  IF pg_catalog.to_regnamespace('stockwise') IS NOT NULL THEN
    RAISE EXCEPTION 'Run file 02 before migration 0001; do not rewrite deployed memberships';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl WHERE defaclrole=v_owner) THEN
    RAISE EXCEPTION 'Owner must have clean default privileges before migration 0001';
  END IF;
  IF NOT pg_catalog.has_database_privilege(current_user,pg_catalog.current_database(),
                                            'CREATE WITH GRANT OPTION') THEN
    RAISE EXCEPTION 'Provisioning operator needs database CREATE grant authority';
  END IF;
  IF pg_catalog.has_database_privilege('stockwise_owner',pg_catalog.current_database(),'CREATE') THEN
    RAISE EXCEPTION 'Unexpected owner database CREATE privilege; inspect inherited or PUBLIC grants';
  END IF;
  IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE oid=v_operator)
     AND EXISTS (
       SELECT 1 FROM (VALUES(v_owner),(v_migrator)) AS roles(roleid)
       WHERE NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_auth_members m
         WHERE m.roleid=roles.roleid AND m.member=v_operator AND m.admin_option
       )
     ) THEN
    RAISE EXCEPTION 'Use the role creator with direct ADMIN authority on both new roles';
  END IF;
  -- Reject unexpected graph edges instead of revoking unrelated privileges.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members m
    WHERE (m.member=v_owner)
       OR (m.member=v_migrator AND m.roleid<>v_owner)
       OR (m.roleid=v_owner AND m.member NOT IN (v_operator,v_migrator))
       OR (m.roleid=v_migrator AND m.member<>v_operator)
  ) THEN
    RAISE EXCEPTION 'Unexpected StockWise membership graph; inspect rather than repair automatically';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members m
    WHERE (m.roleid=v_owner AND m.member=v_migrator
           AND (m.admin_option OR m.inherit_option OR NOT m.set_option))
       OR (m.roleid IN (v_owner,v_migrator) AND m.member=v_operator
           AND (m.inherit_option
                OR (m.grantor=v_operator
                    AND (m.roleid<>v_migrator OR m.admin_option OR NOT m.set_option))
                OR (m.grantor<>v_operator
                    AND (NOT m.admin_option OR m.set_option))))
  ) THEN
    RAISE EXCEPTION 'Unexpected deployment membership options; review explicit SET/INHERIT/ADMIN flags';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND (pg_catalog.pg_has_role(api.oid,v_owner,'MEMBER')
           OR pg_catalog.pg_has_role(api.oid,v_migrator,'MEMBER'))
  ) THEN
    RAISE EXCEPTION 'API roles must not have StockWise deployment membership';
  END IF;
END;
$preflight$;

-- Keep the creator's administrative memberships. Removing them can invalidate
-- dependent role grants made by that creator. These are not runtime rights.
-- Do not re-grant ADMIN to the creator: PostgreSQL 17 rejects that with 0LP01.
-- A separate creator-granted, non-admin SET membership is intentionally added.
-- Explicit edge options matter in PostgreSQL 17, not just role NOINHERIT flags.
DO $permissions$
BEGIN
  GRANT stockwise_owner TO stockwise_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
  EXECUTE pg_catalog.format(
    'GRANT stockwise_migrator TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',current_user);
  EXECUTE pg_catalog.format(
    'GRANT CREATE ON DATABASE %I TO stockwise_migrator',pg_catalog.current_database());
END;
$permissions$;

COMMIT;
