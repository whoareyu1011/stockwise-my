-- PREPARED FOR REVIEW ONLY. Run ONLY AFTER unchanged migration 0001 commits.
-- Caller must be an approved operator able to assume stockwise_migrator.
-- Owner-specific GLOBAL scope is intentional: a per-schema REVOKE cannot
-- remove PostgreSQL's built-in global default PUBLIC function EXECUTE.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL ROLE stockwise_migrator;

DO $preflight$
DECLARE v_owner oid := pg_catalog.to_regrole('stockwise_owner');
BEGIN
  IF pg_catalog.current_setting('server_version_num')::integer / 10000 <> 17 THEN
    RAISE EXCEPTION 'This hardening package requires reviewed PostgreSQL 17';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_roles
      WHERE rolname IN ('stockwise_owner','stockwise_migrator')
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
        AND NOT rolcreaterole AND NOT rolcreatedb
        AND NOT rolinherit AND NOT rolreplication) <> 2 THEN
    RAISE EXCEPTION 'Deployment roles no longer have the approved restricted flags';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=v_owner)
     OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_auth_members m
       WHERE m.member=pg_catalog.to_regrole('stockwise_migrator')
         AND (m.roleid<>v_owner OR m.admin_option OR m.inherit_option OR NOT m.set_option)
     ) THEN
    RAISE EXCEPTION 'Unexpected deployment membership graph before hardening';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace
    WHERE nspname='stockwise' AND nspowner=v_owner
      AND pg_catalog.obj_description(oid,'pg_namespace') =
        'StockWise inventory migration 0001; no runtime access granted; no browser data imported.'
  ) THEN
    RAISE EXCEPTION 'Verified migration 0001 must be installed before owner-default hardening';
  END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='stockwise' AND c.relkind='r'
        AND c.relowner=v_owner AND c.relrowsecurity AND NOT c.relforcerowsecurity) <> 8
     OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p
         JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
         WHERE n.nspname='stockwise' AND p.proowner=v_owner) <> 14 THEN
    RAISE EXCEPTION 'Unexpected migration ownership or RLS state; inspect before hardening';
  END IF;
  -- Do not pretend a global PUBLIC revoke overrides positive schema grants,
  -- or silently delete a separate administrator's custom grants.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl a
    CROSS JOIN LATERAL pg_catalog.aclexplode(a.defaclacl) acl
    WHERE a.defaclrole=v_owner AND a.defaclobjtype='f'
      AND acl.grantee<>v_owner
      AND (a.defaclnamespace<>0 OR acl.grantee<>0)
  ) THEN
    RAISE EXCEPTION 'Unexpected positive owner function defaults; review schema-specific or named-role grants';
  END IF;
END;
$preflight$;

SET LOCAL ROLE stockwise_owner;
ALTER DEFAULT PRIVILEGES FOR ROLE stockwise_owner
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Existing function ACLs are deliberately unchanged; 0001 already revoked them.
-- Only functions created later by this dedicated owner receive the new default.
COMMIT;
