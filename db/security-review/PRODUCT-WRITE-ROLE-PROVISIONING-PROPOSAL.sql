-- REVIEW-ONLY PROPOSAL. DO NOT EXECUTE.
--
-- Adds non-login function-owner roles for the additive product-write and
-- stock-adjustment proposal. This is not part of application startup or the
-- existing deployment SQL.
--
-- Prerequisites:
--   * 0001_inventory.sql has been applied to an approved isolated target.
--   * The separately reviewed read-role provisioning proposal has been
--     applied, including stockwise_owner and stockwise_migrator.
--   * A trusted role administrator and stockwise_migrator identity have been
--     independently reviewed. No Supabase API role is a member of either role.
--
-- The only role membership added here lets the controlled migrator SET ROLE
-- while creating objects. It does not grant any role to authenticator,
-- authenticated, anon, service_role, or a runtime login.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'stockwise_migrator'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit
  ) THEN
    RAISE EXCEPTION 'Reviewed stockwise_migrator role is required';
  END IF;
  IF pg_catalog.to_regrole('stockwise_product_writer') IS NOT NULL
     OR pg_catalog.to_regrole('stockwise_inventory_writer') IS NOT NULL THEN
    RAISE EXCEPTION 'A write-owner role already exists; inspect it instead of replacing it';
  END IF;
  IF pg_catalog.to_regnamespace('stockwise') IS NULL
     OR pg_catalog.to_regnamespace('stockwise_api') IS NULL
     OR pg_catalog.to_regnamespace('stockwise_private') IS NULL THEN
    RAISE EXCEPTION 'Base and approved read-proposal schemas are required';
  END IF;
END
$preflight$;

CREATE ROLE stockwise_product_writer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE stockwise_inventory_writer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;

GRANT stockwise_product_writer TO stockwise_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT stockwise_inventory_writer TO stockwise_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

ALTER DEFAULT PRIVILEGES FOR ROLE stockwise_product_writer
  IN SCHEMA stockwise_api REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE stockwise_inventory_writer
  IN SCHEMA stockwise_api REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

DO $postflight$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname IN ('stockwise_product_writer','stockwise_inventory_writer')
      AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole
           OR rolcreatedb OR rolinherit OR rolreplication)
  ) THEN
    RAISE EXCEPTION 'A write function-owner role has an unsafe role attribute';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
    JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = m.roleid
    WHERE granted_role.rolname IN (
      'stockwise_product_writer','stockwise_inventory_writer')
      AND member_role.rolname <> 'stockwise_migrator'
  ) THEN
    RAISE EXCEPTION 'A runtime or unexpected role can assume a write function-owner role';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND (pg_catalog.pg_has_role(api.oid,'stockwise_product_writer','MEMBER')
        OR pg_catalog.pg_has_role(api.oid,'stockwise_inventory_writer','MEMBER'))
  ) THEN
    RAISE EXCEPTION 'A Supabase API role can assume a write function-owner role';
  END IF;
END
$postflight$;

COMMIT;
