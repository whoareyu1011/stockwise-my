-- PREPARED FOR REVIEW ONLY. No Supabase execution is authorized.
-- Cluster-scoped roles: run only on an explicitly approved target.
-- Use the same administrative current_user for files 01 and 02.
-- No passwords, login roles, schema objects or runtime permissions are created.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
BEGIN
  IF pg_catalog.current_setting('server_version_num')::integer / 10000 <> 17 THEN
    RAISE EXCEPTION 'This provisioning package requires reviewed PostgreSQL 17';
  END IF;
  IF current_user IN ('anon','authenticated','service_role','authenticator',
                      'stockwise_owner','stockwise_migrator') THEN
    RAISE EXCEPTION 'Use a separately approved administrative provisioning role';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname=current_user AND (rolcreaterole OR rolsuper)
  ) THEN
    RAISE EXCEPTION 'Provisioning operator needs approved CREATEROLE capability';
  END IF;
  IF pg_catalog.to_regrole('stockwise_owner') IS NOT NULL
     OR pg_catalog.to_regrole('stockwise_migrator') IS NOT NULL THEN
    RAISE EXCEPTION 'StockWise role name already exists; inspect, do not overwrite';
  END IF;
  IF pg_catalog.to_regnamespace('stockwise') IS NOT NULL THEN
    RAISE EXCEPTION 'stockwise schema already exists; inspect deployment state';
  END IF;
END;
$preflight$;

CREATE ROLE stockwise_owner NOLOGIN NOSUPERUSER NOBYPASSRLS
  NOCREATEROLE NOCREATEDB NOINHERIT NOREPLICATION;
CREATE ROLE stockwise_migrator NOLOGIN NOSUPERUSER NOBYPASSRLS
  NOCREATEROLE NOCREATEDB NOINHERIT NOREPLICATION;

-- PostgreSQL 17 automatically gives a non-superuser role creator an
-- administrative membership in each created role. File 02 makes all intended
-- membership options explicit; no API/runtime membership is ever granted.
COMMIT;
