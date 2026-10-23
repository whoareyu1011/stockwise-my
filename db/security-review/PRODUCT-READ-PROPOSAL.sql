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
--
-- Required separately approved prerequisites:
--   * NOLOGIN, NOBYPASSRLS roles stockwise_auth_owner and
--     stockwise_product_reader; only stockwise_migrator may SET into them.
--   * stockwise_migrator has explicit SET membership in stockwise_owner,
--     stockwise_auth_owner, and stockwise_product_reader.
--   * stockwise_auth_owner has only the approved REFERENCES/EXECUTE access
--     required for stockwise.companies, auth.users, and auth.uid().
--   * stockwise_product_reader has no login, no BYPASSRLS, no role memberships,
--     and no direct callers other than the owned API function.
--   * Only stockwise_api is configured as an exposed Supabase Data API schema.
--
-- The first Owner must be provisioned separately by a trusted operator after
-- verifying the Supabase Auth identity and company. There is no self-service
-- bootstrap path in this proposal.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
DECLARE
  v_role text;
BEGIN
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

  IF NOT pg_catalog.pg_has_role(session_user, 'stockwise_owner', 'SET')
     OR NOT pg_catalog.pg_has_role(session_user, 'stockwise_auth_owner', 'SET')
     OR NOT pg_catalog.pg_has_role(session_user, 'stockwise_product_reader', 'SET') THEN
    RAISE EXCEPTION 'Migration session needs explicit SET membership in each owner role';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles r
    WHERE r.rolname IN ('stockwise_owner','stockwise_auth_owner','stockwise_product_reader')
      AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb
           OR r.rolcreaterole OR r.rolinherit)
  ) THEN
    RAISE EXCEPTION 'Object-owner roles must be restricted NOLOGIN/NOBYPASS roles';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles target ON target.oid = m.member
    WHERE target.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
  ) THEN
    RAISE EXCEPTION 'Function-owner roles must not be members of other roles';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
    JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
    WHERE granted.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND member_role.rolname IN ('anon','authenticated','service_role','authenticator')
  ) THEN
    RAISE EXCEPTION 'Supabase API roles must not be members of function-owner roles';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles granted ON granted.oid = m.roleid
    JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
    WHERE granted.rolname IN ('stockwise_auth_owner','stockwise_product_reader')
      AND member_role.rolname <> 'stockwise_migrator'
  ) THEN
    RAISE EXCEPTION 'Only the migration role may SET into function-owner roles';
  END IF;

  IF NOT pg_catalog.has_table_privilege(
       'stockwise_auth_owner','stockwise.companies','REFERENCES')
     OR NOT pg_catalog.has_table_privilege(
       'stockwise_auth_owner','auth.users','REFERENCES')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','stockwise','USAGE')
     OR NOT pg_catalog.has_schema_privilege(
       'stockwise_auth_owner','auth','USAGE')
     OR NOT pg_catalog.has_function_privilege(
       'stockwise_auth_owner','auth.uid()','EXECUTE') THEN
    RAISE EXCEPTION 'Auth-owner REFERENCES/uid privileges require separate review';
  END IF;
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

-- The migrator has database CREATE and SET rights only through separately
-- approved grants. It creates schemas for their intended NOLOGIN owners.
SET LOCAL ROLE stockwise_migrator;
CREATE SCHEMA stockwise_private AUTHORIZATION stockwise_auth_owner;
CREATE SCHEMA stockwise_api AUTHORIZATION stockwise_owner;
RESET ROLE;

SET LOCAL ROLE stockwise_auth_owner;
REVOKE ALL ON SCHEMA stockwise_private
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
REVOKE ALL ON ALL TABLES IN SCHEMA stockwise_private
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
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
  FROM PUBLIC, anon, authenticated, service_role;

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
REVOKE ALL ON FUNCTION stockwise_private.current_company_role(uuid)
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
GRANT USAGE ON SCHEMA stockwise_private TO stockwise_product_reader;
GRANT EXECUTE ON FUNCTION stockwise_private.current_company_role(uuid)
  TO stockwise_product_reader;
RESET ROLE;

SET LOCAL ROLE stockwise_owner;
REVOKE ALL ON SCHEMA stockwise_api
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
REVOKE ALL ON SCHEMA stockwise
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA stockwise
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
REVOKE ALL ON ALL TABLES IN SCHEMA stockwise
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA stockwise
  FROM PUBLIC, anon, authenticated, service_role, authenticator;

GRANT USAGE ON SCHEMA stockwise TO stockwise_product_reader;
GRANT SELECT (
  id, company_id, sku, name, category, unit_code, classification_code,
  unit_cost, selling_price, low_stock_threshold, is_active
) ON stockwise.products TO stockwise_product_reader;
GRANT SELECT (company_id, product_id, quantity)
  ON stockwise.stock_balances TO stockwise_product_reader;

CREATE POLICY products_member_read
  ON stockwise.products
  FOR SELECT TO stockwise_product_reader
  USING (stockwise_private.current_company_role(company_id) IS NOT NULL);
CREATE POLICY balances_member_read
  ON stockwise.stock_balances
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
  IF v_role IS NULL THEN
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
-- service_role remain denied. Dashboard Data API schema exposure still needs
-- separate review and must expose stockwise_api without exposing stockwise or
-- stockwise_private.

COMMIT;
