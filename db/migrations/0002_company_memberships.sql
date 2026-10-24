-- StockWise MY: company membership foundation. PREPARED ONLY -- NOT APPLIED.
-- Apply only after the independently reviewed 0001_inventory.sql.
-- This migration grants authenticated users read access to their own membership
-- rows only. It does not grant access to any business table or create onboarding
-- or membership-management functions.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
DECLARE
  v_table text;
  v_rel regclass;
BEGIN
  IF pg_catalog.to_regnamespace('stockwise') IS NULL
     OR pg_catalog.to_regclass('stockwise.companies') IS NULL
     OR pg_catalog.to_regprocedure('stockwise.touch_updated_at()') IS NULL THEN
    RAISE EXCEPTION 'Migration 0001 inventory schema is required';
  END IF;
  IF pg_catalog.to_regclass('stockwise.company_memberships') IS NOT NULL THEN
    RAISE EXCEPTION 'stockwise.company_memberships already exists; inspect migration state';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'stockwise_owner'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit
  ) OR NOT pg_catalog.pg_has_role(current_user, 'stockwise_owner', 'MEMBER') THEN
    RAISE EXCEPTION 'Approved stockwise_owner role and migration membership are required';
  END IF;
  IF (
    SELECT pg_catalog.count(*) FROM pg_catalog.pg_roles
    WHERE rolname IN ('anon','authenticated','service_role','authenticator')
  ) <> 4 THEN
    RAISE EXCEPTION 'Expected Supabase API roles are required; roles are never created here';
  END IF;
  IF pg_catalog.pg_has_role('authenticated','stockwise_owner','MEMBER')
     OR pg_catalog.pg_has_role('anon','stockwise_owner','MEMBER')
     OR pg_catalog.pg_has_role('service_role','stockwise_owner','MEMBER')
     OR pg_catalog.pg_has_role('authenticator','stockwise_owner','MEMBER') THEN
    RAISE EXCEPTION 'Supabase API roles must not inherit stockwise_owner';
  END IF;
  IF pg_catalog.to_regclass('auth.users') IS NULL
     OR pg_catalog.to_regprocedure('auth.uid()') IS NULL THEN
    RAISE EXCEPTION 'Supabase Auth users table and auth.uid() are required';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute
    WHERE attrelid = pg_catalog.to_regclass('auth.users')
      AND attname = 'id' AND atttypid = 'uuid'::pg_catalog.regtype
      AND NOT attisdropped
  ) THEN
    RAISE EXCEPTION 'auth.users.id must be UUID';
  END IF;
  IF NOT pg_catalog.has_schema_privilege('stockwise_owner','auth','USAGE')
     OR NOT pg_catalog.has_table_privilege('stockwise_owner','auth.users','REFERENCES') THEN
    RAISE EXCEPTION 'stockwise_owner needs pre-approved USAGE on auth and REFERENCES on auth.users';
  END IF;
  IF NOT pg_catalog.has_schema_privilege('authenticated','auth','USAGE')
     OR NOT pg_catalog.has_function_privilege('authenticated','auth.uid()','EXECUTE') THEN
    RAISE EXCEPTION 'authenticated must be able to call the existing auth.uid() identity helper';
  END IF;

  -- This migration intentionally does not make the existing business tables
  -- readable. Abort rather than broadening schema visibility over unexpected
  -- grants or permissive policies.
  FOREACH v_table IN ARRAY ARRAY[
    'companies','products','contacts','orders','order_items',
    'stock_balances','stock_movements','audit_logs'
  ] LOOP
    v_rel := pg_catalog.to_regclass('stockwise.' || v_table);
    IF v_rel IS NULL OR NOT (
      SELECT c.relrowsecurity
      FROM pg_catalog.pg_class c WHERE c.oid = v_rel
    ) THEN
      RAISE EXCEPTION 'Expected RLS-enabled stockwise.% from migration 0001', v_table;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = v_rel) THEN
      RAISE EXCEPTION 'Unexpected existing policy on stockwise.%; review before continuing', v_table;
    END IF;
    IF pg_catalog.has_table_privilege('authenticated',v_rel,'SELECT')
       OR pg_catalog.has_table_privilege('authenticated',v_rel,'INSERT')
       OR pg_catalog.has_table_privilege('authenticated',v_rel,'UPDATE')
       OR pg_catalog.has_table_privilege('authenticated',v_rel,'DELETE')
       OR pg_catalog.has_table_privilege('authenticated',v_rel,'TRUNCATE') THEN
      RAISE EXCEPTION 'authenticated already has direct access to stockwise.%; review grants first', v_table;
    END IF;
  END LOOP;
END;
$preflight$;

SET LOCAL ROLE stockwise_owner;

CREATE TABLE stockwise.company_memberships (
  company_id uuid NOT NULL
    REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  -- Stable Supabase Auth user UUID (auth.users.id). The issuer is fixed by the
  -- trusted project configuration and must be checked by the server adapter.
  user_id uuid NOT NULL
    REFERENCES auth.users(id) ON DELETE RESTRICT,
  role text NOT NULL
    CHECK (role IN ('Owner','Admin','Staff','Viewer')),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','inactive')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (company_id, user_id)
);

-- At most one active Owner per company. Membership insertion and role changes
-- remain unavailable to API roles; ownership transfer needs a separate design.
CREATE UNIQUE INDEX company_memberships_one_active_owner_uq
  ON stockwise.company_memberships (company_id)
  WHERE role = 'Owner' AND status = 'active';
CREATE INDEX company_memberships_user_active_idx
  ON stockwise.company_memberships (user_id, company_id)
  WHERE status = 'active';

CREATE TRIGGER company_memberships_updated
  BEFORE UPDATE ON stockwise.company_memberships
  FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();

ALTER TABLE stockwise.company_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY company_memberships_read_self
  ON stockwise.company_memberships
  FOR SELECT TO authenticated
  USING (user_id = (SELECT auth.uid()));

REVOKE ALL ON TABLE stockwise.company_memberships
  FROM PUBLIC, anon, authenticated, service_role, authenticator;
GRANT USAGE ON SCHEMA stockwise TO authenticated;
GRANT SELECT ON TABLE stockwise.company_memberships TO authenticated;

COMMENT ON TABLE stockwise.company_memberships IS
  'Company membership mapping for Supabase Auth UUIDs; authenticated users may read only their own rows. Membership writes require a separately reviewed trusted workflow.';
COMMENT ON COLUMN stockwise.company_memberships.user_id IS
  'Stable UUID from auth.users.id; never accepted as authority from browser input.';
COMMENT ON COLUMN stockwise.company_memberships.role IS
  'Company role: Owner, Admin, Staff, or Viewer. Read-only membership exposure does not grant business-table access.';
COMMENT ON COLUMN stockwise.company_memberships.status IS
  'Active memberships may authorize future reviewed operations; inactive memberships must be denied.';

COMMIT;
