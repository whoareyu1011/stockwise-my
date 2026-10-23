-- REVIEW-ONLY, ADDITIVE PROPOSAL. DO NOT EXECUTE.
--
-- Depends on:
--   1. db/migrations/0001_inventory.sql;
--   2. approved deployment role prerequisites and function-default hardening;
--   3. PRODUCT-READ-ROLE-PROVISIONING-PROPOSAL.sql;
--   4. PRODUCT-READ-PROPOSAL.sql (including its numeric-as-text correction);
--   5. PRODUCT-WRITE-ROLE-PROVISIONING-PROPOSAL.sql.
--
-- This is not a migration run by npm start. No API grant, RLS policy, role,
-- function, or table from this proposal has been applied or PostgreSQL-tested.
--
-- Trust model:
--   * Public RPC callers are authenticated Supabase users; auth.uid() is read
--     from the same user JWT forwarded by the request-scoped Data API client.
--   * The function-owner roles are NOLOGIN/NOBYPASSRLS and are not granted to
--     Supabase API roles. They receive only the table columns and RPC grants
--     needed for their respective commands.
--   * The only write path is a single RPC transaction. The RPC locks and checks
--     company membership in PostgreSQL, performs the mutation, writes the
--     actor-attributed private audit event and stores the idempotent response.
--   * stockwise.post_order remains the sole inventory-ledger posting path.
--     Its existing movement trigger updates stock_balances atomically and
--     rejects a balance that would become negative. This proposal never grants
--     API roles direct table access or balance-update access.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '90s';

DO $preflight$
BEGIN
  IF pg_catalog.to_regnamespace('stockwise') IS NULL
     OR pg_catalog.to_regnamespace('stockwise_api') IS NULL
     OR pg_catalog.to_regnamespace('stockwise_private') IS NULL
     OR pg_catalog.to_regprocedure('stockwise_private.current_company_role(uuid)') IS NULL
     OR pg_catalog.to_regprocedure('stockwise.post_order(uuid,uuid,uuid)') IS NULL THEN
    RAISE EXCEPTION 'Base inventory and approved product-read proposals are required';
  END IF;
  IF pg_catalog.to_regclass('stockwise_private.company_memberships') IS NULL THEN
    RAISE EXCEPTION 'Approved company-membership table is required';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'stockwise_product_writer'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'stockwise_inventory_writer'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'stockwise_auth_owner'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
  ) THEN
    RAISE EXCEPTION 'Separately reviewed NOLOGIN function-owner roles are required';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles api
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND (pg_catalog.pg_has_role(api.oid,'stockwise_product_writer','MEMBER')
        OR pg_catalog.pg_has_role(api.oid,'stockwise_inventory_writer','MEMBER')
        OR pg_catalog.pg_has_role(api.oid,'stockwise_auth_owner','MEMBER'))
  ) THEN
    RAISE EXCEPTION 'A Supabase API role can assume a protected function-owner role';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='stockwise_api'
      AND p.proname IN ('get_product','create_product','update_product',
                        'archive_product','adjust_stock')
  ) THEN
    RAISE EXCEPTION 'A proposed RPC name already exists; inspect every overload';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='stockwise'
      AND c.relname IN ('products','stock_balances','orders','order_items')
      AND (NOT c.relrowsecurity OR c.relowner <> 'stockwise_owner'::regrole)
  ) THEN
    RAISE EXCEPTION 'Protected table owner or RLS state differs from the reviewed base migration';
  END IF;
END
$preflight$;

SET LOCAL ROLE stockwise_owner;
GRANT REFERENCES (company_id,id) ON stockwise.products TO stockwise_auth_owner;
GRANT REFERENCES (company_id,id) ON stockwise.orders TO stockwise_auth_owner;
RESET ROLE;

-- Private idempotency and user-audit tables have no API grants and no RLS
-- policies. Only the narrowly scoped auth-owner helper functions access them.
SET LOCAL ROLE stockwise_auth_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise_private
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE stockwise_private.command_results (
  company_id uuid NOT NULL
    REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  auth_user_id uuid NOT NULL
    REFERENCES auth.users(id) ON DELETE RESTRICT,
  command text NOT NULL CHECK (
    command IN ('product.create','product.update','product.archive','stock.adjust')),
  idempotency_key text NOT NULL CHECK (
    idempotency_key ~ '^[A-Za-z0-9._~-]{8,128}$'),
  request_payload jsonb NOT NULL CHECK (
    pg_catalog.jsonb_typeof(request_payload)='object'),
  response_payload jsonb NOT NULL CHECK (
    pg_catalog.jsonb_typeof(response_payload)='object'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (company_id,auth_user_id,command,idempotency_key)
);
ALTER TABLE stockwise_private.command_results ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON stockwise_private.command_results
  FROM PUBLIC,anon,authenticated,service_role,authenticator,
       stockwise_product_reader,stockwise_product_writer,
       stockwise_inventory_writer;

CREATE TABLE stockwise_private.user_audit_events (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL
    REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  actor_auth_user_id uuid NOT NULL
    REFERENCES auth.users(id) ON DELETE RESTRICT,
  action text NOT NULL CHECK (
    action IN ('product_created','product_updated','product_archived','stock_adjusted')),
  target_kind text NOT NULL CHECK (target_kind IN ('product','order')),
  target_product_id uuid,
  target_order_id uuid,
  details jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(details)='object'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  CHECK (
    (target_kind='product' AND target_product_id IS NOT NULL AND target_order_id IS NULL)
    OR
    (target_kind='order' AND target_order_id IS NOT NULL AND target_product_id IS NULL)
  ),
  CHECK (
    (action='stock_adjusted' AND target_kind='order')
    OR
    (action<>'stock_adjusted' AND target_kind='product')
  ),
  FOREIGN KEY (company_id,target_product_id)
    REFERENCES stockwise.products(company_id,id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id,target_order_id)
    REFERENCES stockwise.orders(company_id,id) ON DELETE RESTRICT
);
CREATE INDEX user_audit_events_company_time_idx
  ON stockwise_private.user_audit_events(company_id,created_at DESC);
ALTER TABLE stockwise_private.user_audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON stockwise_private.user_audit_events
  FROM PUBLIC,anon,authenticated,service_role,authenticator,
       stockwise_product_reader,stockwise_product_writer,
       stockwise_inventory_writer;

CREATE FUNCTION stockwise_private.lock_company_role(p_company_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role text;
  v_user_id uuid := auth.uid();
BEGIN
  IF p_company_id IS NULL OR v_user_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  SELECT m.role INTO v_role
  FROM stockwise_private.company_memberships AS m
  WHERE m.company_id=p_company_id
    AND m.auth_user_id=v_user_id
    AND m.status='active'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  RETURN v_role;
END
$function$;

CREATE FUNCTION stockwise_private.begin_command(
  p_company_id uuid,p_command text,p_key text,p_payload jsonb
)
RETURNS TABLE(is_replay boolean,prior_response jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_user_id uuid := auth.uid();
  v_payload jsonb;
  v_response jsonb;
BEGIN
  IF v_user_id IS NULL OR p_company_id IS NULL
     OR p_command NOT IN ('product.create','product.update','product.archive','stock.adjust')
     OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9._~-]{8,128}$'
     OR p_payload IS NULL OR pg_catalog.jsonb_typeof(p_payload)<>'object' THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid command';
  END IF;
  -- Hash collisions only serialize unrelated requests; the table's full unique
  -- key remains authoritative. Transaction-scoped lock survives through commit.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
    p_company_id::text||':'||v_user_id::text||':'||p_command||':'||p_key,0));
  SELECT r.request_payload,r.response_payload
    INTO v_payload,v_response
  FROM stockwise_private.command_results AS r
  WHERE r.company_id=p_company_id AND r.auth_user_id=v_user_id
    AND r.command=p_command AND r.idempotency_key=p_key;
  IF FOUND THEN
    IF v_payload IS DISTINCT FROM p_payload THEN
      RAISE EXCEPTION USING ERRCODE='PZ001', MESSAGE='idempotency key conflict';
    END IF;
    RETURN QUERY SELECT true,v_response;
    RETURN;
  END IF;
  RETURN QUERY SELECT false,NULL::jsonb;
END
$function$;

CREATE FUNCTION stockwise_private.finish_command(
  p_company_id uuid,p_command text,p_key text,p_payload jsonb,p_response jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE v_user_id uuid := auth.uid();
BEGIN
  IF v_user_id IS NULL OR p_company_id IS NULL
     OR p_command NOT IN ('product.create','product.update','product.archive','stock.adjust')
     OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9._~-]{8,128}$'
     OR p_payload IS NULL OR pg_catalog.jsonb_typeof(p_payload)<>'object'
     OR p_response IS NULL
     OR pg_catalog.jsonb_typeof(p_response)<>'object' THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid command result';
  END IF;
  PERFORM stockwise_private.lock_company_role(p_company_id);
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
    p_company_id::text||':'||v_user_id::text||':'||p_command||':'||p_key,0));
  INSERT INTO stockwise_private.command_results(
    company_id,auth_user_id,command,idempotency_key,request_payload,response_payload
  ) VALUES(p_company_id,v_user_id,p_command,p_key,p_payload,p_response);
END
$function$;

CREATE FUNCTION stockwise_private.record_user_event(
  p_company_id uuid,p_action text,p_target_kind text,
  p_target_product_id uuid,p_target_order_id uuid,p_details jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE v_role text;
BEGIN
  v_role := stockwise_private.lock_company_role(p_company_id);
  IF v_role NOT IN ('Owner','Admin')
     OR p_action NOT IN ('product_created','product_updated','product_archived','stock_adjusted')
     OR p_details IS NULL OR pg_catalog.jsonb_typeof(p_details)<>'object' THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  INSERT INTO stockwise_private.user_audit_events(
    company_id,actor_auth_user_id,action,target_kind,
    target_product_id,target_order_id,details
  ) VALUES(
    p_company_id,auth.uid(),p_action,p_target_kind,
    p_target_product_id,p_target_order_id,p_details
  );
END
$function$;

CREATE FUNCTION stockwise_private.validate_product_payload(
  p_payload jsonb,p_partial boolean
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE v_key text;
BEGIN
  IF p_payload IS NULL OR pg_catalog.jsonb_typeof(p_payload)<>'object'
     OR (p_partial AND p_payload='{}'::jsonb)
     OR (p_payload - ARRAY[
       'sku','name','category','unit_code','selling_price','cost_price',
       'low_stock_threshold','classification_code'
     ]) <> '{}'::jsonb
     OR (NOT p_partial AND (NOT (p_payload ? 'sku') OR NOT (p_payload ? 'name'))) THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid product';
  END IF;
  FOREACH v_key IN ARRAY ARRAY['sku','name','category','unit_code'] LOOP
    IF p_payload ? v_key THEN
      IF pg_catalog.jsonb_typeof(p_payload->v_key)<>'string'
          OR p_payload->>v_key <> pg_catalog.btrim(p_payload->>v_key)
          OR p_payload->>v_key ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid product';
      END IF;
    END IF;
  END LOOP;
  IF (p_payload ? 'sku' AND (pg_catalog.length(p_payload->>'sku') NOT BETWEEN 1 AND 128))
     OR (p_payload ? 'name' AND (
       pg_catalog.length(pg_catalog.btrim(p_payload->>'name')) NOT BETWEEN 1 AND 255))
     OR (p_payload ? 'category' AND pg_catalog.length(p_payload->>'category')>120)
     OR (p_payload ? 'unit_code' AND pg_catalog.length(p_payload->>'unit_code') NOT BETWEEN 1 AND 16) THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid product';
  END IF;
  FOREACH v_key IN ARRAY ARRAY['selling_price','cost_price'] LOOP
    IF p_payload ? v_key AND (
      pg_catalog.jsonb_typeof(p_payload->v_key)<>'string'
      OR p_payload->>v_key !~ '^(0|[1-9][0-9]{0,13})([.][0-9]{1,6})?$'
    ) THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid product amount';
    END IF;
  END LOOP;
  IF p_payload ? 'low_stock_threshold' AND (
    pg_catalog.jsonb_typeof(p_payload->'low_stock_threshold')<>'number'
    OR p_payload->>'low_stock_threshold' !~ '^(0|[1-9][0-9]{0,15})$'
    OR (p_payload->>'low_stock_threshold')::numeric>9007199254740991
  ) THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid stock threshold';
  END IF;
  IF p_payload ? 'classification_code' AND
     pg_catalog.jsonb_typeof(p_payload->'classification_code') NOT IN ('string','null') THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid classification';
  END IF;
  IF p_payload ? 'classification_code'
     AND p_payload->'classification_code'<>'null'::jsonb
      AND (pg_catalog.length(p_payload->>'classification_code')>64
           OR p_payload->>'classification_code' ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid classification';
  END IF;
END
$function$;

REVOKE ALL ON FUNCTION stockwise_private.lock_company_role(uuid)
  FROM PUBLIC,anon,authenticated,service_role,authenticator,
       stockwise_product_reader;
REVOKE ALL ON FUNCTION stockwise_private.begin_command(uuid,text,text,jsonb)
  FROM PUBLIC,anon,authenticated,service_role,authenticator,stockwise_product_reader;
REVOKE ALL ON FUNCTION stockwise_private.finish_command(uuid,text,text,jsonb,jsonb)
  FROM PUBLIC,anon,authenticated,service_role,authenticator,stockwise_product_reader;
REVOKE ALL ON FUNCTION stockwise_private.record_user_event(uuid,text,text,uuid,uuid,jsonb)
  FROM PUBLIC,anon,authenticated,service_role,authenticator,stockwise_product_reader;
REVOKE ALL ON FUNCTION stockwise_private.validate_product_payload(jsonb,boolean)
  FROM PUBLIC,anon,authenticated,service_role,authenticator,stockwise_product_reader;
GRANT USAGE ON SCHEMA stockwise_private TO stockwise_product_writer,stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise_private.lock_company_role(uuid)
  TO stockwise_product_writer,stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise_private.current_company_role(uuid)
  TO stockwise_product_writer,stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise_private.begin_command(uuid,text,text,jsonb)
  TO stockwise_product_writer,stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise_private.finish_command(uuid,text,text,jsonb,jsonb)
  TO stockwise_product_writer,stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise_private.record_user_event(uuid,text,text,uuid,uuid,jsonb)
  TO stockwise_product_writer,stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise_private.validate_product_payload(jsonb,boolean)
  TO stockwise_product_writer;
RESET ROLE;

-- Least-privilege table rights; RLS still applies to these non-owner,
-- non-BYPASSRLS function roles.
SET LOCAL ROLE stockwise_owner;
GRANT USAGE ON SCHEMA stockwise TO stockwise_product_writer,stockwise_inventory_writer;
GRANT USAGE,CREATE ON SCHEMA stockwise_api TO stockwise_product_writer,stockwise_inventory_writer;
GRANT SELECT (
  id,company_id,sku,name,category,unit_code,classification_code,unit_cost,
  selling_price,low_stock_threshold,is_active
) ON stockwise.products TO stockwise_product_writer;
GRANT INSERT (
  id,company_id,sku,name,category,unit_code,unit_cost,selling_price,
  low_stock_threshold,classification_code
) ON stockwise.products TO stockwise_product_writer;
GRANT UPDATE (
  sku,name,category,unit_code,unit_cost,selling_price,low_stock_threshold,
  classification_code,is_active
) ON stockwise.products TO stockwise_product_writer;
GRANT SELECT (company_id,product_id,quantity)
  ON stockwise.stock_balances TO stockwise_product_writer;

GRANT SELECT (id,company_id,is_active)
  ON stockwise.products TO stockwise_inventory_writer;
GRANT SELECT (company_id,product_id,quantity)
  ON stockwise.stock_balances TO stockwise_inventory_writer;
GRANT SELECT (company_id,id,status,kind)
  ON stockwise.orders TO stockwise_inventory_writer;
-- The base guard_order_item trigger locks its parent with SELECT ... FOR UPDATE.
-- PostgreSQL requires UPDATE privilege on at least one parent column for that
-- lock; only notes is granted, and no API function exposes a notes update.
GRANT UPDATE (notes) ON stockwise.orders TO stockwise_inventory_writer;
GRANT SELECT (id,company_id,order_id,kind,product_id)
  ON stockwise.stock_movements TO stockwise_inventory_writer;
GRANT INSERT (id,company_id,reference,kind,business_date,notes)
  ON stockwise.orders TO stockwise_inventory_writer;
GRANT INSERT (
  id,company_id,order_id,product_id,line_number,quantity,unit_price,discount
) ON stockwise.order_items TO stockwise_inventory_writer;
GRANT EXECUTE ON FUNCTION stockwise.post_order(uuid,uuid,uuid)
  TO stockwise_inventory_writer;

CREATE POLICY products_writer_read
  ON stockwise.products AS PERMISSIVE FOR SELECT
  TO stockwise_product_writer USING (
    stockwise_private.current_company_role(company_id) IS NOT NULL
  );
CREATE POLICY products_writer_read_company
  ON stockwise.products AS RESTRICTIVE FOR SELECT
  TO stockwise_product_writer USING (
    stockwise_private.current_company_role(company_id) IS NOT NULL
  );
CREATE POLICY products_writer_insert
  ON stockwise.products AS PERMISSIVE FOR INSERT
  TO stockwise_product_writer WITH CHECK (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY products_writer_insert_company
  ON stockwise.products AS RESTRICTIVE FOR INSERT
  TO stockwise_product_writer WITH CHECK (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY products_writer_update
  ON stockwise.products AS PERMISSIVE FOR UPDATE
  TO stockwise_product_writer
  USING (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'))
  WITH CHECK (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'));
CREATE POLICY products_writer_update_company
  ON stockwise.products AS RESTRICTIVE FOR UPDATE
  TO stockwise_product_writer
  USING (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'))
  WITH CHECK (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'));
CREATE POLICY balances_writer_read
  ON stockwise.stock_balances AS PERMISSIVE FOR SELECT
  TO stockwise_product_writer USING (
    stockwise_private.current_company_role(company_id) IS NOT NULL
  );
CREATE POLICY balances_writer_read_company
  ON stockwise.stock_balances AS RESTRICTIVE FOR SELECT
  TO stockwise_product_writer USING (
    stockwise_private.current_company_role(company_id) IS NOT NULL
  );

CREATE POLICY products_inventory_read
  ON stockwise.products AS PERMISSIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY products_inventory_read_company
  ON stockwise.products AS RESTRICTIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY balances_inventory_read
  ON stockwise.stock_balances AS PERMISSIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY balances_inventory_read_company
  ON stockwise.stock_balances AS RESTRICTIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY movements_inventory_read
  ON stockwise.stock_movements AS PERMISSIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY movements_inventory_read_company
  ON stockwise.stock_movements AS RESTRICTIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY orders_inventory_insert
  ON stockwise.orders AS PERMISSIVE FOR INSERT
  TO stockwise_inventory_writer WITH CHECK (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY orders_inventory_insert_company
  ON stockwise.orders AS RESTRICTIVE FOR INSERT
  TO stockwise_inventory_writer WITH CHECK (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY orders_inventory_read
  ON stockwise.orders AS PERMISSIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY orders_inventory_read_company
  ON stockwise.orders AS RESTRICTIVE FOR SELECT
  TO stockwise_inventory_writer USING (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY orders_inventory_parent_lock
  ON stockwise.orders AS PERMISSIVE FOR UPDATE
  TO stockwise_inventory_writer
  USING (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'))
  WITH CHECK (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'));
CREATE POLICY orders_inventory_parent_lock_company
  ON stockwise.orders AS RESTRICTIVE FOR UPDATE
  TO stockwise_inventory_writer
  USING (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'))
  WITH CHECK (stockwise_private.current_company_role(company_id) IN ('Owner','Admin'));
CREATE POLICY order_items_inventory_insert
  ON stockwise.order_items AS PERMISSIVE FOR INSERT
  TO stockwise_inventory_writer WITH CHECK (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
CREATE POLICY order_items_inventory_insert_company
  ON stockwise.order_items AS RESTRICTIVE FOR INSERT
  TO stockwise_inventory_writer WITH CHECK (
    stockwise_private.current_company_role(company_id) IN ('Owner','Admin')
  );
RESET ROLE;

-- Create product RPCs under the restricted owner. No defaults are used on RPC
-- args, avoiding PostgREST overload/default-argument resolution ambiguity.
SET LOCAL ROLE stockwise_product_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise_api
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION stockwise_api.get_product(p_company_id uuid,p_product_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE v_role text; v_row record;
BEGIN
  v_role := stockwise_private.lock_company_role(p_company_id);
  SELECT p.id,p.sku,p.name,p.category,p.unit_code,p.is_active,b.quantity,
         p.selling_price,p.unit_cost,p.low_stock_threshold,p.classification_code
    INTO v_row
  FROM stockwise.products p
  JOIN stockwise.stock_balances b
    ON b.company_id=p.company_id AND b.product_id=p.id
  WHERE p.company_id=p_company_id AND p.id=p_product_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='product not found';
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'id',v_row.id,'sku',v_row.sku,'name',v_row.name,'category',v_row.category,
    'unit_code',v_row.unit_code,'is_active',v_row.is_active,
    'stock_quantity',v_row.quantity::text
  ) || CASE
    WHEN v_role IN ('Owner','Admin') THEN pg_catalog.jsonb_build_object(
      'selling_price',v_row.selling_price::text,
      'cost_price',v_row.unit_cost::text,
      'low_stock_threshold',v_row.low_stock_threshold::text,
      'classification_code',v_row.classification_code)
    WHEN v_role='Staff' THEN pg_catalog.jsonb_build_object(
      'selling_price',v_row.selling_price::text,
      'low_stock_threshold',v_row.low_stock_threshold::text)
    ELSE '{}'::jsonb
  END;
END
$function$;

CREATE FUNCTION stockwise_api.create_product(
  p_company_id uuid,p_idempotency_key text,p_product jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role text; v_replay boolean; v_prior jsonb; v_id uuid;
  v_payload jsonb; v_result jsonb;
BEGIN
  v_role := stockwise_private.lock_company_role(p_company_id);
  IF v_role NOT IN ('Owner','Admin') THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  PERFORM stockwise_private.validate_product_payload(p_product,false);
  v_payload := pg_catalog.jsonb_build_object('product',p_product);
  SELECT b.is_replay,b.prior_response INTO v_replay,v_prior
    FROM stockwise_private.begin_command(
      p_company_id,'product.create',p_idempotency_key,v_payload) b;
  IF v_replay THEN RETURN v_prior; END IF;
  v_id := pg_catalog.gen_random_uuid();
  INSERT INTO stockwise.products(
    id,company_id,sku,name,category,unit_code,unit_cost,selling_price,
    low_stock_threshold,classification_code
  ) VALUES (
    v_id,p_company_id,p_product->>'sku',p_product->>'name',
    COALESCE(p_product->>'category',''),COALESCE(p_product->>'unit_code','EA'),
    COALESCE((p_product->>'cost_price')::numeric,0),
    COALESCE((p_product->>'selling_price')::numeric,0),
    COALESCE((p_product->>'low_stock_threshold')::bigint,0),
    p_product->>'classification_code'
  );
  PERFORM stockwise_private.record_user_event(
    p_company_id,'product_created','product',v_id,NULL,
    pg_catalog.jsonb_build_object('changed_fields',
      (SELECT COALESCE(pg_catalog.jsonb_agg(k),'[]'::jsonb)
       FROM pg_catalog.jsonb_object_keys(p_product) AS k))
  );
  v_result := stockwise_api.get_product(p_company_id,v_id);
  PERFORM stockwise_private.finish_command(
    p_company_id,'product.create',p_idempotency_key,v_payload,v_result);
  RETURN v_result;
END
$function$;

CREATE FUNCTION stockwise_api.update_product(
  p_company_id uuid,p_product_id uuid,p_idempotency_key text,p_changes jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role text; v_replay boolean; v_prior jsonb; v_payload jsonb; v_result jsonb;
  v_count bigint;
BEGIN
  v_role := stockwise_private.lock_company_role(p_company_id);
  IF v_role NOT IN ('Owner','Admin') THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  PERFORM stockwise_private.validate_product_payload(p_changes,true);
  v_payload := pg_catalog.jsonb_build_object(
    'product_id',p_product_id,'changes',p_changes);
  SELECT b.is_replay,b.prior_response INTO v_replay,v_prior
    FROM stockwise_private.begin_command(
      p_company_id,'product.update',p_idempotency_key,v_payload) b;
  IF v_replay THEN RETURN v_prior; END IF;
  UPDATE stockwise.products p SET
    sku=CASE WHEN p_changes ? 'sku' THEN p_changes->>'sku' ELSE p.sku END,
    name=CASE WHEN p_changes ? 'name' THEN p_changes->>'name' ELSE p.name END,
    category=CASE WHEN p_changes ? 'category' THEN p_changes->>'category' ELSE p.category END,
    unit_code=CASE WHEN p_changes ? 'unit_code' THEN p_changes->>'unit_code' ELSE p.unit_code END,
    unit_cost=CASE WHEN p_changes ? 'cost_price' THEN (p_changes->>'cost_price')::numeric ELSE p.unit_cost END,
    selling_price=CASE WHEN p_changes ? 'selling_price' THEN (p_changes->>'selling_price')::numeric ELSE p.selling_price END,
    low_stock_threshold=CASE WHEN p_changes ? 'low_stock_threshold' THEN (p_changes->>'low_stock_threshold')::bigint ELSE p.low_stock_threshold END,
    classification_code=CASE WHEN p_changes ? 'classification_code' THEN p_changes->>'classification_code' ELSE p.classification_code END
  WHERE p.company_id=p_company_id AND p.id=p_product_id AND p.is_active;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count<>1 THEN
    RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='product not found';
  END IF;
  PERFORM stockwise_private.record_user_event(
    p_company_id,'product_updated','product',p_product_id,NULL,
    pg_catalog.jsonb_build_object('changed_fields',
      (SELECT COALESCE(pg_catalog.jsonb_agg(k),'[]'::jsonb)
       FROM pg_catalog.jsonb_object_keys(p_changes) AS k))
  );
  v_result := stockwise_api.get_product(p_company_id,p_product_id);
  PERFORM stockwise_private.finish_command(
    p_company_id,'product.update',p_idempotency_key,v_payload,v_result);
  RETURN v_result;
END
$function$;

CREATE FUNCTION stockwise_api.archive_product(
  p_company_id uuid,p_product_id uuid,p_idempotency_key text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role text; v_replay boolean; v_prior jsonb; v_payload jsonb; v_result jsonb;
  v_count bigint;
BEGIN
  v_role := stockwise_private.lock_company_role(p_company_id);
  IF v_role NOT IN ('Owner','Admin') THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  v_payload := pg_catalog.jsonb_build_object('product_id',p_product_id);
  SELECT b.is_replay,b.prior_response INTO v_replay,v_prior
    FROM stockwise_private.begin_command(
      p_company_id,'product.archive',p_idempotency_key,v_payload) b;
  IF v_replay THEN RETURN v_prior; END IF;
  UPDATE stockwise.products SET is_active=false
  WHERE company_id=p_company_id AND id=p_product_id AND is_active;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count=0 AND NOT EXISTS (
    SELECT 1 FROM stockwise.products
    WHERE company_id=p_company_id AND id=p_product_id AND NOT is_active
  ) THEN
    RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='product not found';
  END IF;
  IF v_count=1 THEN
    PERFORM stockwise_private.record_user_event(
      p_company_id,'product_archived','product',p_product_id,NULL,
      pg_catalog.jsonb_build_object('changed_fields',pg_catalog.jsonb_build_array('is_active'))
    );
  END IF;
  v_result := pg_catalog.jsonb_build_object('id',p_product_id,'is_active',false);
  PERFORM stockwise_private.finish_command(
    p_company_id,'product.archive',p_idempotency_key,v_payload,v_result);
  RETURN v_result;
END
$function$;
RESET ROLE;

-- Grant the exact reader and writer RPC signatures. No direct API table grants.
SET LOCAL ROLE stockwise_owner;
GRANT USAGE ON SCHEMA stockwise_api TO authenticated;
RESET ROLE;
SET LOCAL ROLE stockwise_product_writer;
REVOKE ALL ON FUNCTION stockwise_api.get_product(uuid,uuid)
  FROM PUBLIC,anon,authenticated,service_role,authenticator;
REVOKE ALL ON FUNCTION stockwise_api.create_product(uuid,text,jsonb)
  FROM PUBLIC,anon,authenticated,service_role,authenticator;
REVOKE ALL ON FUNCTION stockwise_api.update_product(uuid,uuid,text,jsonb)
  FROM PUBLIC,anon,authenticated,service_role,authenticator;
REVOKE ALL ON FUNCTION stockwise_api.archive_product(uuid,uuid,text)
  FROM PUBLIC,anon,authenticated,service_role,authenticator;
GRANT EXECUTE ON FUNCTION stockwise_api.get_product(uuid,uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION stockwise_api.create_product(uuid,text,jsonb) TO authenticated;
GRANT EXECUTE ON FUNCTION stockwise_api.update_product(uuid,uuid,text,jsonb) TO authenticated;
GRANT EXECUTE ON FUNCTION stockwise_api.archive_product(uuid,uuid,text) TO authenticated;
RESET ROLE;

SET LOCAL ROLE stockwise_inventory_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise_api
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE FUNCTION stockwise_api.adjust_stock(
  p_company_id uuid,p_product_id uuid,p_direction text,p_quantity bigint,
  p_reason text,p_idempotency_key text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
  v_role text; v_replay boolean; v_prior jsonb; v_payload jsonb; v_result jsonb;
  v_before bigint; v_after bigint; v_order_id uuid; v_movement_id uuid;
  v_kind text; v_reference text; v_date date;
BEGIN
  v_role := stockwise_private.lock_company_role(p_company_id);
  IF v_role NOT IN ('Owner','Admin') THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='not authorized';
  END IF;
  IF p_direction NOT IN ('in','out') OR p_quantity IS NULL
     OR p_quantity<1 OR p_quantity>1000000000
     OR p_reason IS NULL OR pg_catalog.length(pg_catalog.btrim(p_reason)) NOT BETWEEN 3 AND 300
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid adjustment';
  END IF;
  v_payload := pg_catalog.jsonb_build_object(
    'product_id',p_product_id,'direction',p_direction,
    'quantity',p_quantity,'reason',pg_catalog.btrim(p_reason));
  SELECT b.is_replay,b.prior_response INTO v_replay,v_prior
    FROM stockwise_private.begin_command(
      p_company_id,'stock.adjust',p_idempotency_key,v_payload) b;
  IF v_replay THEN RETURN v_prior; END IF;

  PERFORM p.id FROM stockwise.products p
  WHERE p.company_id=p_company_id AND p.id=p_product_id AND p.is_active
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='active product not found';
  END IF;
  SELECT b.quantity INTO v_before
  FROM stockwise.stock_balances b
  WHERE b.company_id=p_company_id AND b.product_id=p_product_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='product balance not found';
  END IF;
  IF v_before>9007199254740991 THEN
    RAISE EXCEPTION USING ERRCODE='PZ003', MESSAGE='stock exceeds exact client range';
  END IF;
  IF p_direction='out' AND v_before<p_quantity THEN
    RAISE EXCEPTION USING ERRCODE='PZ002', MESSAGE='insufficient stock';
  END IF;
  IF p_direction='in'
     AND v_before::numeric+p_quantity::numeric>9007199254740991 THEN
    RAISE EXCEPTION USING ERRCODE='PZ003', MESSAGE='stock exceeds exact client range';
  END IF;
  v_after := CASE WHEN p_direction='in' THEN v_before+p_quantity ELSE v_before-p_quantity END;
  v_order_id := pg_catalog.gen_random_uuid();
  v_reference := 'ADJ-'||v_order_id::text;
  v_kind := CASE WHEN p_direction='in' THEN 'adjustment_in' ELSE 'adjustment_out' END;
  v_date := (pg_catalog.transaction_timestamp() AT TIME ZONE 'Asia/Kuala_Lumpur')::date;

  INSERT INTO stockwise.orders(
    id,company_id,reference,kind,business_date,notes
  ) VALUES (
    v_order_id,p_company_id,v_reference,v_kind,v_date,pg_catalog.btrim(p_reason)
  );
  INSERT INTO stockwise.order_items(
    id,company_id,order_id,product_id,line_number,quantity,unit_price,discount
  ) VALUES (
    pg_catalog.gen_random_uuid(),p_company_id,v_order_id,p_product_id,1,
    p_quantity,0,0
  );
  -- This existing SECURITY DEFINER command is the only ledger-posting path.
  -- Its aggregate product/balance locks and triggers serialize this adjustment.
  PERFORM stockwise.post_order(p_company_id,v_order_id,pg_catalog.gen_random_uuid());
  SELECT m.id INTO v_movement_id FROM stockwise.stock_movements m
  WHERE m.company_id=p_company_id AND m.order_id=v_order_id
    AND m.kind=v_kind AND m.product_id=p_product_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='adjustment movement missing';
  END IF;
  PERFORM stockwise_private.record_user_event(
    p_company_id,'stock_adjusted','order',NULL,v_order_id,
    pg_catalog.jsonb_build_object(
      'product_id',p_product_id,'movement_id',v_movement_id,
      'direction',p_direction,'quantity',p_quantity,'reason',pg_catalog.btrim(p_reason))
  );
  v_result := pg_catalog.jsonb_build_object(
    'movementId',v_movement_id,'balanceBefore',v_before,'balanceAfter',v_after);
  PERFORM stockwise_private.finish_command(
    p_company_id,'stock.adjust',p_idempotency_key,v_payload,v_result);
  RETURN v_result;
END
$function$;
RESET ROLE;

SET LOCAL ROLE stockwise_inventory_writer;
REVOKE ALL ON FUNCTION stockwise_api.adjust_stock(uuid,uuid,text,bigint,text,text)
  FROM PUBLIC,anon,authenticated,service_role,authenticator;
GRANT EXECUTE ON FUNCTION stockwise_api.adjust_stock(uuid,uuid,text,bigint,text,text)
  TO authenticated;
RESET ROLE;

-- Schema CREATE is only needed while the migration creates functions.
SET LOCAL ROLE stockwise_owner;
REVOKE CREATE ON SCHEMA stockwise_api
  FROM stockwise_product_writer,stockwise_inventory_writer;
RESET ROLE;

-- The existing generic poster is not itself a user-authorized API. Only the
-- inventory-writer definer function above may call it through this grant.
SET LOCAL ROLE stockwise_owner;
REVOKE ALL ON FUNCTION stockwise.post_order(uuid,uuid,uuid)
  FROM PUBLIC,anon,authenticated,service_role,authenticator,stockwise_product_reader;
GRANT EXECUTE ON FUNCTION stockwise.post_order(uuid,uuid,uuid)
  TO stockwise_inventory_writer;
RESET ROLE;

DO $postflight$
DECLARE
  v_api_role text;
  v_table text;
BEGIN
  IF EXISTS (
    SELECT 1 FROM (
      VALUES
        ('get_product','uuid,uuid','stockwise_product_writer'),
        ('create_product','uuid,text,jsonb','stockwise_product_writer'),
        ('update_product','uuid,uuid,text,jsonb','stockwise_product_writer'),
        ('archive_product','uuid,uuid,text','stockwise_product_writer'),
        ('adjust_stock','uuid,uuid,text,bigint,text,text','stockwise_inventory_writer')
    ) expected(function_name,argument_types,expected_owner)
    LEFT JOIN pg_catalog.pg_proc p ON p.oid=(
      ('stockwise_api.'||expected.function_name||'('||expected.argument_types||')')::regprocedure
    )
    WHERE p.oid IS NULL
       OR pg_catalog.pg_get_userbyid(p.proowner)<>expected.expected_owner
       OR NOT p.prosecdef OR p.proconfig IS NULL
       OR NOT ('search_path=pg_catalog, pg_temp'=ANY(p.proconfig))
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc overload
           WHERE overload.pronamespace=p.pronamespace
             AND overload.proname=p.proname)<>1
  ) THEN
    RAISE EXCEPTION 'A product/inventory RPC owner, SECURITY DEFINER flag or search_path is unsafe';
  END IF;
  IF pg_catalog.has_table_privilege('authenticated','stockwise.products','INSERT')
     OR pg_catalog.has_table_privilege('authenticated','stockwise.products','UPDATE')
     OR pg_catalog.has_table_privilege('authenticated','stockwise.stock_balances','UPDATE')
     OR pg_catalog.has_table_privilege('authenticated','stockwise.stock_movements','INSERT')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.stock_balances','UPDATE')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.stock_movements','INSERT')
     OR pg_catalog.has_table_privilege('stockwise_product_writer','stockwise.products','DELETE')
     OR pg_catalog.has_table_privilege('stockwise_product_writer','stockwise.stock_balances','UPDATE')
     OR pg_catalog.has_table_privilege('stockwise_product_writer','stockwise.stock_movements','INSERT')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.products','INSERT')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.products','UPDATE')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.products','DELETE')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.orders','DELETE')
     OR pg_catalog.has_column_privilege('stockwise_inventory_writer',
       'stockwise.orders','status','UPDATE')
     OR pg_catalog.has_column_privilege('stockwise_inventory_writer',
       'stockwise.orders','posting_key','UPDATE')
     OR pg_catalog.has_table_privilege('stockwise_inventory_writer','stockwise.order_items','UPDATE') THEN
    RAISE EXCEPTION 'Direct business-table write privilege was granted unexpectedly';
  END IF;
  FOREACH v_api_role IN ARRAY ARRAY['anon','authenticated','service_role','authenticator'] LOOP
    IF pg_catalog.has_schema_privilege(v_api_role,'stockwise','USAGE')
       OR pg_catalog.has_schema_privilege(v_api_role,'stockwise_private','USAGE') THEN
      RAISE EXCEPTION 'An API role can access a non-exposed StockWise schema';
    END IF;
    FOREACH v_table IN ARRAY ARRAY[
      'companies','products','contacts','orders','order_items',
      'stock_balances','stock_movements','audit_logs'
    ] LOOP
      IF pg_catalog.has_table_privilege(v_api_role,'stockwise.'||v_table,'SELECT')
         OR pg_catalog.has_table_privilege(v_api_role,'stockwise.'||v_table,'INSERT')
         OR pg_catalog.has_table_privilege(v_api_role,'stockwise.'||v_table,'UPDATE')
         OR pg_catalog.has_table_privilege(v_api_role,'stockwise.'||v_table,'DELETE')
         OR pg_catalog.has_table_privilege(v_api_role,'stockwise.'||v_table,'TRUNCATE') THEN
        RAISE EXCEPTION 'An API role has direct access to a business base table';
      END IF;
    END LOOP;
    FOREACH v_table IN ARRAY ARRAY['command_results','user_audit_events'] LOOP
      IF pg_catalog.has_table_privilege(
           v_api_role,'stockwise_private.'||v_table,'SELECT')
         OR pg_catalog.has_table_privilege(
           v_api_role,'stockwise_private.'||v_table,'INSERT')
         OR pg_catalog.has_table_privilege(
           v_api_role,'stockwise_private.'||v_table,'UPDATE')
         OR pg_catalog.has_table_privilege(
           v_api_role,'stockwise_private.'||v_table,'DELETE') THEN
        RAISE EXCEPTION 'An API role has direct access to private command/audit data';
      END IF;
    END LOOP;
  END LOOP;
  IF EXISTS (
    SELECT 1 FROM (VALUES
      ('get_product','uuid,uuid'),
      ('create_product','uuid,text,jsonb'),
      ('update_product','uuid,uuid,text,jsonb'),
      ('archive_product','uuid,uuid,text'),
      ('adjust_stock','uuid,uuid,text,bigint,text,text')
    ) rpc(function_name,argument_types)
    WHERE pg_catalog.has_function_privilege(
      'anon',
      ('stockwise_api.'||rpc.function_name||'('||rpc.argument_types||')')::regprocedure,
      'EXECUTE')
       OR pg_catalog.has_function_privilege(
      'service_role',
      ('stockwise_api.'||rpc.function_name||'('||rpc.argument_types||')')::regprocedure,
      'EXECUTE')
       OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc p
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
         WHERE p.oid=(
           ('stockwise_api.'||rpc.function_name||'('||rpc.argument_types||')')::regprocedure
         )
         AND a.grantee=0 AND a.privilege_type='EXECUTE'
       )
  ) THEN
    RAISE EXCEPTION 'An unapproved role can execute a product/inventory RPC';
  END IF;
  IF NOT pg_catalog.has_function_privilege(
       'stockwise_inventory_writer','stockwise.post_order(uuid,uuid,uuid)','EXECUTE')
     OR pg_catalog.has_function_privilege(
       'anon','stockwise.post_order(uuid,uuid,uuid)','EXECUTE')
     OR pg_catalog.has_function_privilege(
       'authenticated','stockwise.post_order(uuid,uuid,uuid)','EXECUTE')
     OR pg_catalog.has_function_privilege(
       'service_role','stockwise.post_order(uuid,uuid,uuid)','EXECUTE')
     OR pg_catalog.has_function_privilege(
       'authenticator','stockwise.post_order(uuid,uuid,uuid)','EXECUTE')
     OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_proc p
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
       WHERE p.oid=pg_catalog.to_regprocedure('stockwise.post_order(uuid,uuid,uuid)')
         AND a.grantee=0 AND a.privilege_type='EXECUTE'
     ) THEN
    RAISE EXCEPTION 'The generic order poster has an unintended effective executor';
  END IF;
  IF pg_catalog.has_function_privilege('anon',
       'stockwise_api.adjust_stock(uuid,uuid,text,bigint,text,text)','EXECUTE')
     OR pg_catalog.has_function_privilege('service_role',
       'stockwise_api.adjust_stock(uuid,uuid,text,bigint,text,text)','EXECUTE')
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.pg_proc p
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
       WHERE p.oid=pg_catalog.to_regprocedure(
         'stockwise_api.adjust_stock(uuid,uuid,text,bigint,text,text)')
         AND a.grantee=0 AND a.privilege_type='EXECUTE'
     ) THEN
    RAISE EXCEPTION 'An unintended role can execute the stock adjustment RPC';
  END IF;
END
$postflight$;

COMMIT;
