-- Replit-managed development PostgreSQL only.
-- Additive: creates a new isolated schema; never run on the Supabase project.
-- Not applied by npm start. The API remains disabled until trusted auth,
-- membership checks, and a restricted runtime connection are configured.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
BEGIN
  IF pg_catalog.to_regnamespace('stockwise_mvp') IS NOT NULL THEN
    RAISE EXCEPTION 'stockwise_mvp already exists; inspect it before applying this migration';
  END IF;
END
$preflight$;

CREATE SCHEMA stockwise_mvp;
REVOKE ALL ON SCHEMA stockwise_mvp FROM PUBLIC;

CREATE TABLE stockwise_mvp.companies (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  name text NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(name)) BETWEEN 1 AND 200),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp()
);

CREATE TABLE stockwise_mvp.company_memberships (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL
    REFERENCES stockwise_mvp.companies(id) ON DELETE RESTRICT,
  identity_provider text NOT NULL CHECK (identity_provider = 'replit'),
  identity_subject text NOT NULL
    CHECK (pg_catalog.length(identity_subject) BETWEEN 1 AND 256),
  role text NOT NULL CHECK (role IN ('Owner', 'Admin', 'Staff', 'Viewer')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id),
  UNIQUE (company_id, identity_provider, identity_subject)
);

CREATE TABLE stockwise_mvp.products (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL
    REFERENCES stockwise_mvp.companies(id) ON DELETE RESTRICT,
  sku text NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(sku)) BETWEEN 1 AND 128),
  name text NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(name)) BETWEEN 1 AND 255),
  category text NOT NULL DEFAULT '' CHECK (pg_catalog.length(category) <= 120),
  unit_code text NOT NULL DEFAULT 'unit'
    CHECK (pg_catalog.length(pg_catalog.btrim(unit_code)) BETWEEN 1 AND 16),
  selling_price numeric(20,6) NOT NULL DEFAULT 0 CHECK (selling_price >= 0),
  cost_price numeric(20,6) NOT NULL DEFAULT 0 CHECK (cost_price >= 0),
  low_stock_threshold bigint NOT NULL DEFAULT 0 CHECK (low_stock_threshold >= 0),
  classification_code text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id)
);

CREATE UNIQUE INDEX products_company_sku_ci_uidx
  ON stockwise_mvp.products (company_id, pg_catalog.lower(sku));
CREATE INDEX products_company_active_sku_idx
  ON stockwise_mvp.products (company_id, is_active, pg_catalog.lower(sku), id);

CREATE TABLE stockwise_mvp.stock_movements (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL,
  product_id uuid NOT NULL,
  actor_membership_id uuid NOT NULL,
  movement_kind text NOT NULL CHECK (movement_kind IN ('opening', 'adjustment')),
  quantity_delta bigint NOT NULL CHECK (quantity_delta <> 0),
  reason text NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) BETWEEN 3 AND 300),
  idempotency_key text NOT NULL CHECK (
    idempotency_key ~ '^[A-Za-z0-9._~-]{8,128}$'
  ),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  CHECK (movement_kind <> 'opening' OR quantity_delta > 0),
  FOREIGN KEY (company_id, product_id)
    REFERENCES stockwise_mvp.products(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, actor_membership_id)
    REFERENCES stockwise_mvp.company_memberships(company_id, id) ON DELETE RESTRICT,
  UNIQUE (company_id, actor_membership_id, idempotency_key)
);
CREATE INDEX stock_movements_company_product_time_idx
  ON stockwise_mvp.stock_movements (company_id, product_id, created_at DESC, id);

CREATE TABLE stockwise_mvp.command_idempotency (
  company_id uuid NOT NULL
    REFERENCES stockwise_mvp.companies(id) ON DELETE RESTRICT,
  actor_membership_id uuid NOT NULL,
  command text NOT NULL CHECK (
    command IN ('product.create', 'product.update', 'product.archive', 'stock.adjust')
  ),
  idempotency_key text NOT NULL CHECK (
    idempotency_key ~ '^[A-Za-z0-9._~-]{8,128}$'
  ),
  request_payload jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(request_payload) = 'object'),
  response_payload jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(response_payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (company_id, actor_membership_id, command, idempotency_key),
  FOREIGN KEY (company_id, actor_membership_id)
    REFERENCES stockwise_mvp.company_memberships(company_id, id) ON DELETE RESTRICT
);

-- The balance is derived from the append-only ledger; it cannot drift through
-- an independent balance update.
CREATE VIEW stockwise_mvp.stock_balances
WITH (security_invoker = true)
AS
SELECT p.company_id,
       p.id AS product_id,
       COALESCE(pg_catalog.sum(m.quantity_delta), 0::numeric)::bigint AS quantity
FROM stockwise_mvp.products AS p
LEFT JOIN stockwise_mvp.stock_movements AS m
  ON m.company_id = p.company_id AND m.product_id = p.id
GROUP BY p.company_id, p.id;

CREATE FUNCTION stockwise_mvp.guard_stock_movement_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
  v_balance numeric;
BEGIN
  -- Serialize movements for a product before checking the derived balance.
  PERFORM 1
  FROM stockwise_mvp.products AS p
  WHERE p.company_id = NEW.company_id AND p.id = NEW.product_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'product not found';
  END IF;

  SELECT COALESCE(pg_catalog.sum(m.quantity_delta), 0::numeric)
    INTO v_balance
  FROM stockwise_mvp.stock_movements AS m
  WHERE m.company_id = NEW.company_id AND m.product_id = NEW.product_id;

  IF v_balance + NEW.quantity_delta < 0 THEN
    RAISE EXCEPTION USING ERRCODE = 'PZ002', MESSAGE = 'insufficient stock';
  END IF;
  RETURN NEW;
END
$function$;

CREATE TRIGGER stock_movements_guard_insert
BEFORE INSERT ON stockwise_mvp.stock_movements
FOR EACH ROW EXECUTE FUNCTION stockwise_mvp.guard_stock_movement_insert();

CREATE FUNCTION stockwise_mvp.reject_stock_movement_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'stock movements are append-only';
END
$function$;

CREATE TRIGGER stock_movements_append_only
BEFORE UPDATE OR DELETE ON stockwise_mvp.stock_movements
FOR EACH ROW EXECUTE FUNCTION stockwise_mvp.reject_stock_movement_mutation();

-- Fail closed for non-owner roles: no policies or runtime grants are created.
ALTER TABLE stockwise_mvp.companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.companies FORCE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.company_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.company_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.products FORCE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.stock_movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.stock_movements FORCE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.command_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.command_idempotency FORCE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA stockwise_mvp FROM PUBLIC;
REVOKE ALL ON FUNCTION stockwise_mvp.guard_stock_movement_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION stockwise_mvp.reject_stock_movement_mutation() FROM PUBLIC;

COMMIT;
