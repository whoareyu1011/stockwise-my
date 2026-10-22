-- StockWise MY: inventory foundation. PREPARED ONLY -- NOT APPLIED.
-- Manual, administrator-reviewed migration; never load from application startup.
-- Prerequisites and approval gates: db/README.md.
-- Exactly eight application tables. No credentials, auth, invoices or data import.
--
-- Fail closed: stockwise_owner must be separately provisioned and approved.
-- This file neither creates roles nor grants a runtime role access.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '90s';

DO $preflight$
BEGIN
  IF pg_catalog.to_regnamespace('stockwise') IS NOT NULL THEN
    RAISE EXCEPTION 'stockwise schema already exists; inspect migration state, do not overwrite';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'stockwise_owner'
      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit
  ) THEN
    RAISE EXCEPTION 'Approved non-login, non-privileged stockwise_owner role is required';
  END IF;
  IF NOT pg_catalog.pg_has_role(current_user, 'stockwise_owner', 'MEMBER') THEN
    RAISE EXCEPTION 'Migration operator must have approved membership in stockwise_owner';
  END IF;
  IF NOT pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'Migration operator needs approved database CREATE privilege for the schema';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member
    WHERE r.rolname='stockwise_owner'
  ) THEN
    RAISE EXCEPTION 'stockwise_owner must not be a member of any other role';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles api CROSS JOIN pg_catalog.pg_roles owner_role
    WHERE api.rolname IN ('anon','authenticated','service_role','authenticator')
      AND owner_role.rolname='stockwise_owner'
      AND pg_catalog.pg_has_role(api.oid,owner_role.oid,'MEMBER')
  ) THEN
    RAISE EXCEPTION 'Supabase API roles must not be members of stockwise_owner';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl a JOIN pg_catalog.pg_roles r ON r.oid=a.defaclrole
    WHERE r.rolname='stockwise_owner'
  ) THEN
    RAISE EXCEPTION 'Use a clean owner with no custom default privileges; review defaults separately';
  END IF;
END;
$preflight$;

CREATE SCHEMA stockwise AUTHORIZATION stockwise_owner;
SET LOCAL ROLE stockwise_owner;
REVOKE ALL ON SCHEMA stockwise FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise REVOKE ALL ON FUNCTIONS FROM PUBLIC;

CREATE TABLE stockwise.companies (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  legal_name text NOT NULL CHECK (pg_catalog.btrim(legal_name) <> ''),
  trading_name text,
  tin text,
  registration_type text,
  registration_number text,
  sst_registration_number text,
  msic_code text,
  email text,
  phone text,
  address jsonb NOT NULL DEFAULT '{}' CHECK (pg_catalog.jsonb_typeof(address) = 'object'),
  currency text NOT NULL DEFAULT 'MYR' CHECK (currency = 'MYR'),
  timezone text NOT NULL DEFAULT 'Asia/Kuala_Lumpur' CHECK (timezone = 'Asia/Kuala_Lumpur'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp()
);

CREATE TABLE stockwise.products (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  sku text NOT NULL CHECK (sku = pg_catalog.btrim(sku) AND sku <> ''),
  name text NOT NULL CHECK (pg_catalog.btrim(name) <> ''),
  category text NOT NULL DEFAULT '',
  unit_code text NOT NULL DEFAULT 'EA' CHECK (pg_catalog.btrim(unit_code) <> ''),
  classification_code text,
  unit_cost numeric(20,6) NOT NULL DEFAULT 0 CHECK (unit_cost >= 0 AND unit_cost < 'Infinity'::numeric),
  selling_price numeric(20,6) NOT NULL DEFAULT 0 CHECK (selling_price >= 0 AND selling_price < 'Infinity'::numeric),
  low_stock_threshold bigint NOT NULL DEFAULT 0 CHECK (low_stock_threshold >= 0),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id)
);
CREATE UNIQUE INDEX products_company_sku_uq ON stockwise.products (company_id, pg_catalog.upper(sku));
CREATE INDEX products_company_category_idx ON stockwise.products (company_id, category);

CREATE TABLE stockwise.contacts (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  legal_name text NOT NULL CHECK (pg_catalog.btrim(legal_name) <> ''),
  contact_kind text NOT NULL CHECK (contact_kind IN ('customer', 'supplier', 'both')),
  identification_type text,
  identification_number text,
  tin text,
  sst_registration_number text,
  email text,
  phone text,
  address jsonb NOT NULL DEFAULT '{}' CHECK (pg_catalog.jsonb_typeof(address) = 'object'),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id)
);
CREATE INDEX contacts_company_name_idx ON stockwise.contacts (company_id, legal_name);

CREATE TABLE stockwise.orders (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  contact_id uuid,
  reference text NOT NULL CHECK (pg_catalog.btrim(reference) <> ''),
  kind text NOT NULL CHECK (kind IN ('sale', 'purchase', 'adjustment_in', 'adjustment_out', 'opening_balance', 'reversal')),
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'posted', 'reversed')),
  business_date date NOT NULL,
  currency text NOT NULL DEFAULT 'MYR' CHECK (currency = 'MYR'),
  payment_status text NOT NULL DEFAULT 'unspecified'
    CHECK (payment_status IN ('unspecified', 'paid', 'partially_paid', 'unpaid')),
  notes text NOT NULL DEFAULT '',
  subtotal numeric(30,6) NOT NULL DEFAULT 0 CHECK (subtotal >= 0 AND subtotal < 'Infinity'::numeric),
  discount_total numeric(30,6) NOT NULL DEFAULT 0 CHECK (discount_total >= 0 AND discount_total <= subtotal),
  total numeric(30,6) GENERATED ALWAYS AS (subtotal - discount_total) STORED,
  posting_key uuid,
  original_order_id uuid,
  posted_at timestamptz,
  reversed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id),
  UNIQUE (company_id, reference),
  UNIQUE (company_id, posting_key),
  FOREIGN KEY (company_id, contact_id) REFERENCES stockwise.contacts(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, original_order_id) REFERENCES stockwise.orders(company_id, id) ON DELETE RESTRICT,
  CHECK (kind NOT IN ('sale', 'purchase') OR contact_id IS NOT NULL),
  CHECK ((kind = 'reversal') = (original_order_id IS NOT NULL)),
  CHECK (original_order_id IS NULL OR original_order_id <> id),
  CHECK ((status = 'draft' AND posting_key IS NULL AND posted_at IS NULL AND reversed_at IS NULL)
      OR (status = 'posted' AND posting_key IS NOT NULL AND posted_at IS NOT NULL AND reversed_at IS NULL)
      OR (status = 'reversed' AND posting_key IS NOT NULL AND posted_at IS NOT NULL AND reversed_at IS NOT NULL)),
  CHECK (kind <> 'reversal' OR status <> 'reversed')
);
CREATE UNIQUE INDEX orders_one_full_reversal_uq ON stockwise.orders (company_id, original_order_id)
  WHERE original_order_id IS NOT NULL;
CREATE INDEX orders_company_date_idx ON stockwise.orders (company_id, business_date DESC, id);
CREATE INDEX orders_company_contact_date_idx ON stockwise.orders (company_id, contact_id, business_date DESC);

CREATE TABLE stockwise.order_items (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL,
  order_id uuid NOT NULL,
  product_id uuid NOT NULL,
  line_number integer NOT NULL CHECK (line_number > 0),
  quantity bigint NOT NULL CHECK (quantity > 0),
  unit_price numeric(20,6) NOT NULL CHECK (unit_price >= 0 AND unit_price < 'Infinity'::numeric),
  discount numeric(30,6) NOT NULL DEFAULT 0 CHECK (discount >= 0 AND discount < 'Infinity'::numeric),
  sku_snapshot text NOT NULL DEFAULT '',
  name_snapshot text NOT NULL DEFAULT '',
  unit_code_snapshot text NOT NULL DEFAULT '',
  unit_cost_snapshot numeric(20,6) NOT NULL DEFAULT 0
    CHECK (unit_cost_snapshot >= 0 AND unit_cost_snapshot < 'Infinity'::numeric),
  line_subtotal numeric(30,6) GENERATED ALWAYS AS (quantity::numeric * unit_price) STORED,
  line_total numeric(30,6) GENERATED ALWAYS AS (quantity::numeric * unit_price - discount) STORED,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id),
  UNIQUE (company_id, order_id, id),
  UNIQUE (company_id, order_id, line_number),
  FOREIGN KEY (company_id, order_id) REFERENCES stockwise.orders(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, product_id) REFERENCES stockwise.products(company_id, id) ON DELETE RESTRICT,
  CHECK (discount <= quantity::numeric * unit_price)
);
CREATE INDEX order_items_company_product_idx ON stockwise.order_items (company_id, product_id);

CREATE TABLE stockwise.stock_balances (
  company_id uuid NOT NULL,
  product_id uuid NOT NULL,
  quantity bigint NOT NULL DEFAULT 0 CHECK (quantity >= 0),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  PRIMARY KEY (company_id, product_id),
  FOREIGN KEY (company_id, product_id) REFERENCES stockwise.products(company_id, id) ON DELETE RESTRICT
);

CREATE TABLE stockwise.stock_movements (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL,
  order_id uuid NOT NULL,
  order_item_id uuid,
  product_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('sale', 'purchase', 'adjustment_in', 'adjustment_out', 'opening_balance', 'reversal')),
  quantity_delta bigint NOT NULL CHECK (quantity_delta <> 0 AND quantity_delta > '-9223372036854775808'::bigint),
  effective_date date NOT NULL,
  reversal_of_movement_id uuid,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  UNIQUE (company_id, id),
  FOREIGN KEY (company_id, order_id) REFERENCES stockwise.orders(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, order_id, order_item_id) REFERENCES stockwise.order_items(company_id, order_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, product_id) REFERENCES stockwise.products(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, reversal_of_movement_id) REFERENCES stockwise.stock_movements(company_id, id) ON DELETE RESTRICT,
  CHECK ((kind = 'reversal' AND reversal_of_movement_id IS NOT NULL AND order_item_id IS NULL)
      OR (kind <> 'reversal' AND reversal_of_movement_id IS NULL AND order_item_id IS NOT NULL)),
  CHECK (reversal_of_movement_id IS NULL OR reversal_of_movement_id <> id)
);
CREATE UNIQUE INDEX stock_movements_one_original_item_uq ON stockwise.stock_movements (company_id, order_item_id)
  WHERE order_item_id IS NOT NULL;
CREATE UNIQUE INDEX stock_movements_one_reversal_uq ON stockwise.stock_movements (company_id, reversal_of_movement_id)
  WHERE reversal_of_movement_id IS NOT NULL;
CREATE UNIQUE INDEX stock_movements_one_opening_uq ON stockwise.stock_movements (company_id, product_id)
  WHERE kind = 'opening_balance';
CREATE INDEX stock_movements_company_product_date_idx ON stockwise.stock_movements (company_id, product_id, effective_date, id);
CREATE INDEX stock_movements_company_order_idx ON stockwise.stock_movements (company_id, order_id);

CREATE TABLE stockwise.audit_logs (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  action text NOT NULL CHECK (pg_catalog.btrim(action) <> ''),
  target_kind text NOT NULL CHECK (target_kind IN ('company','product','contact','order')),
  target_id uuid NOT NULL,
  order_id uuid,
  actor_kind text NOT NULL DEFAULT 'database_operator' CHECK (actor_kind = 'database_operator'),
  database_actor text NOT NULL DEFAULT session_user,
  details jsonb NOT NULL DEFAULT '{}' CHECK (pg_catalog.jsonb_typeof(details) = 'object'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  FOREIGN KEY (company_id, order_id) REFERENCES stockwise.orders(company_id, id) ON DELETE RESTRICT,
  CHECK ((target_kind='order' AND order_id IS NOT NULL AND target_id=order_id)
      OR (target_kind<>'order' AND order_id IS NULL)),
  CHECK (target_kind<>'company' OR target_id=company_id),
  CHECK (action NOT IN ('order_posted','order_reversed') OR target_kind='order')
);
CREATE UNIQUE INDEX audit_logs_posting_once_uq ON stockwise.audit_logs (company_id, order_id, action)
  WHERE action IN ('order_posted','order_reversed');
CREATE INDEX audit_logs_company_time_idx ON stockwise.audit_logs (company_id, created_at DESC);
CREATE INDEX audit_logs_company_order_idx ON stockwise.audit_logs (company_id, order_id)
  WHERE order_id IS NOT NULL;

-- Trigger helpers use fully qualified relations and a trusted, fixed search path.
CREATE FUNCTION stockwise.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  NEW.updated_at := pg_catalog.clock_timestamp();
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.reject_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  RAISE EXCEPTION 'This inventory history is append-only';
END;
$fn$;

CREATE FUNCTION stockwise.guard_company_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR (pg_catalog.to_jsonb(NEW)->'company_id') IS DISTINCT FROM (pg_catalog.to_jsonb(OLD)->'company_id') THEN
    RAISE EXCEPTION 'Record identity and company cannot change';
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.guard_order() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'draft' THEN RAISE EXCEPTION 'Orders must start as drafts'; END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'draft' THEN RAISE EXCEPTION 'Posted orders cannot be deleted'; END IF;
    RETURN OLD;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.company_id IS DISTINCT FROM OLD.company_id THEN
    RAISE EXCEPTION 'Order identity and company cannot change';
  END IF;
  IF OLD.status = 'draft' THEN
    IF NEW.status NOT IN ('draft', 'posted') THEN RAISE EXCEPTION 'Invalid draft transition'; END IF;
  ELSIF NOT (
    OLD.status = 'posted' AND NEW.status = 'reversed'
    -- Do not access generated total in BEFORE triggers. Compare every ordinary
    -- immutable column explicitly; total is derived from unchanged source fields.
    AND ROW(NEW.contact_id,NEW.reference,NEW.kind,NEW.business_date,NEW.currency,
      NEW.payment_status,NEW.notes,NEW.subtotal,NEW.discount_total,NEW.posting_key,
      NEW.original_order_id,NEW.posted_at,NEW.created_at)
      IS NOT DISTINCT FROM
      ROW(OLD.contact_id,OLD.reference,OLD.kind,OLD.business_date,OLD.currency,
      OLD.payment_status,OLD.notes,OLD.subtotal,OLD.discount_total,OLD.posting_key,
      OLD.original_order_id,OLD.posted_at,OLD.created_at)
  ) THEN
    RAISE EXCEPTION 'Posted orders are immutable except for a full reversal';
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.guard_order_item() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  v_company uuid;
  v_order uuid;
  v_status text;
  v_kind text;
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.id IS DISTINCT FROM OLD.id OR NEW.company_id IS DISTINCT FROM OLD.company_id
      OR NEW.order_id IS DISTINCT FROM OLD.order_id) THEN
    RAISE EXCEPTION 'Order item identity and parent cannot change';
  END IF;
  IF TG_OP = 'DELETE' THEN v_company := OLD.company_id; v_order := OLD.order_id;
  ELSE v_company := NEW.company_id; v_order := NEW.order_id; END IF;
  SELECT o.status, o.kind INTO v_status, v_kind
    FROM stockwise.orders o WHERE o.company_id = v_company AND o.id = v_order FOR UPDATE;
  IF NOT FOUND OR v_status <> 'draft' OR v_kind = 'reversal' THEN
    RAISE EXCEPTION 'Only ordinary draft order items may be changed';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.guard_balance_write() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  -- Defense in depth only: ACLs are the security boundary, not trigger depth.
  -- Legitimate writes are nested in product-init or ledger-insert triggers.
  IF TG_OP = 'DELETE' OR pg_catalog.pg_trigger_depth() <> 2 THEN
    RAISE EXCEPTION 'Balances may only be maintained by inventory triggers';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.company_id IS DISTINCT FROM OLD.company_id OR NEW.product_id IS DISTINCT FROM OLD.product_id) THEN
    RAISE EXCEPTION 'Balance identity cannot change';
  END IF;
  IF TG_OP = 'INSERT' AND NEW.quantity <> 0 THEN
    RAISE EXCEPTION 'Initial balance must be zero; use an opening movement';
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.initialize_balance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  INSERT INTO stockwise.stock_balances(company_id, product_id) VALUES (NEW.company_id, NEW.id);
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.audit_catalogue_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE v_company uuid; v_kind text; v_fields jsonb;
BEGIN
  v_kind := CASE TG_TABLE_NAME WHEN 'companies' THEN 'company' WHEN 'products' THEN 'product' ELSE 'contact' END;
  v_company := CASE WHEN TG_TABLE_NAME='companies' THEN NEW.id
    ELSE (pg_catalog.to_jsonb(NEW)->>'company_id')::uuid END;
  IF TG_OP='UPDATE' THEN
    SELECT pg_catalog.jsonb_agg(n.key ORDER BY n.key) INTO v_fields
      FROM pg_catalog.jsonb_each(pg_catalog.to_jsonb(NEW)) n
      WHERE n.key<>'updated_at' AND n.value IS DISTINCT FROM (pg_catalog.to_jsonb(OLD)->n.key);
    IF v_fields IS NULL THEN RETURN NEW; END IF;
  END IF;
  -- Field names only: do not duplicate tax IDs, personal details or notes in logs.
  INSERT INTO stockwise.audit_logs(company_id,action,target_kind,target_id,details)
    VALUES(v_company,v_kind||CASE WHEN TG_OP='INSERT' THEN '_created' ELSE '_updated' END,
      v_kind,NEW.id,pg_catalog.jsonb_build_object('changed_fields',COALESCE(v_fields,'[]'::jsonb)));
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.validate_movement() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  v_order stockwise.orders%ROWTYPE;
  v_item stockwise.order_items%ROWTYPE;
  v_original stockwise.stock_movements%ROWTYPE;
  v_direction integer;
BEGIN
  PERFORM b.product_id FROM stockwise.stock_balances b
    WHERE b.company_id=NEW.company_id AND b.product_id=NEW.product_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Movement requires an initialized product balance'; END IF;
  IF NEW.kind='opening_balance' AND EXISTS (
    SELECT 1 FROM stockwise.stock_movements m WHERE m.company_id=NEW.company_id AND m.product_id=NEW.product_id
  ) THEN RAISE EXCEPTION 'Opening movement requires a product with no movement history'; END IF;
  SELECT * INTO v_order FROM stockwise.orders
    WHERE company_id = NEW.company_id AND id = NEW.order_id;
  IF NOT FOUND OR v_order.status <> 'posted' OR NEW.kind <> v_order.kind
     OR NEW.effective_date <> v_order.business_date THEN
    RAISE EXCEPTION 'Movement must match a posted order and its business date';
  END IF;
  IF NEW.kind = 'reversal' THEN
    SELECT * INTO v_original FROM stockwise.stock_movements
      WHERE company_id = NEW.company_id AND id = NEW.reversal_of_movement_id;
    IF NOT FOUND OR v_original.kind = 'reversal'
       OR v_original.order_id <> v_order.original_order_id
       OR v_original.product_id <> NEW.product_id
       OR NEW.quantity_delta <> -v_original.quantity_delta THEN
      RAISE EXCEPTION 'Reversal must exactly negate its original company/product movement';
    END IF;
  ELSE
    SELECT * INTO v_item FROM stockwise.order_items
      WHERE company_id = NEW.company_id AND order_id = NEW.order_id AND id = NEW.order_item_id;
    v_direction := CASE WHEN NEW.kind IN ('sale','adjustment_out') THEN -1 ELSE 1 END;
    IF NOT FOUND OR v_item.product_id <> NEW.product_id
       OR NEW.quantity_delta <> v_direction * v_item.quantity THEN
      RAISE EXCEPTION 'Movement must match its order item and direction';
    END IF;
  END IF;
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.apply_movement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
BEGIN
  -- Atomic UPDATE is also a concurrency-safe final check, even after prechecks.
  UPDATE stockwise.stock_balances
    SET quantity = quantity + NEW.quantity_delta
    WHERE company_id = NEW.company_id AND product_id = NEW.product_id
      AND quantity::numeric + NEW.quantity_delta::numeric >= 0;
  IF NOT FOUND THEN RAISE EXCEPTION 'Insufficient stock or missing balance; entire posting is rolled back'; END IF;
  RETURN NEW;
END;
$fn$;

CREATE FUNCTION stockwise.check_balance_integrity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE v_balance bigint; v_ledger numeric;
BEGIN
  -- A deferred callback can run after the posting definer has returned.
  -- Validate as the trusted owner, without requiring caller table-read grants.
  SELECT quantity INTO v_balance FROM stockwise.stock_balances
    WHERE company_id = NEW.company_id AND product_id = NEW.product_id;
  SELECT COALESCE(pg_catalog.sum(quantity_delta), 0) INTO v_ledger FROM stockwise.stock_movements
    WHERE company_id = NEW.company_id AND product_id = NEW.product_id;
  IF v_balance IS NULL OR v_balance::numeric <> v_ledger THEN
    RAISE EXCEPTION 'Balance and ledger disagree';
  END IF;
  RETURN NULL;
END;
$fn$;

CREATE FUNCTION stockwise.check_order_integrity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  v_company uuid; v_id uuid;
  v_order stockwise.orders%ROWTYPE;
  v_original stockwise.orders%ROWTYPE;
  v_items bigint; v_movements bigint; v_expected bigint;
  v_subtotal numeric; v_discount numeric;
BEGIN
  IF TG_TABLE_NAME = 'orders' THEN
    v_company := NEW.company_id; v_id := NEW.id;
  ELSIF TG_OP = 'DELETE' THEN
    v_company := OLD.company_id; v_id := OLD.order_id;
  ELSE
    v_company := NEW.company_id; v_id := NEW.order_id;
  END IF;
  -- Deferred checks must read final rows, not the trigger's old row snapshot.
  SELECT * INTO v_order FROM stockwise.orders WHERE company_id = v_company AND id = v_id;
  IF NOT FOUND OR v_order.status = 'draft' THEN RETURN NULL; END IF;
  SELECT pg_catalog.count(*) INTO v_movements FROM stockwise.stock_movements
    WHERE company_id = v_company AND order_id = v_id;
  IF v_order.kind = 'reversal' THEN
    SELECT * INTO v_original FROM stockwise.orders
      WHERE company_id = v_company AND id = v_order.original_order_id;
    IF NOT FOUND OR v_original.kind = 'reversal' THEN
      RAISE EXCEPTION 'Reversal must reference an ordinary original order';
    END IF;
    IF EXISTS (
      SELECT 1 FROM stockwise.order_items WHERE company_id=v_company AND order_id=v_id
    ) THEN
      RAISE EXCEPTION 'A reversal has linked opposite movements, not ordinary order items';
    END IF;
    SELECT pg_catalog.count(*) INTO v_expected FROM stockwise.stock_movements
      WHERE company_id = v_company AND order_id = v_original.id;
    IF v_original.status IS DISTINCT FROM 'reversed' OR v_expected = 0 OR v_movements <> v_expected
       OR v_order.subtotal <> v_original.subtotal OR v_order.discount_total <> v_original.discount_total
       OR v_order.contact_id IS DISTINCT FROM v_original.contact_id THEN
      RAISE EXCEPTION 'Full reversal is incomplete or does not match original';
    END IF;
  ELSE
    SELECT pg_catalog.count(*), COALESCE(pg_catalog.sum(line_subtotal),0), COALESCE(pg_catalog.sum(discount),0)
      INTO v_items, v_subtotal, v_discount FROM stockwise.order_items
      WHERE company_id = v_company AND order_id = v_id;
    IF v_items = 0 OR v_movements <> v_items OR v_order.subtotal <> v_subtotal OR v_order.discount_total <> v_discount THEN
      RAISE EXCEPTION 'Posted order totals or movement count are inconsistent';
    END IF;
    IF v_order.status = 'reversed' AND NOT EXISTS (
      SELECT 1 FROM stockwise.orders r WHERE r.company_id = v_company AND r.original_order_id = v_id AND r.status = 'posted'
    ) THEN
      RAISE EXCEPTION 'Reversed order must have a complete posted reversal';
    END IF;
  END IF;
  -- Audit insertion occurs after the header/movements in both commands.
  -- Check the final transaction state so a late audit failure cannot leave
  -- a committed posting without its matching operation event.
  IF NOT EXISTS (
    SELECT 1 FROM stockwise.audit_logs a
    WHERE a.company_id=v_company AND a.order_id=v_id
      AND a.target_kind='order' AND a.target_id=v_id
      AND a.action=CASE WHEN v_order.kind='reversal' THEN 'order_reversed' ELSE 'order_posted' END
      AND a.details->>'operation_key'=v_order.posting_key::text
  ) THEN
    RAISE EXCEPTION 'Posted order requires its matching operation audit event';
  END IF;
  RETURN NULL;
END;
$fn$;

CREATE TRIGGER companies_identity BEFORE UPDATE ON stockwise.companies FOR EACH ROW EXECUTE FUNCTION stockwise.guard_company_identity();
CREATE TRIGGER companies_updated BEFORE UPDATE ON stockwise.companies FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();
CREATE TRIGGER companies_audit AFTER INSERT OR UPDATE ON stockwise.companies FOR EACH ROW EXECUTE FUNCTION stockwise.audit_catalogue_change();
CREATE TRIGGER products_identity BEFORE UPDATE ON stockwise.products FOR EACH ROW EXECUTE FUNCTION stockwise.guard_company_identity();
CREATE TRIGGER products_updated BEFORE UPDATE ON stockwise.products FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();
CREATE TRIGGER products_initialize_balance AFTER INSERT ON stockwise.products FOR EACH ROW EXECUTE FUNCTION stockwise.initialize_balance();
CREATE TRIGGER products_audit AFTER INSERT OR UPDATE ON stockwise.products FOR EACH ROW EXECUTE FUNCTION stockwise.audit_catalogue_change();
CREATE TRIGGER contacts_identity BEFORE UPDATE ON stockwise.contacts FOR EACH ROW EXECUTE FUNCTION stockwise.guard_company_identity();
CREATE TRIGGER contacts_updated BEFORE UPDATE ON stockwise.contacts FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();
CREATE TRIGGER contacts_audit AFTER INSERT OR UPDATE ON stockwise.contacts FOR EACH ROW EXECUTE FUNCTION stockwise.audit_catalogue_change();
CREATE TRIGGER orders_guard BEFORE INSERT OR UPDATE OR DELETE ON stockwise.orders FOR EACH ROW EXECUTE FUNCTION stockwise.guard_order();
CREATE TRIGGER orders_updated BEFORE UPDATE ON stockwise.orders FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();
CREATE TRIGGER order_items_guard BEFORE INSERT OR UPDATE OR DELETE ON stockwise.order_items FOR EACH ROW EXECUTE FUNCTION stockwise.guard_order_item();
CREATE TRIGGER order_items_updated BEFORE UPDATE ON stockwise.order_items FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();
CREATE TRIGGER stock_balances_guard BEFORE INSERT OR UPDATE OR DELETE ON stockwise.stock_balances FOR EACH ROW EXECUTE FUNCTION stockwise.guard_balance_write();
CREATE TRIGGER stock_balances_updated BEFORE UPDATE ON stockwise.stock_balances FOR EACH ROW EXECUTE FUNCTION stockwise.touch_updated_at();
CREATE TRIGGER stock_movements_validate BEFORE INSERT ON stockwise.stock_movements FOR EACH ROW EXECUTE FUNCTION stockwise.validate_movement();
CREATE TRIGGER stock_movements_immutable BEFORE UPDATE OR DELETE ON stockwise.stock_movements FOR EACH ROW EXECUTE FUNCTION stockwise.reject_mutation();
CREATE TRIGGER stock_movements_apply AFTER INSERT ON stockwise.stock_movements FOR EACH ROW EXECUTE FUNCTION stockwise.apply_movement();
CREATE TRIGGER stock_movements_no_truncate BEFORE TRUNCATE ON stockwise.stock_movements FOR EACH STATEMENT EXECUTE FUNCTION stockwise.reject_mutation();
CREATE TRIGGER stock_balances_no_truncate BEFORE TRUNCATE ON stockwise.stock_balances FOR EACH STATEMENT EXECUTE FUNCTION stockwise.reject_mutation();
CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON stockwise.audit_logs FOR EACH ROW EXECUTE FUNCTION stockwise.reject_mutation();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON stockwise.audit_logs FOR EACH STATEMENT EXECUTE FUNCTION stockwise.reject_mutation();

CREATE CONSTRAINT TRIGGER stock_balances_consistency AFTER INSERT OR UPDATE ON stockwise.stock_balances
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stockwise.check_balance_integrity();
CREATE CONSTRAINT TRIGGER orders_consistency AFTER INSERT OR UPDATE ON stockwise.orders
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stockwise.check_order_integrity();
CREATE CONSTRAINT TRIGGER order_items_consistency AFTER INSERT OR UPDATE OR DELETE ON stockwise.order_items
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stockwise.check_order_integrity();
CREATE CONSTRAINT TRIGGER stock_movements_consistency AFTER INSERT ON stockwise.stock_movements
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stockwise.check_order_integrity();

CREATE FUNCTION stockwise.post_order(p_company_id uuid, p_order_id uuid, p_operation_key uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  v_order stockwise.orders%ROWTYPE;
  v_subtotal numeric; v_discount numeric;
BEGIN
  IF p_company_id IS NULL OR p_order_id IS NULL OR p_operation_key IS NULL THEN
    RAISE EXCEPTION 'Company, order and operation key are required';
  END IF;
  SELECT * INTO v_order FROM stockwise.orders
    WHERE company_id = p_company_id AND id = p_order_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Order not found in this company'; END IF;
  IF v_order.status IN ('posted','reversed') THEN
    IF v_order.posting_key = p_operation_key AND v_order.kind <> 'reversal' THEN RETURN v_order.id; END IF;
    RAISE EXCEPTION 'Order is already posted with another key or is a reversal';
  END IF;
  IF v_order.kind = 'reversal' THEN RAISE EXCEPTION 'Use reverse_order for full reversals'; END IF;
  IF NOT EXISTS (SELECT 1 FROM stockwise.order_items WHERE company_id = p_company_id AND order_id = p_order_id) THEN
    RAISE EXCEPTION 'At least one order item is required';
  END IF;
  -- Lock product masters first, in UUID order: snapshots/active flags stay stable.
  PERFORM p.id FROM stockwise.products p
    WHERE p.company_id = p_company_id AND p.id IN (
      SELECT i.product_id FROM stockwise.order_items i WHERE i.company_id = p_company_id AND i.order_id = p_order_id
    ) ORDER BY p.id FOR SHARE;
  IF EXISTS (
    SELECT 1 FROM stockwise.order_items i JOIN stockwise.products p ON p.company_id=i.company_id AND p.id=i.product_id
    WHERE i.company_id=p_company_id AND i.order_id=p_order_id AND NOT p.is_active
  ) THEN RAISE EXCEPTION 'Archived products cannot be posted'; END IF;
  PERFORM b.product_id FROM stockwise.stock_balances b
    WHERE b.company_id=p_company_id AND b.product_id IN (
      SELECT i.product_id FROM stockwise.order_items i WHERE i.company_id=p_company_id AND i.order_id=p_order_id
    ) ORDER BY b.product_id FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM (
      SELECT product_id, pg_catalog.sum(quantity) AS needed FROM stockwise.order_items
      WHERE company_id=p_company_id AND order_id=p_order_id GROUP BY product_id
    ) q LEFT JOIN stockwise.stock_balances b ON b.company_id=p_company_id AND b.product_id=q.product_id
    WHERE b.product_id IS NULL OR (v_order.kind IN ('sale','adjustment_out') AND b.quantity::numeric < q.needed)
  ) THEN RAISE EXCEPTION 'Insufficient aggregate stock or missing balance'; END IF;
  IF v_order.kind='opening_balance' AND EXISTS (
    SELECT 1 FROM stockwise.stock_movements m JOIN stockwise.order_items i
      ON i.company_id=m.company_id AND i.product_id=m.product_id
    WHERE i.company_id=p_company_id AND i.order_id=p_order_id
  ) THEN RAISE EXCEPTION 'Opening stock requires a product with no previous movements'; END IF;
  IF v_order.kind='opening_balance' AND EXISTS (
    SELECT 1 FROM stockwise.order_items WHERE company_id=p_company_id AND order_id=p_order_id
    GROUP BY product_id HAVING pg_catalog.count(*) > 1
  ) THEN RAISE EXCEPTION 'An opening order must contain each product only once'; END IF;
  UPDATE stockwise.order_items i SET sku_snapshot=p.sku, name_snapshot=p.name,
    unit_code_snapshot=p.unit_code, unit_cost_snapshot=p.unit_cost
    FROM stockwise.products p WHERE i.company_id=p_company_id AND i.order_id=p_order_id
      AND p.company_id=i.company_id AND p.id=i.product_id;
  SELECT pg_catalog.sum(line_subtotal),pg_catalog.sum(discount) INTO v_subtotal,v_discount
    FROM stockwise.order_items WHERE company_id=p_company_id AND order_id=p_order_id;
  UPDATE stockwise.orders SET subtotal=v_subtotal,discount_total=v_discount,
    posting_key=p_operation_key,posted_at=pg_catalog.clock_timestamp(),status='posted'
    WHERE company_id=p_company_id AND id=p_order_id;
  INSERT INTO stockwise.stock_movements(company_id,order_id,order_item_id,product_id,kind,quantity_delta,effective_date)
    SELECT p_company_id,p_order_id,i.id,i.product_id,v_order.kind,
      CASE WHEN v_order.kind IN ('sale','adjustment_out') THEN -i.quantity ELSE i.quantity END,
      v_order.business_date
    FROM stockwise.order_items i WHERE i.company_id=p_company_id AND i.order_id=p_order_id
    ORDER BY i.product_id,i.id;
  INSERT INTO stockwise.audit_logs(company_id,action,target_kind,target_id,order_id,details)
    VALUES(p_company_id,'order_posted','order',p_order_id,p_order_id,
      pg_catalog.jsonb_build_object('operation_key',p_operation_key,'kind',v_order.kind));
  RETURN p_order_id;
END;
$fn$;

CREATE FUNCTION stockwise.reverse_order(
  p_company_id uuid, p_order_id uuid, p_operation_key uuid, p_business_date date, p_reason text
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  v_order stockwise.orders%ROWTYPE;
  v_reversal stockwise.orders%ROWTYPE;
  v_id uuid := pg_catalog.gen_random_uuid();
BEGIN
  IF p_company_id IS NULL OR p_order_id IS NULL OR p_operation_key IS NULL
     OR p_business_date IS NULL OR p_reason IS NULL OR pg_catalog.btrim(p_reason)='' THEN
    RAISE EXCEPTION 'Company, order, key, business date and reversal reason are required';
  END IF;
  SELECT * INTO v_order FROM stockwise.orders
    WHERE company_id=p_company_id AND id=p_order_id FOR UPDATE;
  IF NOT FOUND OR v_order.kind='reversal' THEN RAISE EXCEPTION 'Original order not found or is itself a reversal'; END IF;
  SELECT * INTO v_reversal FROM stockwise.orders WHERE company_id=p_company_id AND original_order_id=p_order_id;
  IF FOUND THEN
    IF v_reversal.status='posted' AND v_reversal.posting_key=p_operation_key
       AND v_reversal.business_date=p_business_date AND v_reversal.notes=pg_catalog.btrim(p_reason) THEN
      RETURN v_reversal.id;
    END IF;
    RAISE EXCEPTION 'Order already has a reversal or key was reused with different input';
  END IF;
  IF v_order.status <> 'posted' THEN RAISE EXCEPTION 'Only a posted order can be reversed'; END IF;
  PERFORM b.product_id FROM stockwise.stock_balances b
    WHERE b.company_id=p_company_id AND b.product_id IN (
      SELECT m.product_id FROM stockwise.stock_movements m WHERE m.company_id=p_company_id AND m.order_id=p_order_id
    ) ORDER BY b.product_id FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM (
      SELECT product_id,pg_catalog.sum(quantity_delta) AS original_delta FROM stockwise.stock_movements
      WHERE company_id=p_company_id AND order_id=p_order_id GROUP BY product_id
    ) q LEFT JOIN stockwise.stock_balances b ON b.company_id=p_company_id AND b.product_id=q.product_id
    WHERE b.product_id IS NULL OR b.quantity::numeric-q.original_delta < 0
  ) THEN RAISE EXCEPTION 'Reversal would make stock negative or balance is missing'; END IF;
  INSERT INTO stockwise.orders(id,company_id,contact_id,reference,kind,business_date,notes,original_order_id)
    VALUES(v_id,p_company_id,v_order.contact_id,'REV-'||v_id::text,'reversal',p_business_date,pg_catalog.btrim(p_reason),p_order_id);
  UPDATE stockwise.orders SET subtotal=v_order.subtotal,discount_total=v_order.discount_total,
    status='posted',posting_key=p_operation_key,posted_at=pg_catalog.clock_timestamp()
    WHERE company_id=p_company_id AND id=v_id;
  INSERT INTO stockwise.stock_movements(company_id,order_id,product_id,kind,quantity_delta,effective_date,reversal_of_movement_id)
    SELECT p_company_id,v_id,m.product_id,'reversal',-m.quantity_delta,p_business_date,m.id
    FROM stockwise.stock_movements m WHERE m.company_id=p_company_id AND m.order_id=p_order_id
    ORDER BY m.product_id,m.id;
  UPDATE stockwise.orders SET status='reversed',reversed_at=pg_catalog.clock_timestamp()
    WHERE company_id=p_company_id AND id=p_order_id;
  INSERT INTO stockwise.audit_logs(company_id,action,target_kind,target_id,order_id,details)
    VALUES(p_company_id,'order_reversed','order',v_id,v_id,
      pg_catalog.jsonb_build_object('operation_key',p_operation_key,'original_order_id',p_order_id));
  RETURN v_id;
END;
$fn$;

-- No policies or runtime grants: non-owner/non-bypass roles receive no access.
ALTER TABLE stockwise.companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.stock_balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.stock_movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise.audit_logs ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA stockwise FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA stockwise FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA stockwise FROM PUBLIC;
-- Revoke named Supabase API roles if present; never create or alter roles.
DO $permissions$
DECLARE v_role text;
BEGIN
  FOREACH v_role IN ARRAY ARRAY['anon','authenticated','service_role','authenticator'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=v_role) THEN
      EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA stockwise FROM %I',v_role);
      EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA stockwise FROM %I',v_role);
      EXECUTE pg_catalog.format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA stockwise FROM %I',v_role);
      EXECUTE pg_catalog.format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA stockwise FROM %I',v_role);
      EXECUTE pg_catalog.format('ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise REVOKE ALL ON TABLES FROM %I',v_role);
      EXECUTE pg_catalog.format('ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise REVOKE ALL ON SEQUENCES FROM %I',v_role);
      EXECUTE pg_catalog.format('ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise REVOKE ALL ON FUNCTIONS FROM %I',v_role);
    END IF;
  END LOOP;
END;
$permissions$;

COMMENT ON SCHEMA stockwise IS 'StockWise inventory migration 0001; no runtime access granted; no browser data imported.';
COMMIT;
