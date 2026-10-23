-- Additive extension for the Replit-managed development schema only.
-- Apply only after 0001_products_inventory.sql.
-- No runtime policies or grants are created.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
BEGIN
  IF pg_catalog.to_regclass('stockwise_mvp.product_audit_events') IS NOT NULL THEN
    RAISE EXCEPTION 'product_audit_events already exists; inspect it before applying this migration';
  END IF;
  IF pg_catalog.to_regclass('stockwise_mvp.company_memberships') IS NULL
     OR pg_catalog.to_regclass('stockwise_mvp.products') IS NULL THEN
    RAISE EXCEPTION '0001_products_inventory.sql must be applied first';
  END IF;
END
$preflight$;

CREATE TABLE stockwise_mvp.product_audit_events (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL,
  actor_membership_id uuid NOT NULL,
  action text NOT NULL CHECK (
    action IN ('product.created', 'product.updated', 'product.archived', 'stock.adjusted')
  ),
  product_id uuid NOT NULL,
  details jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(details) = 'object'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.transaction_timestamp(),
  FOREIGN KEY (company_id, actor_membership_id)
    REFERENCES stockwise_mvp.company_memberships(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, product_id)
    REFERENCES stockwise_mvp.products(company_id, id) ON DELETE RESTRICT
);
CREATE INDEX product_audit_company_time_idx
  ON stockwise_mvp.product_audit_events (company_id, created_at DESC, id);

ALTER TABLE stockwise_mvp.product_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_mvp.product_audit_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE stockwise_mvp.product_audit_events FROM PUBLIC;

COMMIT;
