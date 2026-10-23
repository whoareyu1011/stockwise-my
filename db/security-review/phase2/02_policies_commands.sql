-- PHASE 2A REVIEW CANDIDATE ONLY. Apply after 01 ONLY in approved disposable lab.
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
GRANT SELECT(id,company_id,sku,name,unit_code,is_active) ON stockwise.products TO sw2_basic_reader;
GRANT SELECT(company_id,product_id,quantity) ON stockwise.stock_balances TO sw2_basic_reader;
GRANT SELECT(id,company_id,status) ON stockwise.orders TO sw2_basic_reader;
GRANT SELECT(id,company_id,sku,name,unit_code,is_active,selling_price) ON stockwise.products TO sw2_sales_reader;
GRANT SELECT(id,company_id,kind,status,business_date,contact_id,subtotal,discount_total,total)
  ON stockwise.orders TO sw2_sales_reader;
GRANT SELECT(id,company_id,order_id,product_id,line_number,quantity,unit_price,discount,line_total)
  ON stockwise.order_items TO sw2_sales_reader;
GRANT SELECT ON stockwise.products,stockwise.contacts,stockwise.orders,stockwise.order_items,
  stockwise.stock_balances,stockwise.stock_movements,stockwise.audit_logs TO sw2_business_reader;
GRANT SELECT(id,company_id,kind,status,contact_id,notes,business_date) ON stockwise.orders TO sw2_draft_writer;
GRANT SELECT(id,company_id,order_id,product_id,line_number,quantity,unit_price,discount)
  ON stockwise.order_items TO sw2_draft_writer;
GRANT SELECT(id,company_id,contact_kind,is_active) ON stockwise.contacts TO sw2_draft_writer;
GRANT SELECT(id,company_id,is_active) ON stockwise.products TO sw2_draft_writer;
GRANT INSERT(id,company_id,kind,contact_id,reference,business_date,notes),
  UPDATE(notes,business_date) ON stockwise.orders TO sw2_draft_writer;
GRANT INSERT(id,company_id,order_id,product_id,line_number,quantity,unit_price,discount),
  UPDATE(product_id,quantity,unit_price,discount) ON stockwise.order_items TO sw2_draft_writer;

CREATE POLICY sw2_product_basic ON stockwise.products FOR SELECT TO sw2_basic_reader
  USING(sw2_auth.can_company(company_id,'basic'));
CREATE POLICY sw2_quantity_basic ON stockwise.stock_balances FOR SELECT TO sw2_basic_reader
  USING(sw2_auth.can_company(company_id,'basic'));
CREATE POLICY sw2_order_basic ON stockwise.orders FOR SELECT TO sw2_basic_reader
  USING(sw2_auth.can_company(company_id,'business') OR sw2_auth.can_work(company_id,id)
    OR (SELECT m.role='Viewer' FROM sw2_auth.member(company_id) m));
CREATE POLICY sw2_product_sales ON stockwise.products FOR SELECT TO sw2_sales_reader
  USING(sw2_auth.can_company(company_id,'sales'));
CREATE POLICY sw2_orders_sales ON stockwise.orders FOR SELECT TO sw2_sales_reader
  USING(sw2_auth.can_work(company_id,id));
CREATE POLICY sw2_lines_sales ON stockwise.order_items FOR SELECT TO sw2_sales_reader
  USING(sw2_auth.can_work(company_id,order_id));
CREATE POLICY sw2_orders_writer_read ON stockwise.orders FOR SELECT TO sw2_draft_writer
  USING(sw2_auth.can_work(company_id,id));
CREATE POLICY sw2_orders_insert ON stockwise.orders FOR INSERT TO sw2_draft_writer
  WITH CHECK(status='draft' AND (sw2_auth.can_company(company_id,'business')
    OR (kind='sale' AND sw2_auth.can_company(company_id,'sales'))));
CREATE POLICY sw2_orders_update ON stockwise.orders FOR UPDATE TO sw2_draft_writer
  USING(status='draft' AND sw2_auth.can_work(company_id,id) AND NOT sw2_auth.cancelled(company_id,id))
  WITH CHECK(status='draft' AND sw2_auth.can_work(company_id,id) AND NOT sw2_auth.cancelled(company_id,id));
CREATE POLICY sw2_lines_writer_read ON stockwise.order_items FOR SELECT TO sw2_draft_writer
  USING(sw2_auth.can_work(company_id,order_id));
CREATE POLICY sw2_lines_insert ON stockwise.order_items FOR INSERT TO sw2_draft_writer
  WITH CHECK(sw2_auth.can_work(company_id,order_id) AND NOT sw2_auth.cancelled(company_id,order_id));
CREATE POLICY sw2_lines_update ON stockwise.order_items FOR UPDATE TO sw2_draft_writer
  USING(sw2_auth.can_work(company_id,order_id) AND NOT sw2_auth.cancelled(company_id,order_id))
  WITH CHECK(sw2_auth.can_work(company_id,order_id) AND NOT sw2_auth.cancelled(company_id,order_id));
CREATE POLICY sw2_writer_contacts ON stockwise.contacts FOR SELECT TO sw2_draft_writer
  USING(sw2_auth.can_company(company_id,'sales'));
CREATE POLICY sw2_writer_products ON stockwise.products FOR SELECT TO sw2_draft_writer
  USING(sw2_auth.can_company(company_id,'sales'));
DO $policies$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['products','contacts','orders','order_items','stock_balances','stock_movements','audit_logs']
  LOOP EXECUTE format('CREATE POLICY sw2_business ON stockwise.%I FOR SELECT TO sw2_business_reader USING(sw2_auth.can_company(company_id,''business''))',t); END LOOP;
END $policies$;

CREATE FUNCTION sw2_api.products(p_company uuid)
RETURNS TABLE(id uuid,sku text,name text,unit_code text,is_active boolean)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT id,sku,name,unit_code,is_active FROM stockwise.products WHERE company_id=p_company ORDER BY id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.products(uuid) OWNER TO sw2_basic_reader;
CREATE FUNCTION sw2_api.quantities(p_company uuid) RETURNS TABLE(product_id uuid,quantity bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT product_id,quantity FROM stockwise.stock_balances WHERE company_id=p_company ORDER BY product_id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.quantities(uuid) OWNER TO sw2_basic_reader;
CREATE FUNCTION sw2_api.status(p_company uuid,p_order uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT jsonb_build_object('id',id,'status',CASE WHEN sw2_auth.cancelled(company_id,id)
    THEN 'cancelled' ELSE status END) FROM stockwise.orders WHERE company_id=p_company AND id=p_order
$f$;
ALTER FUNCTION sw2_api.status(uuid,uuid) OWNER TO sw2_basic_reader;
CREATE FUNCTION sw2_api.sales_products(p_company uuid)
RETURNS TABLE(id uuid,sku text,name text,selling_price numeric)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT id,sku,name,selling_price FROM stockwise.products WHERE company_id=p_company ORDER BY id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.sales_products(uuid) OWNER TO sw2_sales_reader;
CREATE FUNCTION sw2_api.sales_order(p_company uuid,p_order uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT jsonb_build_object('id',o.id,'kind',o.kind,'status',CASE WHEN sw2_auth.cancelled(o.company_id,o.id)
    THEN 'cancelled' ELSE o.status END,'business_date',o.business_date,'contact_id',o.contact_id,
    'subtotal',o.subtotal,'discount_total',o.discount_total,'total',o.total,
    'lines',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',i.id,'product_id',i.product_id,
      'quantity',i.quantity,'unit_price',i.unit_price,'discount',i.discount,'line_total',i.line_total)
      ORDER BY i.line_number),'[]'::jsonb) FROM stockwise.order_items i
      WHERE i.company_id=o.company_id AND i.order_id=o.id))
    FROM stockwise.orders o WHERE o.company_id=p_company AND o.id=p_order
$f$;
ALTER FUNCTION sw2_api.sales_order(uuid,uuid) OWNER TO sw2_sales_reader;
CREATE FUNCTION sw2_api.business_products(p_company uuid)
RETURNS TABLE(id uuid,name text,unit_cost numeric,selling_price numeric)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT id,name,unit_cost,selling_price FROM stockwise.products WHERE company_id=p_company ORDER BY id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.business_products(uuid) OWNER TO sw2_business_reader;

CREATE FUNCTION sw2_api.create_draft(p_company uuid,p_contact uuid,p_reference text,p_kind text,p_date date)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE v uuid:=gen_random_uuid(); m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  IF p_kind NOT IN ('sale','purchase') OR NOT (m.role IN ('Owner','Admin') OR (m.role='Staff' AND p_kind='sale'))
    OR NOT EXISTS(SELECT 1 FROM stockwise.contacts WHERE company_id=p_company AND id=p_contact AND is_active
      AND (contact_kind='both' OR (p_kind='sale' AND contact_kind='customer') OR (p_kind='purchase' AND contact_kind='supplier')))
    THEN RAISE EXCEPTION 'Draft denied' USING ERRCODE='42501'; END IF;
  INSERT INTO stockwise.orders(id,company_id,contact_id,reference,kind,business_date)
    VALUES(v,p_company,p_contact,p_reference,p_kind,p_date);
  PERFORM sw2_auth.remember(p_company,v,p_kind);
  PERFORM sw2_auth.event(p_company,'draft_created',v);
  RETURN v;
END $f$;
ALTER FUNCTION sw2_api.create_draft(uuid,uuid,text,text,date) OWNER TO sw2_draft_writer;
CREATE FUNCTION sw2_api.edit_notes(p_company uuid,p_order uuid,p_notes text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
BEGIN
  PERFORM * FROM sw2_auth.member(p_company,true);
  PERFORM id FROM stockwise.orders WHERE company_id=p_company AND id=p_order
    AND status='draft' AND NOT sw2_auth.cancelled(company_id,id) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Draft denied' USING ERRCODE='42501'; END IF;
  UPDATE stockwise.orders SET notes=p_notes WHERE company_id=p_company AND id=p_order;
  PERFORM sw2_auth.event(p_company,'draft_edited',p_order);
END $f$;
ALTER FUNCTION sw2_api.edit_notes(uuid,uuid,text) OWNER TO sw2_draft_writer;
CREATE FUNCTION sw2_api.set_line(p_company uuid,p_order uuid,p_product uuid,p_line integer,p_qty bigint,p_price numeric,p_discount numeric)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE v uuid:=gen_random_uuid();
BEGIN
  PERFORM * FROM sw2_auth.member(p_company,true);
  PERFORM id FROM stockwise.orders WHERE company_id=p_company AND id=p_order
    AND status='draft' AND NOT sw2_auth.cancelled(company_id,id) FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM stockwise.products WHERE company_id=p_company AND id=p_product AND is_active)
    THEN RAISE EXCEPTION 'Draft denied' USING ERRCODE='42501'; END IF;
  INSERT INTO stockwise.order_items(id,company_id,order_id,product_id,line_number,quantity,unit_price,discount)
    VALUES(v,p_company,p_order,p_product,p_line,p_qty,p_price,p_discount)
    ON CONFLICT(company_id,order_id,line_number) DO UPDATE
      SET product_id=excluded.product_id,quantity=excluded.quantity,unit_price=excluded.unit_price,discount=excluded.discount
    RETURNING id INTO v;
  PERFORM sw2_auth.event(p_company,'draft_line_edited',p_order);
  RETURN v;
END $f$;
ALTER FUNCTION sw2_api.set_line(uuid,uuid,uuid,integer,bigint,numeric,numeric) OWNER TO sw2_draft_writer;

-- Owner-context command wrappers are an explicit RLS exception; current
-- identity/company checks are mandatory before even idempotent returns.
CREATE FUNCTION sw2_api.post_order(p_company uuid,p_order uuid,p_key uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record; o stockwise.orders%ROWTYPE; result uuid;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  IF m.role NOT IN ('Owner','Admin') THEN RAISE EXCEPTION 'Posting denied' USING ERRCODE='42501'; END IF;
  SELECT * INTO o FROM stockwise.orders WHERE company_id=p_company AND id=p_order FOR UPDATE;
  -- Phase 2A deliberately exposes ordinary sales/purchases only. Stock
  -- adjustments and opening balances remain unavailable to runtime callers.
  IF NOT FOUND OR o.kind NOT IN ('sale','purchase')
    OR sw2_auth.cancelled(p_company,p_order) THEN RAISE EXCEPTION 'Posting denied' USING ERRCODE='42501'; END IF;
  result:=stockwise.post_order(p_company,p_order,p_key);
  PERFORM sw2_auth.event(p_company,'order_posted',result,p_key);
  RETURN result;
END $f$;
ALTER FUNCTION sw2_api.post_order(uuid,uuid,uuid) OWNER TO stockwise_owner;
CREATE FUNCTION sw2_api.reverse_order(p_company uuid,p_order uuid,p_key uuid,p_date date,p_reason text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record; result uuid;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  IF m.role NOT IN ('Owner','Admin') THEN RAISE EXCEPTION 'Reversal denied' USING ERRCODE='42501'; END IF;
  PERFORM id FROM stockwise.orders WHERE company_id=p_company AND id=p_order FOR UPDATE;
  IF NOT FOUND OR sw2_auth.cancelled(p_company,p_order) THEN RAISE EXCEPTION 'Reversal denied' USING ERRCODE='42501'; END IF;
  result:=stockwise.reverse_order(p_company,p_order,p_key,p_date,p_reason);
  PERFORM sw2_auth.event(p_company,'order_reversed',result,p_key);
  RETURN result;
END $f$;
ALTER FUNCTION sw2_api.reverse_order(uuid,uuid,uuid,date,text) OWNER TO stockwise_owner;

SET LOCAL ROLE sw2_auth_owner;
CREATE FUNCTION sw2_auth.cancel(p_company uuid,p_order uuid,p_key uuid,p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE old sw2_auth.cancellations%ROWTYPE; m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  IF NOT sw2_auth.can_work(p_company,p_order) OR p_key IS NULL OR p_reason IS NULL OR btrim(p_reason)=''
    THEN RAISE EXCEPTION 'Cancellation denied' USING ERRCODE='42501'; END IF;
  SELECT * INTO old FROM sw2_auth.cancellations WHERE company_id=p_company AND order_id=p_order;
  IF FOUND THEN
    IF old.request_key=p_key AND old.reason=btrim(p_reason) THEN RETURN; END IF;
    RAISE EXCEPTION 'Cancellation conflict' USING ERRCODE='23505';
  END IF;
  INSERT INTO sw2_auth.cancellations VALUES(p_company,p_order,m.identity_id,p_key,btrim(p_reason),clock_timestamp());
  PERFORM sw2_auth.event(p_company,'draft_cancelled',p_order,p_key);
END $f$;
GRANT EXECUTE ON FUNCTION sw2_auth.cancel(uuid,uuid,uuid,text) TO stockwise_owner;
RESET ROLE;
CREATE FUNCTION sw2_api.cancel_draft(p_company uuid,p_order uuid,p_key uuid,p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record; o stockwise.orders%ROWTYPE;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  IF NOT sw2_auth.can_work(p_company,p_order) THEN RAISE EXCEPTION 'Cancellation denied' USING ERRCODE='42501'; END IF;
  SELECT * INTO o FROM stockwise.orders WHERE company_id=p_company AND id=p_order FOR UPDATE;
  IF NOT FOUND OR o.status<>'draft' OR o.kind NOT IN ('sale','purchase')
    OR EXISTS(SELECT 1 FROM stockwise.stock_movements WHERE company_id=p_company AND order_id=p_order)
    THEN RAISE EXCEPTION 'Ineligible draft' USING ERRCODE='42501'; END IF;
  PERFORM sw2_auth.cancel(p_company,p_order,p_key,p_reason);
END $f$;
ALTER FUNCTION sw2_api.cancel_draft(uuid,uuid,uuid,text) OWNER TO stockwise_owner;
CREATE FUNCTION sw2_auth.guard_cancelled() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE c uuid; o uuid;
BEGIN
  IF TG_TABLE_NAME='orders' THEN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Hard deletion denied'; END IF;
    c:=NEW.company_id; o:=NEW.id;
  ELSE
    IF TG_OP='DELETE' THEN c:=OLD.company_id; o:=OLD.order_id;
    ELSE c:=NEW.company_id; o:=NEW.order_id; END IF;
    PERFORM id FROM stockwise.orders WHERE company_id=c AND id=o FOR UPDATE;
  END IF;
  IF sw2_auth.cancelled(c,o) THEN RAISE EXCEPTION 'Cancelled draft is terminal'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $f$;
ALTER FUNCTION sw2_auth.guard_cancelled() OWNER TO stockwise_owner;
CREATE TRIGGER sw2_cancelled_order BEFORE UPDATE OR DELETE ON stockwise.orders
  FOR EACH ROW EXECUTE FUNCTION sw2_auth.guard_cancelled();
CREATE TRIGGER sw2_cancelled_line BEFORE INSERT OR UPDATE OR DELETE ON stockwise.order_items
  FOR EACH ROW EXECUTE FUNCTION sw2_auth.guard_cancelled();
DO $append_only$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['creators','cancellations','events'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_rows BEFORE UPDATE OR DELETE ON sw2_auth.%I FOR EACH ROW EXECUTE FUNCTION stockwise.reject_mutation()',t);
    EXECUTE format('CREATE TRIGGER immutable_table BEFORE TRUNCATE ON sw2_auth.%I FOR EACH STATEMENT EXECUTE FUNCTION stockwise.reject_mutation()',t);
  END LOOP;
END $append_only$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sw2_api FROM PUBLIC;
REVOKE ALL ON FUNCTION sw2_auth.guard_cancelled() FROM PUBLIC;
-- No runtime execution grant is committed at this stage. The final stage
-- grants the complete reviewed API surface and activates LOGINs atomically.
COMMIT;
