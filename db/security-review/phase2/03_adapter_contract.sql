-- PHASE 2A REVIEW CANDIDATE. Test contract, NOT a production integration.
BEGIN;
-- Laboratory superuser assigns ownership; no temporary runtime-owner CREATE.
GRANT SELECT(id,company_id,legal_name,contact_kind,is_active) ON stockwise.contacts TO sw2_basic_reader;
GRANT SELECT(id,company_id,legal_name,contact_kind,is_active,email,phone,address,tin,identification_number)
  ON stockwise.contacts TO sw2_sales_reader;
CREATE POLICY sw2_customer_selector ON stockwise.contacts FOR SELECT TO sw2_basic_reader
  USING(contact_kind IN ('customer','both') AND sw2_auth.can_company(company_id,'sales'));
CREATE POLICY sw2_linked_customer ON stockwise.contacts FOR SELECT TO sw2_sales_reader
  USING(contact_kind IN ('customer','both') AND EXISTS(SELECT 1 FROM stockwise.orders o
    WHERE o.company_id=contacts.company_id AND o.contact_id=contacts.id
      AND sw2_auth.can_work(o.company_id,o.id)));
CREATE FUNCTION sw2_api.customers(p_company uuid)
RETURNS TABLE(id uuid,legal_name text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT id,legal_name FROM stockwise.contacts WHERE company_id=p_company AND is_active ORDER BY id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.customers(uuid) OWNER TO sw2_basic_reader;
CREATE FUNCTION sw2_api.work_customer(p_company uuid,p_customer uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT jsonb_build_object('id',id,'legal_name',legal_name,'email',email,'phone',phone,
    'address',address,'tin',tin,'registration_number',identification_number)
  FROM stockwise.contacts WHERE company_id=p_company AND id=p_customer
$f$;
ALTER FUNCTION sw2_api.work_customer(uuid,uuid) OWNER TO sw2_sales_reader;
CREATE FUNCTION sw2_api.movements(p_company uuid)
RETURNS TABLE(id uuid,order_id uuid,product_id uuid,kind text,quantity_delta bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT id,order_id,product_id,kind,quantity_delta FROM stockwise.stock_movements
    WHERE company_id=p_company ORDER BY id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.movements(uuid) OWNER TO sw2_business_reader;
CREATE FUNCTION sw2_api.audit(p_company uuid)
RETURNS TABLE(id uuid,action text,target_kind text,target_id uuid,created_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT id,action,target_kind,target_id,created_at FROM stockwise.audit_logs
    WHERE company_id=p_company ORDER BY created_at DESC,id LIMIT 100
$f$;
ALTER FUNCTION sw2_api.audit(uuid) OWNER TO sw2_business_reader;
SET LOCAL ROLE sw2_auth_owner;
CREATE FUNCTION sw2_api.membership(p_company uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE c record; m record;
BEGIN
  SELECT * INTO STRICT c FROM sw2_auth.context();
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company);
  RETURN jsonb_build_object('issuer',c.issuer,'subject',c.subject,'identityId',m.identity_id,
    'companyId',p_company,'role',m.role,'identityStatus','active','companyStatus','active','status','active');
END $f$;
RESET ROLE;
-- Own context helpers are trusted metadata projections, not table reads.
CREATE FUNCTION sw2_api.resource(p_company uuid,p_order uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record; o stockwise.orders%ROWTYPE; creator uuid; state text;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company);
  IF m.role<>'Viewer' AND NOT sw2_auth.can_work(p_company,p_order) THEN RETURN NULL; END IF;
  SELECT * INTO o FROM stockwise.orders WHERE company_id=p_company AND id=p_order;
  IF NOT FOUND THEN RETURN NULL; END IF;
  state:=CASE WHEN sw2_auth.cancelled(p_company,p_order) THEN 'cancelled' ELSE o.status END;
  IF m.role='Viewer' THEN RETURN jsonb_build_object('id',o.id,'companyId',p_company,'state',state); END IF;
  SELECT identity_id INTO creator FROM sw2_auth.creators WHERE company_id=p_company AND order_id=p_order;
  RETURN jsonb_build_object('id',o.id,'companyId',p_company,'creatorIdentityId',creator,'state',state,'kind',o.kind);
END $f$;
-- Owner-context metadata read exception: explicit check above; no SELECT* output.
ALTER FUNCTION sw2_api.resource(uuid,uuid) OWNER TO stockwise_owner;
GRANT SELECT ON sw2_auth.creators TO stockwise_owner;
CREATE POLICY sw2_creator_projection ON sw2_auth.creators FOR SELECT TO stockwise_owner
  USING(sw2_auth.can_work(company_id,order_id));
CREATE FUNCTION sw2_api.target_member(p_company uuid,p_identity uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record; target sw2_auth.memberships%ROWTYPE;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company);
  IF m.role NOT IN ('Owner','Admin') OR m.identity_id=p_identity THEN
    RAISE EXCEPTION 'Membership access denied' USING ERRCODE='42501'; END IF;
  SELECT * INTO target FROM sw2_auth.memberships WHERE company_id=p_company AND identity_id=p_identity AND active;
  IF NOT FOUND OR target.role='Owner' OR (m.role='Admin' AND target.role='Admin') THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('identityId',p_identity,'companyId',p_company,'role',target.role);
END $f$;
ALTER FUNCTION sw2_api.target_member(uuid,uuid) OWNER TO sw2_auth_owner;
CREATE FUNCTION sw2_api.authorize(p_company uuid,p_action text,p_order uuid DEFAULT NULL,
  p_kind text DEFAULT NULL,p_target uuid DEFAULT NULL,p_requested text DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record; c record; o jsonb; target jsonb; allowed boolean:=false; kind text;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  SELECT * INTO STRICT c FROM sw2_auth.context();
  IF p_action IN ('product.basic.read','stock.quantity.read') THEN allowed:=true;
  ELSIF p_action IN ('product.sales.read','contact.select') THEN allowed:=m.role IN ('Owner','Admin','Staff');
  ELSIF p_action IN ('product.cost.read','product.write','stock.history.read','contact.manage','export','audit.read')
    THEN allowed:=m.role IN ('Owner','Admin');
  ELSIF p_action='draft.create' THEN
    kind:=p_kind; allowed:=p_kind IN ('sale','purchase') AND
      (m.role IN ('Owner','Admin') OR (m.role='Staff' AND p_kind='sale'));
  ELSIF p_action='membership.manage' THEN
    target:=sw2_api.target_member(p_company,p_target);
    allowed:=target IS NOT NULL AND p_target<>m.identity_id AND
      (p_requested IN ('Staff','Viewer') OR (p_requested='Admin' AND m.role='Owner'));
  ELSIF p_action IN ('draft.read','draft.edit','draft.cancel','order.basic.read',
                    'order.work.read','contact.work.read','order.post','order.reverse') THEN
    o:=sw2_api.resource(p_company,p_order); kind:=o->>'kind';
    allowed:=o IS NOT NULL AND (m.role IN ('Owner','Admin') OR
      (m.role='Viewer' AND p_action='order.basic.read') OR
      (m.role='Staff' AND p_action NOT IN ('order.post','order.reverse')
        AND sw2_auth.can_work(p_company,p_order)));
    IF p_action IN ('draft.read','draft.edit','draft.cancel','order.post') THEN
      allowed:=allowed AND o->>'state'='draft' AND kind IN ('sale','purchase');
    ELSIF p_action='order.reverse' THEN allowed:=allowed AND o->>'state'='posted'; END IF;
  END IF;
  IF allowed IS DISTINCT FROM true THEN RAISE EXCEPTION 'Operation denied' USING ERRCODE='42501'; END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object('allowed',true,'companyId',p_company,'identityId',m.identity_id,
    'role',m.role,'sessionId',c.session_id,'action',p_action,'resourceId',p_order,'orderKind',kind,
    'targetIdentityId',p_target,'requestedRole',p_requested,'pid',pg_backend_pid(),'xid',pg_current_xact_id()::text));
END $f$;
ALTER FUNCTION sw2_api.authorize(uuid,text,uuid,text,uuid,text) OWNER TO stockwise_owner;
GRANT EXECUTE ON FUNCTION sw2_api.target_member(uuid,uuid) TO stockwise_owner;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sw2_api FROM PUBLIC;
-- Final-stage API grant: no earlier stage makes the runtime role usable.
GRANT EXECUTE ON FUNCTION sw2_api.products(uuid),sw2_api.quantities(uuid),
  sw2_api.status(uuid,uuid),sw2_api.sales_products(uuid),sw2_api.sales_order(uuid,uuid),
  sw2_api.business_products(uuid),sw2_api.create_draft(uuid,uuid,text,text,date),
  sw2_api.edit_notes(uuid,uuid,text),sw2_api.set_line(uuid,uuid,uuid,integer,bigint,numeric,numeric),
  sw2_api.post_order(uuid,uuid,uuid),sw2_api.reverse_order(uuid,uuid,uuid,date,text),
  sw2_api.cancel_draft(uuid,uuid,uuid,text),sw2_api.membership(uuid),sw2_api.resource(uuid,uuid),
  sw2_api.target_member(uuid,uuid),sw2_api.authorize(uuid,text,uuid,text,uuid,text),
  sw2_api.customers(uuid),sw2_api.work_customer(uuid,uuid),sw2_api.movements(uuid),sw2_api.audit(uuid)
  TO sw2_runtime;
REVOKE CREATE ON SCHEMA sw2_api FROM stockwise_owner,sw2_basic_reader,sw2_sales_reader,
  sw2_business_reader,sw2_draft_writer;
REVOKE CREATE ON SCHEMA sw2_auth FROM stockwise_owner;
-- Activation is transactionally coupled to the complete API grant. Until this
-- point both test LOGIN roles are NOLOGIN and have no capability memberships.
GRANT sw2_runtime TO sw2_business WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT sw2_verifier TO sw2_issuer WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
ALTER ROLE sw2_business LOGIN;
ALTER ROLE sw2_issuer LOGIN;
COMMIT;
