-- REVIEW ONLY: tested in a disposable local cluster, NEVER applied to Supabase.
-- Requires unchanged 0001 and deployment steps 01/02/03. No LOGIN credentials.
-- The capability roles/grants below are PROPOSALS, not authorized live access.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
DO $preflight$
BEGIN
  IF pg_catalog.current_setting('server_version_num')::integer/10000<>17
     OR pg_catalog.to_regnamespace('stockwise') IS NULL THEN
    RAISE EXCEPTION 'Reviewed PostgreSQL 17 inventory installation required';
  END IF;
  IF pg_catalog.to_regrole('stockwise_runtime') IS NOT NULL
     OR pg_catalog.to_regrole('stockwise_verifier') IS NOT NULL
     OR pg_catalog.to_regnamespace('stockwise_auth') IS NOT NULL
     OR pg_catalog.to_regnamespace('stockwise_api') IS NOT NULL THEN
    RAISE EXCEPTION 'Security review objects already exist; do not overwrite';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl a
    WHERE a.defaclrole=pg_catalog.to_regrole('stockwise_owner')
      AND a.defaclobjtype='f' AND a.defaclnamespace=0
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(a.defaclacl) x WHERE x.grantee=0)
  ) THEN RAISE EXCEPTION 'Owner-global function hardening must run first'; END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl a
    CROSS JOIN LATERAL pg_catalog.aclexplode(a.defaclacl) x
    WHERE a.defaclrole=pg_catalog.to_regrole('stockwise_owner')
      AND a.defaclobjtype='f' AND x.grantee<>a.defaclrole
  ) THEN RAISE EXCEPTION 'Unexpected owner function default grants'; END IF;
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='stockwise' AND c.relkind='r'
        AND c.relowner=pg_catalog.to_regrole('stockwise_owner')
        AND c.relrowsecurity AND NOT c.relforcerowsecurity)<>8
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_policies WHERE schemaname='stockwise') THEN
    RAISE EXCEPTION 'Expected untouched eight-table RLS installation with no policies';
  END IF;
END;
$preflight$;
CREATE ROLE stockwise_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE
  NOCREATEDB NOINHERIT NOREPLICATION;
CREATE ROLE stockwise_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE
  NOCREATEDB NOINHERIT NOREPLICATION;
SET LOCAL ROLE stockwise_migrator;
CREATE SCHEMA stockwise_auth AUTHORIZATION stockwise_owner;
CREATE SCHEMA stockwise_api AUTHORIZATION stockwise_owner;
SET LOCAL ROLE stockwise_owner;
REVOKE ALL ON SCHEMA stockwise_auth,stockwise_api FROM PUBLIC;

CREATE TABLE stockwise_auth.issuers (
  issuer text PRIMARY KEY CHECK (issuer LIKE 'https://%' AND pg_catalog.btrim(issuer)=issuer),
  enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE stockwise_auth.identities (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  issuer text NOT NULL REFERENCES stockwise_auth.issuers(issuer) ON DELETE RESTRICT,
  subject text NOT NULL CHECK (pg_catalog.length(subject) BETWEEN 1 AND 200),
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  UNIQUE(issuer,subject)
);
CREATE TABLE stockwise_auth.company_memberships (
  company_id uuid NOT NULL REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL REFERENCES stockwise_auth.identities(id) ON DELETE RESTRICT,
  member_role text NOT NULL CHECK (member_role IN ('owner','admin','operator','viewer')),
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY(company_id,identity_id)
);
CREATE INDEX memberships_actor_idx ON stockwise_auth.company_memberships(identity_id,company_id);
-- Only a hash of a server-internal, short-lived random proof is stored.
-- No JWT, password, database credential or raw proof is stored.
CREATE TABLE stockwise_auth.request_proofs (
  proof_hash bytea PRIMARY KEY,
  identity_id uuid NOT NULL REFERENCES stockwise_auth.identities(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
  backend_pid integer NOT NULL CHECK (backend_pid>0),
  transaction_id xid8 NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  UNIQUE(backend_pid,transaction_id)
);
CREATE INDEX request_proofs_expiry_idx ON stockwise_auth.request_proofs(expires_at);
CREATE TABLE stockwise_auth.command_audit (
  id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  company_id uuid NOT NULL REFERENCES stockwise.companies(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL REFERENCES stockwise_auth.identities(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('post','reverse')),
  operation_key uuid NOT NULL,
  order_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  FOREIGN KEY(company_id,order_id) REFERENCES stockwise.orders(company_id,id) ON DELETE RESTRICT,
  UNIQUE(company_id,action,operation_key)
);
CREATE TRIGGER command_audit_immutable BEFORE UPDATE OR DELETE ON stockwise_auth.command_audit
  FOR EACH ROW EXECUTE FUNCTION stockwise.reject_mutation();
CREATE TRIGGER command_audit_no_truncate BEFORE TRUNCATE ON stockwise_auth.command_audit
  FOR EACH STATEMENT EXECUTE FUNCTION stockwise.reject_mutation();
ALTER TABLE stockwise_auth.issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_auth.identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_auth.company_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_auth.request_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE stockwise_auth.command_audit ENABLE ROW LEVEL SECURITY;

-- Trusted verifier only: issuer/subject come from a verified JWT, pid/xid from
-- the checked-out runtime connection. This credential must not serve SQL input.
CREATE FUNCTION stockwise_auth.issue_context(p_issuer text,p_subject text,p_pid integer,p_xid xid8,p_jwt_exp timestamptz)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE v_actor uuid; v_token text;
BEGIN
  SELECT i.id INTO v_actor FROM stockwise_auth.identities i
    JOIN stockwise_auth.issuers s ON s.issuer=i.issuer
    WHERE i.issuer=p_issuer AND i.subject=p_subject AND i.active AND s.enabled;
  IF v_actor IS NULL OR p_pid IS NULL OR p_pid<=0 OR p_xid IS NULL OR p_xid='0'::xid8
     OR p_jwt_exp IS NULL OR p_jwt_exp<=pg_catalog.clock_timestamp() THEN
    RAISE EXCEPTION 'Authenticated context unavailable' USING ERRCODE='42501';
  END IF;
  v_token := pg_catalog.replace(pg_catalog.gen_random_uuid()::text,'-','')
          || pg_catalog.replace(pg_catalog.gen_random_uuid()::text,'-','');
  INSERT INTO stockwise_auth.request_proofs(proof_hash,identity_id,backend_pid,transaction_id,expires_at)
    VALUES(pg_catalog.sha256(pg_catalog.convert_to(v_token,'UTF8')),v_actor,p_pid,p_xid,
      LEAST(p_jwt_exp,pg_catalog.clock_timestamp()+interval '60 seconds'));
  RETURN v_token;
END;
$fn$;

-- Bare actor/company GUCs are never trusted. A proof must match BOTH this
-- backend and this full transaction ID, and still be live in the private table.
CREATE FUNCTION stockwise_auth.verified_context()
RETURNS TABLE(identity_id uuid,request_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE v_token text := pg_catalog.current_setting('stockwise.request_proof',true);
BEGIN
  IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'Security context requires READ COMMITTED' USING ERRCODE='25001';
  END IF;
  IF v_token IS NULL OR pg_catalog.length(v_token)<>64 THEN RETURN; END IF;
  RETURN QUERY SELECT p.identity_id,p.request_id
    FROM stockwise_auth.request_proofs p
    JOIN stockwise_auth.identities i ON i.id=p.identity_id
    JOIN stockwise_auth.issuers s ON s.issuer=i.issuer
    WHERE p.proof_hash=pg_catalog.sha256(pg_catalog.convert_to(v_token,'UTF8'))
      AND p.backend_pid=pg_catalog.pg_backend_pid()
      AND p.transaction_id=pg_catalog.pg_current_xact_id_if_assigned()
      AND p.expires_at>pg_catalog.clock_timestamp() AND i.active AND s.enabled;
END;
$fn$;
CREATE FUNCTION stockwise_auth.activate_context(p_proof text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
  PERFORM pg_catalog.set_config('stockwise.request_proof',COALESCE(p_proof,''),true);
  IF NOT EXISTS (SELECT 1 FROM stockwise_auth.verified_context()) THEN
    RAISE EXCEPTION 'Authenticated context unavailable' USING ERRCODE='42501';
  END IF;
END;
$fn$;
CREATE FUNCTION stockwise_auth.can_read_company(p_company uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
  SELECT EXISTS (
    SELECT 1 FROM stockwise_auth.company_memberships m
    JOIN stockwise_auth.verified_context() c ON c.identity_id=m.identity_id
    WHERE m.company_id=p_company AND m.active
  );
$fn$;
CREATE FUNCTION stockwise_auth.authorize(p_company uuid,p_action text)
RETURNS TABLE(identity_id uuid,request_id uuid,member_role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE v_actor uuid; v_request uuid; v_role text;
BEGIN
  SELECT c.identity_id,c.request_id INTO v_actor,v_request FROM stockwise_auth.verified_context() c;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'Authenticated context unavailable' USING ERRCODE='42501';
  END IF;
  -- Hold authorization rows through the whole command; revocation updates
  -- serialize with a command that already acquired these shared locks.
  SELECT m.member_role INTO v_role FROM stockwise_auth.company_memberships m
    JOIN stockwise_auth.identities i ON i.id=m.identity_id
    JOIN stockwise_auth.issuers s ON s.issuer=i.issuer
    WHERE m.company_id=p_company AND m.identity_id=v_actor
      AND m.active AND i.active AND s.enabled
    FOR SHARE OF m,i,s;
  IF v_role IS NULL OR p_action IS NULL
     OR NOT (p_action='read'
       OR (p_action='post' AND v_role IN ('owner','admin','operator'))
       OR (p_action='reverse' AND v_role IN ('owner','admin'))) THEN
    RAISE EXCEPTION 'Company operation not permitted' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT v_actor,v_request,v_role;
END;
$fn$;

CREATE FUNCTION stockwise_api.my_companies()
RETURNS TABLE(company_id uuid,legal_name text,member_role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE v_actor uuid;
BEGIN
  SELECT c.identity_id INTO v_actor FROM stockwise_auth.verified_context() c;
  IF v_actor IS NULL THEN
    RAISE EXCEPTION 'Authenticated context unavailable' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT m.company_id,c.legal_name,m.member_role
    FROM stockwise_auth.company_memberships m JOIN stockwise.companies c ON c.id=m.company_id
    WHERE m.identity_id=v_actor AND m.active ORDER BY m.company_id;
END;
$fn$;
CREATE FUNCTION stockwise_api.post_order(p_company uuid,p_order uuid,p_key uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE v_actor uuid; v_request uuid; v_role text; v_kind text; v_result uuid;
BEGIN
  SELECT a.identity_id,a.request_id,a.member_role INTO v_actor,v_request,v_role
    FROM stockwise_auth.authorize(p_company,'post') a;
  -- Lock the header before inspecting kind, preserving the core lock order and
  -- preventing a concurrent draft kind change after the permission decision.
  SELECT o.kind INTO v_kind FROM stockwise.orders o
    WHERE o.company_id=p_company AND o.id=p_order FOR UPDATE;
  IF NOT FOUND OR (v_role='operator' AND v_kind NOT IN ('sale','purchase')) THEN
    RAISE EXCEPTION 'Company operation not permitted' USING ERRCODE='42501';
  END IF;
  v_result := stockwise.post_order(p_company,p_order,p_key);
  INSERT INTO stockwise_auth.command_audit(company_id,identity_id,request_id,action,operation_key,order_id)
    VALUES(p_company,v_actor,v_request,'post',p_key,v_result)
    ON CONFLICT(company_id,action,operation_key) DO NOTHING;
  RETURN v_result;
END;
$fn$;
CREATE FUNCTION stockwise_api.reverse_order(p_company uuid,p_order uuid,p_key uuid,p_date date,p_reason text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE v_actor uuid; v_request uuid; v_result uuid;
BEGIN
  SELECT a.identity_id,a.request_id INTO v_actor,v_request
    FROM stockwise_auth.authorize(p_company,'reverse') a;
  v_result := stockwise.reverse_order(p_company,p_order,p_key,p_date,p_reason);
  INSERT INTO stockwise_auth.command_audit(company_id,identity_id,request_id,action,operation_key,order_id)
    VALUES(p_company,v_actor,v_request,'reverse',p_key,v_result)
    ON CONFLICT(company_id,action,operation_key) DO NOTHING;
  RETURN v_result;
END;
$fn$;

-- SELECT-only policies: there is no direct runtime INSERT/UPDATE/DELETE path.
CREATE POLICY runtime_read ON stockwise.companies FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(id));
CREATE POLICY runtime_read ON stockwise.products FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));
CREATE POLICY runtime_read ON stockwise.contacts FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));
CREATE POLICY runtime_read ON stockwise.orders FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));
CREATE POLICY runtime_read ON stockwise.order_items FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));
CREATE POLICY runtime_read ON stockwise.stock_balances FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));
CREATE POLICY runtime_read ON stockwise.stock_movements FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));
CREATE POLICY runtime_read ON stockwise.audit_logs FOR SELECT TO stockwise_runtime
  USING (stockwise_auth.can_read_company(company_id));

REVOKE ALL ON ALL TABLES IN SCHEMA stockwise_auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA stockwise_auth,stockwise_api FROM PUBLIC;
GRANT USAGE ON SCHEMA stockwise_auth TO stockwise_runtime,stockwise_verifier;
GRANT USAGE ON SCHEMA stockwise_api,stockwise TO stockwise_runtime;
GRANT EXECUTE ON FUNCTION stockwise_auth.issue_context(text,text,integer,xid8,timestamptz) TO stockwise_verifier;
GRANT EXECUTE ON FUNCTION stockwise_auth.activate_context(text),
  stockwise_auth.can_read_company(uuid) TO stockwise_runtime;
GRANT EXECUTE ON FUNCTION stockwise_api.my_companies(),
  stockwise_api.post_order(uuid,uuid,uuid),
  stockwise_api.reverse_order(uuid,uuid,uuid,date,text) TO stockwise_runtime;
GRANT SELECT ON stockwise.companies,stockwise.products,stockwise.contacts,
  stockwise.orders,stockwise.order_items,stockwise.stock_balances,
  stockwise.stock_movements,stockwise.audit_logs TO stockwise_runtime;
-- No role is made a member of either capability role here. No credentials.
-- Original stockwise functions remain private; auth internals remain owner-only.
COMMIT;
