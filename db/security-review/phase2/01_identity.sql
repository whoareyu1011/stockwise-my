-- PHASE 2A PROPOSAL ONLY. NOT COMPILED, EXECUTED OR APPROVED FOR DEPLOYMENT.
-- Laboratory bootstrap ONLY, after unchanged 01/02/0001/03 installation.
-- Not a Supabase migration. Local superuser is used only for laboratory DDL.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
DO $gate$
BEGIN
  IF current_setting('server_version_num')::integer / 10000 <> 17
     OR current_setting('listen_addresses') <> ''
     OR current_setting('data_directory') !~ '^/tmp/stockwise-phase2-[A-Za-z0-9]+/data$'
     OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)
     OR to_regnamespace('sw2_auth') IS NOT NULL
     OR (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='stockwise' AND c.relkind='r' AND c.relrowsecurity
         AND NOT c.relforcerowsecurity AND c.relowner='stockwise_owner'::regrole) <> 8
  THEN RAISE EXCEPTION 'Fresh isolated PostgreSQL 17 laboratory required'; END IF;
END $gate$;
CREATE ROLE sw2_auth_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
CREATE ROLE sw2_basic_reader NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
CREATE ROLE sw2_sales_reader NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
CREATE ROLE sw2_business_reader NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
CREATE ROLE sw2_draft_writer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
CREATE ROLE sw2_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
CREATE ROLE sw2_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
-- LOGINs and capability memberships are activated only by the final stage.
-- An interrupted stage 01/02 installation therefore has no usable runtime login.
CREATE ROLE sw2_business NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT;
CREATE ROLE sw2_issuer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT;
CREATE SCHEMA sw2_auth AUTHORIZATION sw2_auth_owner;
CREATE SCHEMA sw2_api AUTHORIZATION sw2_auth_owner;
REVOKE ALL ON SCHEMA sw2_auth,sw2_api FROM PUBLIC;
GRANT USAGE ON SCHEMA stockwise TO sw2_auth_owner,sw2_basic_reader,sw2_sales_reader,
  sw2_business_reader,sw2_draft_writer;
GRANT REFERENCES ON stockwise.companies,stockwise.orders TO sw2_auth_owner;
GRANT USAGE ON SCHEMA sw2_auth TO stockwise_owner,sw2_basic_reader,sw2_sales_reader,
  sw2_business_reader,sw2_draft_writer,sw2_runtime,sw2_verifier;
GRANT USAGE ON SCHEMA sw2_api TO sw2_runtime;
GRANT USAGE ON SCHEMA sw2_api TO stockwise_owner,sw2_basic_reader,sw2_sales_reader,
  sw2_business_reader,sw2_draft_writer;
-- No temporary CREATE grants: this laboratory bootstrap uses its reviewed
-- installer authority to create and reassign function ownership. A hosted
-- deployment authority is a separate unresolved design, not a runtime grant.
DO $defaults$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['sw2_auth_owner','sw2_basic_reader','sw2_sales_reader',
    'sw2_business_reader','sw2_draft_writer','sw2_runtime','sw2_verifier']
  LOOP
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',r);
  END LOOP;
END $defaults$;
SET LOCAL ROLE sw2_auth_owner;
CREATE TABLE sw2_auth.identities (
  id uuid PRIMARY KEY, issuer text NOT NULL, subject text NOT NULL,
  active boolean NOT NULL DEFAULT false, UNIQUE(issuer,subject)
);
CREATE TABLE sw2_auth.companies (
  company_id uuid PRIMARY KEY REFERENCES stockwise.companies(id),
  active boolean NOT NULL DEFAULT false
);
CREATE TABLE sw2_auth.memberships (
  company_id uuid REFERENCES sw2_auth.companies(company_id),
  identity_id uuid REFERENCES sw2_auth.identities(id),
  role text NOT NULL CHECK(role IN ('Owner','Admin','Staff','Viewer')),
  active boolean NOT NULL DEFAULT false, PRIMARY KEY(company_id,identity_id)
);
CREATE UNIQUE INDEX one_owner ON sw2_auth.memberships(company_id) WHERE role='Owner' AND active;
CREATE TABLE sw2_auth.sessions (
  session_id uuid PRIMARY KEY, identity_id uuid NOT NULL REFERENCES sw2_auth.identities(id),
  expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT true,
  -- This is a laboratory status source, NEVER provider-session evidence.
  source text NOT NULL CHECK(source='synthetic-fixture-only'),
  checked_at timestamptz NOT NULL, UNIQUE(session_id,identity_id)
);
CREATE TABLE sw2_auth.proofs (
  digest bytea PRIMARY KEY, identity_id uuid NOT NULL REFERENCES sw2_auth.identities(id),
  session_id uuid NOT NULL REFERENCES sw2_auth.sessions(session_id),
  pid integer NOT NULL, xid xid8 NOT NULL, expires_at timestamptz NOT NULL,
  request_id uuid NOT NULL DEFAULT gen_random_uuid(), UNIQUE(pid,xid),
  FOREIGN KEY(session_id,identity_id) REFERENCES sw2_auth.sessions(session_id,identity_id)
);
CREATE TABLE sw2_auth.creators (
  company_id uuid NOT NULL, order_id uuid NOT NULL,
  identity_id uuid NOT NULL REFERENCES sw2_auth.identities(id),
  kind text NOT NULL CHECK(kind IN ('sale','purchase','adjustment_in','adjustment_out','opening_balance','reversal')),
  PRIMARY KEY(company_id,order_id),
  FOREIGN KEY(company_id,order_id) REFERENCES stockwise.orders(company_id,id),
  FOREIGN KEY(company_id,identity_id) REFERENCES sw2_auth.memberships(company_id,identity_id)
);
CREATE TABLE sw2_auth.cancellations (
  company_id uuid NOT NULL, order_id uuid NOT NULL, identity_id uuid NOT NULL REFERENCES sw2_auth.identities(id),
  request_key uuid NOT NULL, reason text NOT NULL CHECK(btrim(reason)<>''), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(company_id,order_id), UNIQUE(company_id,request_key),
  FOREIGN KEY(company_id,order_id) REFERENCES stockwise.orders(company_id,id),
  FOREIGN KEY(company_id,identity_id) REFERENCES sw2_auth.memberships(company_id,identity_id)
);
CREATE TABLE sw2_auth.events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), company_id uuid NOT NULL REFERENCES sw2_auth.companies(company_id),
  identity_id uuid NOT NULL REFERENCES sw2_auth.identities(id), session_id uuid NOT NULL REFERENCES sw2_auth.sessions(session_id),
  action text NOT NULL, order_id uuid, request_key uuid,
  actor_role text NOT NULL CHECK(actor_role IN ('Owner','Admin','Staff','Viewer')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(company_id,order_id) REFERENCES stockwise.orders(company_id,id),
  FOREIGN KEY(company_id,identity_id) REFERENCES sw2_auth.memberships(company_id,identity_id),
  FOREIGN KEY(session_id,identity_id) REFERENCES sw2_auth.sessions(session_id,identity_id)
);
CREATE UNIQUE INDEX command_event_once ON sw2_auth.events(company_id,action,request_key) WHERE request_key IS NOT NULL;
ALTER TABLE sw2_auth.identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.creators ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.cancellations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sw2_auth.events ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION sw2_auth.context()
RETURNS TABLE(identity_id uuid,session_id uuid,issuer text,subject text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'READ COMMITTED required' USING ERRCODE='25001';
  END IF;
  RETURN QUERY SELECT i.id,s.session_id,i.issuer,i.subject
    FROM sw2_auth.proofs p JOIN sw2_auth.identities i ON i.id=p.identity_id
    JOIN sw2_auth.sessions s ON s.session_id=p.session_id AND s.identity_id=i.id
    WHERE p.digest=sha256(convert_to(current_setting('sw2.proof',true),'UTF8'))
      AND p.pid=pg_backend_pid() AND p.xid=pg_current_xact_id()
      AND p.expires_at>clock_timestamp() AND i.active AND NOT s.revoked
      AND s.expires_at>clock_timestamp() AND s.checked_at<=clock_timestamp()
      AND s.checked_at>clock_timestamp()-interval '30 seconds';
  IF NOT FOUND THEN RAISE EXCEPTION 'Verified context required' USING ERRCODE='42501'; END IF;
END $f$;
CREATE FUNCTION sw2_auth.member(p_company uuid,p_lock boolean DEFAULT false)
RETURNS TABLE(identity_id uuid,role text,session_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE v record;
BEGIN
  SELECT * INTO STRICT v FROM sw2_auth.context();
  IF p_lock THEN
    RETURN QUERY SELECT m.identity_id,m.role,v.session_id FROM sw2_auth.memberships m
      JOIN sw2_auth.companies c USING(company_id) JOIN sw2_auth.identities i ON i.id=m.identity_id
      JOIN sw2_auth.sessions s ON s.session_id=v.session_id
      WHERE m.company_id=p_company AND m.identity_id=v.identity_id AND m.active AND c.active AND i.active
        AND NOT s.revoked AND s.expires_at>clock_timestamp()
      FOR SHARE OF m,c,i,s;
  ELSE
    RETURN QUERY SELECT m.identity_id,m.role,v.session_id FROM sw2_auth.memberships m
      JOIN sw2_auth.companies c USING(company_id)
      WHERE m.company_id=p_company AND m.identity_id=v.identity_id AND m.active AND c.active;
  END IF;
  IF NOT FOUND THEN RAISE EXCEPTION 'Company access denied' USING ERRCODE='42501'; END IF;
END $f$;
CREATE FUNCTION sw2_auth.can_company(p_company uuid,p_tier text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company);
  RETURN p_tier='basic' OR (p_tier='sales' AND m.role IN ('Owner','Admin','Staff'))
    OR (p_tier='business' AND m.role IN ('Owner','Admin'));
EXCEPTION WHEN insufficient_privilege THEN RETURN false;
END $f$;
CREATE FUNCTION sw2_auth.can_work(p_company uuid,p_order uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company);
  RETURN m.role IN ('Owner','Admin') OR (m.role='Staff' AND EXISTS(
    SELECT 1 FROM sw2_auth.creators c WHERE c.company_id=p_company AND c.order_id=p_order
      AND c.identity_id=m.identity_id AND c.kind='sale'));
EXCEPTION WHEN insufficient_privilege THEN RETURN false;
END $f$;
CREATE FUNCTION sw2_auth.cancelled(p_company uuid,p_order uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT EXISTS(SELECT 1 FROM sw2_auth.cancellations WHERE company_id=p_company AND order_id=p_order)
$f$;
CREATE FUNCTION sw2_auth.remember(p_company uuid,p_order uuid,p_kind text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  IF NOT (m.role IN ('Owner','Admin') OR (m.role='Staff' AND p_kind='sale')) THEN
    RAISE EXCEPTION 'Draft creation denied' USING ERRCODE='42501'; END IF;
  INSERT INTO sw2_auth.creators VALUES(p_company,p_order,m.identity_id,p_kind);
END $f$;
CREATE FUNCTION sw2_auth.event(p_company uuid,p_action text,p_order uuid,p_key uuid DEFAULT NULL) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(p_company,true);
  INSERT INTO sw2_auth.events(company_id,identity_id,session_id,action,order_id,request_key,actor_role)
    VALUES(p_company,m.identity_id,m.session_id,p_action,p_order,p_key,m.role)
    ON CONFLICT(company_id,action,request_key) WHERE request_key IS NOT NULL DO NOTHING;
END $f$;
CREATE FUNCTION sw2_auth.session_status(p_issuer text,p_subject text,p_session uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
  SELECT jsonb_build_object('issuer',i.issuer,'subject',i.subject,'sessionId',s.session_id,
    'active',i.active AND NOT s.revoked,'revoked',s.revoked,
    'checkedAt',floor(extract(epoch FROM s.checked_at))::bigint,
    'expiresAt',floor(extract(epoch FROM s.expires_at))::bigint)
  FROM sw2_auth.sessions s JOIN sw2_auth.identities i ON i.id=s.identity_id
  WHERE i.issuer=p_issuer AND i.subject=p_subject AND s.session_id=p_session
$f$;
CREATE FUNCTION sw2_auth.issue(p_issuer text,p_subject text,p_session uuid,p_pid integer,p_xid xid8,p_exp timestamptz)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE v uuid; s sw2_auth.sessions%ROWTYPE; proof text;
BEGIN
  SELECT i.id INTO v FROM sw2_auth.identities i WHERE i.issuer=p_issuer AND i.subject=p_subject AND i.active;
  SELECT * INTO s FROM sw2_auth.sessions WHERE session_id=p_session AND identity_id=v
    AND NOT revoked AND expires_at>clock_timestamp() AND checked_at<=clock_timestamp()
    AND checked_at>clock_timestamp()-interval '30 seconds';
  IF NOT FOUND OR p_pid IS NULL OR p_pid<=0 OR p_xid IS NULL OR p_exp IS NULL
     OR p_exp<=clock_timestamp() OR p_exp>clock_timestamp()+interval '30 seconds'
     OR p_exp>s.expires_at OR p_exp>s.checked_at+interval '30 seconds' THEN
    RAISE EXCEPTION 'Proof denied' USING ERRCODE='42501'; END IF;
  -- Two CSPRNG UUIDs: 244 random bits; no extension/private key required.
  proof:=replace(gen_random_uuid()::text||gen_random_uuid()::text,'-','');
  INSERT INTO sw2_auth.proofs(digest,identity_id,session_id,pid,xid,expires_at)
    VALUES(sha256(convert_to(proof,'UTF8')),v,p_session,p_pid,p_xid,p_exp);
  RETURN proof;
END $f$;
CREATE FUNCTION sw2_auth.activate(p_proof text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
BEGIN
  IF p_proof IS NULL OR p_proof!~'^[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'Invalid proof' USING ERRCODE='42501'; END IF;
  PERFORM set_config('sw2.proof',p_proof,true);
  PERFORM * FROM sw2_auth.context();
END $f$;
CREATE FUNCTION sw2_auth.revalidate_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $f$
DECLARE m record;
BEGIN
  SELECT * INTO STRICT m FROM sw2_auth.member(NEW.company_id,true);
  IF m.identity_id<>NEW.identity_id OR m.session_id<>NEW.session_id THEN
    RAISE EXCEPTION 'Transaction identity changed' USING ERRCODE='42501'; END IF;
  RETURN NULL;
END $f$;
CREATE CONSTRAINT TRIGGER event_identity_at_commit AFTER INSERT ON sw2_auth.events
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sw2_auth.revalidate_event();
REVOKE ALL ON ALL TABLES IN SCHEMA sw2_auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA sw2_auth FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sw2_auth.issue(text,text,uuid,integer,xid8,timestamptz),
  sw2_auth.session_status(text,text,uuid) TO sw2_verifier;
GRANT EXECUTE ON FUNCTION sw2_auth.activate(text) TO sw2_runtime;
GRANT EXECUTE ON FUNCTION sw2_auth.context(),sw2_auth.member(uuid,boolean),
  sw2_auth.can_company(uuid,text),sw2_auth.can_work(uuid,uuid),sw2_auth.cancelled(uuid,uuid)
  TO stockwise_owner,sw2_basic_reader,sw2_sales_reader,sw2_business_reader,sw2_draft_writer;
GRANT EXECUTE ON FUNCTION sw2_auth.remember(uuid,uuid,text),sw2_auth.event(uuid,text,uuid,uuid)
  TO stockwise_owner,sw2_draft_writer;
COMMIT;
