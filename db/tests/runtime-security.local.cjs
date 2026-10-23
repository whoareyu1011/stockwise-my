"use strict";
// Test-only Phase 1 -> PostgreSQL wiring. Never imported by the live server.
const h=require("./phase2/common.cjs"),f=require("./phase2/fixtures.cjs");
const {createPostgresAdapters}=require("./phase2/postgres-adapter.cjs");
const {createSecurityConfig}=require("../../server/security/config.cjs");
const {createTokenVerifier}=require("../../server/security/verify-token.cjs");
const {createSessionStatusVerifier}=require("../../server/security/session-status.cjs");
const {createPoolBoundary}=require("../../server/security/pools.cjs");
const {createTransactionRunner}=require("../../server/security/transaction.cjs");
const {assert,id}=h;
async function main(){
  const root=process.argv[2];h.gate(root,"phase2");
  const r=h.report(root);let admin,db;
  try{
    await r.check("S01 original foundation installs before the additive stages",async()=>{
      admin=await h.installFoundation(root,false);
    });
    await r.check("S01a interruption after stage 02 leaves all runtime access disabled",async()=>{
      await h.installSecurityStage(admin,"01_identity.sql");
      await h.installSecurityStage(admin,"02_policies_commands.sql");
      const roles=(await admin.query(`SELECT rolname,rolcanlogin FROM pg_roles
        WHERE rolname IN ('sw2_business','sw2_issuer') ORDER BY rolname`)).rows;
      assert.deepEqual(roles,[{rolname:"sw2_business",rolcanlogin:false},
        {rolname:"sw2_issuer",rolcanlogin:false}]);
      for(const [member,parent] of [["sw2_business","sw2_runtime"],["sw2_issuer","sw2_verifier"]])
        assert.equal((await admin.query("SELECT pg_has_role($1,$2,'MEMBER') b",[member,parent])).rows[0].b,false);
      assert.equal((await admin.query(`SELECT count(*)::int n FROM pg_proc p
        WHERE p.pronamespace='sw2_api'::regnamespace
          AND has_function_privilege('sw2_business',p.oid,'EXECUTE')`)).rows[0].n,0);
      for(const role of ["stockwise_owner","sw2_basic_reader","sw2_sales_reader","sw2_business_reader","sw2_draft_writer"])
        assert.equal((await admin.query("SELECT has_schema_privilege($1,'sw2_api','CREATE') b",[role])).rows[0].b,false);
    });
    await r.check("S01b final stage compiles and atomically activates the exact API",async()=>{
      await h.installSecurityStage(admin,"03_adapter_contract.sql");
      for(const role of ["sw2_business","sw2_issuer"])
        assert.equal((await admin.query("SELECT rolcanlogin FROM pg_roles WHERE rolname=$1",[role])).rows[0].rolcanlogin,true);
    });
    await f.seedCore(admin);await f.seedSecurity(admin);
    db=createPostgresAdapters(root);
    const {generateKeyPair,exportJWK,SignJWT}=await import("jose");
    const {privateKey,publicKey}=await generateKeyPair("ES256");
    const jwk={...await exportJWK(publicKey),kid:"offline-fixture-key",alg:"ES256",use:"sig"};
    const config=createSecurityConfig({issuer:f.issuer,audience:"authenticated",
      jwksUrl:f.issuer+"/.well-known/jwks.json",algorithms:["ES256"]});
    const verifyToken=await createTokenVerifier({config,trustedJWKS:{keys:[jwk]}});
    const verifySession=createSessionStatusVerifier({lookup:p=>db.lookupSession(p)});
    const run=createTransactionRunner({verifyToken,verifySession,
      pools:createPoolBoundary({runtimePool:db.runtimePool,verifierPool:db.verifierPool}),
      adapter:db.adapter,repositoryFactory:db.repositoryFactory});
    async function token(name,claims={}){
      return new SignJWT({role:"authenticated",session_id:f.session(name),...claims})
        .setProtectedHeader({alg:"ES256",typ:"JWT",kid:jwk.kid})
        .setIssuer(f.issuer).setAudience("authenticated").setSubject(f.people[name])
        .setIssuedAt().setExpirationTime("5m").sign(privateKey);
    }
    async function request(name,action,sql,values=[],options={}){
      await f.refresh(admin,name);
      return run({token:await token(name),companyId:f.A,action,...options,
        work:options.work || (async c=>(await c.query(sql,values)).rows)});
    }
    // Lower-level path intentionally bypasses Node authorization to test whether
    // the SQL independently denies a malicious caller with a valid own proof.
    async function raw(name,fn){
      await f.refresh(admin,name);
      const c=await db.runtimePool.connect(),v=await db.verifierPool.connect();
      try{
        await db.adapter.beginReadCommitted(c);
        const target=await db.adapter.transactionIdentity(c);
        const proof=await db.adapter.issueProof(v,{issuer:f.issuer,subject:f.people[name],
          sessionId:f.session(name),...target,expiresAt:Math.floor(Date.now()/1000)+20});
        await db.adapter.activateProof(c,proof);
        return await fn(c,{proof,target});
      }finally{
        await c.query("ROLLBACK").catch(()=>{});
        let destroy=false;
        try{await db.adapter.reset(c);}catch{destroy=true;}
        c.release(destroy);v.release();
      }
    }
    const sqlDenied=(fn)=>h.denied(fn,["42501","P0001","25001","23505"]);
    async function noRows(c,sql,values){
      try{const rows=(await c.query(sql,values)).rows;
        assert(rows.length===0 || (rows.length===1 && rows[0].value===null));
      }catch(e){assert.equal(e.code,"42501");}
    }
    await r.check("S02 actual roles/ownership/default ACL/RLS/no inherited owner",async()=>{
      const roles=["sw2_auth_owner","sw2_basic_reader","sw2_sales_reader","sw2_business_reader","sw2_draft_writer","sw2_runtime","sw2_verifier"];
      for(const role of roles){
        assert.deepEqual((await admin.query("SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=$1",[role])).rows[0],
          {rolcanlogin:false,rolsuper:false,rolbypassrls:false,rolcreaterole:false,rolcreatedb:false});
      }
      for(const who of ["sw2_business","sw2_issuer","anon","authenticated","service_role","authenticator"])
        for(const owner of ["stockwise_owner","stockwise_migrator",...roles.slice(0,5)])
          assert.equal((await admin.query("SELECT pg_has_role($1,$2,'MEMBER') b",[who,owner])).rows[0].b,false);
      assert.equal((await admin.query(`SELECT count(*)::int n FROM pg_proc p CROSS JOIN LATERAL
        aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE p.pronamespace IN('stockwise'::regnamespace,'sw2_auth'::regnamespace,'sw2_api'::regnamespace)
        AND a.grantee=0 AND a.privilege_type='EXECUTE'`)).rows[0].n,0);
      assert.equal((await admin.query(`SELECT count(*)::int n FROM pg_class WHERE relkind='r'
        AND relnamespace IN('stockwise'::regnamespace,'sw2_auth'::regnamespace) AND NOT relrowsecurity`)).rows[0].n,0);
      assert.equal((await admin.query("SELECT count(*)::int n FROM pg_auth_members WHERE member='stockwise_owner'::regrole")).rows[0].n,0);
      assert.deepEqual((await admin.query(`SELECT admin_option,inherit_option,set_option FROM pg_auth_members
        WHERE roleid='sw2_runtime'::regrole AND member='sw2_business'::regrole`)).rows[0],
        {admin_option:false,inherit_option:true,set_option:false});
    });
    await r.check("S03 unauthenticated backend denies before work",async()=>{
      let work=false;
      await assert.rejects(run({token:"not-a-jwt",companyId:f.A,action:"product.basic.read",work:()=>{work=true;}}),
        e=>e.code==="AUTH_INVALID");assert.equal(work,false);
    });
    await r.check("S04 all roles basic products, quantities; Viewer no finance",async()=>{
      for(const name of ["Owner","Admin","Staff","Viewer"]){
        const rows=await request(name,"product.basic.read","SELECT * FROM sw2_api.products($1)",[f.A]);
        assert.equal(rows.length,2);assert(!Object.hasOwn(rows[0],"unit_cost"));
        assert(!Object.hasOwn(rows[0],"selling_price"));
        assert.equal((await request(name,"stock.quantity.read","SELECT * FROM sw2_api.quantities($1)",[f.A])).length,2);
      }
      await assert.rejects(request("Viewer","product.cost.read","SELECT * FROM sw2_api.business_products($1)",[f.A]));
      await raw("Viewer",c=>noRows(c,"SELECT * FROM sw2_api.business_products($1)",[f.A]));
      await raw("Viewer",c=>noRows(c,"SELECT * FROM sw2_api.sales_products($1)",[f.A]));
      await raw("Viewer",c=>noRows(c,"SELECT * FROM sw2_api.customers($1)",[f.A]));
      await raw("Staff",c=>noRows(c,"SELECT * FROM sw2_api.business_products($1)",[f.A]));
    });
    const drafts={};
    await r.check("S05 creator assigned by database; Staff sales only",async()=>{
      for(const name of ["Owner","Admin","Staff","OtherStaff"]){
        drafts[name]=(await request(name,"draft.create",
          "SELECT sw2_api.create_draft($1,$2,$3,'sale','2026-01-01') id",[f.A,f.C,`SEC-${name}`],{orderKind:"sale"}))[0].id;
      }
      assert.equal((await admin.query("SELECT identity_id FROM sw2_auth.creators WHERE order_id=$1",[drafts.Staff])).rows[0].identity_id,f.people.Staff);
      await assert.rejects(request("Staff","draft.create","SELECT 1",[],{orderKind:"purchase"}));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.create_draft($1,$2,'BAD','purchase','2026-01-01')",[f.A,f.C])));
      await raw("Viewer",c=>sqlDenied(()=>c.query("SELECT sw2_api.create_draft($1,$2,'BAD2','sale','2026-01-01')",[f.A,f.C])));
    });
    await r.check("S06 own draft edit allowed; other Staff/Owner drafts backend + SQL deny",async()=>{
      await request("Staff","draft.edit","SELECT sw2_api.edit_notes($1,$2,'own edit')",[f.A,drafts.Staff],{resourceId:drafts.Staff});
      for(const target of [drafts.OtherStaff,drafts.Owner]){
        await assert.rejects(request("Staff","draft.edit","SELECT 1",[],{resourceId:target}));
        await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.edit_notes($1,$2,'forged')",[f.A,target])));
        await raw("Staff",c=>noRows(c,"SELECT sw2_api.sales_order($1,$2) value",[f.A,target]));
      }
    });
    await r.check("S07 Owner/Admin manage every in-company draft",async()=>{
      for(const name of ["Owner","Admin"])for(const order of Object.values(drafts))
        await request(name,"draft.edit","SELECT sw2_api.edit_notes($1,$2,'managed')",[f.A,order],{resourceId:order});
    });
    await r.check("S08 forged company/actor/role claims cannot cross tenant",async()=>{
      const forged=await token("Staff",{company_id:f.B,user_id:f.people.OtherCompany,app_metadata:{role:"Owner"}});
      let work=false;
      await assert.rejects(run({token:forged,companyId:f.B,action:"draft.create",orderKind:"sale",work:()=>{work=true;}}));
      assert.equal(work,false);
      await raw("Owner",c=>noRows(c,"SELECT * FROM sw2_api.products($1)",[f.B]));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.create_draft($1,$2,'CROSS','sale','2026-01-01')",[f.B,f.CB])));
      // Same-company wrapper with cross-company referenced contact fails too.
      await raw("Owner",c=>sqlDenied(()=>c.query("SELECT sw2_api.create_draft($1,$2,'BAD-FK','sale','2026-01-01')",[f.A,f.CB])));
    });
    await r.check("S09 runtime cannot read/write raw tables or execute core/private functions",async()=>{
      const c=await h.connect(root,"sw2_business");
      try{
        for(const table of ["stockwise.companies","stockwise.products","stockwise.contacts","stockwise.orders",
          "stockwise.order_items","stockwise.stock_balances","stockwise.stock_movements","stockwise.audit_logs",
          "sw2_auth.identities","sw2_auth.companies","sw2_auth.memberships","sw2_auth.sessions",
          "sw2_auth.proofs","sw2_auth.creators","sw2_auth.cancellations","sw2_auth.events"])
          await sqlDenied(()=>c.query(`SELECT * FROM ${table}`));
        for(const sql of ["SET ROLE stockwise_owner","SET ROLE stockwise_migrator","SET ROLE sw2_draft_writer","SET ROLE sw2_runtime",
          "SELECT sw2_auth.context()","SELECT stockwise.post_order(NULL,NULL,NULL)",
          "UPDATE stockwise.stock_balances SET quantity=999",
          "INSERT INTO sw2_auth.memberships VALUES(NULL,NULL,'Owner',true)"])
          await sqlDenied(()=>c.query(sql));
      }finally{await c.end();}
      await raw("Owner",c=>sqlDenied(()=>c.query("SELECT sw2_auth.issue(NULL,NULL,NULL,1,'1',now())")));
    });
    await r.check("S10 Staff cannot post; Owner posts; Staff cannot modify posted",async()=>{
      await admin.query("SET ROLE stockwise_owner");
      const receipt=await f.draft(admin,{kind:"purchase",lines:[[f.P,10,4]]});await f.post(admin,receipt);
      await admin.query("RESET ROLE");
      await request("Staff","draft.edit","SELECT sw2_api.set_line($1,$2,$3,1,2,10,0)",[f.A,drafts.Staff,f.P],{resourceId:drafts.Staff});
      await assert.rejects(request("Staff","order.post","SELECT 1",[],{resourceId:drafts.Staff}));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.post_order($1,$2,$3)",[f.A,drafts.Staff,id(5000)])));
      await request("Owner","order.post","SELECT sw2_api.post_order($1,$2,$3)",[f.A,drafts.Staff,id(5000)],{resourceId:drafts.Staff});
      await assert.rejects(request("Staff","draft.edit","SELECT 1",[],{resourceId:drafts.Staff}));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.edit_notes($1,$2,'posted edit')",[f.A,drafts.Staff])));
      assert.equal(await f.balance(admin),"8");
    });
    await r.check("S11 SQL post/reversal retries; Phase 1 post retry limitation recorded",async()=>{
      await raw("Owner",async c=>{
        assert.equal((await c.query("SELECT sw2_api.post_order($1,$2,$3) value",[f.A,drafts.Staff,id(5000)])).rows[0].value,drafts.Staff);
      });
      // This confirms a known limitation, NOT an end-to-end retry success.
      await assert.rejects(request("Owner","order.post","SELECT 1",[],{resourceId:drafts.Staff}));
      await request("Admin","order.reverse","SELECT sw2_api.reverse_order($1,$2,$3,'2026-01-02','security fixture')",
        [f.A,drafts.Staff,id(5001)],{resourceId:drafts.Staff});
      await raw("Admin",async c=>{
        const a=(await c.query("SELECT sw2_api.reverse_order($1,$2,$3,'2026-01-02','security fixture') value",[f.A,drafts.Staff,id(5001)])).rows[0].value;
        assert(a);
      });assert.equal(await f.balance(admin),"10");
      await assert.rejects(request("Admin","order.reverse","SELECT 1",[],{resourceId:drafts.Staff}),
        e=>e.code==="AUTHORIZATION_DENIED");
    });
    await r.check("S12 Viewer status projection only; private/missing creators fail closed for Staff",async()=>{
      const rows=await request("Viewer","order.basic.read","SELECT sw2_api.status($1,$2) value",[f.A,drafts.Staff],{resourceId:drafts.Staff});
      assert.deepEqual(Object.keys(rows[0].value).sort(),["id","status"]);
      await raw("Viewer",c=>noRows(c,"SELECT sw2_api.sales_order($1,$2) value",[f.A,drafts.Staff]));
      const unowned=await f.draft(admin);
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.edit_notes($1,$2,'missing metadata')",[f.A,unowned])));
    });
    await r.check("S13 cancellation terminal/idempotent/audited/stock-neutral",async()=>{
      const before=await f.balance(admin),order=drafts.OtherStaff,key=id(5100);
      await request("OtherStaff","draft.cancel","SELECT sw2_api.cancel_draft($1,$2,$3,'unused')",[f.A,order,key],{resourceId:order});
      await raw("OtherStaff",async c=>{await c.query("SELECT sw2_api.cancel_draft($1,$2,$3,'unused')",[f.A,order,key]);});
      // Known Phase 1 state mismatch, not an end-to-end retry success.
      await assert.rejects(request("OtherStaff","draft.cancel","SELECT 1",[],{resourceId:order}),
        e=>e.code==="AUTHORIZATION_DENIED");
      await raw("Owner",c=>sqlDenied(()=>c.query("SELECT sw2_api.post_order($1,$2,$3)",[f.A,order,id(5101)])));
      await raw("OtherStaff",c=>sqlDenied(()=>c.query("SELECT sw2_api.edit_notes($1,$2,'reopen')",[f.A,order])));
      assert.equal(await f.balance(admin),before);
      assert.equal((await admin.query("SELECT count(*)::int n FROM sw2_auth.events WHERE order_id=$1 AND action='draft_cancelled'",[order])).rows[0].n,1);
    });
    await r.check("S14 revoked membership/identity/company/session immediately deny next statement",async()=>{
      for(const [sql,undo,params] of [
        ["UPDATE sw2_auth.memberships SET active=false WHERE company_id=$1 AND identity_id=$2",
          "UPDATE sw2_auth.memberships SET active=true WHERE company_id=$1 AND identity_id=$2",[f.A,f.people.Staff]],
        ["UPDATE sw2_auth.identities SET active=false WHERE id=$1","UPDATE sw2_auth.identities SET active=true WHERE id=$1",[f.people.Staff]],
        ["UPDATE sw2_auth.companies SET active=false WHERE company_id=$1","UPDATE sw2_auth.companies SET active=true WHERE company_id=$1",[f.A]],
        ["UPDATE sw2_auth.sessions SET revoked=true WHERE session_id=$1","UPDATE sw2_auth.sessions SET revoked=false WHERE session_id=$1",[f.session("Staff")]],
      ]){
        await raw("Staff",async c=>{
          await admin.query(sql,params);
          try{await sqlDenied(()=>c.query("SELECT sw2_api.authorize($1,'product.basic.read')",[f.A]));}
          finally{await admin.query(undo,params);}
        });
      }
    });
    await r.check("S15 proofs bind PID/XID, cannot forge/replay; pool reuse loses context",async()=>{
      let previous;
      await raw("Staff",async(c,state)=>{
        previous=state.proof;
        const other=await h.connect(root,"sw2_business");
        try{await other.query("BEGIN");await sqlDenied(()=>db.adapter.activateProof(other,state.proof));}
        finally{await other.query("ROLLBACK");await other.end();}
      });
      const c=await db.runtimePool.connect();
      try{
        await c.query("BEGIN");await sqlDenied(()=>db.adapter.activateProof(c,previous));await c.query("ROLLBACK");
        await c.query("BEGIN");await c.query("SELECT set_config('sw2.proof',$1,true)",["0".repeat(64)]);
        await sqlDenied(()=>c.query("SELECT sw2_api.membership($1)",[f.A]));await c.query("ROLLBACK");
        assert.equal((await c.query("SELECT nullif(current_setting('sw2.proof',true),'') v")).rows[0].v,null);
      }finally{await c.query("ROLLBACK");c.release();}
    });
    await r.check("S16 membership ceilings independently enforced in database",async()=>{
      await raw("Admin",c=>sqlDenied(()=>c.query("SELECT sw2_api.authorize($1,'membership.manage',NULL,NULL,$2,'Owner')",[f.A,f.people.Staff])));
      await raw("Admin",c=>sqlDenied(()=>c.query("SELECT sw2_api.authorize($1,'membership.manage',NULL,NULL,$2,'Staff')",[f.A,f.people.Owner])));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.authorize($1,'membership.manage',NULL,NULL,$2,'Admin')",[f.A,f.people.Viewer])));
      await request("Owner","membership.manage","SELECT 1",[],{targetIdentityId:f.people.Viewer,requestedRole:"Admin"});
    });
    await r.check("S17 runtime error rolls back data + audit and pooled next identity is distinct",async()=>{
      const before=await f.snapshot(admin),events=(await admin.query("SELECT count(*)::int n FROM sw2_auth.events")).rows[0].n;
      let wrote=false;
      await assert.rejects(request("Owner","draft.edit",null,[],{resourceId:drafts.Owner,
        work:async c=>{await c.query("SELECT sw2_api.edit_notes($1,$2,'rollback')",[f.A,drafts.Owner]);
          wrote=true;await c.query("SELECT 1/0");}}));
      assert.equal(wrote,true);
      assert.deepEqual(await f.snapshot(admin),before);
      assert.equal((await admin.query("SELECT count(*)::int n FROM sw2_auth.events")).rows[0].n,events);
      const a=await request("Owner","product.basic.read","SELECT pg_backend_pid() pid",[]);
      const b=await request("Viewer","product.basic.read","SELECT pg_backend_pid() pid,sw2_api.membership($1) actor",[f.A]);
      assert.equal(a[0].pid,b[0].pid);assert.equal(b[0].actor.identityId,f.people.Viewer);
    });
    await r.check("S17b DISCARD ALL removes session contamination before pooled reuse",async()=>{
      const first=await request("Owner","product.basic.read",null,[],{work:async c=>{
        await c.query("SET search_path=pg_temp,public; SET application_name='phase2-contaminated'; CREATE TEMP TABLE pool_contamination(id int)");
        return (await c.query("SELECT pg_backend_pid() pid")).rows[0].pid;
      }});
      const second=await request("Viewer","product.basic.read",null,[],{work:async c=>
        (await c.query(`SELECT pg_backend_pid() pid,current_user role,current_setting('search_path') search_path,
          current_setting('application_name') app,to_regclass('pg_temp.pool_contamination') temp_table`)).rows[0]});
      assert.equal(first,second.pid);
      assert.equal(second.role,"sw2_business");
      assert(!second.search_path.includes("pg_temp"));
      assert.equal(second.app,"stockwise_disposable_phase2");
      assert.equal(second.temp_table,null);
    });
    await r.check("S18 exact definer ownership, paths, execute allowlists and column grants",async()=>{
      const owners={products:"sw2_basic_reader",quantities:"sw2_basic_reader",status:"sw2_basic_reader",
        sales_products:"sw2_sales_reader",sales_order:"sw2_sales_reader",customers:"sw2_basic_reader",
        work_customer:"sw2_sales_reader",business_products:"sw2_business_reader",
        movements:"sw2_business_reader",audit:"sw2_business_reader",create_draft:"sw2_draft_writer",
        edit_notes:"sw2_draft_writer",set_line:"sw2_draft_writer",post_order:"stockwise_owner",
        reverse_order:"stockwise_owner",cancel_draft:"stockwise_owner",authorize:"stockwise_owner",
        resource:"stockwise_owner",membership:"sw2_auth_owner",target_member:"sw2_auth_owner"};
      const functions=(await admin.query(`SELECT p.proname,p.prosecdef,p.proconfig,r.rolname owner
        FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.pronamespace='sw2_api'::regnamespace`)).rows;
      assert.equal(functions.length,Object.keys(owners).length);
      for(const row of functions){assert.equal(row.owner,owners[row.proname]);assert.equal(row.prosecdef,true);
        assert(row.proconfig.some(v=>v.replace(/\s/g,"")==="search_path=pg_catalog,pg_temp"));}
      for(const role of ["sw2_basic_reader","sw2_sales_reader","sw2_draft_writer"])
        assert.equal((await admin.query("SELECT has_column_privilege($1,'stockwise.products','unit_cost','SELECT') b",[role])).rows[0].b,false);
      const privileged=(await admin.query(`SELECT n.nspname,p.proname,p.proconfig,r.rolname owner
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_roles r ON r.oid=p.proowner
        WHERE p.prosecdef AND n.nspname IN ('stockwise','sw2_auth','sw2_api')
        ORDER BY n.nspname,p.proname`)).rows;
      assert(privileged.length>0);
      for(const row of privileged){
        const expected=row.nspname==="stockwise"?"stockwise_owner":
          row.nspname==="sw2_auth"?(row.proname==="guard_cancelled"?"stockwise_owner":"sw2_auth_owner"):owners[row.proname];
        assert.equal(row.owner,expected,`Unexpected SECURITY DEFINER owner: ${row.nspname}.${row.proname}`);
        assert(row.proconfig.some(v=>v.replace(/\s/g,"")==="search_path=pg_catalog,pg_temp"));
      }
      const apiSignatures=["products(uuid)","quantities(uuid)","status(uuid,uuid)","sales_products(uuid)",
        "sales_order(uuid,uuid)","business_products(uuid)","create_draft(uuid,uuid,text,text,date)",
        "edit_notes(uuid,uuid,text)","set_line(uuid,uuid,uuid,integer,bigint,numeric,numeric)",
        "post_order(uuid,uuid,uuid)","reverse_order(uuid,uuid,uuid,date,text)","cancel_draft(uuid,uuid,uuid,text)",
        "membership(uuid)","resource(uuid,uuid)","target_member(uuid,uuid)",
        "authorize(uuid,text,uuid,text,uuid,text)","customers(uuid)","work_customer(uuid,uuid)",
        "movements(uuid)","audit(uuid)"].map(s=>"sw2_api."+s);
      const catalog=(await admin.query(`SELECT n.nspname,p.proname,p.prosecdef,p.proconfig,
        pg_get_userbyid(p.proowner) owner,
        n.nspname||'.'||p.proname||'('||oidvectortypes(p.proargtypes)||')' signature
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname IN ('stockwise','sw2_auth','sw2_api')`)).rows;
      assert.deepEqual(catalog.filter(x=>x.nspname==="sw2_api").map(x=>x.signature.replace(/ /g,"")).sort(),
        [...apiSignatures].sort());
      const privateSignatures=["context()","member(uuid,boolean)","can_company(uuid,text)",
        "can_work(uuid,uuid)","cancelled(uuid,uuid)","remember(uuid,uuid,text)",
        "event(uuid,text,uuid,uuid)","session_status(text,text,uuid)",
        "issue(text,text,uuid,integer,xid8,timestampwithtimezone)","activate(text)",
        "revalidate_event()","cancel(uuid,uuid,uuid,text)","guard_cancelled()"];
      const coreSignatures=["touch_updated_at()","reject_mutation()","guard_company_identity()",
        "guard_order()","guard_order_item()","guard_balance_write()","initialize_balance()",
        "audit_catalogue_change()","validate_movement()","apply_movement()","check_balance_integrity()",
        "check_order_integrity()","post_order(uuid,uuid,uuid)","reverse_order(uuid,uuid,uuid,date,text)"];
      for(const [schema,expected] of [["sw2_auth",privateSignatures],["stockwise",coreSignatures]])
        assert.deepEqual(catalog.filter(x=>x.nspname===schema).map(x=>x.signature.replace(/ /g,"")).sort(),
          expected.map(x=>schema+"."+x).sort());
      const coreDefiners=new Set(["initialize_balance","audit_catalogue_change","apply_movement",
        "check_balance_integrity","check_order_integrity","post_order","reverse_order"]);
      for(const row of catalog){
        assert.equal(row.prosecdef,row.nspname!=="stockwise" || coreDefiners.has(row.proname));
        const expectedOwner=row.nspname==="stockwise"?"stockwise_owner":
          row.nspname==="sw2_auth"?(row.proname==="guard_cancelled"?"stockwise_owner":"sw2_auth_owner"):owners[row.proname];
        assert.equal(row.owner,expectedOwner);
        assert.deepEqual(row.proconfig.filter(x=>x.startsWith("search_path=")).map(x=>x.replace(/\s/g,"")),
          ["search_path=pg_catalog,pg_temp"]);
      }
      // Reject unexpected overloads, including private helper/trigger overloads.
      const names=catalog.map(x=>x.nspname+"."+x.proname);
      assert.equal(new Set(names).size,names.length);
      const runtimeExpected=new Set([...apiSignatures,"sw2_auth.activate(text)"]);
      const verifierExpected=new Set(["sw2_auth.issue(text,text,uuid,integer,xid8,timestampwithtimezone)",
        "sw2_auth.session_status(text,text,uuid)"]);
      for(const [role,expected] of [["sw2_business",runtimeExpected],["sw2_issuer",verifierExpected]]){
        const rows=(await admin.query(`SELECT n.nspname||'.'||p.proname||'('||oidvectortypes(p.proargtypes)||')' signature
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname IN ('stockwise','sw2_auth','sw2_api')
            AND has_function_privilege($1,p.oid,'EXECUTE')`,[role])).rows;
        const actual=new Set(rows.map(row=>row.signature.replace(/ /g,"")));
        assert.deepEqual([...actual].sort(),[...expected].sort(),`Unexpected function EXECUTE set for ${role}`);
      }
      for(const role of ["sw2_business","sw2_issuer"]){
        for(const table of ["companies","products","contacts","orders","order_items","stock_balances","stock_movements","audit_logs"])
          for(const privilege of ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"])
            assert.equal((await admin.query("SELECT has_table_privilege($1,$2,$3) b",[role,"stockwise."+table,privilege])).rows[0].b,
              false,`${role} must not have ${privilege} on stockwise.${table}`);
      }
      await h.denied(()=>admin.query("UPDATE sw2_auth.memberships SET role='Operator' WHERE company_id=$1 AND identity_id=$2",[f.A,f.people.Staff]),["23514"]);
      await h.denied(()=>admin.query("UPDATE sw2_auth.memberships SET role='root' WHERE company_id=$1 AND identity_id=$2",[f.A,f.people.Staff]),["23514"]);
      for(const role of ["anon","authenticated","service_role","authenticator"]){
        assert.equal((await admin.query(`SELECT count(*)::int n FROM pg_proc p
          WHERE p.pronamespace IN ('stockwise'::regnamespace,'sw2_auth'::regnamespace,'sw2_api'::regnamespace)
            AND has_function_privilege($1,p.oid,'EXECUTE')`,[role])).rows[0].n,0);
        for(const table of ["companies","products","contacts","orders","order_items","stock_balances","stock_movements","audit_logs"])
          for(const privilege of ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"])
            assert.equal((await admin.query("SELECT has_table_privilege($1,$2,$3) b",
              [role,"stockwise."+table,privilege])).rows[0].b,false);
        await admin.query(`SET ROLE ${role}`);
        try{
          await sqlDenied(()=>admin.query("SELECT * FROM stockwise.orders"));
          await sqlDenied(()=>admin.query("SELECT sw2_api.products(NULL)"));
          await sqlDenied(()=>admin.query("SELECT sw2_auth.issue(NULL,NULL,NULL,1,'1',now())"));
        }finally{await admin.query("RESET ROLE");}
      }
    });
    await r.check("S19 expired proofs and unsupported isolation fail closed",async()=>{
      await raw("Staff",async(c,state)=>{
        await admin.query("UPDATE sw2_auth.proofs SET expires_at=clock_timestamp()-interval '1 second' WHERE pid=$1 AND xid=$2::xid8",
          [state.target.pid,state.target.xid]);
        await sqlDenied(()=>c.query("SELECT sw2_api.membership($1)",[f.A]));
      });
      const c=await h.connect(root,"sw2_business");
      try{await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
        await h.denied(()=>c.query("SELECT sw2_api.membership($1)",[f.A]),["25001"]);
      }finally{await c.query("ROLLBACK");await c.end();}
    });
    await r.check("S20 deferred identity revalidation rejects expired-context COMMIT",async()=>{
      const before=await f.snapshot(admin),events=(await admin.query("SELECT count(*)::int n FROM sw2_auth.events")).rows[0].n;
      await raw("Owner",async(c,state)=>{
        await c.query("SELECT sw2_api.edit_notes($1,$2,'must rollback')",[f.A,drafts.Owner]);
        await admin.query("UPDATE sw2_auth.proofs SET expires_at=clock_timestamp()-interval '1 second' WHERE pid=$1 AND xid=$2::xid8",
          [state.target.pid,state.target.xid]);
        await h.denied(()=>c.query("COMMIT"),["42501"]);
      });
      assert.deepEqual(await f.snapshot(admin),before);
      assert.equal((await admin.query("SELECT count(*)::int n FROM sw2_auth.events")).rows[0].n,events);
    });
    await r.check("S21 membership revocation waits for existing authorization transaction",async()=>{
      await raw("Staff",async c=>{
        await c.query("SELECT sw2_api.authorize($1,'product.basic.read')",[f.A]);
        const revoker=await h.connect(root);let pending;
        try{
          const pid=(await revoker.query("SELECT pg_backend_pid() pid")).rows[0].pid;
          pending=revoker.query("UPDATE sw2_auth.memberships SET active=false WHERE company_id=$1 AND identity_id=$2",
            [f.A,f.people.Staff]).then(()=>({ok:true}),e=>({ok:false,code:e.code}));
          await require("./phase2/inventory-concurrency.cjs").blocked(admin,pid);
          await c.query("ROLLBACK");assert.deepEqual(await pending,{ok:true});
        }finally{await c.query("ROLLBACK").catch(()=>{});if(pending)await pending;await revoker.end();
          await admin.query("UPDATE sw2_auth.memberships SET active=true WHERE company_id=$1 AND identity_id=$2",[f.A,f.people.Staff]);}
      });
    });
    await r.check("S22 stale synthetic status or unavailable status lookup denies before work",async()=>{
      let work=false;
      const invoke=async()=>run({token:await token("Staff"),companyId:f.A,action:"product.basic.read",work:()=>{work=true;}});
      await admin.query("UPDATE sw2_auth.sessions SET checked_at=clock_timestamp()-interval '1 minute' WHERE session_id=$1",[f.session("Staff")]);
      await assert.rejects(invoke());assert.equal(work,false);await f.refresh(admin,"Staff");
      await admin.query("REVOKE EXECUTE ON FUNCTION sw2_auth.session_status(text,text,uuid) FROM sw2_verifier");
      try{await assert.rejects(invoke());assert.equal(work,false);}
      finally{await admin.query("GRANT EXECUTE ON FUNCTION sw2_auth.session_status(text,text,uuid) TO sw2_verifier");}
    });
    await r.check("S23 actual company-B order cannot be read/edited under company A",async()=>{
      const order=(await request("OtherCompany","draft.create","SELECT sw2_api.create_draft($1,$2,'B-ORDER','sale','2026-01-01') id",
        [f.B,f.CB],{companyId:f.B,orderKind:"sale"}))[0].id;
      await assert.rejects(request("Staff","draft.edit","SELECT 1",[],{companyId:f.B,resourceId:order}));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.edit_notes($1,$2,'cross')",[f.B,order])));
      await raw("Owner",c=>noRows(c,"SELECT sw2_api.sales_order($1,$2) value",[f.A,order]));
      await raw("Viewer",c=>noRows(c,"SELECT sw2_api.status($1,$2) value",[f.A,order]));
      await raw("Staff",c=>sqlDenied(()=>c.query("SELECT sw2_api.set_line($1,$2,$3,1,1,10,0)",[f.A,drafts.Owner,f.PB])));
    });
    await r.check("S24 hostile temporary objects do not override fixed SQL targets",async()=>{
      await raw("Viewer",async c=>{
        await c.query("CREATE TEMP TABLE products(id uuid); SET LOCAL search_path=pg_temp,public");
        const rows=(await c.query("SELECT * FROM sw2_api.products($1)",[f.A])).rows;assert.equal(rows.length,2);
      });
    });
    await r.check("S25 multi-company identity uses the role of the selected company",async()=>{
      const a=await request("MultiCompany","product.basic.read","SELECT sw2_api.membership($1) value",[f.A]);
      const b=await request("MultiCompany","product.basic.read","SELECT sw2_api.membership($1) value",[f.B],{companyId:f.B});
      assert.equal(a[0].value.role,"Staff");assert.equal(b[0].value.role,"Viewer");
      const own=(await request("MultiCompany","draft.create",
        "SELECT sw2_api.create_draft($1,$2,'MULTI-A','sale','2026-01-01') id",[f.A,f.C],{orderKind:"sale"}))[0].id;
      await request("MultiCompany","draft.edit","SELECT sw2_api.edit_notes($1,$2,'own')",[f.A,own],{resourceId:own});
      await assert.rejects(request("MultiCompany","draft.create","SELECT 1",[],{companyId:f.B,orderKind:"sale"}));
      await raw("MultiCompany",c=>sqlDenied(()=>c.query(
        "SELECT sw2_api.create_draft($1,$2,'MULTI-B','sale','2026-01-01')",[f.B,f.CB])));
      await raw("MultiCompany",c=>sqlDenied(()=>c.query("SELECT sw2_api.edit_notes($1,$2,'wrong company')",[f.B,own])));
    });
    await r.check("S26 pending identity and disabled membership deny backend and SQL access",async()=>{
      for(const name of ["Pending","DisabledMember"]){
        let worked=false;
        await assert.rejects(request(name,"product.basic.read",null,[],{work:async()=>{worked=true;}}));
        assert.equal(worked,false);
        await sqlDenied(()=>raw(name,c=>c.query("SELECT sw2_api.authorize($1,'product.basic.read')",[f.A])));
      }
    });
    await r.check("S27 adjustments/opening stock remain unavailable through runtime",async()=>{
      for(const name of ["Owner","Admin","Staff","Viewer"]){
        await assert.rejects(request(name,"stock.adjust","SELECT 1"));
        await raw(name,c=>sqlDenied(()=>c.query("SELECT sw2_api.authorize($1,'stock.adjust')",[f.A])));
        for(const kind of ["opening_balance","adjustment_in","adjustment_out"])
          await raw(name,c=>sqlDenied(()=>c.query(
            "SELECT sw2_api.create_draft($1,NULL,'DEFERRED',$2,'2026-01-01')",[f.A,kind])));
      }
    });
    await r.check("FINAL security suite ledger reconciliation",()=>h.reconcile(admin));
  }finally{if(db)await db.end();if(admin)await admin.end();r.finish();}
}
if(require.main===module)main().catch(e=>{console.error("STOP",e.code||"ASSERTION");process.exitCode=1;});
