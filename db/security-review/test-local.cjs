// Local-only integration/security tests; never loaded by the application.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {Client,Pool}=require('pg');
const {verifyAccessToken}=require('./verify-jwt.reference.cjs');
const {withAuthorizedTransaction}=require('./transaction.reference.cjs');
const root=process.argv[2];
assert(/^\/tmp\/stockwise-security-[A-Za-z0-9]+$/.test(root||''));
assert.equal(fs.realpathSync(root),root);
assert.equal(fs.readFileSync(path.join(root,'data/PG_VERSION'),'utf8').trim(),'17');
const socket=path.join(root,'socket');
const config=(user,database='security_test')=>({host:socket,port:6543,user,database,ssl:false});
const sql=p=>fs.readFileSync(p,'utf8');
assert.equal(crypto.createHash('sha256').update(sql('db/migrations/0001_inventory.sql')).digest('hex'),
  'b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0');
const rows=[],clients=[],pools=[];
async function connect(user,db){const c=new Client(config(user,db));await c.connect();clients.push(c);return c;}
async function check(name,fn){
  try{await fn();rows.push({name,status:'PASS'});console.log('PASS',name);}
  catch(e){rows.push({name,status:'FAIL',code:e.code,message:e.message});throw e;}
}
async function fails(fn,code){let caught;try{await fn();}catch(e){caught=e;}
  assert(caught,'expected rejection');assert.equal(caught.code,code);return caught;}
async function deny(c,text,values=[],code='42501'){
  await c.query('SAVEPOINT denied');
  const e=await fails(()=>c.query(text,values),code);
  await c.query('ROLLBACK TO SAVEPOINT denied');await c.query('RELEASE SAVEPOINT denied');return e;
}
const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const A=id(1),B=id(2),PA=id(11),PB=id(12),CA=id(13),CB=id(14);
const alice=id(101),bob=id(102),admin=id(103),viewer=id(104),shared=id(105);
const purchase=id(201),sale=id(202),bigSale=id(203),adjust=id(204),sale2=id(205),purchaseB=id(206);
const key=n=>id(1000+n),issuer='https://identity.test.invalid';
let owner,rt,verifier,runtimePool,verifierPool;
async function context(c,subject,{isolation='READ COMMITTED',activate=true}={}){
  await c.query(`BEGIN ISOLATION LEVEL ${isolation}`);
  const target=(await c.query('SELECT pg_backend_pid() AS pid,pg_current_xact_id()::text AS xid')).rows[0];
  const proof=(await verifier.query('SELECT stockwise_auth.issue_context($1,$2,$3,$4::xid8,$5) AS proof',
    [issuer,subject,target.pid,target.xid,new Date(Date.now()+600000)])).rows[0].proof;
  if(activate)await c.query('SELECT stockwise_auth.activate_context($1)',[proof]);
  return {...target,proof};
}
async function tx(subject,fn,commit=true){
  const c=await runtimePool.connect();
  try{const ctx=await context(c,subject);const value=await fn(c,ctx);
    await c.query(commit?'COMMIT':'ROLLBACK');return value;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}
const quantity=async company=>(await owner.query('SELECT quantity::text AS q FROM stockwise.stock_balances WHERE company_id=$1',[company])).rows[0].q;
async function main(){
  const bootstrap=await connect('runner','postgres');
  const meta=(await bootstrap.query("SELECT current_setting('data_directory') AS dir,current_setting('listen_addresses') AS host")).rows[0];
  assert.equal(meta.dir,path.join(root,'data'));assert.equal(meta.host,'');
  await bootstrap.query(`CREATE ROLE sw_provisioner LOGIN CREATEROLE NOCREATEDB NOSUPERUSER NOBYPASSRLS NOINHERIT;
    CREATE ROLE anon NOLOGIN;CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS;CREATE ROLE authenticator NOLOGIN;`);
  await bootstrap.query('CREATE DATABASE security_test OWNER sw_provisioner');
  owner=await connect('sw_provisioner');
  await check('01 prerequisite package + exact original migration installs',async()=>{
    for(const f of ['db/deployment/01_create_roles.sql','db/deployment/02_grant_migration_access.sql'])
      await owner.query(sql(f));
    await owner.query('SET ROLE stockwise_migrator');
    await owner.query(sql('db/migrations/0001_inventory.sql'));
    await owner.query(sql('db/deployment/03_harden_owner_function_defaults.sql'));
    await owner.query('RESET ROLE');
  });
  await check('02 proposed security SQL compiles and commits',()=>owner.query(sql('db/security-review/runtime-boundary.sql')));
  await bootstrap.query(`CREATE ROLE sw_business LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
    CREATE ROLE sw_verifier LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
    GRANT stockwise_runtime TO sw_business WITH ADMIN FALSE,INHERIT TRUE,SET FALSE;
    GRANT stockwise_verifier TO sw_verifier WITH ADMIN FALSE,INHERIT TRUE,SET FALSE;`);
  await owner.query('SET ROLE stockwise_owner');
  await check('03 synthetic two-company fixtures and issuer/identity mappings',async()=>{
    await owner.query('BEGIN');
    await owner.query("INSERT INTO stockwise.companies(id,legal_name) VALUES($1,'Synthetic A'),($2,'Synthetic B')",[A,B]);
    await owner.query("INSERT INTO stockwise.products(id,company_id,sku,name) VALUES($1,$2,'A','Synthetic A item'),($3,$4,'B','Synthetic B item')",[PA,A,PB,B]);
    await owner.query("INSERT INTO stockwise.contacts(id,company_id,legal_name,contact_kind) VALUES($1,$2,'Synthetic contact A','both'),($3,$4,'Synthetic contact B','both')",[CA,A,CB,B]);
    for(const [oid,comp,contact,kind,qty] of [[purchase,A,CA,'purchase',4],[sale,A,CA,'sale',3],
      [bigSale,A,CA,'sale',999],[adjust,A,null,'adjustment_in',10],[sale2,A,CA,'sale',2],[purchaseB,B,CB,'purchase',7]]){
      await owner.query(`INSERT INTO stockwise.orders(id,company_id,contact_id,reference,kind,business_date)
        VALUES($1::uuid,$2,$3,($1::uuid)::text,$4,'2026-10-23')`,[oid,comp,contact,kind]);
      await owner.query(`INSERT INTO stockwise.order_items(company_id,order_id,product_id,line_number,quantity,unit_price)
        VALUES($1,$2,$3,1,$4,1)`,[comp,oid,comp===A?PA:PB,qty]);
    }
    await owner.query(`INSERT INTO stockwise.order_items(company_id,order_id,product_id,line_number,quantity,unit_price)
      VALUES($1,$2,$3,2,6,1)`,[A,purchase,PA]);
    await owner.query('SELECT stockwise.post_order($1,$2,$3)',[B,purchaseB,key(1)]);
    await owner.query('INSERT INTO stockwise_auth.issuers(issuer) VALUES($1)',[issuer]);
    for(const [i,s] of [[alice,'alice'],[bob,'bob'],[admin,'admin'],[viewer,'viewer'],[shared,'shared']])
      await owner.query('INSERT INTO stockwise_auth.identities(id,issuer,subject) VALUES($1,$2,$3)',[i,issuer,s]);
    for(const [company,actor,role] of [[A,alice,'operator'],[B,bob,'admin'],[A,admin,'admin'],
      [A,viewer,'viewer'],[A,shared,'viewer'],[B,shared,'viewer']])
      await owner.query('INSERT INTO stockwise_auth.company_memberships(company_id,identity_id,member_role) VALUES($1,$2,$3)',[company,actor,role]);
    await owner.query('COMMIT');
  });
  rt=await connect('sw_business');verifier=await connect('sw_verifier');
  runtimePool=new Pool({...config('sw_business'),max:1});pools.push(runtimePool);
  verifierPool=new Pool({...config('sw_verifier'),max:1});pools.push(verifierPool);
  await check('04 actual business and verifier sessions lack admin/bypass rights',async()=>{
    for(const c of [rt,verifier]){
      const r=(await c.query('SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user')).rows[0];
      assert(Object.values(r).every(x=>x===false));
    }
  });
  await check('05 anonymous business connection reads zero rows; commands reject',async()=>{
    await rt.query('BEGIN');assert.equal((await rt.query('SELECT * FROM stockwise.products')).rowCount,0);
    await deny(rt,'SELECT stockwise_api.post_order($1,$2,$3)',[A,purchase,key(2)]);
    await rt.query('ROLLBACK');
  });
  await check('06 forged actor/company/JWT-claims GUCs cannot authenticate',async()=>{
    await rt.query('BEGIN');
    for(const [k,v] of [['stockwise.identity_id',bob],['stockwise.company_id',B],
      ['request.jwt.claims',JSON.stringify({sub:'bob',company_id:B})],['stockwise.request_proof','f'.repeat(64)]])
      await rt.query('SELECT set_config($1,$2,true)',[k,v]);
    assert.equal((await rt.query('SELECT * FROM stockwise.orders')).rowCount,0);
    await deny(rt,'SELECT stockwise_auth.activate_context($1)',['f'.repeat(64)]);
    await rt.query('ROLLBACK');
  });
  await check('07 raw memberships/proofs/identity minting inaccessible to runtime',async()=>{
    await rt.query('BEGIN');
    for(const t of ['company_memberships','identities','request_proofs','command_audit'])
      await deny(rt,`SELECT * FROM stockwise_auth.${t}`);
    await deny(rt,"SELECT stockwise_auth.issue_context($1,$2,1,'1'::xid8,now())",[issuer,'bob']);
    await deny(rt,'SELECT * FROM stockwise_auth.authorize($1,$2)',[B,'reverse']);
    await rt.query('ROLLBACK');
  });
  await check('08 verifier cannot read business data or invoke commands',async()=>{
    await verifier.query('BEGIN');
    await deny(verifier,'SELECT * FROM stockwise.products');
    await deny(verifier,'SELECT stockwise_api.post_order($1,$2,$3)',[A,purchase,key(3)]);
    await verifier.query('ROLLBACK');
  });
  await check('09 core helpers stay private; role/schema/RLS escalation denied',async()=>{
    await tx('alice',async c=>{
      for(const s of ['SET ROLE stockwise_owner','SET ROLE stockwise_migrator','SET ROLE stockwise_verifier',
        'CREATE TABLE stockwise_api.escalation(id int)','SET LOCAL row_security=off; SELECT * FROM stockwise.products'])
        await deny(c,s);
      await deny(c,'SELECT stockwise.post_order($1,$2,$3)',[A,purchase,key(4)]);
      const p=(await owner.query(`SELECT bool_or(has_function_privilege('sw_business',p.oid,'EXECUTE')) AS any
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='stockwise'`)).rows[0];
      assert.equal(p.any,false);
    });
  });
  await check('10 enumeration is membership-derived, supports genuine multi-company users',async()=>{
    await tx('alice',async c=>assert.deepEqual((await c.query('SELECT company_id FROM stockwise_api.my_companies()')).rows,[{company_id:A}]));
    await tx('shared',async c=>assert.deepEqual((await c.query('SELECT company_id FROM stockwise_api.my_companies()')).rows,[{company_id:A},{company_id:B}]));
  });
  await check('11 cross-company IDs and mismatched order/company denied before changes',async()=>{
    await tx('alice',async c=>{
      await deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[B,purchaseB,key(5)]);
      await deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,purchaseB,key(6)]);
      await deny(c,"SELECT stockwise_api.reverse_order($1,$2,$3,'2026-10-23','Synthetic reversal')",[B,purchaseB,key(7)]);
    });
    assert.equal(await quantity(B),'7');
  });
  await check('12 viewer cannot post; operator cannot adjust or reverse',async()=>{
    await tx('viewer',c=>deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,purchase,key(8)]));
    await tx('alice',async c=>{
      await deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,adjust,key(9)]);
      await deny(c,"SELECT stockwise_api.reverse_order($1,$2,$3,'2026-10-23','Synthetic')",[A,purchase,key(10)]);
    });
  });
  await check('13 direct business writes and self-granted memberships are denied',async()=>{
    await tx('alice',async c=>{
      await deny(c,'UPDATE stockwise.stock_balances SET quantity=99 WHERE company_id=$1',[A]);
      await deny(c,'UPDATE stockwise.orders SET company_id=$1 WHERE id=$2',[B,sale]);
      await deny(c,'INSERT INTO stockwise.products(company_id,sku,name) VALUES($1,$2,$3)',[B,'FORGED','forged']);
      await deny(c,'DELETE FROM stockwise.stock_movements WHERE company_id=$1',[A]);
      await deny(c,"UPDATE stockwise_auth.company_memberships SET member_role='owner'");
      await deny(c,"INSERT INTO stockwise_auth.company_memberships(company_id,identity_id,member_role) VALUES($1,$2,'owner')",[B,alice]);
    });
  });
  let oldProof;
  await check('14 authorized multi-item posting, real actor audit and idempotent retry',async()=>{
    await tx('alice',async(c,ctx)=>{oldProof=ctx.proof;
      await c.query("SET LOCAL search_path=pg_temp,public");
      await c.query('CREATE TEMP TABLE products(dummy int)');
      assert.equal((await c.query('SELECT stockwise_api.post_order($1,$2,$3) AS id',[A,purchase,key(11)])).rows[0].id,purchase);
    });
    await tx('alice',c=>c.query('SELECT stockwise_api.post_order($1,$2,$3)',[A,purchase,key(11)]));
    assert.equal(await quantity(A),'10');
    const audit=(await owner.query('SELECT identity_id,count(*) OVER()::int AS n FROM stockwise_auth.command_audit WHERE order_id=$1',[purchase])).rows[0];
    assert.equal(audit.identity_id,alice);assert.equal(audit.n,1);
    assert.equal((await owner.query('SELECT * FROM stockwise.stock_movements WHERE order_id=$1',[purchase])).rowCount,2);
  });
  await check('15 all eight core tables filter other-company rows under RLS',async()=>{
    for(const subject of ['alice','bob'])await tx(subject,async c=>{
      const expected=subject==='alice'?A:B;
      for(const t of ['companies','products','contacts','orders','order_items','stock_balances','stock_movements','audit_logs']){
        const result=await c.query(`SELECT ${t==='companies'?'id':'company_id'} AS company FROM stockwise.${t}`);
        assert(result.rowCount>0);assert(result.rows.every(r=>r.company===expected),t);
      }
    });
  });
  await check('16 prior-transaction proof cannot replay after commit or SESSION poisoning',async()=>{
    await rt.query("SELECT set_config('stockwise.request_proof',$1,false)",[oldProof]);
    assert.equal((await rt.query('SELECT * FROM stockwise.products')).rowCount,0);
    await rt.query('BEGIN');await rt.query('SELECT pg_current_xact_id()');
    await deny(rt,'SELECT stockwise_auth.activate_context($1)',[oldProof]);
    await rt.query('ROLLBACK');await rt.query('RESET stockwise.request_proof');
  });
  await check('17 proof cannot be used on another backend',async()=>{
    await tx('alice',async(c,ctx)=>{
      await rt.query('BEGIN');await rt.query('SELECT pg_current_xact_id()');
      await deny(rt,'SELECT stockwise_auth.activate_context($1)',[ctx.proof]);
      await rt.query('ROLLBACK');
      assert.equal((await c.query('SELECT * FROM stockwise.products')).rowCount,1);
    });
  });
  await check('18 expired proof stops reads and commands',async()=>{
    await tx('alice',async(c,ctx)=>{
      await owner.query("UPDATE stockwise_auth.request_proofs SET expires_at=clock_timestamp()-interval '1 second' WHERE backend_pid=$1 AND transaction_id=$2::xid8",[ctx.pid,ctx.xid]);
      assert.equal((await c.query('SELECT * FROM stockwise.products')).rowCount,0);
      await deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,sale,key(12)]);
    });
  });
  await check('19 REPEATABLE READ fails closed instead of using stale identity snapshots',async()=>{
    await context(rt,'alice',{isolation:'REPEATABLE READ',activate:false});
    await fails(()=>rt.query("SELECT stockwise_auth.activate_context('invalid')"),'25001');
    await rt.query('ROLLBACK');
  });
  await check('20 membership revoked after minting is not cached',async()=>{
    await tx('alice',async c=>{
      await owner.query('UPDATE stockwise_auth.company_memberships SET active=false WHERE identity_id=$1',[alice]);
      assert.equal((await c.query('SELECT * FROM stockwise.products')).rowCount,0);
      assert.equal((await c.query('SELECT * FROM stockwise_api.my_companies()')).rowCount,0);
      await deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,sale,key(13)]);
      await deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,purchase,key(11)]);
    });
    await owner.query('UPDATE stockwise_auth.company_memberships SET active=true WHERE identity_id=$1',[alice]);
  });
  await check('21 identity disabling and issuer disabling invalidate existing context',async()=>{
    await tx('alice',async c=>{
      await owner.query('UPDATE stockwise_auth.identities SET active=false WHERE id=$1',[alice]);
      assert.equal((await c.query('SELECT * FROM stockwise.products')).rowCount,0);
      await owner.query('UPDATE stockwise_auth.identities SET active=true WHERE id=$1',[alice]);
      await owner.query('UPDATE stockwise_auth.issuers SET enabled=false');
      assert.equal((await c.query('SELECT * FROM stockwise.products')).rowCount,0);
      await owner.query('UPDATE stockwise_auth.issuers SET enabled=true');
    });
  });
  await check('22 insufficient-stock error rolls back ledger, balances and both audits',async()=>{
    const before=(await owner.query('SELECT count(*)::int AS n FROM stockwise_auth.command_audit')).rows[0].n;
    await fails(()=>tx('alice',c=>c.query('SELECT stockwise_api.post_order($1,$2,$3)',[A,bigSale,key(14)])),'P0001');
    assert.equal(await quantity(A),'10');
    assert.equal((await owner.query('SELECT status FROM stockwise.orders WHERE id=$1',[bigSale])).rows[0].status,'draft');
    assert.equal((await owner.query('SELECT count(*)::int AS n FROM stockwise_auth.command_audit')).rows[0].n,before);
  });
  let reversal;
  await check('23 authorized admin reversal and retry preserve deferred checks and audit',async()=>{
    reversal=await tx('admin',async c=>(await c.query("SELECT stockwise_api.reverse_order($1,$2,$3,'2026-10-23','Synthetic reversal') AS id",[A,purchase,key(15)])).rows[0].id);
    const again=await tx('admin',async c=>(await c.query("SELECT stockwise_api.reverse_order($1,$2,$3,'2026-10-23','Synthetic reversal') AS id",[A,purchase,key(15)])).rows[0].id);
    assert.equal(again,reversal);assert.equal(await quantity(A),'0');
    assert.equal((await owner.query("SELECT * FROM stockwise_auth.command_audit WHERE action='reverse'")).rowCount,1);
    assert.equal((await owner.query("SELECT status FROM stockwise.orders WHERE id=$1",[purchase])).rows[0].status,'reversed');
  });
  await check('24 admin adjustment succeeds, business rollback leaves no changes or replay',async()=>{
    await tx('admin',c=>c.query('SELECT stockwise_api.post_order($1,$2,$3)',[A,adjust,key(16)]));
    let proof;
    await tx('alice',async(c,ctx)=>{proof=ctx.proof;
      await c.query('SELECT stockwise_api.post_order($1,$2,$3)',[A,sale,key(17)]);},false);
    assert.equal(await quantity(A),'10');
    assert.equal((await owner.query('SELECT * FROM stockwise_auth.command_audit WHERE order_id=$1',[sale])).rowCount,0);
    await rt.query('BEGIN');await rt.query('SELECT pg_current_xact_id()');
    await deny(rt,'SELECT stockwise_auth.activate_context($1)',[proof]);await rt.query('ROLLBACK');
  });
  await check('25 company-aware contact and product references reject cross-company links',async()=>{
    await owner.query('BEGIN');
    await deny(owner,`INSERT INTO stockwise.orders(company_id,contact_id,reference,kind,business_date)
      VALUES($1,$2,'invalid-cross-company','sale','2026-10-23')`,[A,CB],'23503');
    await deny(owner,`INSERT INTO stockwise.order_items(company_id,order_id,product_id,line_number,quantity,unit_price)
      VALUES($1,$2,$3,10,1,1)`,[A,sale,PB],'23503');
    await owner.query('ROLLBACK');
  });
  await check('26 authorization locks serialize in-flight command versus revocation',async()=>{
    await tx('alice',async c=>{
      await c.query('SELECT stockwise_api.post_order($1,$2,$3)',[A,sale2,key(18)]);
      await owner.query('BEGIN');await owner.query("SET LOCAL lock_timeout='250ms'");
      await fails(()=>owner.query('UPDATE stockwise_auth.company_memberships SET active=false WHERE identity_id=$1',[alice]),'55P03');
      await owner.query('ROLLBACK');
    });
    await owner.query('UPDATE stockwise_auth.company_memberships SET active=false WHERE identity_id=$1',[alice]);
    await tx('alice',c=>deny(c,'SELECT stockwise_api.post_order($1,$2,$3)',[A,sale,key(19)]));
    await owner.query('UPDATE stockwise_auth.company_memberships SET active=true WHERE identity_id=$1',[alice]);
    assert.equal(await quantity(A),'8');
  });
  await check('27 repeated pool reuse switches actors without tenant leakage',async()=>{
    for(const s of ['bob','alice','viewer','bob','admin'])await tx(s,async c=>{
      const companies=(await c.query('SELECT id FROM stockwise.companies')).rows.map(r=>r.id);
      assert.deepEqual(companies,[s==='bob'?B:A]);
    });
  });
  await check('28 stock ledger sums, core audit and verified command audit remain consistent',async()=>{
    const balances=(await owner.query(`SELECT b.quantity::text AS q,COALESCE(sum(m.quantity_delta),0)::text AS ledger
      FROM stockwise.stock_balances b LEFT JOIN stockwise.stock_movements m
        ON m.company_id=b.company_id AND m.product_id=b.product_id GROUP BY b.company_id,b.product_id,b.quantity`)).rows;
    assert(balances.every(r=>r.q===r.ledger));
    assert.equal(await quantity(B),'7');
    await owner.query('BEGIN');await deny(owner,'UPDATE stockwise_auth.command_audit SET action=action',[],'P0001');
    await owner.query('ROLLBACK');
  });
  await check('29 fake Supabase API roles receive no new access',async()=>{
    for(const role of ['anon','authenticated','service_role','authenticator']){
      for(const schema of ['stockwise','stockwise_auth','stockwise_api'])
        assert.equal((await owner.query('SELECT has_schema_privilege($1,$2,$3) AS ok',[role,schema,'USAGE'])).rows[0].ok,false);
      assert.equal((await owner.query("SELECT pg_has_role($1,'stockwise_runtime','MEMBER') AS ok",[role])).rows[0].ok,false);
    }
  });
  await check('30 owner/fixed search paths and RLS policies/catalog privileges',async()=>{
    const funcs=(await owner.query(`SELECT p.proowner='stockwise_owner'::regrole AS owned,p.prosecdef,p.proconfig
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('stockwise_auth','stockwise_api')`)).rows;
    assert.equal(funcs.length,8);assert(funcs.every(f=>f.owned&&f.prosecdef&&f.proconfig.includes('search_path=pg_catalog, pg_temp')));
    assert.equal((await owner.query("SELECT * FROM pg_policies WHERE schemaname='stockwise' AND cmd='SELECT'")).rowCount,8);
    assert.equal((await owner.query(`SELECT * FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname IN ('stockwise','stockwise_auth') AND c.relkind='r' AND c.relrowsecurity`)).rowCount,13);
  });
  // Offline cryptographic JWT tests: generated test keys never leave this process.
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const jwk={...pair.publicKey.export({format:'jwk'}),kid:'local-test-key',alg:'ES256',use:'sig'};
  const jwtConfig={issuer,audience:'authenticated',keyring:new Map([[jwk.kid,jwk]])};
  const now=Math.floor(Date.now()/1000);
  const base={iss:issuer,sub:'alice',aud:'authenticated',role:'authenticated',iat:now,exp:now+300};
  function token(change={},head={}){
    const h=Buffer.from(JSON.stringify({alg:'ES256',kid:jwk.kid,...head})).toString('base64url');
    const p=Buffer.from(JSON.stringify({...base,...change})).toString('base64url');
    return h+'.'+p+'.'+crypto.sign('sha256',Buffer.from(h+'.'+p),
      {key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
  }
  await check('31 valid offline ES256 JWT yields only verified issuer/subject/expiry',async()=>{
    assert.deepEqual(verifyAccessToken(token({company_id:B,user_id:bob,member_role:'owner'}),jwtConfig),
      {issuer,subject:'alice',expiresAt:base.exp});
  });
  let n=31;
  for(const [name,claims,head] of [
    ['wrong issuer',{iss:'https://untrusted.invalid'}],['wrong audience',{aud:'admin'}],
    ['expired',{exp:now-1}],['future nbf',{nbf:now+100}],['future iat',{iat:now+10}],
    ['too-long lifetime',{exp:now+7200}],['service-role token',{role:'service_role'}],
    ['missing subject',{sub:''}],['none algorithm',{}, {alg:'none'}],
    ['HS256 confusion',{}, {alg:'HS256'}],['unknown kid',{}, {kid:'unknown'}],
    ['attacker key URL',{}, {jku:'https://attacker.invalid'}],['embedded key',{}, {jwk:{}}]
  ])await check(`${++n} JWT rejects ${name}`,()=>fails(async()=>verifyAccessToken(token(claims,head),jwtConfig),'AUTH_INVALID'));
  await check(`${++n} JWT rejects forged signature`,async()=>{
    const parts=token().split('.');parts[1]=Buffer.from(JSON.stringify({...base,sub:'bob'})).toString('base64url');
    await fails(async()=>verifyAccessToken(parts.join('.'),jwtConfig),'AUTH_INVALID');
  });
  await check(`${++n} anonymous/invalid JWT never obtains a business connection`,async()=>{
    let touched=false;
    await fails(()=>withAuthorizedTransaction({token:undefined,jwtConfig,runtimePool:{connect(){touched=true;}},
      verifierPool,work:()=>{}}),'AUTH_INVALID');assert.equal(touched,false);
  });
  await check(`${++n} JWT-to-proof-to-RLS Node reference works; forged browser fields ignored`,async()=>{
    await withAuthorizedTransaction({token:token({user_id:bob,company_id:B}),jwtConfig,runtimePool,verifierPool,
      work:async c=>assert.deepEqual((await c.query('SELECT id FROM stockwise.companies')).rows,[{id:A}])});
  });
  await check(`${++n} Node request exception rolls back and next pooled actor stays isolated`,async()=>{
    await fails(()=>withAuthorizedTransaction({token:token(),jwtConfig,runtimePool,verifierPool,work:async c=>{
      await c.query('SELECT stockwise_api.post_order($1,$2,$3)',[A,sale,key(20)]);
      throw Object.assign(new Error('Synthetic request failure'),{code:'SYNTHETIC'});
    }}),'SYNTHETIC');
    assert.equal(await quantity(A),'8');
    await withAuthorizedTransaction({token:token({sub:'bob'}),jwtConfig,runtimePool,verifierPool,
      work:async c=>assert.deepEqual((await c.query('SELECT id FROM stockwise.companies')).rows,[{id:B}])});
  });
  await check(`${++n} accidental DML grants still hit default-deny RLS write policies`,async()=>{
    await owner.query('GRANT INSERT,UPDATE ON stockwise.products TO stockwise_runtime');
    try{await tx('alice',async c=>{
      assert.equal((await c.query("UPDATE stockwise.products SET name='forged' WHERE company_id=$1",[A])).rowCount,0);
      assert.equal((await c.query("UPDATE stockwise.products SET name='forged' WHERE company_id=$1",[B])).rowCount,0);
      await deny(c,"INSERT INTO stockwise.products(company_id,sku,name) VALUES($1,'forged','forged')",[A]);
      await deny(c,"INSERT INTO stockwise.products(company_id,sku,name) VALUES($1,'forged','forged')",[B]);
    });}finally{await owner.query('REVOKE INSERT,UPDATE ON stockwise.products FROM stockwise_runtime');}
  });
  await check(`${++n} proof expiry capped by JWT expiry; hashes only; one identity per transaction`,async()=>{
    await rt.query('BEGIN');
    const target=(await rt.query('SELECT pg_backend_pid() AS pid,pg_current_xact_id()::text AS xid')).rows[0];
    const expiry=new Date(Date.now()+10000);
    const args=[issuer,'alice',target.pid,target.xid,expiry];
    const proof=(await verifier.query('SELECT stockwise_auth.issue_context($1,$2,$3,$4::xid8,$5) AS proof',args)).rows[0].proof;
    const stored=(await owner.query(`SELECT expires_at,octet_length(proof_hash) AS bytes
      FROM stockwise_auth.request_proofs WHERE backend_pid=$1 AND transaction_id=$2::xid8`,[target.pid,target.xid])).rows[0];
    assert.equal(stored.bytes,32);assert.equal(stored.expires_at.getTime(),expiry.getTime());
    await rt.query('SELECT stockwise_auth.activate_context($1)',[proof]);
    await fails(()=>verifier.query('SELECT stockwise_auth.issue_context($1,$2,$3,$4::xid8,$5)',
      [issuer,'bob',target.pid,target.xid,expiry]),'23505');
    assert.deepEqual((await rt.query('SELECT id FROM stockwise.companies')).rows,[{id:A}]);
    await rt.query('ROLLBACK');
  });
  await check(`${++n} shared verifier/business pool configuration fails before checkout`,async()=>{
    let touched=false;const pool={connect(){touched=true;}};
    await fails(()=>withAuthorizedTransaction({token:token(),jwtConfig,runtimePool:pool,verifierPool:pool,work(){}}),
      'SECURITY_CONFIGURATION');assert.equal(touched,false);
  });
}
main().catch(e=>{
  if(!rows.some(r=>r.status==='FAIL'))rows.push({name:'setup or cleanup',status:'FAIL',code:e.code,message:e.message});
  console.error('FAILED',e.code||'',e.message);process.exitCode=1;
}).finally(async()=>{
  for(const pool of pools)await pool.end();
  for(const c of clients)await c.end().catch(()=>{});
  const summary={passed:rows.filter(r=>r.status==='PASS').length,failed:rows.filter(r=>r.status==='FAIL').length};
  fs.writeFileSync(path.join(root,'results.json'),JSON.stringify({summary,checks:rows},null,2));
  console.log('SUMMARY',JSON.stringify(summary));
});
