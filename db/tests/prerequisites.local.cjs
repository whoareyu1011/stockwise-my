// Explicitly approved disposable PostgreSQL 17 cluster ONLY.
// No URLs or environment-based connection settings; never invoked at startup.
const {Client} = require('pg');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = process.argv[2];
assert(root && /^\/tmp\/stockwise-prereq-[A-Za-z0-9]+$/.test(root),
  'Supply the explicitly approved fresh disposable cluster directory');
assert.equal(fs.realpathSync(root),root);
assert.equal(fs.readFileSync(path.join(root,'data/PG_VERSION'),'utf8').trim(),'17');
const base=path.resolve(__dirname,'..');
const files={
  roles:fs.readFileSync(path.join(base,'deployment/01_create_roles.sql'),'utf8'),
  access:fs.readFileSync(path.join(base,'deployment/02_grant_migration_access.sql'),'utf8'),
  migration:fs.readFileSync(path.join(base,'migrations/0001_inventory.sql'),'utf8'),
  hardening:fs.readFileSync(path.join(base,'deployment/03_harden_owner_function_defaults.sql'),'utf8'),
};
assert.equal(crypto.createHash('sha256').update(files.migration).digest('hex'),
  'b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0');
const results=[],clients=new Set();
const db='sw_prerequisites';
function info(e){return {code:e.code||'ASSERTION',message:e.message,detail:e.detail};}
function result(name,status,detail){results.push({name,status,detail});console.log(status+' '+name+' '+JSON.stringify(detail||''));}
async function client(user='sw_provisioner',database=db){
  const c=new Client({host:path.join(root,'socket'),port:6543,user,database,
    ssl:false,connectionTimeoutMillis:3000,statement_timeout:10000,
    application_name:'stockwise_disposable_prerequisites'});
  await c.connect();clients.add(c);
  const identity=(await c.query('SELECT session_user,current_database(),inet_server_addr()')).rows[0];
  assert.equal(identity.session_user,user);assert.equal(identity.current_database,database);
  assert.equal(identity.inet_server_addr,null);
  return c;
}
async function close(c){if(clients.delete(c))await c.end();}
async function check(name,fn){
  try{const detail=await fn();result(name,'PASS',detail);}
  catch(e){result(name,'FAIL',info(e));throw e;}
}
async function reject(c,file,setup,pattern,code){
  await c.query('BEGIN');
  if(setup)await setup(c);
  let error;
  try{await c.query(files[file]);}catch(e){error=e;}
  await c.query('ROLLBACK');
  assert.ok(error,'Expected failure but file committed unexpectedly');
  if(pattern)assert.match(error.message,pattern);
  if(code)assert.equal(error.code,code);
  return info(error);
}
async function denied(c,statement,pattern=/permission denied/,code='42501'){
  await c.query('BEGIN');let error;
  try{await c.query(statement);}catch(e){error=e;}
  await c.query('ROLLBACK');assert.ok(error);assert.match(error.message,pattern);
  if(code)assert.equal(error.code,code);return info(error);
}
async function roleFlags(c){
  return (await c.query(`SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,
    rolcreatedb,rolinherit,rolcanlogin,rolreplication FROM pg_roles
    WHERE rolname NOT IN ('stockwise_owner','stockwise_migrator') ORDER BY rolname`)).rows;
}
async function defaultsOtherThanOwner(c){
  return (await c.query(`SELECT defaclrole,defaclnamespace,defaclobjtype,defaclacl::text
    FROM pg_default_acl WHERE defaclrole<>to_regrole('stockwise_owner')
    ORDER BY defaclrole,defaclnamespace,defaclobjtype`)).rows;
}
async function aclSnapshot(c){
  return (await c.query(`SELECT p.proname,p.proacl::text FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='stockwise'
    ORDER BY p.proname`)).rows;
}
async function main(){
  const bootstrap=await client('runner','postgres');
  const identity=(await bootstrap.query(`SELECT current_setting('data_directory') directory,
    current_setting('listen_addresses') addresses,version()`)).rows[0];
  assert.equal(identity.directory,path.join(root,'data'));assert.equal(identity.addresses,'');
  assert.match(identity.version,/PostgreSQL 17\./);
  // LOGIN is for actual non-superuser test sessions over the private socket only.
  await bootstrap.query(`CREATE ROLE sw_provisioner LOGIN CREATEROLE NOCREATEDB
    NOSUPERUSER NOBYPASSRLS NOINHERIT NOREPLICATION;
    CREATE ROLE sw_observer LOGIN NOCREATEROLE NOCREATEDB NOSUPERUSER NOBYPASSRLS;
    CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN BYPASSRLS; CREATE ROLE authenticator NOLOGIN;`);
  await bootstrap.query('CREATE DATABASE '+db+' OWNER sw_provisioner');
  await close(bootstrap);
  const c=await client(),observer=await client('sw_observer');
  const existingFlags=await roleFlags(c);
  await check('T01 actual restricted provisioning session',async()=>{
    const r=(await c.query(`SELECT current_user,session_user,rolsuper,rolbypassrls,
      rolcreaterole FROM pg_roles WHERE rolname=current_user`)).rows[0];
    assert.equal(r.current_user,'sw_provisioner');assert.equal(r.session_user,'sw_provisioner');
    assert.equal(r.rolsuper,false);assert.equal(r.rolbypassrls,false);assert.equal(r.rolcreaterole,true);
    return r;
  });
  await check('T02 access script before role creation rejects',()=>reject(c,'access',null,/file 01 first/));
  await check('T03 unchanged 0001 before role creation rejects',()=>reject(c,'migration',null,/non-login, non-privileged/));
  await check('T04 unprivileged provisioner rejects',()=>reject(observer,'roles',null,/CREATEROLE capability/));
  await check('T05 existing role names reject without overwrite',()=>reject(c,'roles',
    x=>x.query('CREATE ROLE stockwise_owner NOLOGIN'),/already exists/));
  await check('T06 existing schema rejects',()=>reject(c,'roles',
    x=>x.query('CREATE SCHEMA stockwise'),/schema already exists/));
  await check('T07 file 01 atomic restricted role creation',async()=>{
    await c.query(files.roles);
    const r=(await c.query(`SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,
      rolcreatedb,rolinherit,rolcanlogin,rolreplication FROM pg_roles
      WHERE rolname IN ('stockwise_owner','stockwise_migrator') ORDER BY rolname`)).rows;
    assert.equal(r.length,2);
    for(const row of r)for(const [key,value] of Object.entries(row))if(key!=='rolname')assert.equal(value,false);
    return r;
  });
  await check('T08 role creation reapplication rejects',()=>reject(c,'roles',null,/already exists/));
  await check('T09 creator cannot SET restricted roles before explicit access grant',async()=>{
    const errors=[];
    for(const role of ['stockwise_owner','stockwise_migrator'])
      errors.push(await denied(c,'SET LOCAL ROLE '+role,/permission denied to set role/));
    return errors;
  });
  await check('T10 owner flag drift blocks access script',()=>reject(c,'access',
    x=>x.query('ALTER ROLE stockwise_owner LOGIN'),/restricted configuration/));
  await check('T11 unexpected membership blocks access script',()=>reject(c,'access',async x=>{
    await x.query('CREATE ROLE sw_parent NOLOGIN; GRANT sw_parent TO stockwise_owner');
  },/membership graph/));
  await check('T12 unsafe creator inheritance edge blocks access script',()=>reject(c,'access',
    x=>x.query('GRANT stockwise_owner TO sw_provisioner WITH INHERIT TRUE'),/membership options/));
  await check('T13 file 02 grants only deployment access',async()=>{
    await c.query(files.access);
    const rows=(await c.query(`SELECT p.rolname parent,r.rolname member,
      m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m
      JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles r ON r.oid=m.member
      WHERE p.rolname IN ('stockwise_owner','stockwise_migrator')
      ORDER BY p.rolname,r.rolname,m.admin_option`)).rows;
    assert.deepEqual(rows,[
      {parent:'stockwise_migrator',member:'sw_provisioner',admin_option:false,inherit_option:false,set_option:true},
      {parent:'stockwise_migrator',member:'sw_provisioner',admin_option:true,inherit_option:false,set_option:false},
      {parent:'stockwise_owner',member:'stockwise_migrator',admin_option:false,inherit_option:false,set_option:true},
      {parent:'stockwise_owner',member:'sw_provisioner',admin_option:true,inherit_option:false,set_option:false},
    ]);
    const rights=(await c.query(`SELECT
      has_database_privilege('stockwise_migrator',current_database(),'CREATE') migrator_create,
      has_database_privilege('stockwise_owner',current_database(),'CREATE') owner_create,
      pg_has_role('sw_provisioner','stockwise_owner','USAGE') inherits_owner,
      pg_has_role('sw_provisioner','stockwise_migrator','USAGE') inherits_migrator`)).rows[0];
    assert.deepEqual(rights,{migrator_create:true,owner_create:false,inherits_owner:false,inherits_migrator:false});
    return {memberships:rows,rights};
  });
  await check('T14 access script safely repeats before 0001',()=>c.query(files.access).then(()=>({reapplied:true})));
  await check('T15 actual operator to migrator to owner switching',async()=>{
    await c.query('BEGIN');await c.query('SET LOCAL ROLE stockwise_migrator');
    assert.equal((await c.query('SELECT current_user')).rows[0].current_user,'stockwise_migrator');
    await c.query('SET LOCAL ROLE stockwise_owner');
    assert.equal((await c.query('SELECT current_user')).rows[0].current_user,'stockwise_owner');
    await c.query('ROLLBACK');
  });
  await check('T16 unprivileged session cannot switch deployment roles',async()=>{
    const errors=[];
    for(const role of ['stockwise_owner','stockwise_migrator'])
      errors.push(await denied(observer,'SET LOCAL ROLE '+role,/permission denied to set role/));
    return errors;
  });
  await check('T17 owner and migrator cannot log in',async()=>{
    const errors=[];
    for(const user of ['stockwise_owner','stockwise_migrator']){
      let error;try{const x=await client(user);await close(x);}catch(e){error=e;}
      assert.equal(error?.code,'28000');assert.match(error.message,/not permitted to log in/);
      errors.push(info(error));
    }
    return errors;
  });
  await check('T18 hardening before 0001 rejects',()=>reject(c,'hardening',null,/0001 must be installed/));
  await check('T19 unprivileged hardening rejects',()=>reject(observer,'hardening',null,/permission denied to set role/,'42501'));
  const migrationBad=async(setup,pattern)=>reject(c,'migration',async x=>{
    if(setup)await setup(x);
    await x.query('SET LOCAL ROLE stockwise_migrator');
  },pattern);
  await check('T20 0001 unsafe owner flags preflight',()=>migrationBad(
    x=>x.query('ALTER ROLE stockwise_owner LOGIN'),/non-login, non-privileged/));
  await check('T21 0001 owner parent membership preflight',()=>migrationBad(
    x=>x.query('CREATE ROLE sw_parent NOLOGIN; GRANT sw_parent TO stockwise_owner'),/must not be a member/));
  await check('T22 0001 API membership preflight',()=>migrationBad(
    x=>x.query('GRANT stockwise_owner TO anon WITH INHERIT FALSE, SET TRUE'),/API roles must not be members/));
  await check('T23 0001 missing DB CREATE preflight',()=>migrationBad(
    x=>x.query('REVOKE CREATE ON DATABASE '+db+' FROM stockwise_migrator'),/database CREATE privilege/));
  await check('T24 early global hardening would violate 0001 clean-default preflight',()=>migrationBad(async x=>{
    await x.query('SET LOCAL ROLE stockwise_owner; ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC');
  },/clean owner with no custom default/));
  await check('T25 0001 missing owner membership preflight',()=>migrationBad(
    x=>x.query('REVOKE stockwise_owner FROM stockwise_migrator'),/operator must have approved membership/));
  await check('T26 unchanged migration under actual non-superuser migrator',async()=>{
    await c.query('SET ROLE stockwise_migrator');
    await c.query(files.migration);
    assert.equal((await c.query('SELECT current_user')).rows[0].current_user,'stockwise_migrator');
    await c.query('RESET ROLE');
  });
  await check('T27 0001 existing schema preflight',()=>migrationBad(null,/schema already exists/));
  await check('T28 file 02 refuses deployed membership rewrites',()=>reject(c,'access',null,/before migration 0001/));
  const otherDefaults=await defaultsOtherThanOwner(c),existingAcls=await aclSnapshot(c);
  await check('T29 schema PUBLIC default grant blocks global-only hardening',()=>reject(c,'hardening',async x=>{
    await x.query(`SET LOCAL ROLE stockwise_owner;
      ALTER DEFAULT PRIVILEGES IN SCHEMA stockwise GRANT EXECUTE ON FUNCTIONS TO PUBLIC`);
  },/positive owner function defaults/));
  await check('T30 named-role default grant blocks hardening',()=>reject(c,'hardening',async x=>{
    await x.query(`SET LOCAL ROLE stockwise_owner;
      ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO sw_observer`);
  },/positive owner function defaults/));
  await check('T31 file 03 owner-global function hardening',async()=>{
    await c.query(files.hardening);
    const a=(await c.query(`SELECT a.defaclnamespace,a.defaclobjtype,acl.grantee::regrole::text grantee,
      acl.privilege_type FROM pg_default_acl a CROSS JOIN LATERAL aclexplode(a.defaclacl) acl
      WHERE a.defaclrole=to_regrole('stockwise_owner') ORDER BY a.defaclnamespace,grantee`)).rows;
    assert.deepEqual(a,[{defaclnamespace:0,defaclobjtype:'f',grantee:'stockwise_owner',privilege_type:'EXECUTE'}]);
    assert.deepEqual(await defaultsOtherThanOwner(c),otherDefaults);
    assert.deepEqual(await aclSnapshot(c),existingAcls);
    return a;
  });
  await check('T32 hardening repeats without broadening permissions',async()=>{
    await c.query(files.hardening);
    assert.deepEqual(await defaultsOtherThanOwner(c),otherDefaults);
    assert.deepEqual(await aclSnapshot(c),existingAcls);
  });
  await check('T33 object ownership, restricted roles, function paths and RLS',async()=>{
    const tables=(await c.query(`SELECT c.relname,r.rolname owner,c.relrowsecurity,c.relforcerowsecurity
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
      WHERE n.nspname='stockwise' AND c.relkind='r' ORDER BY c.relname`)).rows;
    assert.deepEqual(tables.map(x=>x.relname),['audit_logs','companies','contacts','order_items','orders','products','stock_balances','stock_movements']);
    for(const t of tables){assert.equal(t.owner,'stockwise_owner');assert(t.relrowsecurity);assert(!t.relforcerowsecurity);}
    const funcs=(await c.query(`SELECT p.proname,r.rolname owner,p.prosecdef,p.proconfig
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
      WHERE n.nspname='stockwise' ORDER BY p.proname`)).rows;
    assert.equal(funcs.length,14);
    for(const f of funcs){assert.equal(f.owner,'stockwise_owner');assert.deepEqual(f.proconfig,['search_path=pg_catalog, pg_temp']);}
    assert.deepEqual(funcs.filter(x=>x.prosecdef).map(x=>x.proname),
      ['apply_movement','audit_catalogue_change','check_balance_integrity','check_order_integrity','initialize_balance','post_order','reverse_order']);
    assert.equal((await c.query("SELECT count(*)::int n FROM pg_policies WHERE schemaname='stockwise'")).rows[0].n,0);
    return {tables:8,functions:14,definers:7,policies:0};
  });
  await check('T34 PUBLIC and API/observer effective privileges remain closed',async()=>{
    for(const role of ['anon','authenticated','service_role','authenticator','sw_observer']){
      const r=(await c.query(`SELECT
        has_schema_privilege($1,'stockwise','USAGE') schema_usage,
        EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='stockwise' AND has_function_privilege($1,p.oid,'EXECUTE')) function_execute,
        EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE n.nspname='stockwise' AND t.relkind='r'
          AND has_table_privilege($1,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) table_access,
        pg_has_role($1,'stockwise_owner','MEMBER') owner_member,
        pg_has_role($1,'stockwise_migrator','MEMBER') migrator_member`,[role])).rows[0];
      assert.deepEqual(r,{schema_usage:false,function_execute:false,table_access:false,owner_member:false,migrator_member:false});
    }
    assert.equal((await c.query(`SELECT count(*)::int n FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE n.nspname='stockwise' AND acl.grantee=0 AND acl.privilege_type='EXECUTE'`)).rows[0].n,0);
    return {rolesChecked:5,publicExecuteFunctions:0};
  });
  await check('T35 real unprivileged connection cannot read or execute',async()=>{
    const errors=[];
    errors.push(await denied(observer,'SELECT * FROM stockwise.products'));
    errors.push(await denied(observer,`SELECT stockwise.post_order(gen_random_uuid(),gen_random_uuid(),gen_random_uuid())`));
    return errors;
  });
  await check('T36 newly created owner function denies PUBLIC/API/observer EXECUTE',async()=>{
    await c.query('BEGIN; SET LOCAL ROLE stockwise_owner');
    await c.query(`CREATE FUNCTION stockwise.__future_probe() RETURNS integer
      LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'SELECT 1'`);
    for(const role of ['anon','authenticated','service_role','authenticator','sw_observer'])
      assert.equal((await c.query("SELECT has_function_privilege($1,'stockwise.__future_probe()','EXECUTE') allowed",[role])).rows[0].allowed,false);
    assert.equal((await c.query('SELECT stockwise.__future_probe() n')).rows[0].n,1);
    await c.query('ROLLBACK');
  });
  await check('T37 owner-global default covers second private schema too',async()=>{
    await c.query('BEGIN; SET LOCAL ROLE stockwise_migrator');
    await c.query('CREATE SCHEMA sw_default_probe AUTHORIZATION stockwise_owner; SET LOCAL ROLE stockwise_owner');
    await c.query("CREATE FUNCTION sw_default_probe.probe() RETURNS integer LANGUAGE sql AS 'SELECT 1'");
    assert.equal((await c.query("SELECT has_function_privilege('sw_observer','sw_default_probe.probe()','EXECUTE') allowed")).rows[0].allowed,false);
    await c.query('ROLLBACK');
  });
  await check('T38 other creator default function behavior unchanged',async()=>{
    await c.query('BEGIN');
    await c.query("CREATE FUNCTION public.__other_creator_probe() RETURNS integer LANGUAGE sql AS 'SELECT 1'");
    assert.equal((await c.query("SELECT has_function_privilege('sw_observer','public.__other_creator_probe()','EXECUTE') allowed")).rows[0].allowed,true);
    await c.query('ROLLBACK');
  });
  await check('T39 existing role flags and other-role defaults preserved',async()=>{
    assert.deepEqual(await roleFlags(c),existingFlags);
    assert.deepEqual(await defaultsOtherThanOwner(c),otherDefaults);
  });
  await check('T40 no business fixtures and no probe objects retained',async()=>{
    await c.query('BEGIN; SET LOCAL ROLE stockwise_owner');
    for(const t of ['companies','contacts','products','orders','order_items','stock_balances','stock_movements','audit_logs'])
      assert.equal((await c.query(`SELECT count(*)::int n FROM stockwise.${t}`)).rows[0].n,0);
    await c.query('ROLLBACK');
    assert.equal((await c.query("SELECT to_regnamespace('sw_default_probe') n")).rows[0].n,null);
    assert.equal((await c.query("SELECT count(*)::int n FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='stockwise'")).rows[0].n,14);
  });
  await close(observer);await close(c);
}
main().catch(e=>console.error('TEST_RUN_ABORTED '+JSON.stringify(info(e)))).finally(async()=>{
  for(const c of [...clients])await close(c).catch(()=>{});
  const summary={passed:results.filter(r=>r.status==='PASS').length,failed:results.filter(r=>r.status==='FAIL').length};
  console.log('SUMMARY '+JSON.stringify(summary));
  fs.writeFileSync(path.join(root,'results.json'),JSON.stringify({summary,results},null,2));
  if(summary.failed||summary.passed!==40)process.exitCode=1;
});
