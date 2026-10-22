"use strict";
// REVIEW ONLY. Import does not connect; harnesses require launcher approval gate.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { Client, Pool } = require("pg");
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12,"0")}`;
const source = p => fs.readFileSync(path.resolve(p),"utf8");
const migrationHash = "b83c9ace102a0478a55743c9dac1c9e4e25e8e2672a87a7320be31a91780d7c0";
function gate(root, suite) {
  assert.equal(process.env.STOCKWISE_PHASE2_EXECUTION, "explicitly-approved");
  assert(new RegExp(`^/tmp/stockwise-${suite}-[A-Za-z0-9]+$`).test(root || ""));
  assert.equal(fs.realpathSync(root),root);
  assert.equal(fs.readFileSync(path.join(root,"data/PG_VERSION"),"utf8").trim(),"17");
  const marker = JSON.parse(fs.readFileSync(path.join(root,"approved-lab.json"),"utf8"));
  assert.equal(marker.root,root); assert.equal(marker.suite,suite);
  assert.equal(crypto.createHash("sha256").update(source("db/migrations/0001_inventory.sql")).digest("hex"),migrationHash);
}
function settings(root,user="runner",database="stockwise_lab") {
  return {host:path.join(root,"socket"),port:6543,user,database,ssl:false,
    connectionTimeoutMillis:3000,statement_timeout:5000,lock_timeout:1500,
    query_timeout:8000,application_name:"stockwise_disposable_phase2"};
}
async function connect(root,user="runner",database="stockwise_lab") {
  const c = new Client(settings(root,user,database)); await c.connect(); return c;
}
// CREATE DATABASE cannot share a transaction/multi-command query; the actual
// installer below deliberately sends it separately.
async function installFoundation(root,security=false,tailRollbackProbe=false) {
  const bootstrap=await connect(root,"runner","postgres");
  try {
    const m=(await bootstrap.query(`SELECT current_setting('data_directory') d,
      current_setting('listen_addresses') l,inet_server_addr() a,current_user u`)).rows[0];
    assert.deepEqual(m,{d:path.join(root,"data"),l:"",a:null,u:"runner"});
    await bootstrap.query(`CREATE ROLE sw_provisioner LOGIN CREATEROLE NOCREATEDB NOSUPERUSER NOBYPASSRLS NOINHERIT;
      CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN;
      CREATE ROLE service_role NOLOGIN BYPASSRLS; CREATE ROLE authenticator NOLOGIN;`);
    await bootstrap.query("CREATE DATABASE stockwise_lab OWNER sw_provisioner");
  } finally { await bootstrap.end(); }
  const provisioner=await connect(root,"sw_provisioner");
  try {
    for(const p of ["01_create_roles.sql","02_grant_migration_access.sql"])
      await provisioner.query(source("db/deployment/"+p));
    await provisioner.query("SET ROLE stockwise_migrator");
    if(tailRollbackProbe) {
      const original=source("db/migrations/0001_inventory.sql");
      const faulty=original.replace(/COMMIT;\s*$/,"SELECT 1/0;\nCOMMIT;\n");
      assert.notEqual(original,faulty,"Expected one final COMMIT");
      try {await denied(()=>provisioner.query(faulty),["22012"]);}
      finally {await provisioner.query("ROLLBACK");}
      assert.equal((await provisioner.query("SELECT to_regnamespace('stockwise') n")).rows[0].n,null);
      assert.equal((await provisioner.query("SELECT count(*)::int n FROM pg_default_acl WHERE defaclrole='stockwise_owner'::regrole")).rows[0].n,0);
    }
    await provisioner.query(source("db/migrations/0001_inventory.sql"));
    await provisioner.query(source("db/deployment/03_harden_owner_function_defaults.sql"));
    await provisioner.query("RESET ROLE");
  } finally { await provisioner.end(); }
  const admin=await connect(root);
  try {
    if(security) for(const p of ["01_identity.sql","02_policies_commands.sql","03_adapter_contract.sql"])
      await admin.query(source("db/security-review/phase2/"+p));
    return admin;
  } catch(e) {await admin.end(); throw e;}
}
async function denied(fn, codes=["42501","P0001","23503","23505","23514","22003","22P02"]) {
  let caught;
  try { await fn(); } catch(e) { caught=e; }
  assert(caught,"Expected denial; operation unexpectedly succeeded");
  assert(codes.includes(caught.code),`Unexpected SQLSTATE ${caught.code}`);
  return caught.code;
}
async function transaction(c,fn,{commit=false}={}) {
  await c.query("BEGIN");
  try {const result=await fn(c); await c.query(commit?"COMMIT":"ROLLBACK"); return result;}
  catch(e) {await c.query("ROLLBACK"); throw e;}
}
async function savepoint(c,fn,codes) {
  await c.query("SAVEPOINT expected_denial");
  try {return await denied(fn,codes);}
  finally {await c.query("ROLLBACK TO expected_denial; RELEASE expected_denial");}
}
async function reconcile(c) {
  const q=await c.query(`SELECT count(*)::int n FROM stockwise.stock_balances b
    WHERE b.quantity<0 OR b.quantity::numeric<>coalesce((SELECT sum(m.quantity_delta::numeric)
      FROM stockwise.stock_movements m WHERE m.company_id=b.company_id AND m.product_id=b.product_id),0)`);
  assert.equal(q.rows[0].n,0);
}
function report(root) {
  const results=[];
  const sanitized=e=>String(e.message||"").replace(/postgres(?:ql)?:\/\/\S+/gi,"[connection redacted]")
    .replace(/\b[0-9a-f]{64}\b/gi,"[proof redacted]")
    .replace(/eyJ[\w-]*\.[\w-]+\.[\w-]+/g,"[JWT redacted]").slice(0,1000);
  return {
    async check(name,fn) {
      try {await fn(); results.push({name,status:"PASS"}); console.log("PASS",name);}
      catch(e) {results.push({name,status:"FAIL",code:e.code||"ASSERTION",message:sanitized(e)});
        // No SQL detail, proof, token, bound parameter or arbitrary error text.
        console.error("FAIL",name,e.code||"ASSERTION"); throw e;}
    },
    finish() {fs.writeFileSync(path.join(root,"results.json"),JSON.stringify({results,
      passed:results.filter(x=>x.status==="PASS").length,
      failed:results.filter(x=>x.status==="FAIL").length},null,2));},
  };
}
module.exports={fs,path,assert,Client,Pool,id,source,gate,settings,connect,
  installFoundation,denied,transaction,savepoint,reconcile,report};
