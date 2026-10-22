"use strict";
// Prepared only; requires separately approved launcher. Never uses DATABASE_URL.
const h=require("./phase2/common.cjs"),f=require("./phase2/fixtures.cjs");
async function main() {
  const root=process.argv[2];h.gate(root,"phase2");
  const r=h.report(root);let c;
  try{
    await r.check("I01/I09 compilation + injected migration-tail rollback (in-memory copy)",async()=>{
      c=await h.installFoundation(root,false,true);
    });
    await c.query(`CREATE ROLE sw_invoker LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOINHERIT;
      GRANT USAGE ON SCHEMA stockwise TO sw_invoker;
      GRANT EXECUTE ON FUNCTION stockwise.post_order(uuid,uuid,uuid),
        stockwise.reverse_order(uuid,uuid,uuid,date,text) TO sw_invoker`);
    const api=["anon","authenticated","service_role","authenticator",null];
    for(let n=0;n<5;n++){
      await c.query(`CREATE ROLE sw_invdeny${n} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT`);
      if(api[n])await c.query(`GRANT ${api[n]} TO sw_invdeny${n} WITH ADMIN FALSE,INHERIT TRUE,SET FALSE`);
    }
    await f.seedCore(c);
    await require("./phase2/inventory-cases.cjs").cases(c,r.check,root);
    await require("./phase2/inventory-concurrency.cjs").concurrent(root,c,r.check);
    await r.check("FINAL all balances equal ledger",()=>h.reconcile(c));
  }finally{if(c)await c.end();r.finish();}
}
if(require.main===module)main().catch(e=>{console.error("STOP",e.code||"ASSERTION");process.exitCode=1;});
