"use strict";
const h=require("./common.cjs"),f=require("./fixtures.cjs");
const {assert,id}=h;
const settle=p=>p.then(value=>({ok:true,value}),e=>({ok:false,code:e.code}));
async function blocked(admin,pid) {
  const deadline=Date.now()+2200;
  while(Date.now()<deadline){
    if((await admin.query("SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1",[pid])).rows[0]?.wait_event_type==="Lock")return;
    await new Promise(r=>setTimeout(r,10));
  }
  throw Object.assign(new Error("Expected lock wait not observed"),{code:"BARRIER_TIMEOUT"});
}
async function concurrent(root,admin,check) {
  let counter=20000;
  async function scope({receiptQuantity=10}={}) {
    const company=id(counter++),p=id(counter++),q=id(counter++),contact=id(counter++);
    await h.transaction(admin,async c=>{
      await c.query("SET LOCAL ROLE stockwise_owner");
      await c.query("INSERT INTO stockwise.companies(id,legal_name) VALUES($1,'Concurrency fixture')",[company]);
      await c.query("INSERT INTO stockwise.contacts(id,company_id,legal_name,contact_kind) VALUES($1,$2,'Fixture customer','both')",[contact,company]);
      for(const [product,sku] of [[p,"P"],[q,"Q"]])
        await c.query("INSERT INTO stockwise.products(id,company_id,sku,name) VALUES($1,$2,$3,'Fixture product')",[product,company,sku]);
    },{commit:true});
    const make=(kind,lines)=>h.transaction(admin,async c=>{
      await c.query("SET LOCAL ROLE stockwise_owner");
      return f.draft(c,{company,contact,kind,lines});
    },{commit:true});
    const receipt=await make("purchase",[[p,receiptQuantity,1],[q,receiptQuantity,1]]);
    await h.transaction(admin,c=>f.post(c,receipt,id(counter++),company),{commit:true});
    return {company,p,q,contact,receipt,make,key:()=>id(counter++)};
  }
  async function pair(fn,{diagnostic=false}={}) {
    const a=await h.connect(root,diagnostic?"runner":"sw_invoker");
    const b=await h.connect(root,diagnostic?"runner":"sw_invoker");
    try {
      for(const c of [a,b]) await c.query("BEGIN; SET LOCAL lock_timeout='4500ms'; SET LOCAL statement_timeout='6500ms'");
      const pid=(await b.query("SELECT pg_backend_pid() p")).rows[0].p;
      await fn(a,b,pid);
    }finally{
      for(const c of [a,b]){await c.query("ROLLBACK").catch(()=>{});await c.end();}
    }
  }
  const qty=async(s,expected)=>{assert.equal(await f.balance(admin,s.p,s.company),String(expected));await h.reconcile(admin);};
  for(const rollback of [false,true]) await check(rollback?"I35 first sale rollback unlocks competitor":"I34 competing sales commit no oversell",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,7,1]]),y=await s.make("sale",[[s.p,7,1]]);
    await pair(async(a,b,pid)=>{
      await f.post(a,x,s.key(),s.company);
      const pending=settle(f.post(b,y,s.key(),s.company));await blocked(admin,pid);
      await a.query(rollback?"ROLLBACK":"COMMIT");const result=await pending;
      assert.equal(result.ok,rollback);
      if(!rollback)assert.equal(result.code,"P0001");
      await b.query(result.ok?"COMMIT":"ROLLBACK");
    });await qty(s,3);
  });
  for(const sameOrder of [true,false]) await check(sameOrder?"I36 identical concurrent posting":"I37 operation-key collision",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,2,1]]),y=sameOrder?x:await s.make("sale",[[s.p,2,1]]),key=s.key();
    await pair(async(a,b,pid)=>{
      const first=await f.post(a,x,key,s.company),pending=settle(f.post(b,y,key,s.company));
      await blocked(admin,pid);await a.query("COMMIT");const second=await pending;
      assert.equal(second.ok,sameOrder);
      if(sameOrder)assert.equal(second.value,first);else assert.equal(second.code,"23505");
      await b.query(second.ok?"COMMIT":"ROLLBACK");
    });await qty(s,8);
    assert.equal((await admin.query("SELECT count(*)::int n FROM stockwise.audit_logs WHERE company_id=$1 AND action='order_posted' AND order_id<>$2",[s.company,s.receipt])).rows[0].n,1);
  });
  for(const identical of [true,false]) await check(identical?"I38 identical concurrent reversal":"I39 conflicting reversal keys",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,7,1]]),key=s.key();
    await f.post(admin,x,s.key(),s.company);
    await pair(async(a,b,pid)=>{
      const first=await f.reverse(a,x,key,s.company);
      const pending=settle(f.reverse(b,x,identical?key:s.key(),s.company));
      await blocked(admin,pid);await a.query("COMMIT");const second=await pending;
      assert.equal(second.ok,identical);
      if(identical)assert.equal(second.value,first);else assert.equal(second.code,"P0001");
      await b.query(second.ok?"COMMIT":"ROLLBACK");
    });await qty(s,10);
  });
  await check("I40 opposite UI product order has consistent lock order",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,2,1],[s.q,2,1]]),
      y=await s.make("sale",[[s.q,2,1],[s.p,2,1]]);
    await pair(async(a,b,pid)=>{
      await f.post(a,x,s.key(),s.company);
      const pending=settle(f.post(b,y,s.key(),s.company));await blocked(admin,pid);
      await a.query("COMMIT");assert.equal((await pending).ok,true);await b.query("COMMIT");
    });await qty(s,6);assert.equal(await f.balance(admin,s.q,s.company),"6");
  });
  for(const reversalFirst of [true,false]) await check(reversalFirst?"I41 purchase reversal wins sale race":"I42 sale wins purchase reversal race",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,7,1]]);
    await pair(async(a,b,pid)=>{
      if(reversalFirst)await f.reverse(a,s.receipt,s.key(),s.company);else await f.post(a,x,s.key(),s.company);
      const pending=settle(reversalFirst?f.post(b,x,s.key(),s.company):f.reverse(b,s.receipt,s.key(),s.company));
      await blocked(admin,pid);await a.query("COMMIT");
      assert.deepEqual(await pending,{ok:false,code:"P0001"});await b.query("ROLLBACK");
    });await qty(s,reversalFirst?0:3);
  });
  await check("I43 concurrent repeated-product lines aggregate",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,4,1],[s.p,3,1]]),y=await s.make("sale",[[s.p,4,1],[s.p,3,1]]);
    await pair(async(a,b,pid)=>{
      await f.post(a,x,s.key(),s.company);const pending=settle(f.post(b,y,s.key(),s.company));
      await blocked(admin,pid);await a.query("COMMIT");assert.deepEqual(await pending,{ok:false,code:"P0001"});
      await b.query("ROLLBACK");
    });await qty(s,3);
  });
  for(const isolation of ["REPEATABLE READ","SERIALIZABLE"]) await check(isolation==="SERIALIZABLE"?"I56 serializable conflict then insufficient-stock denial":"I44 repeatable-read conflict then insufficient-stock denial",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,7,1]]),y=await s.make("sale",[[s.p,7,1]]),key=s.key();
    await pair(async(a,b,pid)=>{
      await b.query(`ROLLBACK; BEGIN ISOLATION LEVEL ${isolation}; SET LOCAL lock_timeout='4500ms'`);
      await b.query("SELECT pg_current_snapshot()");
      await f.post(a,x,s.key(),s.company);const pending=settle(f.post(b,y,key,s.company));
      await blocked(admin,pid);await a.query("COMMIT");assert.deepEqual(await pending,{ok:false,code:"40001"});
      await b.query("ROLLBACK; BEGIN");
       // The transaction was safely aborted with 40001. A fresh transaction
       // may retry the original key; it must still fail here because only 3
       // units remain, so this is NOT a successful-retry assertion.
       await h.denied(()=>f.post(b,y,key,s.company),["P0001"]);await b.query("ROLLBACK");
    });await qty(s,3);
  });
  for(const isolation of ["REPEATABLE READ","SERIALIZABLE"]) await check(
    isolation==="SERIALIZABLE"?"I59 serializable 40001 then successful same-key whole-transaction retry":
      "I58 repeatable-read 40001 then successful same-key whole-transaction retry",async()=>{
      const s=await scope({receiptQuantity:20}),x=await s.make("sale",[[s.p,7,1]]),
        y=await s.make("sale",[[s.p,7,1]]),key=s.key();
      await pair(async(a,b,pid)=>{
        await b.query(`ROLLBACK; BEGIN ISOLATION LEVEL ${isolation}; SET LOCAL lock_timeout='4500ms'`);
        await b.query("SELECT pg_current_snapshot()");
        await f.post(a,x,s.key(),s.company);
        const pending=settle(f.post(b,y,key,s.company));
        await blocked(admin,pid);await a.query("COMMIT");
        assert.deepEqual(await pending,{ok:false,code:"40001"});
        await b.query("ROLLBACK; BEGIN");
        assert.equal(await f.post(b,y,key,s.company),y);
        await b.query("COMMIT");
      });
      await qty(s,6);
      assert.equal((await admin.query(`SELECT count(*)::int n FROM stockwise.stock_movements
        WHERE company_id=$1 AND order_id=ANY($2::uuid[])`,[s.company,[x,y]])).rows[0].n,2);
      assert.equal((await admin.query(`SELECT count(*)::int n FROM stockwise.audit_logs
        WHERE company_id=$1 AND order_id=ANY($2::uuid[]) AND action='order_posted'`,[s.company,[x,y]])).rows[0].n,2);
      await h.reconcile(admin);
    });
  for(const editFirst of [true,false]) await check(editFirst?"I54 parent-locked edit wins post race":"I55 post wins item-edit race",async()=>{
    const s=await scope(),x=await s.make("sale",[[s.p,7,1]]);
    await pair(async(a,b,pid)=>{
      if(editFirst){
        await a.query("SELECT id FROM stockwise.orders WHERE id=$1 FOR UPDATE",[x]);
        await a.query("UPDATE stockwise.order_items SET quantity=3 WHERE order_id=$1",[x]);
        const pending=settle(f.post(b,x,s.key(),s.company));await blocked(admin,pid);
        await a.query("COMMIT");assert.equal((await pending).ok,true);await b.query("COMMIT");
      }else{
        await f.post(a,x,s.key(),s.company);
        const pending=settle(b.query("UPDATE stockwise.order_items SET quantity=3 WHERE order_id=$1",[x]));
        await blocked(admin,pid);await a.query("COMMIT");assert.deepEqual(await pending,{ok:false,code:"P0001"});await b.query("ROLLBACK");
      }
    },{diagnostic:true});await qty(s,editFirst?7:3);
  });
  await check("I57 induced deadlock abort and same-key whole-transaction retry",async()=>{
    const s=await scope(),orders=[await s.make("sale",[[s.p,2,1],[s.q,2,1]]),
      await s.make("sale",[[s.q,2,1],[s.p,2,1]])],keys=[s.key(),s.key()];
    await pair(async(a,b,pid)=>{
      await a.query("SELECT product_id FROM stockwise.stock_balances WHERE company_id=$1 AND product_id=$2 FOR UPDATE",[s.company,s.p]);
      await b.query("SELECT product_id FROM stockwise.stock_balances WHERE company_id=$1 AND product_id=$2 FOR UPDATE",[s.company,s.q]);
      const pa=settle(f.post(a,orders[0],keys[0],s.company)),pb=settle(f.post(b,orders[1],keys[1],s.company));
      // Victim releases locks on statement error; survivor then completes.
      const results=await Promise.all([pa,pb]);
      assert.equal(results.filter(r=>r.ok).length,1);
      const victim=results.findIndex(r=>!r.ok);assert.equal(results[victim].code,"40P01");
      const clients=[a,b];await clients[victim].query("ROLLBACK");
      await clients[1-victim].query("COMMIT");
      await clients[victim].query("BEGIN");await f.post(clients[victim],orders[victim],keys[victim],s.company);
      await clients[victim].query("COMMIT");
    },{diagnostic:true});await qty(s,6);
  });
}
module.exports={concurrent,blocked};
