"use strict";
const h=require("./common.cjs"),f=require("./fixtures.cjs");
const {assert,id,transaction,savepoint,reconcile}=h;
async function cases(admin,check,root) {
  const test=(name,fn)=>check(name,()=>transaction(admin,async c=>{
    await c.query("SET LOCAL ROLE stockwise_owner"); await fn(c);
    await c.query("SET CONSTRAINTS ALL IMMEDIATE"); await reconcile(c);
  }));
  const receipt=async(c,qty=10,product=f.P)=>f.post(c,await f.draft(c,{kind:"purchase",lines:[[product,qty,4]]}));
  const sale=async(c,qty=7)=>f.draft(c,{lines:[[f.P,qty,10]]});
  const unchanged=async(c,fn,codes)=>{const before=await f.snapshot(c);await savepoint(c,fn,codes);assert.deepEqual(await f.snapshot(c),before);};
  await check("I11 ownership/RLS/14 functions/7 definers/4 deferred triggers",async()=>{
    const r=(await admin.query(`SELECT count(*)::int n,count(*) FILTER(WHERE relrowsecurity AND NOT relforcerowsecurity
      AND relowner='stockwise_owner'::regrole)::int valid FROM pg_class
      WHERE relnamespace='stockwise'::regnamespace AND relkind='r'`)).rows[0];
    assert.deepEqual(r,{n:8,valid:8});
    assert.deepEqual((await admin.query(`SELECT count(*)::int n,count(*) FILTER(WHERE prosecdef)::int d
      FROM pg_proc WHERE pronamespace='stockwise'::regnamespace`)).rows[0],{n:14,d:7});
    assert.equal((await admin.query(`SELECT count(*)::int n FROM pg_trigger WHERE tgdeferrable
      AND tgrelid IN(SELECT oid FROM pg_class WHERE relnamespace='stockwise'::regnamespace)`)).rows[0].n,4);
  });
  await test("I12 catalogue/zero balances/totals/snapshots",async c=>{
    assert.equal(await f.balance(c),"0"); await receipt(c);
    const order=await f.draft(c,{lines:[[f.P,2,10,3],[f.Q,1,20,2]]});
    await receipt(c,2,f.Q); await f.post(c,order);
    const o=(await c.query("SELECT subtotal::text s,discount_total::text d,total::text t FROM stockwise.orders WHERE id=$1",[order])).rows[0];
    assert.equal(Number(o.s),40);assert.equal(Number(o.d),5);assert.equal(Number(o.t),35);
    const line=(await c.query("SELECT sku_snapshot,unit_cost_snapshot::text c FROM stockwise.order_items WHERE order_id=$1 AND product_id=$2",[order,f.P])).rows[0];
    assert.equal(line.sku_snapshot,"P");assert.equal(Number(line.c),4);
    await c.query("UPDATE stockwise.products SET unit_cost=99 WHERE id=$1",[f.P]);
    assert.equal(Number((await c.query("SELECT unit_cost_snapshot c FROM stockwise.order_items WHERE order_id=$1 AND product_id=$2",[order,f.P])).rows[0].c),4);
  });
  for(const [ids,lines] of [
    ["I13 single-product oversell",[[f.P,11,10]]],
    ["I14 repeated-product aggregate oversell",[[f.P,6,10],[f.P,6,10]]],
    ["I15 multi-product insufficient",[[f.P,1,10],[f.Q,1,20]]],
  ]) await test(ids,async c=>{await receipt(c);const o=await f.draft(c,{lines});await unchanged(c,()=>f.post(c,o),["P0001"]);});
  await test("I16 valid repeated/multi-product sale and exact reversal",async c=>{
    await receipt(c);await receipt(c,10,f.Q);
    const o=await f.draft(c,{lines:[[f.P,2,10],[f.P,3,10],[f.Q,4,20]]});await f.post(c,o);
    assert.equal(await f.balance(c),"5");await f.reverse(c,o);
    assert.equal(await f.balance(c),"10");assert.equal(await f.balance(c,f.Q),"10");
  });
  await test("I17 post/reverse idempotency and conflicting keys/payloads",async c=>{
    await receipt(c);const o=await sale(c),key=id(9001);await f.post(c,o,key);assert.equal(await f.post(c,o,key),o);
    await unchanged(c,()=>f.post(c,o,id(9002)),["P0001"]);
    const r=await f.reverse(c,o,id(9003));assert.equal(await f.reverse(c,o,id(9003)),r);
    assert.equal(await f.post(c,o,key),o);
    await unchanged(c,()=>f.reverse(c,o,id(9003),f.A,"different"),["P0001"]);
    await unchanged(c,()=>f.reverse(c,r,id(9004)),["P0001"]);
    const pending=await sale(c);
    await unchanged(c,()=>f.reverse(c,pending),["P0001"]);
  });
  await test("I18 consumed purchase cannot reverse",async c=>{
    const p=await receipt(c);await f.post(c,await sale(c));await unchanged(c,()=>f.reverse(c,p),["P0001"]);
  });
  await test("I19 post/reverse in same transaction with final deferred checks",async c=>{
    await receipt(c);const o=await sale(c);await f.post(c,o);await f.reverse(c,o);assert.equal(await f.balance(c),"10");
  });
  await check("I20/I21 independent committed post and reversal",async()=>{
    let o;
    await transaction(admin,async c=>{await c.query("SET LOCAL ROLE stockwise_owner");await receipt(c);
      o=await sale(c);await f.post(c,o);},{commit:true});
    await transaction(admin,async c=>{await c.query("SET LOCAL ROLE stockwise_owner");await f.reverse(c,o);},{commit:true});
    await reconcile(admin);
  });
  await test("I22 opening/repeated opening/reversal history",async c=>{
    const p=id(9700);await c.query("INSERT INTO stockwise.products(id,company_id,sku,name) VALUES($1,$2,'OPEN','Opening')",[p,f.A]);
    const o=await f.draft(c,{kind:"opening_balance",lines:[[p,10,0]]});await f.post(c,o);await f.reverse(c,o);
    const again=await f.draft(c,{kind:"opening_balance",lines:[[p,1,0]]});
    await unchanged(c,()=>f.post(c,again),["P0001"]);
    const p2=id(9701);await c.query("INSERT INTO stockwise.products(id,company_id,sku,name) VALUES($1,$2,'OPEN2','Opening2')",[p2,f.A]);
    const repeated=await f.draft(c,{kind:"opening_balance",lines:[[p2,1,0],[p2,1,0]]});
    await unchanged(c,()=>f.post(c,repeated),["P0001"]);
  });
  await test("I23 posted immutability/direct balance/history",async c=>{
    const o=await receipt(c);
    for(const [sql,args] of [
      ["UPDATE stockwise.orders SET notes='bad' WHERE id=$1",[o]],
      ["DELETE FROM stockwise.orders WHERE id=$1",[o]],
      ["UPDATE stockwise.order_items SET quantity=1 WHERE order_id=$1",[o]],
      ["UPDATE stockwise.stock_balances SET quantity=quantity+1 WHERE product_id=$1",[f.P]],
      ["DELETE FROM stockwise.stock_balances WHERE product_id=$1",[f.P]],
      ["DELETE FROM stockwise.stock_movements WHERE order_id=$1",[o]],
      ["DELETE FROM stockwise.audit_logs WHERE order_id=$1",[o]],
    ]) await unchanged(c,()=>c.query(sql,args),["P0001"]);
  });
  await test("I24 incomplete posted/reversed final state rejects",async c=>{
    const o=await sale(c);
    await unchanged(c,async()=>{await c.query("UPDATE stockwise.orders SET status='posted',posting_key=$2,posted_at=clock_timestamp() WHERE id=$1",[o,id(9300)]);
      await c.query("SET CONSTRAINTS ALL IMMEDIATE");},["P0001"]);
    await receipt(c);await f.post(c,o);
    await unchanged(c,async()=>{await c.query("UPDATE stockwise.orders SET status='reversed',reversed_at=clock_timestamp() WHERE id=$1",[o]);
      await c.query("SET CONSTRAINTS ALL IMMEDIATE");},["P0001"]);
  });
  for(const [name,body] of [
    ["I25 missing posting audit","IF NEW.action='order_posted' THEN RETURN NULL; END IF;"],
    ["I26 wrong-key posting audit","IF NEW.action='order_posted' THEN NEW.details=jsonb_build_object('operation_key','wrong'); END IF;"],
    ["I48 late posting audit failure","IF NEW.action='order_posted' THEN RAISE EXCEPTION 'fixture fault'; END IF;"],
  ]) await test(name,async c=>{
    await receipt(c);const o=await sale(c);
    await c.query("SET CONSTRAINTS ALL IMMEDIATE; SET CONSTRAINTS ALL DEFERRED");
    await c.query(`CREATE FUNCTION pg_temp.audit_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN ${body} RETURN NEW; END $f$;
      CREATE TRIGGER fixture_audit BEFORE INSERT ON stockwise.audit_logs FOR EACH ROW EXECUTE FUNCTION pg_temp.audit_fault()`);
    await unchanged(c,async()=>{await f.post(c,o);await c.query("SET CONSTRAINTS ALL IMMEDIATE");},["P0001"]);
    await c.query("DROP TRIGGER fixture_audit ON stockwise.audit_logs");
    await f.post(c,o);
  });
  await check("I27 effective unprivileged caller commits deferred checks",async()=>{
    const c=await h.connect(root,"sw_invoker");
    try {const o=await transaction(admin,async a=>{await a.query("SET LOCAL ROLE stockwise_owner");return f.draft(a,{kind:"purchase",lines:[[f.P,1,4]]});},{commit:true});
      await transaction(c,()=>f.post(c,o),{commit:true});
      await h.denied(()=>c.query("SELECT * FROM stockwise.orders"),["42501"]);
    } finally {await c.end();}
  });
  await check("I28 five ordinary/API-like LOGIN sessions have no table/core access",async()=>{
    for(let n=0;n<5;n++){const c=await h.connect(root,`sw_invdeny${n}`);try{
      await h.denied(()=>c.query("SELECT * FROM stockwise.products"),["42501"]);
      await h.denied(()=>f.post(c,id(1)),["42501"]);
    }finally{await c.end();}}
  });
  await test("I29 SKU/price/cross-company constraints",async c=>{
    for(const [sql,args] of [
      ["INSERT INTO stockwise.products(company_id,sku,name) VALUES($1,'p','dup')",[f.A]],
      ["UPDATE stockwise.products SET unit_cost=-1 WHERE id=$1",[f.P]],
      ["UPDATE stockwise.orders SET contact_id=$2 WHERE id=$1",[await sale(c),f.CB]],
    ]) await unchanged(c,()=>c.query(sql,args),["23505","23514","23503"]);
    await unchanged(c,()=>f.draft(c,{lines:[[f.PB,1,1]]}),["23503"]);
  });
  await test("I30 movement sign/date/product/duplicate protections",async c=>{
    const o=await receipt(c);
    const m=(await c.query("SELECT * FROM stockwise.stock_movements WHERE order_id=$1",[o])).rows[0];
    await unchanged(c,()=>c.query(`INSERT INTO stockwise.stock_movements(company_id,order_id,order_item_id,product_id,kind,quantity_delta,effective_date)
      VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [m.company_id,m.order_id,m.order_item_id,m.product_id,m.kind,m.quantity_delta,m.effective_date]),["23505"]);
    // Each malformed case gets a NEW item, so a duplicate-index violation cannot
    // accidentally stand in for sign/date/product validation. Roll back the
    // deliberately incomplete header together with the rejected insert.
    for(const [product,delta,date] of [[f.P,-1,"2026-01-01"],[f.Q,1,"2026-01-01"],[f.P,1,"2020-01-01"]])
      await unchanged(c,async()=>{
        const order=await f.draft(c,{kind:"purchase",lines:[[f.P,1,4]]});
        const item=(await c.query("SELECT id FROM stockwise.order_items WHERE order_id=$1",[order])).rows[0].id;
        await c.query(`UPDATE stockwise.orders SET subtotal=4,status='posted',posting_key=$2,posted_at=clock_timestamp()
          WHERE id=$1`,[order,id(9800)]);
        await c.query(`INSERT INTO stockwise.stock_movements(company_id,order_id,order_item_id,product_id,kind,quantity_delta,effective_date)
          VALUES($1,$2,$3,$4,'purchase',$5,$6)`,[f.A,order,item,product,delta,date]);
      },["P0001"]);
  });
  await test("I31 bigint overflow rollback",async c=>{
    await receipt(c);
    const o=await f.draft(c,{kind:"purchase",lines:[[f.P,"9223372036854775807",0]]});
    await unchanged(c,()=>f.post(c,o),["22003"]);
  });
  await test("I32 hostile search path cannot redirect core",async c=>{
    await c.query("CREATE TEMP TABLE stock_balances(quantity bigint); SET LOCAL search_path=pg_temp,public");
    const o=await receipt(c);assert(o);await reconcile(c);
  });
  await test("I33 late reversal audit error restores complete state",async c=>{
    await receipt(c);const o=await sale(c);await f.post(c,o);
    await c.query("SET CONSTRAINTS ALL IMMEDIATE; SET CONSTRAINTS ALL DEFERRED");
    await c.query(`CREATE FUNCTION pg_temp.reversal_fault() RETURNS trigger LANGUAGE plpgsql AS $f$
      BEGIN IF NEW.action='order_reversed' THEN RAISE EXCEPTION 'fixture reversal fault'; END IF; RETURN NEW; END $f$;
      CREATE TRIGGER fixture_audit BEFORE INSERT ON stockwise.audit_logs FOR EACH ROW EXECUTE FUNCTION pg_temp.reversal_fault()`);
    await unchanged(c,()=>f.reverse(c,o,id(9400)),["P0001"]);
    await c.query("DROP TRIGGER fixture_audit ON stockwise.audit_logs");
    await f.reverse(c,o,id(9400));
  });
  await test("I45 ledger reconciliation",reconcile);
  await check("I46 restricted provisioning installation evidence",async()=>{
    const r=(await admin.query("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='sw_provisioner'")).rows[0];
    assert.deepEqual(r,{rolsuper:false,rolbypassrls:false});
  });
  await test("I47 adjustment signs/full reversal",async c=>{
    const up=await f.draft(c,{kind:"adjustment_in",lines:[[f.Q,3,0]]});await f.post(c,up);
    const down=await f.draft(c,{kind:"adjustment_out",lines:[[f.Q,2,0]]});await f.post(c,down);
    await f.reverse(c,down);await f.reverse(c,up);assert.equal(await f.balance(c,f.Q),"0");
  });
  await test("I49/I50 reversal item/contact guards",async c=>{
    await receipt(c);const o=await sale(c);await f.post(c,o);const r=await f.reverse(c,o);
    await unchanged(c,()=>c.query(`INSERT INTO stockwise.order_items(company_id,order_id,product_id,line_number,quantity,unit_price)
        VALUES($1,$2,$3,1,1,0)`,[f.A,r,f.P]),["P0001"]);
    const contact=id(9500);await c.query("INSERT INTO stockwise.contacts(id,company_id,legal_name,contact_kind) VALUES($1,$2,'Second','both')",[contact,f.A]);
    await unchanged(c,()=>c.query("UPDATE stockwise.orders SET contact_id=$2 WHERE id=$1",[r,contact]),["P0001"]);
  });
  await test("I51 truncate guards after pending events drained",async c=>{
    await c.query("SET CONSTRAINTS ALL IMMEDIATE");
    for(const table of ["stock_balances","stock_movements","audit_logs"])
      await savepoint(c,()=>c.query(`TRUNCATE stockwise.${table}`),["P0001","0A000"]);
  });
  await test("I52 invalid quantities/fractional input/discount",async c=>{
    for(const lines of [[[f.P,0,10]],[[f.P,-1,10]],[[f.P,"1.5",10]],[[f.P,1,10,11]]])
      await unchanged(c,()=>f.draft(c,{lines}),["23514","22P02"]);
  });
  for(const [name,balanceFault] of [["I53 COMMIT rejects missing audit",false],["I58 COMMIT rejects corrected owner balance corruption",true]]) {
    await check(name,async()=>{
      const before=await f.snapshot(admin);
      await admin.query("BEGIN; SET LOCAL ROLE stockwise_owner");
      try {
        if(balanceFault){
          await admin.query(`CREATE TEMP TABLE balance_fault(product_id uuid);
            CREATE FUNCTION pg_temp.balance_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $f$
              BEGIN UPDATE stockwise.stock_balances SET quantity=quantity+1 WHERE product_id=NEW.product_id;
              RETURN NEW; END $f$;
            CREATE TRIGGER nested_fault AFTER INSERT ON pg_temp.balance_fault
              FOR EACH ROW EXECUTE FUNCTION pg_temp.balance_fault_fn()`);
          await admin.query("INSERT INTO pg_temp.balance_fault VALUES($1)",[f.P]);
        }else{
          await admin.query(`CREATE FUNCTION pg_temp.skip_audit() RETURNS trigger LANGUAGE plpgsql AS $f$
            BEGIN IF NEW.action='order_posted' THEN RETURN NULL; END IF; RETURN NEW; END $f$;
            CREATE TRIGGER fixture_audit BEFORE INSERT ON stockwise.audit_logs FOR EACH ROW EXECUTE FUNCTION pg_temp.skip_audit()`);
          await receipt(admin,1);
        }
        await h.denied(()=>admin.query("COMMIT"),["P0001"]);
      }finally{await admin.query("ROLLBACK");}
      assert.deepEqual(await f.snapshot(admin),before);
    });
  }
}
module.exports={cases};
