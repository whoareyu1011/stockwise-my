"use strict";
// All IDs/records below are deliberately synthetic; never load browser data.
const {id}=require("./common.cjs");
const A=id(1),B=id(2),P=id(11),Q=id(12),PB=id(13),C=id(21),CB=id(22);
const issuer="https://phase2-auth.invalid/auth/v1";
const people={Owner:id(101),Admin:id(102),Staff:id(103),OtherStaff:id(104),Viewer:id(105),
  OtherCompany:id(106),MultiCompany:id(107),Pending:id(108),DisabledMember:id(109)};
const session=name=>id(1000+Number(people[name].slice(-4)));
const memberships={
  Owner:[[A,"Owner",true]], Admin:[[A,"Admin",true]], Staff:[[A,"Staff",true]],
  OtherStaff:[[A,"Staff",true]], Viewer:[[A,"Viewer",true]],
  OtherCompany:[[B,"Owner",true]],
  MultiCompany:[[A,"Staff",true],[B,"Viewer",true]],
  Pending:[[A,"Staff",false]],
  DisabledMember:[[A,"Staff",false]],
};
async function seedCore(c) {
  await c.query("SET ROLE stockwise_owner");
  await c.query(`INSERT INTO stockwise.companies(id,legal_name) VALUES($1,'Fixture A'),($2,'Fixture B')`,[A,B]);
  await c.query(`INSERT INTO stockwise.products(id,company_id,sku,name,unit_cost,selling_price) VALUES
    ($1,$2,'P','Fixture P',4,10),($3,$2,'Q','Fixture Q',7,20),($4,$5,'P','Fixture B product',8,30)`,[P,A,Q,PB,B]);
  await c.query(`INSERT INTO stockwise.contacts(id,company_id,legal_name,contact_kind) VALUES
    ($1,$2,'Fixture Contact A','both'),($3,$4,'Fixture Contact B','both')`,[C,A,CB,B]);
  await c.query("RESET ROLE");
}
async function seedSecurity(c) {
  await c.query(`INSERT INTO sw2_auth.companies VALUES($1,true),($2,true)`,[A,B]);
  for(const [name,identity] of Object.entries(people)) {
    const active=name!=="Pending";
    await c.query("INSERT INTO sw2_auth.identities VALUES($1,$2,$3,$4)",[identity,issuer,identity,active]);
    for(const [company,role,membershipActive] of memberships[name])
      await c.query("INSERT INTO sw2_auth.memberships VALUES($1,$2,$3,$4)",
        [company,identity,role,membershipActive]);
    await c.query(`INSERT INTO sw2_auth.sessions VALUES($1,$2,clock_timestamp()+interval '1 hour',
      false,'synthetic-fixture-only',clock_timestamp())`,[session(name),identity]);
  }
}
async function refresh(c,name) {
  // Trusted fixture upkeep only; NOT a provider-session verification implementation.
  await c.query("UPDATE sw2_auth.sessions SET checked_at=clock_timestamp() WHERE session_id=$1",[session(name)]);
}
async function draft(c,{company=A,contact=C,kind="sale",lines=[[P,1,10,0]],reference}={}) {
  const order=id(cryptoCounter++);
  await c.query(`INSERT INTO stockwise.orders(id,company_id,contact_id,reference,kind,business_date)
    VALUES($1,$2,$3,$4,$5,'2026-01-01')`,[order,company,["sale","purchase"].includes(kind)?contact:null,reference||`F-${order}`,kind]);
  for(let n=0;n<lines.length;n++) {
    const [product,quantity,price=10,discount=0]=lines[n];
    await c.query(`INSERT INTO stockwise.order_items(company_id,order_id,product_id,line_number,quantity,unit_price,discount)
      VALUES($1,$2,$3,$4,$5,$6,$7)`,[company,order,product,n+1,quantity,price,discount]);
  }
  return order;
}
let cryptoCounter=2000;
async function post(c,order,key=id(cryptoCounter++),company=A) {
  return (await c.query("SELECT stockwise.post_order($1,$2,$3) id",[company,order,key])).rows[0].id;
}
async function reverse(c,order,key=id(cryptoCounter++),company=A,reason="fixture reversal") {
  return (await c.query("SELECT stockwise.reverse_order($1,$2,$3,'2026-01-02',$4) id",[company,order,key,reason])).rows[0].id;
}
async function balance(c,product=P,company=A) {
  return (await c.query("SELECT quantity::text q FROM stockwise.stock_balances WHERE company_id=$1 AND product_id=$2",[company,product])).rows[0].q;
}
async function snapshot(c) {
  const result={};
  for(const table of ["orders","order_items","stock_movements","stock_balances","audit_logs"])
    result[table]=(await c.query(`SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) j FROM stockwise.${table} t`)).rows[0].j;
  return result;
}
module.exports={A,B,P,Q,PB,C,CB,people,issuer,session,seedCore,seedSecurity,refresh,draft,post,reverse,balance,snapshot};
