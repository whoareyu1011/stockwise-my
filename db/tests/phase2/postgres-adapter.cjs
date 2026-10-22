"use strict";
// TEST ONLY. No automatic startup and no administrative credential fallback.
const { gate, Pool, settings } = require("./common.cjs");
function createPostgresAdapters(root) {
  gate(root,"phase2");
  const runtimePool=new Pool({...settings(root,"sw2_business"),max:1});
  const verifierPool=new Pool({...settings(root,"sw2_issuer"),max:2});
  const one=async(c,sql,args)=>(await c.query(sql,args)).rows[0]?.value;
  const adapter={
    async beginReadCommitted(c) {
      await c.query(`BEGIN ISOLATION LEVEL READ COMMITTED;
        SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='1500ms';
        SET LOCAL idle_in_transaction_session_timeout='10000ms'`);
    },
    async transactionIdentity(c) {
      return (await c.query("SELECT pg_backend_pid() AS pid,pg_current_xact_id()::text AS xid")).rows[0];
    },
    async issueProof(c,p) {
      return one(c,"SELECT sw2_auth.issue($1,$2,$3,$4,$5::xid8,to_timestamp($6)) AS value",
        [p.issuer,p.subject,p.sessionId,p.pid,p.xid,p.expiresAt]);
    },
    async activateProof(c,proof) {await c.query("SELECT sw2_auth.activate($1)",[proof]);},
    async authorizeInDatabase(c,ctx) {
      return one(c,"SELECT sw2_api.authorize($1,$2,$3,$4,$5,$6) AS value",
        [ctx.companyId,ctx.action,ctx.resourceId,ctx.orderKind,ctx.targetIdentityId,ctx.requestedRole]);
    },
    async commit(c) {await c.query("COMMIT");},
    async rollback(c) {await c.query("ROLLBACK");},
    async reset(c) {await c.query("RESET sw2.proof");},
  };
  function repositoryFactory(c) {
    return {
      async findCurrentMembership({issuer,subject,companyId}) {
        const value=await one(c,"SELECT sw2_api.membership($1) AS value",[companyId]);
        return value?.issuer===issuer && value?.subject===subject ? value : null;
      },
      async findOrder({companyId,orderId}) {
        return one(c,"SELECT sw2_api.resource($1,$2) AS value",[companyId,orderId]);
      },
      async findTargetMembership({companyId,identityId}) {
        return one(c,"SELECT sw2_api.target_member($1,$2) AS value",[companyId,identityId]);
      },
    };
  }
  return {runtimePool,verifierPool,adapter,repositoryFactory,
    async lookupSession(p) {
      return one(verifierPool,"SELECT sw2_auth.session_status($1,$2,$3) AS value",
        [p.issuer,p.subject,p.sessionId]);
    },
    async end() {await Promise.all([runtimePool.end(),verifierPool.end()]);},
  };
}
module.exports={createPostgresAdapters};
