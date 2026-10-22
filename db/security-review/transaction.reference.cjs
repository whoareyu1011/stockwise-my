// REVIEW ONLY: no routes, configuration or real pool connections.
const {verifyAccessToken}=require('./verify-jwt.reference.cjs');
async function withAuthorizedTransaction({token,jwtConfig,runtimePool,verifierPool,work}){
  // Verify before any connection acquisition. Never accept browser actor IDs.
  const principal=verifyAccessToken(token,jwtConfig);
  if(runtimePool===verifierPool)
    throw Object.assign(new Error('Distinct runtime and verifier pools required'),{code:'SECURITY_CONFIGURATION'});
  const client=await runtimePool.connect();
  let broken=false;
  try{
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    await client.query("SET LOCAL statement_timeout='10000ms'");
    await client.query("SET LOCAL lock_timeout='3000ms'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout='10000ms'");
    const target=(await client.query(`SELECT pg_backend_pid() AS pid,
      pg_current_xact_id()::text AS xid`)).rows[0];
    // Dedicated verifier pool uses autocommit: proof must be committed BEFORE
    // the runtime's next READ COMMITTED statement. Never share these pools.
    const proof=(await verifierPool.query(`SELECT stockwise_auth.issue_context($1,$2,$3,$4::xid8,$5) AS proof`,
      [principal.issuer,principal.subject,target.pid,target.xid,new Date(principal.expiresAt*1000)])).rows[0].proof;
    await client.query('SELECT stockwise_auth.activate_context($1)',[proof]);
    const value=await work(client);
    await client.query('COMMIT');return value;
  }catch(error){
    try{await client.query('ROLLBACK');}catch{broken=true;}
    throw error;
  }finally{
    // Correctness does not depend on RESET reaching the same transaction-pool
    // backend: proofs are bound to pid + full xid, and activation is SET LOCAL.
    if(!broken)try{await client.query('RESET stockwise.request_proof');}catch{broken=true;}
    client.release(broken);
  }
}
module.exports={withAuthorizedTransaction};
