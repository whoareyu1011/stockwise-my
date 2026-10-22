// REVIEW-ONLY offline reference. Not imported by the application.
// Trusted issuer/audience/keyring come from server configuration, never a JWT.
// No network fetch, private key, production issuer or secret is included.
const crypto=require('node:crypto');
function invalid(){throw Object.assign(new Error('Unauthenticated'),{code:'AUTH_INVALID'});}
function objectPart(part){
  if(!/^[A-Za-z0-9_-]+$/.test(part))invalid();
  try{const obj=JSON.parse(Buffer.from(part,'base64url').toString('utf8'));
    if(!obj||typeof obj!=='object'||Array.isArray(obj))invalid();return obj;
  }catch{invalid();}
}
function verifyAccessToken(token,{issuer,audience,keyring,now=Math.floor(Date.now()/1000)}){
  if(typeof token!=='string'||token.length>8192)invalid();
  const parts=token.split('.');if(parts.length!==3)invalid();
  const header=objectPart(parts[0]),claims=objectPart(parts[1]);
  if(header.alg!=='ES256'||typeof header.kid!=='string'||header.jku||header.x5u
     ||header.jwk||header.crit)invalid();
  const jwk=keyring.get(header.kid);
  if(!jwk||jwk.kty!=='EC'||jwk.crv!=='P-256'||jwk.alg!=='ES256'||jwk.use!=='sig')invalid();
  if(!/^[A-Za-z0-9_-]+$/.test(parts[2]))invalid();
  let signatureOK=false;
  try{signatureOK=crypto.verify('sha256',Buffer.from(parts[0]+'.'+parts[1]),
    {key:crypto.createPublicKey({key:jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},
    Buffer.from(parts[2],'base64url'));}catch{invalid();}
  if(!signatureOK||claims.iss!==issuer||claims.role!=='authenticated'
     ||typeof claims.sub!=='string'||claims.sub.length<1||claims.sub.length>200
     ||!(claims.aud===audience||(Array.isArray(claims.aud)&&claims.aud.includes(audience)))
     ||!Number.isSafeInteger(claims.exp)||!Number.isSafeInteger(claims.iat)
     ||claims.exp<=now||claims.iat>now||claims.exp<=claims.iat
     ||claims.exp-claims.iat>3600
     ||(claims.nbf!==undefined&&(!Number.isSafeInteger(claims.nbf)||claims.nbf>now)))invalid();
  return Object.freeze({issuer:claims.iss,subject:claims.sub,expiresAt:claims.exp});
}
module.exports={verifyAccessToken};
