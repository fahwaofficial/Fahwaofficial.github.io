// IFZI production API: secure TON Proof sessions, mining rewards, pool accounting and admin registry.
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Address, Cell, contractAddress, loadStateInit } from '@ton/core';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';

type Bindings = {
  DB: D1Database; SITE_ORIGIN: string; SITE_DOMAIN: string; JWT_SECRET: string;
  ADMIN_SECRET: string; TELEGRAM_BOT_TOKEN?: string; JETTON_MASTER: string; JETTON_DECIMALS: string;
  MINING_POOL_IFZI: string; MIN_WITHDRAW_IFZI: string; TONAPI_BASE: string;
  TON_BOOST_RECEIVER: string; TON_BOOST_AMOUNT_NANO: string; TON_BOOST_REWARD_IFZI?: string;
  TASK_REWARD_IFZI: string; DAILY_CHECKIN_REWARD_IFZI: string;
  PRESALE_TREASURY: string; RESEND_API_KEY: string; PRESALE_NOTIFY_EMAIL: string; PRESALE_FROM_EMAIL: string;
};
type User = { id:string; wallet_raw:string; wallet_status:string; network:string; referred_by:string|null };
const app = new Hono<{Bindings:Bindings}>();
const DAY = 86400;
const DECIMALS = 9;
const UNIT = 10n ** 9n;
const MAX_PROOF_AGE = 600;
const levels = [
  [0n,100n],[10_000n,120n],[25_000n,140n],[50_000n,160n],[100_000n,180n],
  [200_000n,200n],[350_000n,220n],[500_000n,240n],[750_000n,260n],
  [1_000_000n,280n],[2_000_000n,300n]
] as const;

app.use('*', cors({
  origin: (origin) => ['https://fahwaofficial.github.io','http://localhost:3000'].includes(origin) ? origin : null,
  allowMethods:['GET','POST','OPTIONS'],
  allowHeaders:['Content-Type','Authorization','x-admin-secret'],
  maxAge:86400
}));
app.get('/health', c => c.json({ok:true, service:'ifzi-mining-api', ts:Date.now()}));
app.get('/health/ready',async c=>{
  try{
    await c.env.DB.prepare('SELECT total_raw,distributed_raw,reserved_raw FROM pool_state WHERE id=1').first();
    await c.env.DB.prepare('SELECT referral_code FROM auth_challenges LIMIT 1').all();
    await c.env.DB.prepare('SELECT wallet_status,network,referral_code FROM users LIMIT 1').all();
    const jwtSecretConfigured=!!c.env.JWT_SECRET&&c.env.JWT_SECRET.length>=32;
    const adminSecretConfigured=!!c.env.ADMIN_SECRET&&c.env.ADMIN_SECRET.length>=32;
    const ready=jwtSecretConfigured&&adminSecretConfigured;
    return c.json({ok:ready,service:'ifzi-mining-api',database:true,migrations:'ready',jwt_secret_configured:jwtSecretConfigured,admin_secret_configured:adminSecretConfigured,ts:Date.now()},ready?200:503);
  }catch(e){
    return c.json({ok:false,service:'ifzi-mining-api',database:false,error:e instanceof Error?e.message:'D1 readiness check failed',ts:Date.now()},503);
  }
});

function jsonError(c:any, message:string, status=400) { return c.json({error:message},status); }
function b64url(data:Uint8Array|string) {
  const bytes=typeof data==='string'?new TextEncoder().encode(data):data;
  let binary=''; for(const b of bytes) binary+=String.fromCharCode(b);
  return btoa(binary).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function fromB64(value:string):Uint8Array {
  const raw=atob(value); return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function concat(...parts:Uint8Array[]) {
  const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0)); let off=0;
  for(const p of parts){out.set(p,off);off+=p.length;} return out;
}
function u32le(n:number){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;}
function u64le(n:bigint){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;}
function u32be(n:number){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,false);return b;}
function u64be(n:bigint){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,false);return b;}
function bytesHex(s:string){if(!/^[0-9a-f]{64}$/i.test(s))throw new Error('Invalid public key');return Uint8Array.from(s.match(/../g)!,x=>parseInt(x,16));}
function rawAddress(input:string){return Address.parse(input).toRawString();}
function parseAmount(value:unknown):bigint {
  if(typeof value!=='string' && typeof value!=='number') throw new Error('amount must be a decimal number');
  const s=String(value).trim();
  if(!/^\d{1,12}(\.\d{1,9})?$/.test(s)) throw new Error('invalid IFZI amount');
  const [whole,frac='']=s.split('.');
  return BigInt(whole)*UNIT+BigInt((frac+'000000000').slice(0,9));
}
function fmt(raw:string|bigint){const n=BigInt(raw);return (Number(n)/1e9).toLocaleString('en-US',{maximumFractionDigits:9});}
function nowSec(){return Math.floor(Date.now()/1000);}
app.post('/api/session/refresh',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Session expired; secure wallet login is required',401);
  return c.json({ok:true,token:await issueJWT(c.env,user),expires_in:30*DAY});
});
async function getUser(c:any):Promise<User|null>{
  const h=c.req.header('Authorization'); if(!h?.startsWith('Bearer '))return null;
  const p=await verifyJWT(c.env,h.slice(7)); if(!p)return null;
  return await c.env.DB.prepare('SELECT id,wallet_raw,wallet_status,network,referred_by FROM users WHERE id=?').bind(p.sub).first() as User|null;
}
async function issueJWT(env:Bindings,user:User){
  if(!env.JWT_SECRET || env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be configured as a strong Cloudflare secret (at least 32 characters)');
  const head=b64url(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const body=b64url(JSON.stringify({sub:user.id,wallet:user.wallet_raw,iat:nowSec(),exp:nowSec()+30*DAY}));
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.JWT_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(head+'.'+body)));
  return head+'.'+body+'.'+b64url(sig);
}
async function verifyJWT(env:Bindings,token:string):Promise<{sub:string;wallet:string}|null>{
  try{
    if(!env.JWT_SECRET||token.length>4096)return null;
    const parts=token.split('.');if(parts.length!==3)return null;
    const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.JWT_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
    const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(parts[0]+'.'+parts[1])));
    if(b64url(sig)!==parts[2])return null;
    const p=JSON.parse(new TextDecoder().decode(fromB64(parts[1])));
    if(!p.sub||!p.wallet||p.exp<nowSec())return null;
    return {sub:p.sub,wallet:p.wallet};
  }catch{return null;}
}
async function getVerifiedIfziBalanceRaw(env:Bindings,walletRaw:string):Promise<bigint>{
  const master=Address.parse(env.JETTON_MASTER).toString({urlSafe:true,bounceable:true,testOnly:false});
  const wallet=Address.parse(walletRaw).toString({urlSafe:true,bounceable:true,testOnly:false});
  const base=(env.TONAPI_BASE||'https://tonapi.io').replace(/\/$/,'');
  const response=await fetch(base+'/v2/accounts/'+encodeURIComponent(wallet)+'/jettons/'+encodeURIComponent(master),{signal:AbortSignal.timeout(8000)});
  if(response.status===404)return 0n;
  if(!response.ok)throw new Error('Unable to verify IFZI balance from TON mainnet (HTTP '+response.status+')');
  const data=await response.json() as any;
  if(!data||data.jetton?.address===undefined)throw new Error('IFZI jetton balance response is incomplete');
  return BigInt(data.balance||'0');
}
// Public-key layouts are enabled only for exact code hashes of standard TON wallets.
const WALLET_CODE_LAYOUTS:Record<string,(slice:any)=>Uint8Array>={
  'a0cfc2c48aee16a271f2cfc0b7382d81756cecb1017d077faaab3bb602f6868c':s=>{s.loadUint(32);return s.loadBuffer(32)}, // v1r1
  'd4902fcc9fad74698fa8e353220a68da0dcf72e32bcb2eb9ee04217c17d3062c':s=>{s.loadUint(32);return s.loadBuffer(32)}, // v1r2
  '587cc789eff1c84f46ec3797e45fc809a14ff5ae24f1e0c7a6a99cc9dc9061ff':s=>{s.loadUint(32);return s.loadBuffer(32)}, // v1r3
  '5c9a5e68c108e18721a07c42f9956bfb39ad77ec6d624b60c576ec88eee65329':s=>{s.loadUint(32);return s.loadBuffer(32)}, // v2r1
  'fe9530d3243853083ef2ef0b4c2908c0abf6fa1c31ea243aacaa5bf8c7d753f1':s=>{s.loadUint(32);return s.loadBuffer(32)}, // v2r2
  'b61041a58a7980b946e8fb9e198e3c904d24799ffa36574ea4251c41a566f581':s=>{s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}, // v3r1
  '84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599':s=>{s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}, // v3r2
  'feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0':s=>{s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}, // v4r2
  '20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f':s=>{s.loadBoolean();s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)} // v5r1
};
function extractWalletKey(stateInit:any):Uint8Array|null {
  if(!stateInit.code||!stateInit.data)return null;
  const layout=WALLET_CODE_LAYOUTS[stateInit.code.hash().toString('hex')];
  if(!layout)return null;
  try{return new Uint8Array(layout(stateInit.data.beginParse()))}catch{return null;}
}
function verifyTonProof(address:string,network:string,stateInitB64:string,proof:any,expectedDomain:string,expectedPayload:string,reportedPublicKey?:string){
  if(network!=='-239')throw new Error('Only TON mainnet wallets are accepted');
  if(!proof||typeof proof.signature!=='string'||typeof proof.payload!=='string')throw new Error('TON Proof is incomplete');
  const ts=Number(proof.timestamp);if(!Number.isInteger(ts)||Math.abs(nowSec()-ts)>MAX_PROOF_AGE)throw new Error('TON Proof timestamp expired');
  const domain=proof.domain?.value;
  const domainBytes=new TextEncoder().encode(String(domain||''));
  if(domain!==expectedDomain||proof.domain?.lengthBytes!==domainBytes.length)throw new Error('TON Proof domain mismatch');
  if(proof.payload!==expectedPayload)throw new Error('TON Proof challenge mismatch');
  const addr=Address.parse(address);
  const state=loadStateInit(Cell.fromBase64(stateInitB64).beginParse());
  if(!contractAddress(addr.workChain,state).equals(addr))throw new Error('Wallet StateInit does not match address');
  const publicKey=extractWalletKey(state);
  if(!publicKey||publicKey.length!==32)throw new Error('Unsupported wallet contract. This wallet version is not yet approved for secure login.');
  if(reportedPublicKey && !bytesHex(reportedPublicKey).every((b,i)=>b===publicKey[i]))throw new Error('Wallet public key mismatch');
  const wc=new Uint8Array(4);new DataView(wc.buffer).setInt32(0,addr.workChain,false);
  const domainLen=u32le(domainBytes.length);
  const message=concat(new TextEncoder().encode('ton-proof-item-v2/'),wc,new Uint8Array(addr.hash),domainLen,domainBytes,u64le(BigInt(ts)),new TextEncoder().encode(proof.payload));
  const digest=sha256(concat(new Uint8Array([255,255]),new TextEncoder().encode('ton-connect'),sha256(message)));
  const sig=fromB64(proof.signature);
  if(sig.length!==64||!ed25519.verify(sig,digest,publicKey))throw new Error('TON Proof signature invalid');
}


async function validateTelegramInitData(raw:string,botToken:string):Promise<string>{
  if(!raw||raw.length>8192)throw new Error('Telegram Mini App initData is missing or too large');
  const params=new URLSearchParams(raw),hash=params.get('hash');
  if(!hash||!/^[0-9a-f]{64}$/i.test(hash))throw new Error('Telegram initData signature is missing');
  const authDate=Number(params.get('auth_date'));
  if(!Number.isInteger(authDate)||Math.abs(nowSec()-authDate)>3600)throw new Error('Telegram login expired. Reopen IFZI from Telegram.');
  const userText=params.get('user');if(!userText)throw new Error('Telegram user identity is missing');
  let tgUser:any;try{tgUser=JSON.parse(userText)}catch{throw new Error('Telegram user identity is invalid');}
  const telegramId=String(tgUser?.id??'');
  if(!/^[0-9]{5,20}$/.test(telegramId))throw new Error('Telegram numeric user ID is invalid');
  const checkString=[...params.entries()].filter(([key])=>key!=='hash').sort(([a],[b])=>a.localeCompare(b)).map(([key,value])=>key+'='+value).join(String.fromCharCode(10));
  const encoder=new TextEncoder();
  const secretKey=await crypto.subtle.importKey('raw',encoder.encode('WebAppData'),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const secret=new Uint8Array(await crypto.subtle.sign('HMAC',secretKey,encoder.encode(botToken)));
  const dataKey=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const expected=new Uint8Array(await crypto.subtle.sign('HMAC',dataKey,encoder.encode(checkString)));
  const actual=Uint8Array.from(hash.match(/../g)!,x=>parseInt(x,16));
  if(actual.length!==expected.length||!actual.every((byte,i)=>byte===expected[i]))throw new Error('Telegram initData signature is invalid');
  return telegramId;
}
app.post('/api/ton-proof/payload',async c=>{
  const body=await c.req.json().catch(()=>({}));
  const nonce=crypto.randomUUID();
  const referralCode=typeof body.referralCode==='string'&&/^[A-Z0-9]{5,20}$/.test(body.referralCode.toUpperCase())?body.referralCode.toUpperCase():null;
  let telegramId:string|null=null;
  if(typeof body.telegramInitData==='string'&&body.telegramInitData&&c.env.TELEGRAM_BOT_TOKEN){
    try{telegramId=await validateTelegramInitData(body.telegramInitData,c.env.TELEGRAM_BOT_TOKEN)}catch(e){return jsonError(c,e instanceof Error?e.message:'Telegram identity verification failed',401)}
  }
  await c.env.DB.prepare('INSERT INTO auth_challenges(nonce,wallet_raw,expires_at,used,referral_code,telegram_id) VALUES(?,NULL,?,0,?,?)').bind(nonce,Date.now()+5*60*1000,referralCode,telegramId).run();
  return c.json({payload:nonce});
});
app.post('/api/ton-proof/verify',async c=>{
  const body=await c.req.json().catch(()=>({}));
  let wallet:string;try{wallet=rawAddress(body.address)}catch{return jsonError(c,'Invalid wallet address');}
  const challenge=await c.env.DB.prepare('SELECT nonce,referral_code,telegram_id FROM auth_challenges WHERE nonce=? AND (wallet_raw IS NULL OR wallet_raw=?) AND used=0 AND expires_at>?').bind(body.proof?.payload,wallet,Date.now()).first() as {nonce:string;referral_code:string|null;telegram_id:string|null}|null;
  if(!challenge)return jsonError(c,'Challenge invalid, expired, or already used',401);
  try{verifyTonProof(wallet,String(body.network),body.walletStateInit||body.proof?.state_init,body.proof,c.env.SITE_DOMAIN,challenge.nonce,body.publicKey||body.public_key);}
  catch(e){return jsonError(c,e instanceof Error?e.message:'Proof verification failed',401);}
  const used=await c.env.DB.prepare('UPDATE auth_challenges SET used=1,wallet_raw=? WHERE nonce=? AND (wallet_raw IS NULL OR wallet_raw=?) AND used=0 AND expires_at>?').bind(wallet,challenge.nonce,wallet,Date.now()).run();
  if(used.meta.changes!==1)return jsonError(c,'Challenge already consumed',409);
  let user=await c.env.DB.prepare('SELECT id,wallet_raw,wallet_status,network,referred_by FROM users WHERE wallet_raw=?').bind(wallet).first() as User|null;
  if(!user){
    const id=crypto.randomUUID();
    if(challenge.telegram_id){
      const linkedTelegram=await c.env.DB.prepare('SELECT id FROM users WHERE telegram_id=?').bind(challenge.telegram_id).first() as any;
      if(linkedTelegram)return jsonError(c,'This Telegram account is already linked to another IFZI wallet.',409);
    }
    const referral=challenge.referral_code?await c.env.DB.prepare('SELECT id FROM users WHERE referral_code=? OR telegram_id=?').bind(challenge.referral_code,challenge.referral_code).first() as any:null;
    const newCode=crypto.randomUUID().replace(/-/g,'').slice(0,12).toUpperCase();
    // A valid TON Proof is the wallet-ownership approval for public mining.
    await c.env.DB.prepare("INSERT INTO users(id,wallet_raw,referred_by,created_at,network,wallet_status,wallet_verified_at,updated_at,referral_code,telegram_id) VALUES(?,?,?,?,'-239','approved',?,?,?,?)").bind(id,wallet,referral?.id||null,nowSec(),nowSec(),nowSec(),challenge.telegram_id||newCode,challenge.telegram_id).run();
    await c.env.DB.prepare("INSERT OR IGNORE INTO reward_balances(user_id,available_raw,total_earned_raw,total_referral_raw) VALUES(?,'0','0','0')").bind(id).run();
    user={id,wallet_raw:wallet,wallet_status:'approved',network:'-239',referred_by:referral?.id||null};
  }else{
    if(user.wallet_status==='suspended'||user.wallet_status==='under_review')return jsonError(c,'This wallet is restricted and requires administrator review.',403);
    if(challenge.telegram_id){
      const linked=await c.env.DB.prepare('SELECT telegram_id FROM users WHERE id=?').bind(user.id).first() as any;
      if(linked?.telegram_id&&String(linked.telegram_id)!==challenge.telegram_id)return jsonError(c,'This Telegram account is already linked to a different identity.',409);
      await c.env.DB.prepare('UPDATE users SET telegram_id=COALESCE(telegram_id,?),updated_at=? WHERE id=?').bind(challenge.telegram_id,nowSec(),user.id).run();
    }
    await c.env.DB.prepare("UPDATE users SET network='-239',wallet_status=CASE WHEN wallet_status='pending' THEN 'approved' ELSE wallet_status END,wallet_verified_at=COALESCE(wallet_verified_at,?),updated_at=? WHERE id=? AND wallet_status IN ('pending','approved')").bind(nowSec(),nowSec(),user.id).run();
    user=await c.env.DB.prepare('SELECT id,wallet_raw,wallet_status,network,referred_by FROM users WHERE id=?').bind(user.id).first() as User|null;
    if(!user||user.wallet_status!=='approved')return jsonError(c,'Wallet approval could not be completed. Please retry or contact support.',403);
  }
  return c.json({ok:true,token:await issueJWT(c.env,user),wallet_status:user.wallet_status});
});
app.get('/api/user',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  const bal=await c.env.DB.prepare('SELECT available_raw,total_earned_raw,total_referral_raw FROM reward_balances WHERE user_id=?').bind(user.id).first() as any;
  const totals=await c.env.DB.prepare("SELECT COALESCE(SUM(CAST(gross_raw AS INTEGER)),0) AS gross FROM claims WHERE user_id=?").bind(user.id).first() as any;
  const profile=await c.env.DB.prepare('SELECT referral_code,telegram_id FROM users WHERE id=?').bind(user.id).first() as any;
  return c.json({address:user.wallet_raw,wallet_status:user.wallet_status,referral_code:profile?.telegram_id||profile?.referral_code||null,telegram_id:profile?.telegram_id||null,mining_rewards:fmt(totals?.gross||'0'),available_rewards:fmt(bal?.available_raw||'0'),available_raw:bal?.available_raw||'0',lifetime_mined:fmt(bal?.total_earned_raw||'0'),referral_rewards:fmt(bal?.total_referral_raw||'0')});
});
app.get('/api/mining/status',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  const cycle=await c.env.DB.prepare("SELECT id,level,daily_rate_raw,gross_reward_raw,started_at,ends_at,status FROM mining_cycles WHERE user_id=? AND status IN ('running','completed') ORDER BY started_at DESC LIMIT 1").bind(user.id).first() as any;
  if(!cycle)return c.json({status:'idle'});
  return c.json({status:cycle.ends_at<=nowSec()?'ready':'active',ends_at:cycle.ends_at*1000,level:cycle.level,reward:fmt(cycle.gross_reward_raw),daily_rate:fmt(cycle.daily_rate_raw)});
});
app.post('/api/mining/start',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet is awaiting manual admin approval.',403);
  const existing=await c.env.DB.prepare("SELECT id FROM mining_cycles WHERE user_id=? AND status IN ('running','completed') LIMIT 1").bind(user.id).first();
  if(existing)return jsonError(c,'You already have an unclaimed mining cycle.',409);
  let balanceRaw:bigint;try{balanceRaw=await getVerifiedIfziBalanceRaw(c.env,user.wallet_raw)}catch(e){return jsonError(c,e instanceof Error?e.message:'Could not verify IFZI balance',503);}
  const wholeBalance=balanceRaw/UNIT;
  let level=1,baseRateTokens=100n;for(let i=0;i<levels.length;i++){if(wholeBalance>=levels[i][0]){level=i+1;baseRateTokens=levels[i][1]}}
  const holdingEligible=balanceRaw>=10_000n*UNIT;
  const holdingBonusPercent=holdingEligible?(level<=5?50n:25n):0n;
  const rate=baseRateTokens*UNIT*(100n+holdingBonusPercent)/100n,reward=rate,started=nowSec(),ends=started+DAY,id=crypto.randomUUID();
  const insert=await c.env.DB.prepare("INSERT INTO mining_cycles(id,user_id,level,daily_rate_raw,gross_reward_raw,started_at,ends_at,status) VALUES(?,?,?,?,?,?,?,'running')").bind(id,user.id,level,rate.toString(),reward.toString(),started,ends).run();
  if(insert.meta.changes!==1)return jsonError(c,'Could not start mining cycle',500);
  return c.json({ok:true,cycle_id:id,ends_at:ends*1000,reward:fmt(reward),level,daily_rate:fmt(rate),base_daily_rate:fmt(baseRateTokens*UNIT),holding_bonus_percent:Number(holdingBonusPercent),verified_balance:fmt(balanceRaw)});
});
app.post('/api/mining/claim',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet is not approved.',403);
  const cycle=await c.env.DB.prepare("SELECT * FROM mining_cycles WHERE user_id=? AND status='running' ORDER BY started_at DESC LIMIT 1").bind(user.id).first() as any;
  if(!cycle)return jsonError(c,'No claimable mining cycle',404);
  const now=nowSec();if(cycle.ends_at>now)return jsonError(c,'Mining cycle is not complete yet',400);
  const gross=BigInt(cycle.gross_reward_raw), referral=user.referred_by?gross/10n:0n, own=gross-referral;
  const distributed=own+referral;
  const pool=await c.env.DB.prepare('SELECT total_raw,distributed_raw,reserved_raw FROM pool_state WHERE id=1').first() as any;
  if(!pool)return jsonError(c,'Mining pool is not initialized',503);
  if(distributed>BigInt(pool.total_raw)-BigInt(pool.distributed_raw)-BigInt(pool.reserved_raw))return jsonError(c,'Mining pool allocation exhausted',409);
  const statements=[
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(total_raw AS INTEGER)-CAST(distributed_raw AS INTEGER)-CAST(reserved_raw AS INTEGER)>=? AND EXISTS(SELECT 1 FROM mining_cycles WHERE id=? AND status='running' AND ends_at<=?)").bind(distributed.toString(),distributed.toString(),cycle.id,now),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'mining_claim',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),user.id,distributed.toString(),cycle.id,now),
    c.env.DB.prepare("UPDATE mining_cycles SET status='claimed' WHERE id=? AND status='running' AND ends_at<=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='mining_claim' AND reference_id=?)").bind(cycle.id,now,cycle.id),
    c.env.DB.prepare("INSERT INTO claims(cycle_id,user_id,gross_raw,user_raw,referral_raw,referral_user_id,created_at) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='mining_claim' AND reference_id=?)").bind(cycle.id,user.id,gross.toString(),own.toString(),referral.toString(),user.referred_by,now,cycle.id),
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='mining_claim' AND reference_id=?)").bind(own.toString(),own.toString(),user.id,cycle.id)
  ];
  if(user.referred_by){
    statements.push(c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'referral',?,?,?,? WHERE EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='mining_claim' AND reference_id=?)").bind(crypto.randomUUID(),user.referred_by,referral.toString(),cycle.id,now,cycle.id));
    statements.push(c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+?,total_referral_raw=CAST(total_referral_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='referral' AND reference_id=?)").bind(referral.toString(),referral.toString(),referral.toString(),user.referred_by,cycle.id));
  }
  const results=await c.env.DB.batch(statements);
  if(results[0]?.meta?.changes!==1 || results[1]?.meta?.changes!==1)return jsonError(c,'Cycle already claimed or mining pool allocation exhausted',409);
  return c.json({ok:true,reward:fmt(own),gross_reward:fmt(gross),referral_reward:fmt(referral)});
});
app.post('/api/withdrawals/request',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet is not approved.',403);
  const completedTask=await c.env.DB.prepare("SELECT id FROM task_submissions WHERE user_id=? AND status='approved' LIMIT 1").bind(user.id).first();
  if(!completedTask)return jsonError(c,'Complete at least one approved social task before requesting a withdrawal.',403);
  const body=await c.req.json().catch(()=>({}));
  let amount:bigint;try{amount=parseAmount(body.amount)}catch(e){return jsonError(c,e instanceof Error?e.message:'Invalid amount');}
  const min=BigInt(c.env.MIN_WITHDRAW_IFZI||'1000')*UNIT;
  if(amount<min)return jsonError(c,'Minimum withdrawal is '+(c.env.MIN_WITHDRAW_IFZI||'1000')+' IFZI');
  const pending=await c.env.DB.prepare("SELECT id FROM withdrawals WHERE user_id=? AND status IN ('pending','approved') LIMIT 1").bind(user.id).first();
  if(pending)return jsonError(c,'You already have a withdrawal awaiting admin review.',409);
  const id=crypto.randomUUID(),now=nowSec();
  const balance=await c.env.DB.prepare('SELECT available_raw FROM reward_balances WHERE user_id=?').bind(user.id).first() as any;
  if(!balance||BigInt(balance.available_raw)<amount)return jsonError(c,'Insufficient available IFZI balance',409);
  const results=await c.env.DB.batch([
    c.env.DB.prepare("INSERT INTO withdrawals(id,user_id,wallet_raw,amount_raw,status,created_at,updated_at) SELECT ?,?,?,?,'pending',?,? WHERE EXISTS (SELECT 1 FROM reward_balances WHERE user_id=? AND CAST(available_raw AS INTEGER)>=?) AND NOT EXISTS (SELECT 1 FROM withdrawals WHERE user_id=? AND status IN ('pending','approved'))").bind(id,user.id,user.wallet_raw,amount.toString(),now,now,user.id,amount.toString(),user.id),
    c.env.DB.prepare('UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)-? WHERE user_id=? AND CAST(available_raw AS INTEGER)>=? AND EXISTS(SELECT 1 FROM withdrawals WHERE id=?)').bind(amount.toString(),user.id,amount.toString(),id)
  ]);
  if(results[0]?.meta?.changes!==1 || results[1]?.meta?.changes!==1)return jsonError(c,'Insufficient balance or balance changed; refresh and try again',409);
  return c.json({ok:true,id,amount:fmt(amount),status:'pending'});
});

app.get('/api/withdrawals/history',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  const rows=await c.env.DB.prepare('SELECT id,amount_raw,status,tx_hash,created_at,updated_at FROM withdrawals WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(user.id).all();
  return c.json({items:(rows.results||[]).map((x:any)=>({...x,amount:fmt(x.amount_raw)}))});
});
async function requireAdmin(c:any){return !!c.env.ADMIN_SECRET && c.req.header('x-admin-secret')===c.env.ADMIN_SECRET;}
app.get('/api/admin/withdrawals',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const rows=await c.env.DB.prepare("SELECT id,user_id,wallet_raw,amount_raw,status,tx_hash,created_at,updated_at,review_note FROM withdrawals ORDER BY created_at DESC LIMIT 500").all();
  return c.json({items:(rows.results||[]).map((x:any)=>({...x,amount:fmt(x.amount_raw)}))});
});
app.post('/api/admin/withdrawals/:id/:action',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const {id,action}=c.req.param(),now=nowSec();
  const w=await c.env.DB.prepare('SELECT * FROM withdrawals WHERE id=?').bind(id).first() as any;
  if(!w)return jsonError(c,'Withdrawal not found',404);
  if(action==='approve'){
    if(w.status!=='pending')return jsonError(c,'Only pending requests can be approved',409);
    await c.env.DB.prepare("UPDATE withdrawals SET status='approved',updated_at=? WHERE id=? AND status='pending'").bind(now,id).run();
  }else if(action==='reject'){
    if(!['pending','approved'].includes(w.status))return jsonError(c,'Request cannot be rejected',409);
    const results=await c.env.DB.batch([
      c.env.DB.prepare("UPDATE withdrawals SET status='rejected',updated_at=? WHERE id=? AND status IN ('pending','approved')").bind(now,id),
      c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'withdrawal_refund',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),w.user_id,w.amount_raw,id,now),
      c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='withdrawal_refund' AND reference_id=?)").bind(w.amount_raw,w.user_id,id)
    ]);
    if(results[0]?.meta?.changes!==1||results[1]?.meta?.changes!==1)return jsonError(c,'Withdrawal was already reviewed',409);
  }else if(action==='paid'){
    const body=await c.req.json().catch(()=>({}));
    if(w.status!=='approved')return jsonError(c,'Only approved requests can be marked paid',409);
    if(typeof body.txHash!=='string'||body.txHash.length<20||body.txHash.length>160)return jsonError(c,'Valid transaction hash required');
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE withdrawals SET status='paid',tx_hash=?,updated_at=? WHERE id=? AND status='approved'").bind(body.txHash,now,id),
      c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),'withdrawal_paid',w.user_id,w.amount_raw,id,now)
    ]);
  }else return jsonError(c,'Unknown action');
  await c.env.DB.prepare('INSERT INTO admin_audit(id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(),'withdrawal_'+action,'withdrawal',id,null,now).run();
  return c.json({ok:true});
});
app.get('/api/pool/status',async c=>{
  const pool=await c.env.DB.prepare('SELECT total_raw,distributed_raw,reserved_raw FROM pool_state WHERE id=1').first() as any;
  if(!pool)return jsonError(c,'Mining pool is not initialized',503);
  const total=BigInt(pool.total_raw),distributed=BigInt(pool.distributed_raw),reserved=BigInt(pool.reserved_raw);
  const remaining=total>distributed+reserved?total-distributed-reserved:0n;
  const percent=total>0n?Number(distributed*10000n/total)/100:0;
  return c.json({total:fmt(total),distributed:fmt(distributed),reserved:fmt(reserved),remaining:fmt(remaining),distributed_percent:percent,total_raw:total.toString(),distributed_raw:distributed.toString(),reserved_raw:reserved.toString(),remaining_raw:remaining.toString()});
});
app.get('/api/admin/wallets/all',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const rows=await c.env.DB.prepare('SELECT id,wallet_raw,wallet_status,network,created_at,wallet_verified_at FROM users ORDER BY created_at ASC LIMIT 1000').all();
  return c.json({items:(rows.results||[]).map((x:any)=>({...x,wallet_friendly:Address.parse(x.wallet_raw).toString({urlSafe:true,bounceable:true,testOnly:false})})),total:(rows.results||[]).length});
});
app.get('/api/admin/wallets',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const rows=await c.env.DB.prepare("SELECT id,wallet_raw,wallet_status,network,created_at FROM users WHERE wallet_status IN ('pending','under_review') ORDER BY created_at ASC LIMIT 200").all();
  return c.json({items:rows.results||[]});
});
app.post('/api/admin/wallets/:id/approve',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const id=c.req.param('id');
  const r=await c.env.DB.prepare("UPDATE users SET wallet_status='approved',wallet_verified_at=?,updated_at=? WHERE id=? AND wallet_status IN ('pending','under_review')").bind(nowSec(),nowSec(),id).run();
  if(r.meta.changes!==1)return jsonError(c,'Wallet not found or not pending',409);
  await c.env.DB.prepare("INSERT INTO admin_audit(id,action,target_type,target_id,created_at) VALUES(?,'wallet_approved','user',?,?)").bind(crypto.randomUUID(),id,nowSec()).run();
  return c.json({ok:true});
});

// Community tasks: user submissions are reviewed manually; rewards are server-calculated.
app.post('/api/tasks/submit',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet approval is required before task rewards.',403);
  const body=await c.req.json().catch(()=>({}));
  const key=body.taskKey;
  if(!['telegram','youtube','x'].includes(key))return jsonError(c,'Unsupported task');
  let proofUrl:string;try{const u=new URL(String(body.proofUrl||''));if(u.protocol!=='https:')throw 0;proofUrl=u.toString()}catch{return jsonError(c,'A valid HTTPS proof link is required');}
  const exists=await c.env.DB.prepare("SELECT id FROM task_submissions WHERE user_id=? AND task_key=? AND status IN ('pending','approved') LIMIT 1").bind(user.id,key).first();
  if(exists)return jsonError(c,'This task has already been submitted or approved.',409);
  const id=crypto.randomUUID();
  await c.env.DB.prepare("INSERT INTO task_submissions(id,user_id,task_key,proof_url,status,created_at) VALUES(?,?,?,?,'pending',?)").bind(id,user.id,key,proofUrl,nowSec()).run();
  return c.json({ok:true,id,status:'pending'});
});
function utcDateOffset(date:string,days:number){const d=new Date(date+'T00:00:00.000Z');d.setUTCDate(d.getUTCDate()+days);return d.toISOString().slice(0,10);}
async function readStreak(c:any,userId:string){
  const today=new Date().toISOString().slice(0,10);
  const rows=await c.env.DB.prepare('SELECT checkin_date FROM daily_checkins WHERE user_id=? ORDER BY checkin_date DESC LIMIT 60').bind(userId).all();
  const dates=(rows.results||[]).map((x:any)=>String(x.checkin_date));
  const dateSet=new Set(dates);
  const anchor=dateSet.has(today)?today:utcDateOffset(today,-1);
  let raw=0;
  if(dateSet.has(anchor)){let cursor=anchor;while(dateSet.has(cursor)&&raw<365){raw++;cursor=utcDateOffset(cursor,-1)}}
  const cycleDay=raw?((raw-1)%30)+1:0;
  const cycleStart=raw?utcDateOffset(anchor,-(cycleDay-1)):null;
  const calendar=Array.from({length:30},(_,i)=>{const date=utcDateOffset(today,i-29);return {date,checked:dateSet.has(date)}});
  const badges=await c.env.DB.prepare('SELECT cycle_start_date,badge_code,awarded_at FROM monthly_badges WHERE user_id=? ORDER BY awarded_at DESC LIMIT 12').bind(userId).all();
  return {today,streak_days:cycleDay,continuous_days:raw,last_checkin:dates[0]||null,next_weekly_milestone:cycleDay<7?7:cycleDay<14?14:cycleDay<21?21:cycleDay<28?28:cycleDay<30?30:null,calendar,badges:badges.results||[],badge_count:(badges.results||[]).length,cycle_start_date:cycleStart};
}
app.get('/api/tasks/streak',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  return c.json(await readStreak(c,user.id));
});
app.post('/api/tasks/daily-checkin',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet approval is required before task rewards.',403);
  const date=new Date().toISOString().slice(0,10);
  const amount=BigInt(c.env.DAILY_CHECKIN_REWARD_IFZI||'10')*UNIT,now=nowSec(),ref=user.id+':'+date;
  const results=await c.env.DB.batch([
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(total_raw AS INTEGER)-CAST(distributed_raw AS INTEGER)-CAST(reserved_raw AS INTEGER)>=? AND NOT EXISTS(SELECT 1 FROM daily_checkins WHERE user_id=? AND checkin_date=?)").bind(amount.toString(),amount.toString(),user.id,date),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'daily_checkin',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),user.id,amount.toString(),ref,now),
    c.env.DB.prepare("INSERT INTO daily_checkins(user_id,checkin_date,created_at) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='daily_checkin' AND reference_id=?)").bind(user.id,date,now,ref),
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='daily_checkin' AND reference_id=?)").bind(amount.toString(),amount.toString(),user.id,ref)
  ]);
  if(results[0]?.meta?.changes!==1||results[1]?.meta?.changes!==1)return jsonError(c,'Daily check-in already claimed or community reward allocation exhausted',409);
  const stats=await readStreak(c,user.id);
  let weeklyBonus=0n,weeklyMilestone=0;
  if([7,14,21,28].includes(stats.streak_days)&&stats.cycle_start_date){
    weeklyMilestone=stats.streak_days;
    weeklyBonus=70n*BigInt(stats.streak_days/7)*UNIT;
    const rewardRef=user.id+':'+stats.cycle_start_date+':'+weeklyMilestone;
    const bonusResults=await c.env.DB.batch([
      c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(total_raw AS INTEGER)-CAST(distributed_raw AS INTEGER)-CAST(reserved_raw AS INTEGER)>=? AND NOT EXISTS(SELECT 1 FROM streak_rewards WHERE user_id=? AND cycle_start_date=? AND milestone_day=?)").bind(weeklyBonus.toString(),weeklyBonus.toString(),user.id,stats.cycle_start_date,weeklyMilestone),
      c.env.DB.prepare("INSERT INTO streak_rewards(user_id,cycle_start_date,milestone_day,reward_raw,created_at) SELECT ?,?,?,?,? WHERE changes()=1").bind(user.id,stats.cycle_start_date,weeklyMilestone,weeklyBonus.toString(),now),
      c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'daily_checkin',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),user.id,weeklyBonus.toString(),rewardRef,now),
      c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='daily_checkin' AND reference_id=?)").bind(weeklyBonus.toString(),weeklyBonus.toString(),user.id,rewardRef)
    ]);
    if(bonusResults[0]?.meta?.changes!==1||bonusResults[1]?.meta?.changes!==1)weeklyBonus=0n;
  }
  let monthlyBadgeAwarded=false;
  if(stats.streak_days===30&&stats.cycle_start_date){
    const badge=await c.env.DB.prepare("INSERT OR IGNORE INTO monthly_badges(user_id,cycle_start_date,badge_code,awarded_at) VALUES(?,?,'IFZI-30-DAY',?)").bind(user.id,stats.cycle_start_date,now).run();
    monthlyBadgeAwarded=badge.meta.changes===1;
  }
  return c.json({ok:true,reward:fmt(amount),weekly_bonus:fmt(weeklyBonus),weekly_milestone:weeklyMilestone||null,monthly_badge_awarded:monthlyBadgeAwarded,streak_days:stats.streak_days,date});
});
// One optional, one-time 0.05 TON task. A successful TON Mainnet payment credits 50,000 IFZI immediately.
app.post('/api/boost/verify',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet approval is required.',403);
  const body=await c.req.json().catch(()=>({}));
  const hash=String(body.txHash||'').trim().toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(hash))return jsonError(c,'Transaction hash must be 64 hexadecimal characters');
  const already=await c.env.DB.prepare("SELECT id FROM ton_boost_payments WHERE user_id=? AND status='verified' UNION SELECT id FROM pool_ledger WHERE event_type='boost_task' AND reference_id=? LIMIT 1").bind(user.id,user.id).first();
  if(already)return jsonError(c,'The optional 0.05 TON task has already been used by this wallet.',409);
  const base=(c.env.TONAPI_BASE||'https://tonapi.io').replace(/\/$/,'');
  let tx:any;
  try{const r=await fetch(base+'/v2/blockchain/transactions/'+hash,{signal:AbortSignal.timeout(8000)});if(!r.ok)return jsonError(c,'Transaction not found on TON Mainnet',404);tx=await r.json()}catch{return jsonError(c,'TON Mainnet transaction lookup failed',503);}
  const msg=tx?.in_msg;
  if(tx?.success!==true||!msg?.source||!msg?.destination)return jsonError(c,'Transaction is not a successful incoming payment',400);
  let sender:string,destination:string,expected:string;
  try{sender=rawAddress(msg.source);destination=rawAddress(msg.destination);expected=rawAddress(c.env.TON_BOOST_RECEIVER)}catch{return jsonError(c,'Transaction address data is invalid',400);}
  if(sender!==user.wallet_raw)return jsonError(c,'Payment sender does not match your verified wallet',403);
  if(destination!==expected)return jsonError(c,'Payment destination mismatch',400);
  if(BigInt(msg.value||'0')!==BigInt(c.env.TON_BOOST_AMOUNT_NANO||'50000000'))return jsonError(c,'Payment must be exactly 0.05 TON',400);
  const registered=await c.env.DB.prepare('SELECT created_at FROM users WHERE id=?').bind(user.id).first() as any;
  if(Number(tx.utime||0)<Number(registered?.created_at||0))return jsonError(c,'Payment must be made after wallet registration',400);
  const reward=BigInt(c.env.TON_BOOST_REWARD_IFZI||'50000')*UNIT,now=nowSec(),paymentId=crypto.randomUUID();
  const results=await c.env.DB.batch([
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(total_raw AS INTEGER)-CAST(distributed_raw AS INTEGER)-CAST(reserved_raw AS INTEGER)>=? AND NOT EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='boost_task' AND reference_id=?) AND NOT EXISTS(SELECT 1 FROM ton_boost_payments WHERE user_id=? AND status='verified') AND NOT EXISTS(SELECT 1 FROM ton_boost_payments WHERE tx_hash=?)").bind(reward.toString(),reward.toString(),user.id,user.id,hash),
    c.env.DB.prepare("INSERT INTO ton_boost_payments(id,user_id,tx_hash,sender_raw,destination_raw,amount_nano,network,status,verified_at,created_at) SELECT ?,?,?,?,?,?,'-239','verified',?,? WHERE changes()=1").bind(paymentId,user.id,hash,sender,destination,String(msg.value),now,now),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'boost_task',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),user.id,reward.toString(),user.id,now),
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='boost_task' AND reference_id=?)").bind(reward.toString(),reward.toString(),user.id,user.id)
  ]);
  if(results[0]?.meta?.changes!==1||results[1]?.meta?.changes!==1||results[2]?.meta?.changes!==1||results[3]?.meta?.changes!==1)return jsonError(c,'Payment was already used, the task was already claimed, or the IFZI reward pool is exhausted.',409);
  await c.env.DB.prepare("INSERT INTO admin_audit(id,action,target_type,target_id,details,created_at) VALUES(?,'optional_boost_paid','user',?,?,?)").bind(crypto.randomUUID(),user.id,'reward_raw='+reward.toString()+';tx='+hash,now).run();
  return c.json({ok:true,status:'verified',reward:fmt(reward),message:'0.05 TON verified on TON Mainnet. 50,000 IFZI credited to your rewards balance.'});
});
app.get('/api/admin/tasks',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const rows=await c.env.DB.prepare("SELECT t.id,t.user_id,t.task_key,t.proof_url,t.created_at,u.wallet_raw FROM task_submissions t JOIN users u ON u.id=t.user_id WHERE t.status='pending' ORDER BY t.created_at ASC LIMIT 200").all();
  return c.json({items:rows.results||[]});
});
app.post('/api/admin/tasks/:id/:action',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const id=c.req.param('id'),action=c.req.param('action');
  if(!['approve','reject'].includes(action))return jsonError(c,'Unknown action');
  const task=await c.env.DB.prepare("SELECT t.*,u.task_boost_multiplier FROM task_submissions t JOIN users u ON u.id=t.user_id WHERE t.id=? AND t.status='pending'").bind(id).first() as any;
  if(!task)return jsonError(c,'Pending task not found',404);
  const now=nowSec();
  if(action==='reject'){
    const r=await c.env.DB.prepare("UPDATE task_submissions SET status='rejected',reviewed_at=?,reviewed_by='admin' WHERE id=? AND status='pending'").bind(now,id).run();
    if(r.meta.changes!==1)return jsonError(c,'Task was already reviewed',409);
    await c.env.DB.prepare("INSERT INTO admin_audit(id,action,target_type,target_id,created_at) VALUES(?,'task_rejected','task',?,?)").bind(crypto.randomUUID(),id,now).run();
    return c.json({ok:true});
  }
  // Ordinary social tasks have one fixed reward; the optional TON task is credited separately.
  const multiplier=1;
  const amount=BigInt(c.env.TASK_REWARD_IFZI||'50')*BigInt(multiplier)*UNIT;
  const results=await c.env.DB.batch([
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(total_raw AS INTEGER)-CAST(distributed_raw AS INTEGER)-CAST(reserved_raw AS INTEGER)>=? AND EXISTS(SELECT 1 FROM task_submissions WHERE id=? AND status='pending')").bind(amount.toString(),amount.toString(),id),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'task_reward',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),task.user_id,amount.toString(),id,now),
    c.env.DB.prepare("UPDATE task_submissions SET status='approved',reviewed_at=?,reviewed_by='admin' WHERE id=? AND status='pending' AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='task_reward' AND reference_id=?)").bind(now,id,id),
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='task_reward' AND reference_id=?)").bind(amount.toString(),amount.toString(),task.user_id,id),
    c.env.DB.prepare("UPDATE users SET task_boost_multiplier=1 WHERE id=? AND task_boost_multiplier=3 AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='task_reward' AND reference_id=?)").bind(task.user_id,id)
  ]);
  if(results[0]?.meta?.changes!==1||results[1]?.meta?.changes!==1||results[2]?.meta?.changes!==1)return jsonError(c,'Task already reviewed or community reward allocation exhausted',409);
  await c.env.DB.prepare('INSERT INTO admin_audit(id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(),'task_approved','task',id,'reward_raw='+amount.toString(),now).run();
  return c.json({ok:true,reward:fmt(amount),multiplier});
});
app.post('/api/admin/bonus',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const body=await c.req.json().catch(()=>({}));
  let amount:bigint;try{amount=parseAmount(body.amount)}catch(e){return jsonError(c,e instanceof Error?e.message:'Invalid amount');}
  let wallet:string;try{wallet=rawAddress(body.wallet)}catch{return jsonError(c,'Invalid wallet address');}
  const user=await c.env.DB.prepare('SELECT id FROM users WHERE wallet_raw=? AND wallet_status=?').bind(wallet,'approved').first() as any;
  if(!user)return jsonError(c,'Approved wallet not found',404);
  const ref=crypto.randomUUID(),now=nowSec();
  const results=await c.env.DB.batch([
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(total_raw AS INTEGER)-CAST(distributed_raw AS INTEGER)-CAST(reserved_raw AS INTEGER)>=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND wallet_status='approved')").bind(amount.toString(),amount.toString(),user.id),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) SELECT ?,'manual_bonus',?,?,?,? WHERE changes()=1").bind(crypto.randomUUID(),user.id,amount.toString(),ref,now),
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=? AND EXISTS(SELECT 1 FROM pool_ledger WHERE event_type='manual_bonus' AND reference_id=?)").bind(amount.toString(),amount.toString(),user.id,ref)
  ]);
  if(results[0]?.meta?.changes!==1||results[1]?.meta?.changes!==1)return jsonError(c,'Mining allocation limit exceeded',409);
  await c.env.DB.prepare("INSERT INTO admin_audit(id,action,target_type,target_id,details,created_at) VALUES(?,'manual_bonus','user',?,?,?)").bind(crypto.randomUUID(),user.id,'reward_raw='+amount.toString(),now).run();
  return c.json({ok:true});
});

async function sendPresaleEmail(env:Bindings,subject:string,html:string){
  if(!env.RESEND_API_KEY||!env.PRESALE_NOTIFY_EMAIL||!env.PRESALE_FROM_EMAIL)return false;
  try{
    const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{'Authorization':'Bearer '+env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:env.PRESALE_FROM_EMAIL,to:[env.PRESALE_NOTIFY_EMAIL],subject,html})});
    return r.ok;
  }catch{return false;}
}
function safeText(v:unknown,max=500){return String(v??'').replace(/[<>]/g,'').slice(0,max);}
app.post('/api/presale/orders',async c=>{
  const body=await c.req.json().catch(()=>({}));
  if(body.website)return jsonError(c,'Invalid request',400);
  let amount:bigint;try{amount=BigInt(String(body.amount||''));}catch{return jsonError(c,'Enter a whole IFZI amount',400);}
  if(amount<1n||amount>10000000n)return jsonError(c,'Amount must be between 1 and 10,000,000 IFZI',400);
  let wallet:string;try{wallet=rawAddress(String(body.wallet||''));}catch{return jsonError(c,'Enter a valid TON wallet address',400);}
  const asset=String(body.asset||'TON').toUpperCase();
  if(!['TON','USDT','OTHER'].includes(asset))return jsonError(c,'Unsupported settlement asset',400);
  const offer=safeText(body.offer,900),note=safeText(body.note,700);
  const id=crypto.randomUUID(),now=nowSec();
  const offerText=[offer,note].filter(Boolean).join(' | ').slice(0,900)||null;
  const recent=await c.env.DB.prepare("SELECT COUNT(*) AS n FROM presale_orders WHERE buyer_wallet_raw=? AND created_at>?").bind(wallet,now-86400).first() as any;
  if(Number(recent?.n||0)>=3)return jsonError(c,'Order limit reached for this wallet. Contact the project owner directly.',429);
  await c.env.DB.prepare("INSERT INTO presale_orders(id,amount_raw,buyer_wallet_raw,settlement_asset,offer_text,status,created_at,updated_at) VALUES(?,?,?,?,?,'new',?,?)").bind(id,(amount*UNIT).toString(),wallet,asset,offerText,now,now).run();
  const html='<h2>New IFZI private allocation inquiry</h2><p><b>Order:</b> '+id+'</p><p><b>Amount:</b> '+amount.toString()+' IFZI</p><p><b>Buyer wallet:</b> '+wallet+'</p><p><b>Preferred asset:</b> '+asset+'</p><p><b>Offer / note:</b> '+(offerText||'—')+'</p><p>Open the IFZI Admin page to review this inquiry. Do not treat this email as payment confirmation.</p>';
  const notified=await sendPresaleEmail(c.env,'New IFZI private sale inquiry · '+amount.toString()+' IFZI',html);
  return c.json({ok:true,id,status:'new',email_notified:notified});
});
app.post('/api/presale/orders/:id/payment',async c=>{
  const id=c.req.param('id'),body=await c.req.json().catch(()=>({}));
  const hash=String(body.txHash||'').trim().toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(hash))return jsonError(c,'Transaction hash must be 64 hexadecimal characters');
  const order=await c.env.DB.prepare('SELECT * FROM presale_orders WHERE id=?').bind(id).first() as any;
  if(!order)return jsonError(c,'Order not found',404);
  if(order.status!=='awaiting_payment')return jsonError(c,'This order is not awaiting a TON payment',409);
  if(order.settlement_asset!=='TON')return jsonError(c,'Automatic verification is currently available for TON only. Contact the owner for USDT or other assets.',400);
  if(!order.agreed_amount_nano)return jsonError(c,'The owner has not issued a payment quote yet',409);
  const base=(c.env.TONAPI_BASE||'https://tonapi.io').replace(/\/$/,'');
  let tx:any;try{const r=await fetch(base+'/v2/blockchain/transactions/'+hash);if(!r.ok)return jsonError(c,'Transaction not found on TON Mainnet',404);tx=await r.json();}catch{return jsonError(c,'TON Mainnet lookup failed',503);}
  const msg=tx?.in_msg;
  if(tx?.success!==true||!msg?.source||!msg?.destination)return jsonError(c,'Transaction is not a successful incoming TON payment');
  let sender:string,destination:string,treasury:string;
  try{sender=rawAddress(msg.source);destination=rawAddress(msg.destination);treasury=rawAddress(c.env.PRESALE_TREASURY);}catch{return jsonError(c,'Transaction address data is invalid');}
  if(destination!==treasury)return jsonError(c,'Payment destination does not match the official IFZI treasury');
  if(sender!==order.buyer_wallet_raw)return jsonError(c,'Payment sender does not match the wallet on this order');
  if(BigInt(msg.value||'0')!==BigInt(order.agreed_amount_nano))return jsonError(c,'Payment amount does not exactly match the agreed TON quote');
  if(Number(tx.utime||0)<Number(order.created_at||0))return jsonError(c,'Payment must be made after this order was created');
  try{await c.env.DB.prepare("UPDATE presale_orders SET status='payment_verified',payment_tx_hash=?,payment_amount_nano=?,updated_at=? WHERE id=? AND status='awaiting_payment'").bind(hash,String(msg.value),nowSec(),id).run();
    const check=await c.env.DB.prepare('SELECT payment_tx_hash FROM presale_orders WHERE id=?').bind(id).first() as any;
    if(check?.payment_tx_hash!==hash)return jsonError(c,'Order payment was already updated',409);
  }catch{return jsonError(c,'This transaction may already be linked to another order',409);}
  await sendPresaleEmail(c.env,'IFZI payment verified · order '+id,'<h2>IFZI TON payment verified</h2><p><b>Order:</b> '+id+'</p><p><b>Amount:</b> '+fmt(order.amount_raw)+' IFZI</p><p><b>TON tx:</b> '+hash+'</p><p>Manual approval and token delivery are still required.</p>');
  return c.json({ok:true,status:'payment_verified',message:'TON Mainnet payment verified. The project owner must still approve delivery.'});
});
app.get('/api/admin/presale/orders',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const rows=await c.env.DB.prepare("SELECT * FROM presale_orders WHERE status!='delivered' ORDER BY created_at ASC LIMIT 200").all();
  return c.json({items:(rows.results||[]).map((x:any)=>({...x,amount:fmt(x.amount_raw)}))});
});
app.post('/api/admin/presale/orders/:id/quote',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const id=c.req.param('id'),body=await c.req.json().catch(()=>({}));
  const order=await c.env.DB.prepare('SELECT * FROM presale_orders WHERE id=?').bind(id).first() as any;
  if(!order)return jsonError(c,'Order not found',404);
  if(order.settlement_asset!=='TON')return jsonError(c,'Automated quote verification is only enabled for TON orders. Handle this asset manually and verify on-chain.',400);
  const value=String(body.tonAmount||'');
  if(!/^\d{1,9}(\.\d{1,9})?$/.test(value))return jsonError(c,'Enter a valid TON amount');
  const [whole,frac='']=value.split('.');
  const nano=(BigInt(whole)*1000000000n+BigInt((frac+'000000000').slice(0,9))).toString();
  if(BigInt(nano)<=0n)return jsonError(c,'TON quote must be greater than zero');
  await c.env.DB.prepare("UPDATE presale_orders SET agreed_amount_nano=?,status='awaiting_payment',updated_at=? WHERE id=? AND status='new'").bind(nano,nowSec(),id).run();
  await sendPresaleEmail(c.env,'IFZI quote issued · order '+id,'<h2>IFZI order quote issued</h2><p>Order '+id+' is awaiting '+value+' TON. Share the official treasury address and order ID with the buyer directly.</p>');
  return c.json({ok:true,status:'awaiting_payment',tonAmount:value});
});
app.post('/api/admin/presale/orders/:id/:action',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const id=c.req.param('id'),action=c.req.param('action'),body=await c.req.json().catch(()=>({}));
  const order=await c.env.DB.prepare('SELECT * FROM presale_orders WHERE id=?').bind(id).first() as any;
  if(!order)return jsonError(c,'Order not found',404);
  const now=nowSec();
  if(action==='approve'){
    if(order.status!=='payment_verified')return jsonError(c,'Only a verified payment can be approved',409);
    await c.env.DB.prepare("UPDATE presale_orders SET status='approved',updated_at=? WHERE id=? AND status='payment_verified'").bind(now,id).run();
  }else if(action==='manual-verify'){
    if(order.settlement_asset==='TON')return jsonError(c,'TON orders must use automatic on-chain verification',400);
    const hash=safeText(body.txHash,160);
    if(hash.length<20)return jsonError(c,'Enter the externally verified transaction hash');
    await c.env.DB.prepare("UPDATE presale_orders SET status='payment_verified',payment_tx_hash=?,updated_at=? WHERE id=? AND status='new'").bind(hash,now,id).run();
  }else if(action==='deliver'){
    if(order.status!=='approved')return jsonError(c,'Approve the order before recording delivery',409);
    const hash=safeText(body.txHash,160);
    if(hash.length<20)return jsonError(c,'Enter the outgoing IFZI transaction hash');
    await c.env.DB.prepare("UPDATE presale_orders SET status='delivered',outgoing_tx_hash=?,updated_at=? WHERE id=? AND status='approved'").bind(hash,now,id).run();
  }else if(action==='reject'){
    if(['delivered','rejected'].includes(order.status))return jsonError(c,'This order can no longer be rejected',409);
    await c.env.DB.prepare("UPDATE presale_orders SET status='rejected',admin_note=?,updated_at=? WHERE id=?").bind(safeText(body.note,500),now,id).run();
  }else return jsonError(c,'Unknown action');
  await sendPresaleEmail(c.env,'IFZI order status updated · '+id,'<p>Order '+id+' status changed to '+action+'. Check Admin.html for details.</p>');
  return c.json({ok:true});
});

export default app;
