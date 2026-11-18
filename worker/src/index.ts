import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Address, Cell, contractAddress, loadStateInit } from '@ton/core';
import { Buffer } from 'buffer';
import {
  WalletContractV1R1, WalletContractV1R2, WalletContractV1R3,
  WalletContractV2R1, WalletContractV2R2, WalletContractV3R1,
  WalletContractV3R2, WalletContractV4, WalletContractV5R1
} from '@ton/ton';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';

type Bindings = {
  DB: D1Database; SITE_ORIGIN: string; SITE_DOMAIN: string; JWT_SECRET: string;
  ADMIN_SECRET: string; JETTON_MASTER: string; JETTON_DECIMALS: string;
  MINING_POOL_IFZI: string; MIN_WITHDRAW_IFZI: string; TONAPI_BASE: string;
  TON_BOOST_RECEIVER: string; TON_BOOST_AMOUNT_NANO: string; TON_BOOST_MULTIPLIER: string;
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
async function getUser(c:any):Promise<User|null>{
  const h=c.req.header('Authorization'); if(!h?.startsWith('Bearer '))return null;
  const p=await verifyJWT(c.env,h.slice(7)); if(!p)return null;
  return await c.env.DB.prepare('SELECT id,wallet_raw,wallet_status,network,referred_by FROM users WHERE id=?').bind(p.sub).first() as User|null;
}
async function issueJWT(env:Bindings,user:User){
  if(!env.JWT_SECRET || env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be configured as a strong Cloudflare secret (at least 32 characters)');
  const head=b64url(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const body=b64url(JSON.stringify({sub:user.id,wallet:user.wallet_raw,iat:nowSec(),exp:nowSec()+86400}));
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
  const base=(env.TONAPI_BASE||'https://tonapi.io').replace(/\\/$/,'');
  const response=await fetch(base+'/v2/accounts/'+encodeURIComponent(wallet)+'/jettons/'+encodeURIComponent(master));
  if(!response.ok)throw new Error('Unable to verify IFZI balance from TON mainnet');
  const data=await response.json() as any;
  if(!data||data.jetton?.address===undefined)throw new Error('IFZI jetton balance response is incomplete');
  return BigInt(data.balance||'0');
}
function extractWalletKey(stateInit:any):Uint8Array|null {
  if(!stateInit.code||!stateInit.data)return null;
  const parsers=[
    {contract:WalletContractV1R1,load:(s:any)=>{s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV1R2,load:(s:any)=>{s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV1R3,load:(s:any)=>{s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV2R1,load:(s:any)=>{s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV2R2,load:(s:any)=>{s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV3R1,load:(s:any)=>{s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV3R2,load:(s:any)=>{s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV4,load:(s:any)=>{s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}},
    {contract:WalletContractV5R1,load:(s:any)=>{s.loadBoolean();s.loadUint(32);s.loadUint(32);return s.loadBuffer(32)}}
  ];
  for(const item of parsers){
    try{
      const code=item.contract.create({workchain:0,publicKey:Buffer.alloc(32)}).init.code;
      if(code.equals(stateInit.code))return new Uint8Array(item.load(stateInit.data.beginParse()));
    }catch{/* try next reviewed standard wallet layout */}
  }
  return null;
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

app.post('/api/ton-proof/payload',async c=>{
  const body=await c.req.json().catch(()=>({}));
  const nonce=crypto.randomUUID();
  await c.env.DB.prepare('INSERT INTO auth_challenges(nonce,wallet_raw,expires_at,used) VALUES(?,NULL,?,0)').bind(nonce,Date.now()+5*60*1000).run();
  return c.json({payload:nonce});
});
app.post('/api/ton-proof/verify',async c=>{
  const body=await c.req.json().catch(()=>({}));
  let wallet:string;try{wallet=rawAddress(body.address)}catch{return jsonError(c,'Invalid wallet address');}
  const challenge=await c.env.DB.prepare('SELECT nonce FROM auth_challenges WHERE nonce=? AND (wallet_raw IS NULL OR wallet_raw=?) AND used=0 AND expires_at>?').bind(body.proof?.payload,wallet,Date.now()).first();
  if(!challenge)return jsonError(c,'Challenge invalid, expired, or already used',401);
  try{verifyTonProof(wallet,String(body.network),body.walletStateInit||body.proof?.state_init,body.proof,c.env.SITE_DOMAIN,challenge.nonce,body.publicKey||body.public_key);}
  catch(e){return jsonError(c,e instanceof Error?e.message:'Proof verification failed',401);}
  const used=await c.env.DB.prepare('UPDATE auth_challenges SET used=1,wallet_raw=? WHERE nonce=? AND (wallet_raw IS NULL OR wallet_raw=?) AND used=0 AND expires_at>?').bind(wallet,challenge.nonce,wallet,Date.now()).run();
  if(used.meta.changes!==1)return jsonError(c,'Challenge already consumed',409);
  let user=await c.env.DB.prepare('SELECT id,wallet_raw,wallet_status,network,referred_by FROM users WHERE wallet_raw=?').bind(wallet).first() as User|null;
  if(!user){
    const id=crypto.randomUUID();
    await c.env.DB.prepare("INSERT INTO users(id,wallet_raw,created_at,network,wallet_status,updated_at) VALUES(?,?,?,'-239','pending',?)").bind(id,wallet,nowSec(),nowSec()).run();
    await c.env.DB.prepare("INSERT OR IGNORE INTO reward_balances(user_id,available_raw,total_earned_raw,total_referral_raw) VALUES(?,'0','0','0')").bind(id).run();
    user={id,wallet_raw:wallet,wallet_status:'pending',network:'-239',referred_by:null};
  }else{
    await c.env.DB.prepare("UPDATE users SET network='-239',updated_at=? WHERE id=?").bind(nowSec(),user.id).run();
  }
  return c.json({ok:true,token:await issueJWT(c.env,user),wallet_status:user.wallet_status});
});
app.get('/api/user',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  const bal=await c.env.DB.prepare('SELECT available_raw,total_earned_raw,total_referral_raw FROM reward_balances WHERE user_id=?').bind(user.id).first() as any;
  const totals=await c.env.DB.prepare("SELECT COALESCE(SUM(CAST(gross_raw AS INTEGER)),0) AS gross FROM claims WHERE user_id=?").bind(user.id).first() as any;
  return c.json({address:user.wallet_raw,wallet_status:user.wallet_status,mining_rewards:fmt(totals?.gross||'0'),available_rewards:fmt(bal?.available_raw||'0'),available_raw:bal?.available_raw||'0',lifetime_mined:fmt(bal?.total_earned_raw||'0'),referral_rewards:fmt(bal?.total_referral_raw||'0')});
});
app.get('/api/mining/status',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  const cycle=await c.env.DB.prepare("SELECT id,level,daily_rate_raw,gross_reward_raw,started_at,ends_at,status FROM mining_cycles WHERE user_id=? AND status IN ('running','completed') ORDER BY started_at DESC LIMIT 1").bind(user.id).first() as any;
  if(!cycle)return c.json({status:'idle'});
  return c.json({status:cycle.ends_at<=nowSec()?'ready':'active',ends_at:cycle.ends_at*1000,level:cycle.level,reward:fmt(cycle.gross_reward_raw)});
});
app.post('/api/mining/start',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet is awaiting manual admin approval.',403);
  const existing=await c.env.DB.prepare("SELECT id FROM mining_cycles WHERE user_id=? AND status IN ('running','completed') LIMIT 1").bind(user.id).first();
  if(existing)return jsonError(c,'You already have an unclaimed mining cycle.',409);
  let balanceRaw:bigint;try{balanceRaw=await getVerifiedIfziBalanceRaw(c.env,user.wallet_raw)}catch(e){return jsonError(c,e instanceof Error?e.message:'Could not verify IFZI balance',503);}
  const wholeBalance=balanceRaw/UNIT;
  let level=1,rateTokens=100n;for(let i=0;i<levels.length;i++){if(wholeBalance>=levels[i][0]){level=i+1;rateTokens=levels[i][1]}}
  const rate=rateTokens*UNIT,reward=rate,started=nowSec(),ends=started+DAY,id=crypto.randomUUID();
  const insert=await c.env.DB.prepare("INSERT INTO mining_cycles(id,user_id,level,daily_rate_raw,gross_reward_raw,started_at,ends_at,status) VALUES(?,?,?,?,?,?,?,'running')").bind(id,user.id,level,rate.toString(),reward.toString(),started,ends).run();
  if(insert.meta.changes!==1)return jsonError(c,'Could not start mining cycle',500);
  return c.json({ok:true,cycle_id:id,ends_at:ends*1000,reward:fmt(reward),level,daily_rate:fmt(rate),verified_balance:fmt(balanceRaw)});
});
app.post('/api/mining/claim',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet is not approved.',403);
  const cycle=await c.env.DB.prepare("SELECT * FROM mining_cycles WHERE user_id=? AND status='running' ORDER BY started_at DESC LIMIT 1").bind(user.id).first() as any;
  if(!cycle)return jsonError(c,'No claimable mining cycle',404);
  const now=nowSec();if(cycle.ends_at>now)return jsonError(c,'Mining cycle is not complete yet',400);
  const gross=BigInt(cycle.gross_reward_raw), referral=gross/10n, own=gross-referral;
  const pool=await c.env.DB.prepare('SELECT total_raw,distributed_raw,reserved_raw FROM pool_state WHERE id=1').first() as any;
  if(!pool)return jsonError(c,'Mining pool is not initialized',503);
  const remaining=BigInt(pool.total_raw)-BigInt(pool.distributed_raw)-BigInt(pool.reserved_raw);
  if(gross>remaining)return jsonError(c,'Mining pool allocation exhausted',409);
  const distributed= user.referred_by ? gross : own;
  const statements=[
    c.env.DB.prepare("UPDATE mining_cycles SET status='claimed' WHERE id=? AND status='running' AND ends_at<=?").bind(cycle.id,now),
    c.env.DB.prepare("INSERT INTO claims(cycle_id,user_id,gross_raw,user_raw,referral_raw,referral_user_id,created_at) VALUES(?,?,?,?,?,?,?)").bind(cycle.id,user.id,gross.toString(),own.toString(),referral.toString(),user.referred_by,now),
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=?").bind(own.toString(),own.toString(),user.id),
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1").bind(distributed.toString()),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),'mining_claim',user.id,gross.toString(),cycle.id,now)
  ];
  if(user.referred_by){
    statements.push(c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+?,total_referral_raw=CAST(total_referral_raw AS INTEGER)+? WHERE user_id=?").bind(referral.toString(),referral.toString(),referral.toString(),user.referred_by));
    statements.push(c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),'referral',user.referred_by,referral.toString(),cycle.id,now));
  }
  const results=await c.env.DB.batch(statements);
  if(results[0]?.meta?.changes!==1)return jsonError(c,'Cycle already claimed',409);
  return c.json({ok:true,reward:fmt(own),gross_reward:fmt(gross),referral_reward:fmt(user.referred_by?referral:0n)});
});
app.post('/api/withdrawals/request',async c=>{
  const user=await getUser(c);if(!user)return jsonError(c,'Unauthorized',401);
  if(user.wallet_status!=='approved')return jsonError(c,'Wallet is not approved.',403);
  const body=await c.req.json().catch(()=>({}));
  let amount:bigint;try{amount=parseAmount(body.amount)}catch(e){return jsonError(c,e instanceof Error?e.message:'Invalid amount');}
  const min=BigInt(c.env.MIN_WITHDRAW_IFZI||'1000')*UNIT;
  if(amount<min)return jsonError(c,'Minimum withdrawal is '+(c.env.MIN_WITHDRAW_IFZI||'1000')+' IFZI');
  const id=crypto.randomUUID(),now=nowSec();
  const balance=await c.env.DB.prepare('SELECT available_raw FROM reward_balances WHERE user_id=?').bind(user.id).first() as any;
  if(!balance||BigInt(balance.available_raw)<amount)return jsonError(c,'Insufficient available IFZI balance',409);
  const upd=await c.env.DB.prepare('UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)-? WHERE user_id=? AND CAST(available_raw AS INTEGER)>=?').bind(amount.toString(),user.id,amount.toString()).run();
  if(upd.meta.changes!==1)return jsonError(c,'Balance changed; refresh and try again',409);
  try{
    await c.env.DB.prepare("INSERT INTO withdrawals(id,user_id,wallet_raw,amount_raw,status,created_at,updated_at) VALUES(?,?,?,?,'pending',?,?)").bind(id,user.id,user.wallet_raw,amount.toString(),now,now).run();
    await c.env.DB.prepare("UPDATE pool_state SET reserved_raw=CAST(reserved_raw AS INTEGER)+? WHERE id=1").bind(amount.toString()).run();
  }catch(e){
    await c.env.DB.prepare('UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+? WHERE user_id=?').bind(amount.toString(),user.id).run();
    throw e;
  }
  return c.json({ok:true,id,amount:fmt(amount),status:'pending'});
});

async function requireAdmin(c:any){return !!c.env.ADMIN_SECRET && c.req.header('x-admin-secret')===c.env.ADMIN_SECRET;}
app.get('/api/admin/withdrawals',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const rows=await c.env.DB.prepare("SELECT id,user_id,wallet_raw,amount_raw,status,tx_hash,created_at,updated_at,review_note FROM withdrawals WHERE status IN ('pending','approved') ORDER BY created_at ASC LIMIT 200").all();
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
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE withdrawals SET status='rejected',updated_at=? WHERE id=? AND status IN ('pending','approved')").bind(now,id),
      c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+? WHERE user_id=?").bind(w.amount_raw,w.user_id),
      c.env.DB.prepare("UPDATE pool_state SET reserved_raw=CAST(reserved_raw AS INTEGER)-? WHERE id=1 AND CAST(reserved_raw AS INTEGER)>=?").bind(w.amount_raw,w.amount_raw)
    ]);
  }else if(action==='paid'){
    const body=await c.req.json().catch(()=>({}));
    if(w.status!=='approved')return jsonError(c,'Only approved requests can be marked paid',409);
    if(typeof body.txHash!=='string'||body.txHash.length<20||body.txHash.length>160)return jsonError(c,'Valid transaction hash required');
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE withdrawals SET status='paid',tx_hash=?,updated_at=? WHERE id=? AND status='approved'").bind(body.txHash,now,id),
      c.env.DB.prepare("UPDATE pool_state SET reserved_raw=CAST(reserved_raw AS INTEGER)-?,distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1 AND CAST(reserved_raw AS INTEGER)>=?").bind(w.amount_raw,w.amount_raw,w.amount_raw),
      c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(),'withdrawal_paid',w.user_id,w.amount_raw,id,now)
    ]);
  }else return jsonError(c,'Unknown action');
  await c.env.DB.prepare('INSERT INTO admin_audit(id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(),'withdrawal_'+action,'withdrawal',id,null,now).run();
  return c.json({ok:true});
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
app.post('/api/admin/bonus',async c=>{
  if(!await requireAdmin(c))return jsonError(c,'Admin unauthorized',401);
  const body=await c.req.json().catch(()=>({}));
  let amount:bigint;try{amount=parseAmount(body.amount)}catch(e){return jsonError(c,e instanceof Error?e.message:'Invalid amount');}
  const user=await c.env.DB.prepare('SELECT id FROM users WHERE wallet_raw=? AND wallet_status=?').bind(rawAddress(body.wallet),'approved').first() as any;
  if(!user)return jsonError(c,'Approved wallet not found',404);
  const pool=await c.env.DB.prepare('SELECT total_raw,distributed_raw,reserved_raw FROM pool_state WHERE id=1').first() as any;
  if(!pool||amount>BigInt(pool.total_raw)-BigInt(pool.distributed_raw)-BigInt(pool.reserved_raw))return jsonError(c,'Mining allocation limit exceeded',409);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE reward_balances SET available_raw=CAST(available_raw AS INTEGER)+?,total_earned_raw=CAST(total_earned_raw AS INTEGER)+? WHERE user_id=?").bind(amount.toString(),amount.toString(),user.id),
    c.env.DB.prepare("UPDATE pool_state SET distributed_raw=CAST(distributed_raw AS INTEGER)+? WHERE id=1").bind(amount.toString()),
    c.env.DB.prepare("INSERT INTO pool_ledger(id,event_type,user_id,amount_raw,reference_id,created_at) VALUES(?,'manual_bonus',?,?,?,?)").bind(crypto.randomUUID(),user.id,amount.toString(),crypto.randomUUID(),nowSec())
  ]);
  return c.json({ok:true});
});
export default app;
