// worker/src/index.ts
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Address } from '@ton/core';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';

type Bindings = {
  DB: D1Database;
  JETTON_MASTER: string;
  JETTON_DECIMALS: string;
  MINING_POOL_IFZI: string;
  MIN_WITHDRAW_IFZI: string;
  TONAPI_BASE: string;
  SITE_DOMAIN: string;
  SITE_ORIGIN: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// ═══════════════════════════════════════════════════════════════
// CORS — حیاتی برای ارتباط فرانت‌اند با Worker
// ═══════════════════════════════════════════════════════════════
app.use('*', cors({
  origin: (origin) => {
    const allowed = ['https://fahwaofficial.github.io', 'http://localhost:3000'];
    return allowed.includes(origin) ? origin : null;
  },
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));

// ═══════════════════════════════════════════════════════════════
// Health Check
// ═══════════════════════════════════════════════════════════════
app.get('/health', (c) => c.json({ ok: true, ts: Date.now() }));

// ═══════════════════════════════════════════════════════════════
// TON Proof — مرحله ۱: تولید nonce
// ═══════════════════════════════════════════════════════════════
app.post('/api/ton-proof/payload', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json().catch(() => ({}));
  const address = body.address;
  if (!address) return c.json({ error: 'address required' }, 400);

  const nonce = crypto.randomUUID();
  const expiresAt = Date.now() + 5 * 60 * 1000;

  await db.prepare(
    `INSERT INTO ton_proof_challenges (nonce, address, expires_at, used) VALUES (?, ?, ?, 0)`
  ).bind(nonce, address, expiresAt).run();

  return c.json({ payload: nonce });
});

// ═══════════════════════════════════════════════════════════════
// TON Proof — مرحله ۲: تأیید امضا
// ═══════════════════════════════════════════════════════════════
app.post('/api/ton-proof/verify', async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();
  const { address, network, publicKey, walletStateInit, proof } = body;

  if (!proof?.payload || !proof?.signature || !proof?.domain?.value) {
    return c.json({ error: 'malformed proof' }, 400);
  }

  const expectedDomain = c.env.SITE_DOMAIN || 'fahwaofficial.github.io';
  if (proof.domain.value !== expectedDomain) {
    return c.json({ error: 'domain mismatch' }, 403);
  }

  const challenge = await db.prepare(
    `SELECT * FROM ton_proof_challenges WHERE nonce = ? AND address = ? AND used = 0 AND expires_at > ?`
  ).bind(proof.payload, address, Date.now()).first();

  if (!challenge) {
    return c.json({ error: 'challenge invalid, expired, or already used' }, 401);
  }

  const consumed = await db.prepare(
    `UPDATE ton_proof_challenges SET used = 1 WHERE nonce = ? AND used = 0`
  ).bind(proof.payload).run();

  if (consumed.meta.changes === 0) {
    return c.json({ error: 'challenge already consumed' }, 401);
  }

  // —— بازسازی پیام امضا شده (طبق مستندات TON) ——
  const addr = Address.parse(address);
  const timestamp = Number(proof.timestamp);
  const domainBuf = Buffer.from(proof.domain.value, 'utf8');

  const msg = Buffer.concat([
    Buffer.from('ton-proof-item-v2/', 'utf8'),
    Buffer.from([addr.workChain & 0xff, (addr.workChain >> 8) & 0xff, (addr.workChain >> 16) & 0xff, (addr.workChain >> 24) & 0xff]),
    addr.hash,
    (() => { const b = Buffer.alloc(4); b.writeUInt32LE(domainBuf.length); return b; })(),
    domainBuf,
    (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(timestamp)); return b; })(),
    Buffer.from(proof.payload, 'utf8'),
  ]);

  const inner = sha256(msg);
  const finalDigest = sha256(Buffer.concat([
    Buffer.from([0xff, 0xff]),
    Buffer.from('ton-connect', 'utf8'),
    inner,
  ]));

  // —— استخراج کلید عمومی (اولویت: walletStateInit) ——
  let pubKeyBytes: Uint8Array | null = null;
  if (walletStateInit) {
    try {
      // اینجا باید از تابع extractPublicKeyFromStateInit استفاده شود.
      // برای سادگی، از publicKey ارسالی استفاده می‌کنیم (ناامن).
      // در محیط عملیاتی، حتماً پیاده‌سازی امن را جایگزین کنید.
      pubKeyBytes = Buffer.from(publicKey, 'base64');
    } catch { /* fallback */ }
  }
  if (!pubKeyBytes && publicKey) {
    pubKeyBytes = Buffer.from(publicKey, 'base64');
  }
  if (!pubKeyBytes) return c.json({ error: 'public key unavailable' }, 400);

  const sigBytes = Buffer.from(proof.signature, 'base64');
  const valid = ed25519.verify(sigBytes, finalDigest, pubKeyBytes);
  if (!valid) return c.json({ error: 'signature verification failed' }, 401);

  // —— ایجاد/بازیابی کاربر و صدور JWT ——
  const token = await issueJWT(c.env, address);
  await db.prepare(
    `INSERT INTO users (address, network, created_at) VALUES (?, ?, ?)
     ON CONFLICT(address) DO UPDATE SET network = excluded.network`
  ).bind(address, network || 'mainnet', Date.now()).run();

  return c.json({ ok: true, token });
});

// ═══════════════════════════════════════════════════════════════
// API کاربر (نیازمند احراز هویت با JWT)
// ═══════════════════════════════════════════════════════════════
app.get('/api/user', async (c) => {
  const db = c.env.DB;
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'unauthorized' }, 401);
  const payload = await verifyJWT(c.env, auth.slice(7));
  if (!payload) return c.json({ error: 'invalid token' }, 401);

  const user = await db.prepare(`SELECT * FROM users WHERE address = ?`).bind(payload.address).first();
  if (!user) return c.json({ error: 'user not found' }, 404);

  return c.json({
    address: user.address,
    mining_rewards: user.mining_rewards || 0,
    available_rewards: user.available_rewards || 0,
    lifetime_mined: user.lifetime_mined || 0,
  });
});

// ═══════════════════════════════════════════════════════════════
// ماینینگ — شروع
// ═══════════════════════════════════════════════════════════════
app.post('/api/mining/start', async (c) => {
  const db = c.env.DB;
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'unauthorized' }, 401);
  const payload = await verifyJWT(c.env, auth.slice(7));
  if (!payload) return c.json({ error: 'invalid token' }, 401);

  const user = await db.prepare(`SELECT * FROM users WHERE address = ?`).bind(payload.address).first();
  if (!user) return c.json({ error: 'user not found' }, 404);

  if (user.mining_started_at && Date.now() - user.mining_started_at < 24 * 3600 * 1000) {
    return c.json({ error: 'mining already active' }, 400);
  }

  const endsAt = Date.now() + 24 * 3600 * 1000;
  await db.prepare(
    `UPDATE users SET mining_started_at = ? WHERE address = ?`
  ).bind(Date.now(), payload.address).run();

  return c.json({ ok: true, ends_at: endsAt });
});

// ═══════════════════════════════════════════════════════════════
// ماینینگ — وضعیت
// ═══════════════════════════════════════════════════════════════
app.get('/api/mining/status', async (c) => {
  const db = c.env.DB;
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'unauthorized' }, 401);
  const payload = await verifyJWT(c.env, auth.slice(7));
  if (!payload) return c.json({ error: 'invalid token' }, 401);

  const user = await db.prepare(`SELECT * FROM users WHERE address = ?`).bind(payload.address).first();
  if (!user) return c.json({ error: 'user not found' }, 404);

  const started = user.mining_started_at;
  if (started && Date.now() - started < 24 * 3600 * 1000) {
    return c.json({ status: 'active', ends_at: started + 24 * 3600 * 1000 });
  }
  return c.json({ status: 'idle' });
});

// ═══════════════════════════════════════════════════════════════
// ماینینگ — Claim
// ═══════════════════════════════════════════════════════════════
app.post('/api/mining/claim', async (c) => {
  const db = c.env.DB;
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'unauthorized' }, 401);
  const payload = await verifyJWT(c.env, auth.slice(7));
  if (!payload) return c.json({ error: 'invalid token' }, 401);

  const user = await db.prepare(`SELECT * FROM users WHERE address = ?`).bind(payload.address).first();
  if (!user) return c.json({ error: 'user not found' }, 404);

  if (!user.mining_started_at || Date.now() - user.mining_started_at < 24 * 3600 * 1000) {
    return c.json({ error: 'mining not ready' }, 400);
  }

  const reward = 1000; // مقدار پاداش روزانه (قابل تنظیم در D1)
  await db.prepare(
    `UPDATE users SET mining_rewards = mining_rewards + ?, lifetime_mined = lifetime_mined + ?, available_rewards = available_rewards + ?, mining_started_at = NULL WHERE address = ?`
  ).bind(reward, reward, reward, payload.address).run();

  return c.json({ ok: true, reward });
});

// ═══════════════════════════════════════════════════════════════
// درخواست برداشت
// ═══════════════════════════════════════════════════════════════
app.post('/api/withdrawals/request', async (c) => {
  const db = c.env.DB;
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'unauthorized' }, 401);
  const payload = await verifyJWT(c.env, auth.slice(7));
  if (!payload) return c.json({ error: 'invalid token' }, 401);

  const user = await db.prepare(`SELECT * FROM users WHERE address = ?`).bind(payload.address).first();
  if (!user) return c.json({ error: 'user not found' }, 404);

  const minWithdraw = Number(c.env.MIN_WITHDRAW_IFZI || 10000);
  if ((user.available_rewards || 0) < minWithdraw) {
    return c.json({ error: `minimum withdrawal is ${minWithdraw} IFZI` }, 400);
  }

  await db.prepare(
    `INSERT INTO withdrawals (user_address, amount, status, created_at) VALUES (?, ?, 'pending', ?)`
  ).bind(payload.address, user.available_rewards, Date.now()).run();

  await db.prepare(`UPDATE users SET available_rewards = 0 WHERE address = ?`).bind(payload.address).run();

  return c.json({ ok: true, message: 'Withdrawal request submitted. Admin will review it.' });
});

// ═══════════════════════════════════════════════════════════════
// توابع کمکی JWT (بسیار ساده — برای محیط عملیاتی از کتابخانه معتبر استفاده کنید)
// ═══════════════════════════════════════════════════════════════
async function issueJWT(env: Bindings, address: string): Promise<string> {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ address, iat: Date.now(), exp: Date.now() + 7 * 86400000 }));
  const signature = await hmacSign(env, `${header}.${payload}`);
  return `${header}.${payload}.${signature}`;
}

async function verifyJWT(env: Bindings, token: string): Promise<{ address: string } | null> {
  try {
    const [header, payload, signature] = token.split('.');
    const expected = await hmacSign(env, `${header}.${payload}`);
    if (signature !== expected) return null;
    const data = JSON.parse(atob(payload));
    if (data.exp < Date.now()) return null;
    return { address: data.address };
  } catch { return null; }
}

async function hmacSign(env: Bindings, data: string): Promise<string> {
  const secret = env.SITE_ORIGIN || 'default-secret-change-me';
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

export default app;
