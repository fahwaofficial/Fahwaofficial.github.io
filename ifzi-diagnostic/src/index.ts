import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Address, Cell, contractAddress, loadStateInit } from '@ton/core';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';

const app = new Hono();
app.onError((error, c) => {
  console.error('Diagnostic Worker exception', error);
  return c.json({ ok: false, error: 'runtime exception' }, 500);
});

const dependencyProbe = {
  address: typeof Address.parse,
  cell: typeof Cell.fromBase64,
  contractAddress: typeof contractAddress,
  stateInit: typeof loadStateInit,
  sha256: typeof sha256,
  ed25519: typeof ed25519.verify,
};

app.get('/health', c => c.json({ ok: true, route: 'before-cors', dependencyProbe }));
app.use('*', cors({
  origin: ['https://fahwaofficial.github.io'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));
app.get('/health/cors', c => c.json({ ok: true, route: 'after-cors' }));

export default app;
