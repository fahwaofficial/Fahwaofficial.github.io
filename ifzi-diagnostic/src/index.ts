import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();
app.onError((error, c) => {
  console.error('Minimal diagnostic exception', error);
  return c.json({ ok: false, error: 'runtime exception' }, 500);
});

app.get('/health', c => c.json({ ok: true, route: 'before-cors' }));
app.use('*', cors({
  origin: ['https://fahwaofficial.github.io'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));
app.get('/health/cors', c => c.json({ ok: true, route: 'after-cors' }));

export default app;
