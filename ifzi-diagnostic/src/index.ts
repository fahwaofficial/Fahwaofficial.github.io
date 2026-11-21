export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    return new Response(JSON.stringify({ ok: true, path: url.pathname, runtime: 'plain-worker' }), {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  },
};
