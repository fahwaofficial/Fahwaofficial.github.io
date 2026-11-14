interface Env {
  DB: any;
  SITE_ORIGIN: string;
}

const json = (data: unknown, status = 200) => {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
};

function corsHeaders(origin: string, env: Env) {
  const allowed = env.SITE_ORIGIN || "https://fahwaofficial.github.io";

  return {
    "Access-Control-Allow-Origin": origin === allowed ? allowed : allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    const headers = corsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    let response: Response;

    try {
      if (url.pathname === "/" || url.pathname === "/health") {
        let database = "not_checked";

        try {
          await env.DB.prepare("SELECT 1 AS ok").first();
          database = "connected";
        } catch {
          database = "error";
        }

        response = json({
          success: true,
          worker: "ifzi-mining-api",
          status: "online",
          database,
          time: new Date().toISOString()
        });
      } else {
        response = json({
          success: false,
          error: "API endpoint is not implemented yet",
          path: url.pathname
        }, 404);
      }
    } catch {
      response = json({
        success: false,
        error: "Internal server error"
      }, 500);
    }

    const responseHeaders = new Headers(response.headers);

    for (const [key, value] of Object.entries(headers)) {
      responseHeaders.set(key, value);
    }

    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  }
};
