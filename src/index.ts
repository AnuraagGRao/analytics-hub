export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD?: string;
  SESSION_SECRET?: string;
}

// ---------------------------------------------------------------------------
// Cryptographic Authentication & Session Utilities
// ---------------------------------------------------------------------------

async function getHmacKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

// Constant-time comparison using SHA-256 digests to eliminate timing attacks
async function verifyPassword(provided: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const hashA = await crypto.subtle.digest("SHA-256", enc.encode(provided));
  const hashB = await crypto.subtle.digest("SHA-256", enc.encode(expected));
  return crypto.subtle.timingSafeEqual(hashA, hashB);
}

// Generate signed HMAC-SHA256 JWT-style session token (valid for 30 days)
async function generateSessionToken(secret: string): Promise<string> {
  const enc = new TextEncoder();
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })).replace(/=/g, "");
  const payload = btoa(
    JSON.stringify({
      user: "anuraag",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60, // 30 days
    })
  ).replace(/=/g, "");

  const data = `${header}.${payload}`;
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(data));

  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${data}.${sigBase64}`;
}

// Verify HMAC-SHA256 signature and expiration
async function verifySessionToken(token: string, secret: string): Promise<boolean> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [header, payload, signature] = parts;
    const data = `${header}.${payload}`;

    const key = await getHmacKey(secret);

    // Decode base64url signature
    const sigStr = signature.replace(/-/g, "+").replace(/_/g, "/");
    const pad = sigStr.length % 4 === 0 ? "" : "=".repeat(4 - (sigStr.length % 4));
    const rawSig = Uint8Array.from(atob(sigStr + pad), (c) => c.charCodeAt(0));

    const enc = new TextEncoder();
    const isValid = await crypto.subtle.verify("HMAC", key, rawSig, enc.encode(data));
    if (!isValid) return false;

    // Check expiration
    const payloadStr = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const parsed = JSON.parse(payloadStr) as { exp?: number };
    if (!parsed.exp || parsed.exp < Math.floor(Date.now() / 1000)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

// Extract token from Cookie or Authorization header
function extractToken(request: Request): string | null {
  const cookieHeader = request.headers.get("Cookie");
  if (cookieHeader) {
    const cookies = Object.fromEntries(
      cookieHeader.split(";").map((c) => {
        const [k, ...v] = c.trim().split("=");
        return [k, v.join("=")];
      })
    );
    if (cookies["analytics_session"]) {
      return cookies["analytics_session"];
    }
  }

  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  return null;
}

// Check if incoming request is authenticated
async function isAuthenticated(request: Request, env: Env): Promise<boolean> {
  const token = extractToken(request);
  if (!token || !env.ADMIN_PASSWORD) return false;

  const secret = env.SESSION_SECRET || env.ADMIN_PASSWORD;

  // 1. Direct Bearer token match with admin password (for curl/scripts)
  if (token === env.ADMIN_PASSWORD) return true;

  // 2. Cryptographic JWT session validation
  return verifySessionToken(token, secret);
}

// ---------------------------------------------------------------------------
// Telemetry Parsing Helpers
// ---------------------------------------------------------------------------

function parseUserAgent(ua: string | null): { device: string; browser: string; os: string } {
  if (!ua) return { device: "desktop", browser: "other", os: "other" };
  const lower = ua.toLowerCase();

  let device = "desktop";
  if (/mobile|android|iphone|ipod/.test(lower)) device = "mobile";
  else if (/tablet|ipad/.test(lower)) device = "tablet";

  let os = "other";
  if (lower.includes("windows")) os = "Windows";
  else if (lower.includes("mac os") || lower.includes("macintosh")) os = "macOS";
  else if (lower.includes("iphone") || lower.includes("ipad")) os = "iOS";
  else if (lower.includes("android")) os = "Android";
  else if (lower.includes("linux")) os = "Linux";

  let browser = "other";
  if (lower.includes("edg/")) browser = "Edge";
  else if (lower.includes("chrome") && !lower.includes("edg/")) browser = "Chrome";
  else if (lower.includes("safari") && !lower.includes("chrome")) browser = "Safari";
  else if (lower.includes("firefox")) browser = "Firefox";

  return { device, browser, os };
}

function sanitizeReferrer(raw: string | null): string {
  if (!raw || raw === "direct") return "direct";
  try {
    const url = new URL(raw);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return raw.slice(0, 50);
  }
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // -----------------------------------------------------------------------
    // 1. PUBLIC INGESTION: /api/hit and /hit.gif
    // -----------------------------------------------------------------------
    if (url.pathname === "/api/hit" || url.pathname === "/hit.gif") {
      let project = url.searchParams.get("project") || "";
      let path = url.searchParams.get("path") || "/";
      let referrer = url.searchParams.get("referrer") || request.headers.get("Referer") || "direct";

      if (request.method === "POST") {
        try {
          const body = (await request.json()) as Record<string, string>;
          if (body.project) project = body.project;
          if (body.path) path = body.path;
          if (body.referrer) referrer = body.referrer;
        } catch {
          // Fall back to query params
        }
      }

      project = (project || "default").trim().toLowerCase().slice(0, 50);
      path = (path || "/").trim().slice(0, 200);
      referrer = sanitizeReferrer(referrer);

      // Cloudflare edge geo metadata
      const cf = (request as unknown as { cf?: Record<string, string> }).cf;
      const country = (cf?.country || "XX").slice(0, 4);
      const city = (cf?.city || "Unknown").slice(0, 100);
      const region = (cf?.region || "").slice(0, 100);

      const ua = request.headers.get("User-Agent");
      const { device, browser, os } = parseUserAgent(ua);

      // Non-blocking asynchronous D1 insert
      ctx.waitUntil(
        env.DB.prepare(
          `INSERT INTO page_views (project, path, referrer, country, city, region, device, browser, os)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(project, path, referrer, country, city, region, device, browser, os)
          .run()
          .catch((err) => console.error("D1 write error:", err))
      );

      // 1x1 transparent GIF response
      if (url.pathname === "/hit.gif") {
        const gifBytes = new Uint8Array([
          0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
          0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
          0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
          0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
          0x01, 0x00, 0x3b,
        ]);
        return new Response(gifBytes, {
          headers: {
            "Content-Type": "image/gif",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            ...CORS_HEADERS,
          },
        });
      }

      return new Response(JSON.stringify({ ok: true, timestamp: Date.now() }), {
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }

    // -----------------------------------------------------------------------
    // 2. PUBLIC SCRIPT: /tracker.js
    // -----------------------------------------------------------------------
    if (url.pathname === "/tracker.js") {
      const script = `
(function(){
  try {
    var cur = document.currentScript || document.querySelector('script[data-project]');
    var project = cur ? cur.getAttribute('data-project') : 'default';
    var endpoint = cur ? cur.src.replace(/\\/tracker\\.js.*$/, '/api/hit') : '/api/hit';

    function sendHit(p) {
      var payload = JSON.stringify({
        project: project,
        path: p || window.location.pathname || '/',
        referrer: document.referrer || 'direct'
      });
      if (navigator.sendBeacon) {
        navigator.sendBeacon(endpoint, payload);
      } else {
        fetch(endpoint, { method: 'POST', body: payload, keepalive: true, headers: { 'Content-Type': 'application/json' } }).catch(function(){});
      }
    }

    var lastPath = window.location.pathname;
    sendHit(lastPath);

    var origPush = history.pushState;
    if (origPush) {
      history.pushState = function() {
        origPush.apply(this, arguments);
        if (window.location.pathname !== lastPath) {
          lastPath = window.location.pathname;
          sendHit(lastPath);
        }
      };
    }
    window.addEventListener('popstate', function() {
      if (window.location.pathname !== lastPath) {
        lastPath = window.location.pathname;
        sendHit(lastPath);
      }
    });
  } catch(e) {}
})();
      `.trim();

      return new Response(script, {
        headers: {
          "Content-Type": "application/javascript; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
          ...CORS_HEADERS,
        },
      });
    }

    // -----------------------------------------------------------------------
    // 3. PUBLIC BADGE: /api/badge
    // -----------------------------------------------------------------------
    if (url.pathname === "/api/badge") {
      const project = url.searchParams.get("project") || "all";
      const whereClause = project !== "all" ? "WHERE project = ?" : "";
      const bindings = project !== "all" ? [project] : [];

      const totalRes = await env.DB.prepare(
        `SELECT COUNT(*) as total FROM page_views ${whereClause}`
      )
        .bind(...bindings)
        .first<{ total: number }>();

      const total = totalRes?.total || 0;
      let countStr = String(total);
      if (total >= 1000000) countStr = (total / 1000000).toFixed(1) + "M";
      else if (total >= 1000) countStr = (total / 1000).toFixed(1) + "k";

      const svg = `
<svg xmlns="http://www.w3.org/2000/svg" width="110" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="110" height="20" rx="4" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <path fill="#0f172a" d="M0 0h55v20H0z"/>
    <path fill="#06b6d4" d="M55 0h55v20H55z"/>
    <path fill="url(#b)" d="M0 0h110v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="11">
    <text x="27.5" y="14" fill="#94a3b8">visitors</text>
    <text x="82.5" y="14" fill="#090d16" font-weight="bold">${countStr}</text>
  </g>
</svg>
      `.trim();

      return new Response(svg, {
        headers: {
          "Content-Type": "image/svg+xml; charset=utf-8",
          "Cache-Control": "no-cache",
          ...CORS_HEADERS,
        },
      });
    }

    // -----------------------------------------------------------------------
    // 3.1. PUBLIC COUNT API: /api/count
    // -----------------------------------------------------------------------
    if (url.pathname === "/api/count") {
      const project = url.searchParams.get("project") || "all";
      const whereClause = project !== "all" ? "WHERE project = ?" : "";
      const bindings = project !== "all" ? [project] : [];

      const totalRes = await env.DB.prepare(
        `SELECT COUNT(*) as total FROM page_views ${whereClause}`
      )
        .bind(...bindings)
        .first<{ total: number }>();

      const total = totalRes?.total || 0;
      return new Response(
        JSON.stringify({ ok: true, project, count: total, timestamp: Date.now() }),
        {
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
            ...CORS_HEADERS,
          },
        }
      );
    }

    // -----------------------------------------------------------------------
    // 4. AUTHENTICATION ENDPOINTS: /api/login and /api/logout
    // -----------------------------------------------------------------------
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const body = (await request.json()) as { password?: string };
        const providedPassword = (body.password || "").trim();
        if (!env.ADMIN_PASSWORD) {
          return new Response(
            JSON.stringify({ ok: false, error: "Server authentication key is not configured" }),
            { status: 500, headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
          );
        }

        const isMatch = await verifyPassword(providedPassword, env.ADMIN_PASSWORD);

        if (!isMatch) {
          return new Response(
            JSON.stringify({ ok: false, error: "Invalid master security key" }),
            { status: 401, headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
          );
        }

        // Generate signed token
        const secret = env.SESSION_SECRET || env.ADMIN_PASSWORD;
        const sessionToken = await generateSessionToken(secret);

        // Set HttpOnly, Secure, SameSite=Strict cookie for 30 days
        const cookie = `analytics_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`;

        return new Response(JSON.stringify({ ok: true, message: "Authenticated successfully" }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie": cookie,
            ...CORS_HEADERS,
          },
        });
      } catch {
        return new Response(
          JSON.stringify({ ok: false, error: "Bad request payload" }),
          { status: 400, headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
        );
      }
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      const clearCookie = `analytics_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
      return new Response(JSON.stringify({ ok: true, message: "Logged out" }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": clearCookie,
          ...CORS_HEADERS,
        },
      });
    }

    // -----------------------------------------------------------------------
    // 5. PROTECTED API: /api/stats
    // -----------------------------------------------------------------------
    if (url.pathname === "/api/stats") {
      const authed = await isAuthenticated(request, env);
      if (!authed) {
        return new Response(
          JSON.stringify({
            error: "Unauthorized",
            message: "Authentication required to access analytics query API. Please log in at /.",
          }),
          {
            status: 401,
            headers: { "Content-Type": "application/json", ...CORS_HEADERS },
          }
        );
      }

      const project = url.searchParams.get("project");
      const whereClause = project && project !== "all" ? "WHERE project = ?" : "";
      const bindings = project && project !== "all" ? [project] : [];

      const totalRes = await env.DB.prepare(
        `SELECT COUNT(*) as total_views FROM page_views ${whereClause}`
      )
        .bind(...bindings)
        .first<{ total_views: number }>();

      const projectsRes = await env.DB.prepare(
        `SELECT project, COUNT(*) as views FROM page_views GROUP BY project ORDER BY views DESC LIMIT 10`
      ).all();

      const countriesRes = await env.DB.prepare(
        `SELECT country, COUNT(*) as views FROM page_views ${whereClause} GROUP BY country ORDER BY views DESC LIMIT 10`
      )
        .bind(...bindings)
        .all();

      const referrersRes = await env.DB.prepare(
        `SELECT referrer, COUNT(*) as views FROM page_views ${whereClause} GROUP BY referrer ORDER BY views DESC LIMIT 10`
      )
        .bind(...bindings)
        .all();

      const pathsRes = await env.DB.prepare(
        `SELECT path, COUNT(*) as views FROM page_views ${whereClause} GROUP BY path ORDER BY views DESC LIMIT 10`
      )
        .bind(...bindings)
        .all();

      const recentRes = await env.DB.prepare(
        `SELECT project, path, country, city, device, browser, created_at FROM page_views ${whereClause} ORDER BY created_at DESC LIMIT 25`
      )
        .bind(...bindings)
        .all();

      return new Response(
        JSON.stringify({
          project: project || "all",
          totalViews: totalRes?.total_views || 0,
          topProjects: projectsRes.results,
          topCountries: countriesRes.results,
          topReferrers: referrersRes.results,
          topPaths: pathsRes.results,
          recent: recentRes.results,
          timestamp: new Date().toISOString(),
        }),
        {
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        }
      );
    }

    // -----------------------------------------------------------------------
    // 6. DASHBOARD & LOGIN PORTAL: /
    // -----------------------------------------------------------------------
    const authed = await isAuthenticated(request, env);

    // If NOT authenticated, render the secure Login Screen
    if (!authed) {
      const loginHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Operator Access Required | Telemetry Hub</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #07090e; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass { background: rgba(13, 18, 30, 0.8); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }
    .shake { animation: shake 0.4s ease-in-out; }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
  <!-- Ambient background glow -->
  <div class="absolute w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -top-24 -left-24"></div>
  <div class="absolute w-[400px] h-[400px] bg-violet-500/10 rounded-full blur-3xl pointer-events-none -bottom-20 -right-20"></div>

  <div class="w-full max-w-md p-8 rounded-3xl glass shadow-2xl relative z-10 border border-white/10 space-y-6">
    <!-- Header -->
    <div class="space-y-2 text-center">
      <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[11px] font-mono text-cyan-400">
        <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
        <span>ANURAAGGRAO.COM / SECURITY</span>
      </div>
      <h1 class="text-2xl font-bold tracking-tight text-white">Operator Access Required</h1>
      <p class="text-xs text-slate-400 leading-relaxed font-mono">
        Telemetry and visitor intelligence are restricted to verified operators. Enter your master access key below.
      </p>
    </div>

    <!-- Error message banner -->
    <div id="errorBanner" class="hidden p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono text-center"></div>

    <!-- Login Form -->
    <form id="loginForm" class="space-y-4" onsubmit="handleLogin(event)">
      <div class="space-y-1.5">
        <label for="password" class="text-xs font-mono text-slate-300 block">Master Security Key</label>
        <div class="relative">
          <input
            type="password"
            id="password"
            required
            autocomplete="current-password"
            placeholder="••••••••••••••••"
            class="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-all"
          />
          <button
            type="button"
            onclick="togglePassword()"
            class="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-slate-200 font-mono px-2 py-1"
          >
            show
          </button>
        </div>
      </div>

      <button
        type="submit"
        id="submitBtn"
        class="w-full py-3.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-sky-500 hover:from-cyan-400 hover:to-sky-400 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-cyan-500/20 hover:scale-[1.01] active:scale-[0.99]"
      >
        Unlock Console
      </button>
    </form>

    <!-- Footer footnote -->
    <div class="pt-4 border-t border-white/10 text-center text-[10px] font-mono text-slate-500 space-y-1">
      <div>Protected by Cloudflare V8 Edge Isolates</div>
      <div class="text-slate-600">Timing-Safe HMAC-SHA256 Cryptographic Sessions</div>
    </div>
  </div>

  <script>
    function togglePassword() {
      const input = document.getElementById('password');
      input.type = input.type === 'password' ? 'text' : 'password';
    }

    async function handleLogin(e) {
      e.preventDefault();
      const pwd = document.getElementById('password').value;
      const btn = document.getElementById('submitBtn');
      const err = document.getElementById('errorBanner');
      const form = document.getElementById('loginForm');

      btn.disabled = true;
      btn.innerText = "Verifying...";
      err.classList.add('hidden');

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: pwd })
        });
        const data = await res.json();

        if (res.ok && data.ok) {
          btn.innerText = "Access Granted";
          btn.classList.remove('from-cyan-500', 'to-sky-500');
          btn.classList.add('from-emerald-500', 'to-teal-500');
          setTimeout(() => {
            window.location.reload();
          }, 300);
        } else {
          err.innerText = data.error || "Invalid security key";
          err.classList.remove('hidden');
          form.classList.add('shake');
          setTimeout(() => form.classList.remove('shake'), 400);
          btn.disabled = false;
          btn.innerText = "Unlock Console";
          document.getElementById('password').focus();
        }
      } catch (e) {
        err.innerText = "Connection failed. Please check network.";
        err.classList.remove('hidden');
        btn.disabled = false;
        btn.innerText = "Unlock Console";
      }
    }
  </script>
</body>
</html>
      `.trim();

      return new Response(loginHtml, {
        headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS },
      });
    }

    // If AUTHENTICATED, render the Full Dashboard with Sign Out button
    const dashboardHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Telemetry Hub | anuraaggrao.com</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #090d16; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); }
  </style>
</head>
<body class="min-h-screen p-4 sm:p-8 max-w-7xl mx-auto flex flex-col gap-6">
  <header class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-6">
    <div>
      <div class="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
        <span>ANURAAGGRAO.COM</span>
        <span>/</span>
        <span>TELEMETRY CLOUD</span>
        <span>/</span>
        <span class="text-emerald-400 font-semibold flex items-center gap-1">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
          AUTHENTICATED
        </span>
      </div>
      <h1 class="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
        Domain Visitor Intelligence
      </h1>
      <p class="text-xs text-slate-400 mt-1">
        Real-time telemetry powered by Cloudflare D1 & Edge Geolocation across all active subdomains.
      </p>
    </div>

    <div class="flex items-center gap-2 flex-wrap">
      <select id="projectSelect" class="bg-slate-900 border border-slate-700 text-xs rounded-xl px-3 py-2 text-slate-200 focus:outline-none font-mono">
        <option value="all">🌐 All Ecosystem Projects</option>
        <option value="craft">craft.anuraaggrao.com (Craft Studio)</option>
        <option value="utils">utils.anuraaggrao.com (Developer Recon)</option>
        <option value="music">music.anuraaggrao.com (Audio DSP)</option>
        <option value="status">status.anuraaggrao.com (Status Biome)</option>
        <option value="portfolio">anuraaggrao.com (Main Portal)</option>
        <option value="volt">volt.anuraaggrao.com (Battery Monitor)</option>
        <option value="quiz">quiz.anuraaggrao.com (Context0 Quiz)</option>
        <option value="tetra">tetra.anuraaggrao.com (Tetra Arcade)</option>
        <option value="countdown">countdown.anuraaggrao.com (EpiCountdown)</option>
        <option value="fidget">fidget.anuraaggrao.com (Sensory Suite)</option>
      </select>
      <button onclick="loadStats()" class="px-3.5 py-2 rounded-xl text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all font-mono">
        Refresh
      </button>
      <button onclick="logout()" class="px-3.5 py-2 rounded-xl text-xs font-semibold bg-white/5 hover:bg-red-500/20 text-slate-300 hover:text-red-300 border border-white/10 hover:border-red-500/30 transition-all font-mono">
        Sign Out
      </button>
    </div>
  </header>

  <!-- Metrics Grid -->
  <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
    <div class="p-5 rounded-2xl glass">
      <span class="text-xs text-slate-400 font-medium">Total Recorded Hits</span>
      <div id="totalViews" class="text-3xl font-bold font-mono text-cyan-400 mt-1">--</div>
      <span class="text-[11px] text-slate-500">Global edge visits</span>
    </div>

    <div class="p-5 rounded-2xl glass">
      <span class="text-xs text-slate-400 font-medium">Active Subdomains</span>
      <div id="activeProjectsCount" class="text-3xl font-bold font-mono text-violet-400 mt-1">--</div>
      <span class="text-[11px] text-slate-500">Live projects reporting</span>
    </div>

    <div class="p-5 rounded-2xl glass">
      <span class="text-xs text-slate-400 font-medium">Top Country Origin</span>
      <div id="topCountry" class="text-3xl font-bold font-mono text-emerald-400 mt-1">--</div>
      <span class="text-[11px] text-slate-500">Dominant demographic</span>
    </div>

    <div class="p-5 rounded-2xl glass">
      <span class="text-xs text-slate-400 font-medium">Auto-Telemetry</span>
      <div class="flex items-center gap-2 mt-2">
        <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
        <span class="text-sm font-bold font-mono text-white">LIVE PROBES</span>
      </div>
      <span class="text-[11px] text-slate-500">Sub-10ms D1 ingestion</span>
    </div>
  </div>

  <!-- Tables Grid: 4 Drilldown Cards -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
    <!-- Top Countries -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Visitor Origin</span>
        <span class="text-[10px] text-cyan-400 font-mono">Countries</span>
      </h3>
      <div id="countriesList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>

    <!-- Top Visited Routes -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Top Routes</span>
        <span class="text-[10px] text-sky-400 font-mono">Paths</span>
      </h3>
      <div id="pathsList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>

    <!-- Top Referrers -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Traffic Sources</span>
        <span class="text-[10px] text-violet-400 font-mono">Referrers</span>
      </h3>
      <div id="referrersList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>

    <!-- Top Projects -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Subdomain Share</span>
        <span class="text-[10px] text-emerald-400 font-mono">Hits</span>
      </h3>
      <div id="projectsList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>
  </div>

  <!-- Live Stream Table -->
  <div class="p-5 rounded-2xl glass">
    <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
      <span>Recent Live Ingestion Stream</span>
      <span class="text-xs font-mono text-cyan-400">Chronological Telemetry</span>
    </h3>
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="text-slate-400 border-b border-slate-800">
          <tr>
            <th class="py-2 px-3">Project</th>
            <th class="py-2 px-3">Path</th>
            <th class="py-2 px-3">Country / City</th>
            <th class="py-2 px-3">Device & Browser</th>
            <th class="py-2 px-3 text-right">Timestamp</th>
          </tr>
        </thead>
        <tbody id="recentTable" class="divide-y divide-slate-800/60 font-mono">
          <tr><td colspan="5" class="py-6 text-center text-slate-500 font-sans">Awaiting hits...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Integration snippet card -->
  <div class="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
    <div class="text-xs">
      <span class="font-bold text-slate-200">How to track any project:</span>
      <p class="text-slate-400 mt-0.5">Drop this single script tag into the &lt;head&gt; or layout of any site:</p>
      <code class="block mt-2 p-2.5 rounded-lg bg-slate-950 font-mono text-cyan-300 border border-slate-800 text-[11px] overflow-x-auto">
        &lt;script defer src="${url.origin}/tracker.js" data-project="craft"&gt;&lt;/script&gt;
      </code>
    </div>
  </div>

  <script>
    async function logout() {
      try {
        await fetch('/api/logout', { method: 'POST' });
      } finally {
        window.location.reload();
      }
    }

    async function loadStats() {
      const proj = document.getElementById('projectSelect').value;
      try {
        const res = await fetch('/api/stats?project=' + encodeURIComponent(proj));
        if (res.status === 401) {
          window.location.reload();
          return;
        }
        const data = await res.json();
        
        document.getElementById('totalViews').innerText = data.totalViews.toLocaleString();
        document.getElementById('activeProjectsCount').innerText = (data.topProjects || []).length;
        document.getElementById('topCountry').innerText = (data.topCountries && data.topCountries[0]) ? data.topCountries[0].country : 'None';

        // Render countries
        const cList = document.getElementById('countriesList');
        cList.innerHTML = (data.topCountries || []).map(c => 
          \`<div class="py-2 flex items-center justify-between"><span class="font-mono text-slate-300">\${c.country}</span><span class="font-bold text-cyan-400 font-mono">\${c.views}</span></div>\`
        ).join('') || '<div class="py-4 text-center text-slate-500">No events yet</div>';

        // Render paths
        const pathList = document.getElementById('pathsList');
        pathList.innerHTML = (data.topPaths || []).map(p => 
          \`<div class="py-2 flex items-center justify-between"><span class="font-mono text-slate-300 truncate max-w-[160px]">\${p.path}</span><span class="font-bold text-sky-400 font-mono">\${p.views}</span></div>\`
        ).join('') || '<div class="py-4 text-center text-slate-500">No events yet</div>';

        // Render referrers
        const rList = document.getElementById('referrersList');
        rList.innerHTML = (data.topReferrers || []).map(r => 
          \`<div class="py-2 flex items-center justify-between"><span class="truncate max-w-[160px] text-slate-300 font-mono">\${r.referrer}</span><span class="font-bold text-violet-400 font-mono">\${r.views}</span></div>\`
        ).join('') || '<div class="py-4 text-center text-slate-500">No events yet</div>';

        // Render projects
        const pList = document.getElementById('projectsList');
        pList.innerHTML = (data.topProjects || []).map(p => 
          \`<div class="py-2 flex items-center justify-between"><span class="text-slate-300 font-mono">\${p.project}</span><span class="font-bold text-emerald-400 font-mono">\${p.views}</span></div>\`
        ).join('') || '<div class="py-4 text-center text-slate-500">No events yet</div>';

        // Render recent
        const tbody = document.getElementById('recentTable');
        tbody.innerHTML = (data.recent || []).map(row => 
          \`<tr class="hover:bg-slate-800/40">
            <td class="py-2 px-3 text-cyan-300 font-semibold">\${row.project}</td>
            <td class="py-2 px-3 text-slate-300 truncate max-w-[140px]">\${row.path}</td>
            <td class="py-2 px-3 text-slate-400">\${row.country} · \${row.city}</td>
            <td class="py-2 px-3 text-slate-400">\${row.device} · \${row.browser}</td>
            <td class="py-2 px-3 text-right text-slate-500 text-[10px]">\${row.created_at}</td>
          </tr>\`
        ).join('') || '<tr><td colspan="5" class="py-6 text-center text-slate-500 font-sans">Awaiting hits...</td></tr>';
      } catch (e) {
        console.error(e);
      }
    }
    document.getElementById('projectSelect').addEventListener('change', loadStats);
    loadStats();
    // Auto-poll every 30s
    setInterval(loadStats, 30000);
  </script>
</body>
</html>
    `.trim();

    return new Response(dashboardHtml, {
      headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS },
    });
  },
};
