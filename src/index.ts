export interface Env {
  DB: D1Database;
}

function parseUserAgent(ua: string | null): { device: string; browser: string; os: string } {
  if (!ua) return { device: "desktop", browser: "other", os: "other" };
  const lower = ua.toLowerCase();

  // Device
  let device = "desktop";
  if (/mobile|android|iphone|ipod/.test(lower)) device = "mobile";
  else if (/tablet|ipad/.test(lower)) device = "tablet";

  // OS
  let os = "other";
  if (lower.includes("windows")) os = "Windows";
  else if (lower.includes("mac os") || lower.includes("macintosh")) os = "macOS";
  else if (lower.includes("iphone") || lower.includes("ipad")) os = "iOS";
  else if (lower.includes("android")) os = "Android";
  else if (lower.includes("linux")) os = "Linux";

  // Browser
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
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 1. Telemetry Ingestion Endpoint: /api/hit
    if (url.pathname === "/api/hit" || url.pathname === "/hit.gif") {
      let project = url.searchParams.get("project") || "";
      let path = url.searchParams.get("path") || "/";
      let referrer = url.searchParams.get("referrer") || request.headers.get("Referer") || "direct";

      if (request.method === "POST") {
        try {
          const body = await request.json() as Record<string, string>;
          if (body.project) project = body.project;
          if (body.path) path = body.path;
          if (body.referrer) referrer = body.referrer;
        } catch {
          // Fall back to query parameters
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

      // 1x1 transparent GIF response if requested as image beacon
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

    // 2. Embeddable Tracking Script: /tracker.js
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

    // 3. Telemetry Query API: /api/stats
    if (url.pathname === "/api/stats") {
      const project = url.searchParams.get("project");
      const whereClause = project && project !== "all" ? "WHERE project = ?" : "";
      const bindings = project && project !== "all" ? [project] : [];

      // Query totals
      const totalRes = await env.DB.prepare(
        `SELECT COUNT(*) as total_views FROM page_views ${whereClause}`
      )
        .bind(...bindings)
        .first<{ total_views: number }>();

      // Query top projects
      const projectsRes = await env.DB.prepare(
        `SELECT project, COUNT(*) as views FROM page_views GROUP BY project ORDER BY views DESC LIMIT 10`
      ).all();

      // Query top countries
      const countriesRes = await env.DB.prepare(
        `SELECT country, COUNT(*) as views FROM page_views ${whereClause} GROUP BY country ORDER BY views DESC LIMIT 10`
      )
        .bind(...bindings)
        .all();

      // Query top referrers
      const referrersRes = await env.DB.prepare(
        `SELECT referrer, COUNT(*) as views FROM page_views ${whereClause} GROUP BY referrer ORDER BY views DESC LIMIT 10`
      )
        .bind(...bindings)
        .all();

      // Query recent hits
      const recentRes = await env.DB.prepare(
        `SELECT project, path, country, city, device, browser, created_at FROM page_views ${whereClause} ORDER BY created_at DESC LIMIT 20`
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
          recent: recentRes.results,
          timestamp: new Date().toISOString(),
        }),
        {
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        }
      );
    }

    // 4. SVG Badge Generator: /api/badge
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

    // 5. Live Glassmorphic Web Dashboard: /
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Telemetry Hub | anuraaggrao.com</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #090d16; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
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
      </div>
      <h1 class="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
        Domain Visitor Intelligence
      </h1>
      <p class="text-xs text-slate-400 mt-1">
        Real-time telemetry powered by Cloudflare D1 & Edge Geolocation across all active subdomains.
      </p>
    </div>

    <div class="flex items-center gap-2">
      <select id="projectSelect" class="bg-slate-900 border border-slate-700 text-xs rounded-xl px-3 py-2 text-slate-200 focus:outline-none">
        <option value="all">All Projects</option>
        <option value="utils">utils.anuraaggrao.com</option>
        <option value="music">music.anuraaggrao.com</option>
        <option value="status">status.anuraaggrao.com</option>
        <option value="portfolio">anuraaggrao.com</option>
        <option value="countdown">countdown.anuraaggrao.com</option>
        <option value="quiz">quiz.anuraaggrao.com</option>
        <option value="volt">volt.anuraaggrao.com</option>
      </select>
      <button onclick="loadStats()" class="px-3 py-2 rounded-xl text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all">
        Refresh
      </button>
    </div>
  </header>

  <!-- Metrics Grid -->
  <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
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
      <span class="text-[11px] text-slate-500">Dominant visitor demographic</span>
    </div>
  </div>

  <!-- Tables Grid -->
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Top Countries -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Visitor Locations (Countries)</span>
        <span class="text-[10px] text-cyan-400 font-mono">Cloudflare CF-IPCountry</span>
      </h3>
      <div id="countriesList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>

    <!-- Top Referrers -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Visitor From (Referrers)</span>
        <span class="text-[10px] text-violet-400 font-mono">Traffic Source</span>
      </h3>
      <div id="referrersList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>

    <!-- Top Projects -->
    <div class="p-5 rounded-2xl glass flex flex-col">
      <h3 class="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
        <span>Traffic per Subdomain</span>
        <span class="text-[10px] text-emerald-400 font-mono">Breakdown</span>
      </h3>
      <div id="projectsList" class="space-y-2 text-xs divide-y divide-slate-800/80 overflow-y-auto max-h-64">
        <div class="py-4 text-center text-slate-500">No events yet</div>
      </div>
    </div>
  </div>

  <!-- Live Stream Table -->
  <div class="p-5 rounded-2xl glass">
    <h3 class="text-sm font-semibold text-slate-200 mb-3">Recent Live Visits</h3>
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="text-slate-400 border-b border-slate-800">
          <tr>
            <th class="py-2 px-3">Project</th>
            <th class="py-2 px-3">Path</th>
            <th class="py-2 px-3">Country / City</th>
            <th class="py-2 px-3">Device & Browser</th>
            <th class="py-2 px-3 text-right">Time</th>
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
        &lt;script defer src="${url.origin}/tracker.js" data-project="utils"&gt;&lt;/script&gt;
      </code>
    </div>
  </div>

  <script>
    async function loadStats() {
      const proj = document.getElementById('projectSelect').value;
      try {
        const res = await fetch('/api/stats?project=' + encodeURIComponent(proj));
        const data = await res.json();
        
        document.getElementById('totalViews').innerText = data.totalViews.toLocaleString();
        document.getElementById('activeProjectsCount').innerText = (data.topProjects || []).length;
        document.getElementById('topCountry').innerText = (data.topCountries && data.topCountries[0]) ? data.topCountries[0].country : 'None';

        // Render countries
        const cList = document.getElementById('countriesList');
        cList.innerHTML = (data.topCountries || []).map(c => 
          \`<div class="py-2 flex items-center justify-between"><span class="font-mono text-slate-300">\${c.country}</span><span class="font-bold text-cyan-400 font-mono">\${c.views}</span></div>\`
        ).join('') || '<div class="py-4 text-center text-slate-500">No events yet</div>';

        // Render referrers
        const rList = document.getElementById('referrersList');
        rList.innerHTML = (data.topReferrers || []).map(r => 
          \`<div class="py-2 flex items-center justify-between"><span class="truncate max-w-[200px] text-slate-300 font-mono">\${r.referrer}</span><span class="font-bold text-violet-400 font-mono">\${r.views}</span></div>\`
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
  </script>
</body>
</html>
    `.trim();

    return new Response(html, {
      headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS },
    });
  },
};
