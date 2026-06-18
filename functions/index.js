// Cloudflare Pages Function
// ---------------------------------------------------------------------------
// Serves the LATEST committed RemoteAccessAudit.ps1 as raw text so that
//   irm audit.nerdyneighbor.net | iex
// always runs the newest version.
//
// It fetches from the GitHub *Contents API* (not raw.githubusercontent.com),
// because the API is not CDN-cached the way the raw host is — so there is no
// up-to-5-minute staleness. The `Accept: application/vnd.github.raw` header
// makes the API return the file bytes directly instead of base64 JSON.
//
// Optional: set a `GITHUB_TOKEN` secret on the Pages project to raise the API
// rate limit from 60 to 5,000 requests/hour (recommended — see README).
// ---------------------------------------------------------------------------

const REPO_API =
  'https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1';

export async function onRequest(context) {
  // If a human opens the URL in a browser, show instructions instead of dumping
  // raw PowerShell. `irm` requests do not send an `Accept: text/html`.
  const accept = context.request.headers.get('Accept') || '';
  if (accept.includes('text/html')) {
    return new Response(LANDING_HTML, {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  const headers = {
    'Accept': 'application/vnd.github.raw',
    'User-Agent': 'nerdyneighbor-audit-proxy',
  };
  if (context.env && context.env.GITHUB_TOKEN) {
    headers['Authorization'] = `Bearer ${context.env.GITHUB_TOKEN}`;
  }

  let upstream;
  try {
    upstream = await fetch(REPO_API, { headers });
  } catch (e) {
    return errorScript(502, `network error reaching GitHub: ${e}`);
  }

  if (!upstream.ok) {
    return errorScript(
      502,
      `GitHub returned ${upstream.status} ${upstream.statusText}` +
        (upstream.status === 403 ? ' (rate limited — set a GITHUB_TOKEN secret)' : '')
    );
  }

  const script = await upstream.text();
  return new Response(script, {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store', // always serve the latest commit
      'x-source': 'github-contents-api',
    },
  });
}

const LANDING_HTML = `<!doctype html><meta charset="utf-8">
<title>Nerdy Neighbor — Remote Access Audit</title>
<body style="font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:60px auto;padding:0 16px;color:#1e293b">
<h1>Remote Access Audit</h1>
<p>Run this on the customer's PC in Windows PowerShell (normal or admin):</p>
<pre style="background:#0f172a;color:#86efac;padding:14px 16px;border-radius:8px;overflow:auto">irm audit.nerdyneighbor.net | iex</pre>
<p style="color:#64748b;font-size:13px">Always serves the latest committed version via the GitHub API.</p>
</body>`;

// Return a tiny PowerShell snippet so that even on failure `| iex` prints a
// clear message instead of executing garbage.
function errorScript(status, reason) {
  const body =
    `Write-Host 'Remote Access Audit could not be downloaded.' -ForegroundColor Red\n` +
    `Write-Host '${reason.replace(/'/g, "''")}' -ForegroundColor Yellow\n`;
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  });
}
