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
  const url = new URL(context.request.url);
  const wantDownload =
    url.searchParams.has('download') ||
    url.pathname.replace(/\/+$/, '').toLowerCase().endsWith('/download');
  const accept = context.request.headers.get('Accept') || '';

  // A human opening the URL in a browser (and not asking to download) gets the
  // instructions page. `irm` requests do not send `Accept: text/html`.
  if (accept.includes('text/html') && !wantDownload) {
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
  const respHeaders = {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store', // always serve the latest commit
    'x-source': 'github-contents-api',
  };
  if (wantDownload) {
    // Force the browser to save the file instead of displaying it.
    respHeaders['content-type'] = 'application/octet-stream';
    respHeaders['content-disposition'] = 'attachment; filename="RemoteAccessAudit.ps1"';
  }
  return new Response(script, { headers: respHeaders });
}

const LANDING_HTML = `<!doctype html><meta charset="utf-8">
<title>Nerdy Neighbor — Remote Access Audit</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<body style="font-family:Segoe UI,Arial,sans-serif;max-width:660px;margin:56px auto;padding:0 18px;color:#1e293b;line-height:1.5">
<h1 style="margin-bottom:4px">Remote Access Audit</h1>
<p style="color:#64748b;margin-top:0">Scan a Windows PC for unauthorized remote-access software.</p>

<h3 style="margin-bottom:6px">Recommended — run it directly</h3>
<p style="margin-top:0">Open <strong>Windows PowerShell</strong> on the PC, paste this line, press Enter, and click <strong>Yes</strong> on the prompt:</p>
<div style="display:flex;gap:8px;align-items:stretch;flex-wrap:wrap">
  <pre id="cmd" style="flex:1;min-width:280px;background:#0f172a;color:#86efac;padding:14px 16px;border-radius:8px;overflow:auto;margin:0">irm audit.nerdyneighbor.net | iex</pre>
  <button onclick="navigator.clipboard.writeText('irm audit.nerdyneighbor.net | iex').then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)})"
          style="border:0;border-radius:8px;background:#1e3a5f;color:#fff;font-weight:600;padding:0 18px;cursor:pointer">Copy</button>
</div>

<h3 style="margin-bottom:6px">Or download the script</h3>
<p style="margin-top:0">Save the file, then right-click it and choose <em>Run with PowerShell</em> (it will request Administrator rights).</p>
<p><a href="?download=1" download="RemoteAccessAudit.ps1"
      style="display:inline-block;background:#16a34a;color:#fff;text-decoration:none;font-weight:700;padding:12px 22px;border-radius:8px">⬇ Download RemoteAccessAudit.ps1</a></p>

<p style="color:#94a3b8;font-size:12px;margin-top:28px">Always serves the latest version via the GitHub API · Nerdy Neighbor</p>
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
