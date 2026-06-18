# Remote Access Audit

A PowerShell tool that scans a Windows PC for remote-access software, hidden
RATs, suspicious services/tasks/startup entries, risky network connections, and
accounts with remote/admin access — then opens an interactive remediation window
and saves an HTML report.

## How to run

On the customer's PC, open **Windows PowerShell** (normal or admin) and paste:

```powershell
irm audit.nerdyneighbor.net | iex
```

> Direct fallback if the proxy is ever down:
> ```powershell
> irm -Headers @{Accept='application/vnd.github.raw'} https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1 | iex
> ```

That's it. The script will:

1. **Pull the latest committed version** straight from the GitHub API (not the
   cached `raw.githubusercontent.com` CDN), so you always run the newest code —
   no stale copies, nothing to update on the machine.
2. **Self-elevate** with a single UAC prompt (click **Yes**).
3. Run every scan, **open the remediation window** (review findings, view or run
   the fix for each one), and **save an HTML report to the Desktop** that opens
   automatically when you close the window.

> If you hit a TLS error on a very old/unpatched machine, run this first in the
> same window, then paste the command again:
> ```powershell
> [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
> ```

## What it checks

| # | Scan | Notes |
|---|------|-------|
| 1 | Running processes | catalogued remote tools + unsigned binaries in user-writable paths |
| 2 | Windows services | binary path + signer + catalog match |
| 3 | Network connections | known remote-access / C2 ports (management ports rated lower) |
| 4 | Scheduled tasks | remote-tool command lines, bad paths, obfuscated names (Microsoft OS tasks excluded) |
| 5 | Registry Run keys | startup entries pointing at remote tools or user-writable paths |
| 6 | Known install folders | TeamViewer, AnyDesk, VNC, ScreenConnect, etc. |
| 7 | RDP configuration | enabled state, port, Network Level Authentication |
| 8 | ScreenConnect / ConnectWise | deep detection incl. the LSA SSP-DLL persistence trick + removal steps |
| 9 | AppData executables | catalogued tools / unsigned remote-named binaries (incl. buried deep) |
|10 | Startup folders | per-user + common Startup persistence (remote tools, scripts, unsigned exes) |
|11 | Defender status & exclusions | real-time protection off, tamper protection off, scan exclusions |
|12 | WMI persistence | event-subscription (CommandLine/ActiveScript) fileless persistence |
|13 | Suspicious outbound traffic | beaconing / odd ports from untrusted processes, with owning process + path |

## How false positives are kept low

- **Authenticode signature trust** — Microsoft-signed OS binaries are never
  flagged on name alone; the signer is shown on every finding.
- **Precise catalog matching** — exact executable names, service patterns,
  install-path hints, and signer names, instead of loose substring keywords
  (so `mailbox.exe`, `toolbox.exe`, `sandboxie.exe`, etc. are no longer flagged).
- **No broad globs / no "buried in AppData" heuristic** — the AppData scan only
  surfaces catalogued tools or unsigned binaries with remote-access names.

## Hosting (`audit.nerdyneighbor.net`)

`audit.nerdyneighbor.net` is a **Cloudflare Pages** project. The page itself has
no static content to speak of — it's a single **Pages Function**
(`functions/index.js`) that, on every request, calls the GitHub Contents API
with `Accept: application/vnd.github.raw` and returns the raw script. That means:

- `irm audit.nerdyneighbor.net | iex` always runs the **latest commit** (the API
  is not CDN-cached like `raw.githubusercontent.com`).
- Opening the URL in a browser shows usage instructions instead of raw script.
- The repo is connected to Pages via Git, so **pushing to `main` redeploys the
  function automatically**. The *script* is always current regardless of deploys.

### Optional: lift the GitHub rate limit
Unauthenticated GitHub API calls are limited to 60/hour per IP. Since the proxy
calls GitHub from Cloudflare's network, set a read-only token to get 5,000/hour:

1. Create a GitHub token (classic, no scopes needed for a public repo — just
   "public access"; or a fine-grained token with **Contents: Read** on this repo).
2. In the Cloudflare dashboard: **Pages → nerdyneighbor-audit → Settings →
   Environment variables → Production**, add `GITHUB_TOKEN` = the token, and
   redeploy. The function picks it up automatically.

## Notes

- The GitHub API allows 60 unauthenticated requests/hour per IP — far above what
  one technician running this on one machine at a time will use.
- Detection is intentionally broad: legitimate RMM/remote tools are reported too,
  so you can confirm each one is authorized.
