# Remote Access Audit

A PowerShell tool that finds remote-access software, hidden RATs and the
backdoors scammers leave behind on a Windows PC - then fixes them from an
interactive window where **every Fix button runs real code and shows the
result**. It self-elevates and runs with a single `irm | iex` command.
Works on **Windows 7 SP1 (WMF 5.1), 8.1, 10 and 11**.

## How to run

On the customer's PC, open **Windows PowerShell** (normal or admin) and paste:

```powershell
irm audit.nerdyneighbor.net | iex
```

Windows 7 (needs WMF 5.1; PowerShell there defaults to TLS 1.0, which GitHub and
Cloudflare reject):

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm audit.nerdyneighbor.net | iex
```

> Direct fallback if the proxy is ever down:
> ```powershell
> irm -Headers @{Accept='application/vnd.github.raw'} https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1 | iex
> ```

The script pulls the latest commit, asks for admin once (UAC), runs 14 scans
(about a minute), opens the remediation window, and saves an HTML + JSON report
to the Desktop when the window is closed.

### Options (set before the `irm` line)

| Variable | Effect |
|----------|--------|
| `$env:NN_AUDIT_MODE = 'report'` | No window and no fixes: scan and save the report only (RMM / SuperOps runs). Report goes to `C:\ProgramData\NerdyNeighbor\RemoteAccessAudit`. |
| `$env:NN_AUDIT_TRUST = 'SuperOps,OpenSSH'` | Remote tools **you** deployed. They are reported as INFO instead of a threat. This is the default; set `'none'` to trust nothing. |
| `$env:NN_AUDIT_OUT = 'C:\Temp'` | Where to save the report. |

## The remediation window

- Findings are grouped by category, most severe first, with a plain-English
  explanation and a **Details** section (paths, signer, command line, and exactly
  what each fix will do).
- **Fix buttons** (`Uninstall`, `Quarantine file`, `Remove startup entry`,
  `Delete task`, `Remove service`, `Full removal` for ScreenConnect, `Disable RDP`,
  `Remove exclusion`, ...) ask once, run **in-process** (the window is already
  elevated), and the card then shows **FIXED / FAILED / PARTIAL** with the result.
- **Fix all HIGH** runs the recommended fix for every HIGH item after one
  confirmation. **Rescan** re-runs every scan to verify.
- **Nothing is deleted outright.** Files and folders are moved to
  `C:\ProgramData\NerdyNeighbor\RemoteAccessAudit\quarantine\<run>` and executables
  renamed `.quarantined`; registry keys and task XML are exported to `...\backup\<run>`
  before any change. Locked files are scheduled for deletion at reboot.
- Every action is logged to `C:\ProgramData\NerdyNeighbor\audit.log` and listed in
  the report.

## What it checks

| Scan | What it looks for |
|------|-------------------|
| Running programs | 70+ catalogued remote tools / RATs / tunnels; unsigned programs running from user folders; fake `svchost.exe`-style names |
| Services | remote-tool services, services running from user-writable folders, download/encoded commands |
| Installed programs | remote tools in Programs and Features (all users) - with an **Uninstall** fix |
| Network | listening remote-access ports, live connections on remote/C2 ports, suspicious outside traffic (beaconing, odd ports, user-folder programs) - `netstat` fallback on Windows 7 |
| Scheduled tasks | read straight from the task XML files: remote tools, encoded/download commands, unsigned programs in user folders, random/hidden tasks |
| Startup registry + backdoors | Run/RunOnce for every loaded user; Winlogon Shell/Userinit; AppInit_DLLs; IFEO debugger hijacks; Sticky-Keys/Utilman replaced with `cmd.exe`; non-Microsoft LSA packages (ScreenConnect's locked DLL) |
| Startup folders | all users: scripts, remote tools, unsigned programs |
| Remote tool folders | TeamViewer, AnyDesk, VNC, ScreenConnect, ... for every profile; ScreenConnect **full removal** (service + uninstaller + LSA package + folders + keys) |
| User folders (deep scan) | AppData/Temp/Public/ProgramData/Downloads, **junction-safe**: hidden remote tools, downloaded remote-tool installers, adware-style installers, fake system files, unsigned programs buried deep |
| Antivirus + exclusions | no AV / AV off / out of date (Security Center), Defender policy kill-switches, Defender **and Security Essentials** exclusions |
| WMI persistence | event subscriptions that run commands |
| RDP / remote settings | RDP + NLA, Remote Assistance, WinRM listeners |
| User accounts | hidden accounts, Guest enabled, recently created/changed admins, list of admins |
| Proxy / hosts file | per-user proxy / PAC scripts, WinHTTP proxy, hosts-file redirects of bank/security sites |

Anything a scan could not check (e.g. a Windows 7 fallback was used, or a folder
was unreadable) is listed under **Scan coverage** in the report instead of being
silently skipped.

## How false positives are kept low

- **Real signature checks, including Windows 7.** Windows 7's
  `Get-AuthenticodeSignature` reports every in-box Windows file as `NotSigned`
  because it does not check catalog signatures. The script asks the Windows
  catalog database directly (same check as signtool/sigcheck), so genuine
  Windows files are recognised on every version.
- **Precise catalog matching** - exact executable names, service patterns,
  install-path patterns and signer names, never loose substrings.
- **Context-aware severity** - scam-favoured tools (AnyDesk, TeamViewer,
  ScreenConnect, UltraViewer, ...) and trojans are HIGH; RMM agents are MEDIUM;
  your own tools (`NN_AUDIT_TRUST`) are INFO. Risk counts only open items.
- **Junction-safe file walk** - `AppData\Local\Application Data` loops are skipped
  (Windows PowerShell's `Get-ChildItem -Recurse` follows them forever).

## Hosting (`audit.nerdyneighbor.net`)

`audit.nerdyneighbor.net` is a **Cloudflare Pages** project. The page itself has
no static content to speak of — it's a single **Pages Function**
(`functions/index.js`) that, on every request, calls the GitHub Contents API
with `Accept: application/vnd.github.raw` and returns the raw script. That means:

- `irm audit.nerdyneighbor.net | iex` always runs the **latest commit** (the API
  is not CDN-cached like `raw.githubusercontent.com`).
- Opening the URL in a **browser** shows usage instructions, a **Copy** button for
  the command, and a **Download `RemoteAccessAudit.ps1`** button (`?download=1`
  returns the file as an attachment).
- A one-page printable technician sheet is served at **`/print`**.
- The **script** is always current regardless of deploys, because the function
  fetches it from the GitHub API at request time. The **function code itself** is
  deployed with `wrangler pages deploy public` (direct upload) and does **not**
  auto-redeploy on push — re-run that command after editing `functions/index.js`
  or `public/`. (Optionally connect the repo under Pages → Settings → Builds &
  deployments to enable push-to-deploy.)

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
