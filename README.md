# Remote Access Audit

A PowerShell tool that scans a Windows PC for remote-access software, hidden
RATs, suspicious services/tasks/startup entries, risky network connections, and
accounts with remote/admin access — then opens an interactive remediation window
and saves an HTML report.

## How to run

On the customer's PC, open **Windows PowerShell** (normal or admin) and paste:

```powershell
irm -Headers @{Accept='application/vnd.github.raw'} https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1 | iex
```

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
| 9 | AppData executables | catalogued tools / unsigned remote-named binaries only |
|10 | Remote-access users | members of Administrators and Remote Desktop Users (SID-based, language-independent) |
|11 | Suspicious outbound traffic | beaconing / odd ports from untrusted processes |

## How false positives are kept low

- **Authenticode signature trust** — Microsoft-signed OS binaries are never
  flagged on name alone; the signer is shown on every finding.
- **Precise catalog matching** — exact executable names, service patterns,
  install-path hints, and signer names, instead of loose substring keywords
  (so `mailbox.exe`, `toolbox.exe`, `sandboxie.exe`, etc. are no longer flagged).
- **No broad globs / no "buried in AppData" heuristic** — the AppData scan only
  surfaces catalogued tools or unsigned binaries with remote-access names.

## Notes

- The GitHub API allows 60 unauthenticated requests/hour per IP — far above what
  one technician running this on one machine at a time will use.
- Detection is intentionally broad: legitimate RMM/remote tools are reported too,
  so you can confirm each one is authorized.
