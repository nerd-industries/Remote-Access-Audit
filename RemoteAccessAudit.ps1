# ============================================================
#  Remote Access Audit  —  nerd industries
# ------------------------------------------------------------
#  Run it (paste into Windows PowerShell — normal OR admin):
#
#    irm audit.nerdyneighbor.net | iex
#
#  (audit.nerdyneighbor.net is a Cloudflare proxy that returns this exact file,
#   latest commit, via the GitHub API. Direct fallback if the proxy is down:
#   irm -Headers @{Accept='application/vnd.github.raw'} https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1 | iex )
#
#  - Pulls the latest committed version every time (GitHub API,
#    not the cached raw CDN) so you never run a stale copy.
#  - Self-elevates with a single UAC prompt, runs every scan,
#    opens the remediation window, and saves an HTML report.
# ============================================================

# Use TLS 1.2 for web calls on older Windows builds
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# Canonical source — used to relaunch elevated as the exact same latest copy
$RAA_Source = 'https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1'

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ── Self-elevation ──────────────────────────────────────────────────────────
# When launched non-elevated via irm|iex there is no script file on disk, so we
# relaunch by re-running the same one-liner inside an elevated PowerShell. The
# elevated copy is fetched fresh from the API, so it is always the latest commit.
if (-not (Test-IsAdmin)) {
    Write-Host ""
    Write-Host "  Remote Access Audit needs Administrator rights." -ForegroundColor Yellow
    Write-Host "  Click YES on the Windows UAC prompt..."          -ForegroundColor Yellow
    $relaunch = "[Net.ServicePointManager]::SecurityProtocol=" +
                "[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; " +
                "irm -Headers @{Accept='application/vnd.github.raw'} '$RAA_Source' | iex"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($relaunch))
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-EncodedCommand',$enc | Out-Null
    } catch {
        Write-Host "  Elevation cancelled — the audit cannot run without admin rights." -ForegroundColor Red
    }
    return
}

# ── Run configuration ───────────────────────────────────────────────────────
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$timestamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm'
$OutDir     = Join-Path $env:USERPROFILE 'Desktop'
$reportFile = Join-Path $OutDir "RemoteAccessAudit_$timestamp.html"

Write-Host ""
Write-Host "  Remote Access Audit  (running as Administrator)" -ForegroundColor Cyan
Write-Host "  Computer: $env:COMPUTERNAME    User: $env:USERNAME" -ForegroundColor Gray
Write-Host ""

# ── Catalog of remote-access / remote-control tools ─────────────────────────
# Matching is PRECISE — exact exe base name, service-name pattern, install-path
# hint, or Authenticode signer — never loose substring matching. This is what
# eliminates the false positives a keyword scanner produces.
$RemoteTools = @(
    @{ Name='TeamViewer';                  Exe=@('teamviewer','teamviewer_service','tv_w32','tv_x64'); Svc=@('teamviewer*'); Path=@('*\teamviewer*'); Signer=@('teamviewer'); Class='Commercial remote control' }
    @{ Name='AnyDesk';                      Exe=@('anydesk'); Svc=@('anydesk*'); Path=@('*\anydesk*'); Signer=@('anydesk','philandro'); Class='Commercial remote control' }
    @{ Name='ScreenConnect / ConnectWise';  Exe=@('screenconnect.clientservice','screenconnect.windowsclient','connectwisecontrol.client'); Svc=@('screenconnect*','connectwisecontrol*'); Path=@('*\screenconnect*','*\connectwisecontrol*','*\connectwise control*'); Signer=@('connectwise','screenconnect','elsinore'); Class='RMM / remote support (heavily abused in scams)' }
    @{ Name='LogMeIn / GoTo';               Exe=@('logmein','lmiguardiansvc','logmeinsystray','ramaint'); Svc=@('logmein*'); Path=@('*\logmein*'); Signer=@('logmein','goto'); Class='Commercial remote control' }
    @{ Name='Splashtop';                    Exe=@('sragent','srservice','strwinclt','splashtop'); Svc=@('splashtop*','sragent*'); Path=@('*\splashtop*'); Signer=@('splashtop'); Class='Commercial remote control' }
    @{ Name='RustDesk';                     Exe=@('rustdesk'); Svc=@('rustdesk*'); Path=@('*\rustdesk*'); Signer=@('rustdesk','purslane'); Class='Open-source remote control (abused)' }
    @{ Name='Radmin';                       Exe=@('radmin','rserver3','famitrfc'); Svc=@('rserver*','radmin*'); Path=@('*\radmin*'); Signer=@('famatech'); Class='Commercial remote control' }
    @{ Name='VNC (Real/Tight/Ultra/Tiger)'; Exe=@('winvnc','winvnc4','vncserver','vncviewer','tvnserver','uvnc_service'); Svc=@('*vnc*'); Path=@('*\realvnc*','*\tightvnc*','*\ultravnc*','*\uvnc*','*\tigervnc*'); Signer=@('realvnc','tightvnc','glavsoft'); Class='VNC remote control' }
    @{ Name='Ammyy Admin';                  Exe=@('aa_v3','ammyy'); Svc=@(); Path=@('*\ammyy*'); Signer=@(); Class='RAT (commonly abused in scams)' }
    @{ Name='DameWare';                     Exe=@('dwrcs','dwrcst','dameware'); Svc=@('dwmrcs*'); Path=@('*\dameware*'); Signer=@('solarwinds','dameware'); Class='Commercial remote control' }
    @{ Name='NetSupport Manager';           Exe=@('client32','pcicfgui'); Svc=@('client32*'); Path=@('*\netsupport*'); Signer=@('netsupport'); Class='Remote control (abused as a RAT)' }
    @{ Name='Atera Agent';                  Exe=@('ateraagent'); Svc=@('ateraagent*'); Path=@('*\atera*'); Signer=@('atera'); Class='RMM agent' }
    @{ Name='Kaseya / VSA';                 Exe=@('agentmon'); Svc=@('kaseya*'); Path=@('*\kaseya*'); Signer=@('kaseya'); Class='RMM agent' }
    @{ Name='NinjaOne / NinjaRMM';          Exe=@('ninjarmmagent','ninjarmmagentpatcher'); Svc=@('ninjarmm*'); Path=@('*\ninjarmm*','*\ninjaone*'); Signer=@('ninja'); Class='RMM agent' }
    @{ Name='Pulseway';                     Exe=@('pcmonitorsrv','pulseway'); Svc=@('pcmonitor*','pulseway*'); Path=@('*\pulseway*','*\pc monitor*'); Signer=@('mmsoft','pulseway'); Class='RMM agent' }
    @{ Name='Supremo';                      Exe=@('supremo','supremosystem'); Svc=@('supremo*'); Path=@('*\supremo*'); Signer=@('nanosystems'); Class='Commercial remote control' }
    @{ Name='UltraViewer';                  Exe=@('ultraviewer','ultraviewer_desktop'); Svc=@('ultraviewer*'); Path=@('*\ultraviewer*'); Signer=@('ductho','ultraviewer'); Class='Remote control (abused in scams)' }
    @{ Name='RemotePC';                     Exe=@('remotepc','rpcservice'); Svc=@('remotepc*'); Path=@('*\remotepc*'); Signer=@('remotepc','idrive'); Class='Commercial remote control' }
    @{ Name='Zoho Assist';                  Exe=@('zaservice','za_access'); Svc=@('zaservice*'); Path=@('*\zoho*'); Signer=@('zoho'); Class='Remote support' }
    @{ Name='AnyViewer';                    Exe=@('anyviewer'); Svc=@('anyviewer*'); Path=@('*\anyviewer*'); Signer=@('aomei'); Class='Remote control (abused in scams)' }
    @{ Name='Remote Utilities';             Exe=@('rutserv','rfusclient'); Svc=@('rmanservice*'); Path=@('*\remote utilities*'); Signer=@('remote utilities'); Class='Remote control (abused as a RAT)' }
    @{ Name='GoToAssist / GoToMyPC';        Exe=@('g2comm','g2svc','gotoassist','gotomypc'); Svc=@('gotoassist*','gotomypc*'); Path=@('*\gotoassist*','*\gotomypc*'); Signer=@('goto','logmein'); Class='Remote support' }
    @{ Name='BeyondTrust / Bomgar';         Exe=@('bomgar'); Svc=@('bomgar*','beyondtrust*'); Path=@('*\bomgar*','*\beyondtrust*'); Signer=@('bomgar','beyondtrust'); Class='Remote support' }
    @{ Name='ngrok (tunnel)';               Exe=@('ngrok'); Svc=@('ngrok*'); Path=@('*\ngrok*'); Signer=@('ngrok'); Class='Tunneling tool (used to expose remote access)' }
    @{ Name='Cloudflared (tunnel)';         Exe=@('cloudflared'); Svc=@('cloudflared*'); Path=@('*\cloudflared*'); Signer=@('cloudflare'); Class='Tunneling tool (used to expose remote access)' }
    @{ Name='Chisel (tunnel)';              Exe=@('chisel'); Svc=@(); Path=@('*\chisel*'); Signer=@(); Class='Tunneling tool (used to expose remote access)' }
    @{ Name='Netcat / Ncat';                Exe=@('ncat','netcat'); Svc=@(); Path=@(); Signer=@(); Class='Reverse-shell tool' }

    # ── Additional RMM / remote-support tools (commonly abused — see lolrmm.io, CISA AA23-025A) ──
    @{ Name='SimpleHelp';                   Exe=@('simplehelpcustomer','simpleservice','simplegatewayservice','remote access'); Svc=@('simplehelp*','simpleservice*'); Path=@('*\simplehelp*','*\simple-help*'); Signer=@('simple-help','jwsoftware'); Class='Remote support (abused in 2025-26 ransomware intrusions)' }
    @{ Name='ITarian / Comodo RMM';         Exe=@('itsmagent','itsmservice','rviewer'); Svc=@('itsm*'); Path=@('*\itarian*','*\comodo\*rmm*'); Signer=@('itarian'); Class='RMM agent (abused)' }
    @{ Name='PDQ Connect / Deploy';         Exe=@('pdq-connect-agent','pdqconnectagent','pdqdeployrunner','pdqinventory'); Svc=@('pdq*'); Path=@('*\pdq*'); Signer=@('pdq'); Class='RMM / software deployment (abused)' }
    @{ Name='N-able Take Control / N-central'; Exe=@('basupsrvc','basupsrvcupdater','basuptshelper'); Svc=@('basupsrvc*','windows agent*','n-central*'); Path=@('*\n-able*','*\solarwinds*msp*','*\take control*','*\beanywhere*'); Signer=@('n-able','solarwinds'); Class='RMM / remote support (abused)' }
    @{ Name='Datto RMM (CentraStage)';      Exe=@('cagservice','aurora-agent','aurora-agent-v2'); Svc=@('cagservice*','datto*'); Path=@('*\centrastage*','*\datto*'); Signer=@('datto','centrastage','kaseya'); Class='RMM agent (abused)' }
    @{ Name='Syncro / Kabuto';              Exe=@('syncro.service','syncro','kabuto.app.service','kabuto'); Svc=@('syncro*','kabuto*'); Path=@('*\syncro*','*\repairtech*','*\kabuto*'); Signer=@('syncromsp','servably','repairtech'); Class='RMM agent (abused)' }
    @{ Name='Action1';                      Exe=@('action1_agent','action1_remote','action1'); Svc=@('action1*'); Path=@('*\action1*'); Signer=@('action1'); Class='RMM agent (abused)' }
    @{ Name='Level.io';                     Exe=@('level-windows-amd64','level-remote-control-ws','levelrmm'); Svc=@('level*'); Path=@('*\level.io*','*\level\agent*'); Signer=@('level'); Class='RMM agent (abused)' }
    @{ Name='Tactical RMM';                 Exe=@('tacticalrmm','tacticalagent','trmm'); Svc=@('tacticalrmm*'); Path=@('*\tacticalagent*','*\tacticalrmm*'); Signer=@('amidaware'); Class='RMM agent (open-source, abused)' }
    @{ Name='MeshCentral / MeshAgent';      Exe=@('meshagent'); Svc=@('mesh agent*','meshagent*'); Path=@('*\meshagent*','*\meshcentral*'); Signer=@('meshcentral'); Class='Remote management (open-source, abused)' }
    @{ Name='ManageEngine Endpoint Central';Exe=@('dcagentservice','dcagenttrayicon','dcfilelogservice'); Svc=@('manageengine*','dcagent*'); Path=@('*\manageengine*','*\desktopcentral*','*\endpoint central*'); Signer=@('zoho'); Class='RMM / endpoint mgmt (abused)' }
    @{ Name='ImmyBot';                      Exe=@('immyagent','immyupdater'); Svc=@('immy*'); Path=@('*\immybot*'); Signer=@('immense','immybot'); Class='RMM agent' }
    @{ Name='Goverlan Reach';               Exe=@('goverrmc','goverlanreach','grcagentservice'); Svc=@('grcagent*','goverlan*'); Path=@('*\goverlan*'); Signer=@('pj technologies','goverlan'); Class='Remote administration (abused)' }
    @{ Name='ISL Online / ISL Light';       Exe=@('isllight','isllightclient','islalwaysonmonitor','isllightservice'); Svc=@('isl*'); Path=@('*\isl online*','*\isllight*'); Signer=@('xlab','isl online'); Class='Remote support (abused)' }
    @{ Name='Parsec';                       Exe=@('parsecd','parsec'); Svc=@('parsec*'); Path=@('*\parsec*'); Signer=@('parsec'); Class='Remote desktop (gaming; abused)' }
    @{ Name='Jump Desktop';                 Exe=@('jumpdesktop','jumpconnect','jwm-prod'); Svc=@('jump*'); Path=@('*\jump desktop*','*\jumpdesktop*'); Signer=@('phase five','jump desktop'); Class='Remote desktop' }
    @{ Name='Getscreen';                    Exe=@('getscreen'); Svc=@('getscreen*'); Path=@('*\getscreen*'); Signer=@('getscreen'); Class='Remote support (abused in scams)' }
    @{ Name='Iperius Remote';               Exe=@('iperiusremote'); Svc=@('iperius*'); Path=@('*\iperius*'); Signer=@('enter srl','iperius'); Class='Remote support' }
    @{ Name='DWService / DWAgent';          Exe=@('dwagent','dwagsvc','dwaglnc'); Svc=@('dwagent*'); Path=@('*\dwagent*','*\dwservice*'); Signer=@('dwservice'); Class='Remote support (open-source, abused)' }
    @{ Name='Distant Desktop';              Exe=@('distant_desktop'); Svc=@(); Path=@('*\distant desktop*'); Signer=@(); Class='Remote control (abused in scams)' }
    @{ Name='LiteManager';                  Exe=@('romserver','romfusclient','romviewer'); Svc=@('romservice*','litemanager*'); Path=@('*\litemanager*'); Signer=@('litemanager'); Class='Remote control (abused as a RAT)' }
    @{ Name='ShowMyPC';                     Exe=@('showmypc'); Svc=@('showmypc*'); Path=@('*\showmypc*'); Signer=@('showmypc'); Class='Remote support (abused)' }
    @{ Name='AeroAdmin';                    Exe=@('aeroadmin'); Svc=@(); Path=@('*\aeroadmin*'); Signer=@('aeroadmin'); Class='Remote control (abused in scams)' }
    @{ Name='AweRay / AweSun';              Exe=@('aweray_remote','awesun','aweray'); Svc=@('aweray*'); Path=@('*\aweray*','*\awesun*'); Signer=@('aweray'); Class='Remote control (abused)' }
    @{ Name='HopToDesk';                    Exe=@('hoptodesk'); Svc=@('hoptodesk*'); Path=@('*\hoptodesk*'); Signer=@('hoptodesk'); Class='Remote control (abused)' }
    @{ Name='Chrome Remote Desktop';        Exe=@('remoting_host','remote_assistance_host'); Svc=@('chrome remote desktop*'); Path=@('*\chrome remote desktop*'); Signer=@(); Class='Remote desktop' }
    @{ Name='FastViewer';                   Exe=@('fastviewer','fastclient','fastmaster'); Svc=@('fastviewer*'); Path=@('*\fastviewer*'); Signer=@('fastviewer'); Class='Remote support (abused)' }
    @{ Name='SuperOps';                     Exe=@('superops','superopsticket'); Svc=@('superops*'); Path=@('*\superops*'); Signer=@('superops'); Class='RMM agent' }
    @{ Name='Mikogo';                       Exe=@('mikogo','mikogo-host','mikogo-service'); Svc=@('mikogo*'); Path=@('*\mikogo*'); Signer=@('mikogo','snapview'); Class='Remote support / screen sharing' }
    @{ Name='Atera Splashtop (Streamer)';   Exe=@('atera_agent'); Svc=@('ateraagent*'); Path=@('*\atera*'); Signer=@('atera'); Class='RMM agent (abused)' }

    # ── Mesh VPN / tunneling (used by attackers to reach a host or for C2) ───────
    @{ Name='Tailscale';                    Exe=@('tailscale','tailscaled','tailscale-ipn'); Svc=@('tailscale*'); Path=@('*\tailscale*'); Signer=@('tailscale'); Class='Mesh VPN (used by attackers for access)' }
    @{ Name='ZeroTier';                     Exe=@('zerotier-one_x64','zerotier-one','zerotier'); Svc=@('zerotier*'); Path=@('*\zerotier*'); Signer=@('zerotier'); Class='Mesh VPN (used by attackers for access)' }
    @{ Name='NetBird';                      Exe=@('netbird','netbird-ui'); Svc=@('netbird*'); Path=@('*\netbird*'); Signer=@('netbird','wiretrustee'); Class='Mesh VPN (used by attackers for access)' }
    @{ Name='frp (Fast Reverse Proxy)';     Exe=@('frpc','frps'); Svc=@(); Path=@('*\frp*'); Signer=@(); Class='Tunneling tool (used to expose remote access)' }
    @{ Name='LocalXpose';                   Exe=@('loclx'); Svc=@(); Path=@('*\localxpose*'); Signer=@(); Class='Tunneling tool' }
    @{ Name='localtonet';                   Exe=@('localtonet'); Svc=@('localtonet*'); Path=@('*\localtonet*'); Signer=@(); Class='Tunneling tool' }
    @{ Name='playit.gg';                    Exe=@('playit'); Svc=@('playit*'); Path=@('*\playit*'); Signer=@(); Class='Tunneling tool' }
    @{ Name='plink (PuTTY link)';           Exe=@('plink'); Svc=@(); Path=@(); Signer=@(); Class='SSH tunneling tool (used for port-forward C2)' }

    # ── Known RAT / C2 families (default names; renamed variants are caught by the
    #    unsigned + user-writable-path + deep-AppData heuristics in the scans) ────
    @{ Name='AsyncRAT (malware)';           Exe=@('asyncrat','asyncclient'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='Remcos (malware)';             Exe=@('remcos'); Svc=@(); Path=@('*\remcos*'); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='njRAT / Bladabindi (malware)'; Exe=@('njrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='Quasar RAT (malware)';         Exe=@('quasar','quasarrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='XWorm (malware)';              Exe=@('xworm'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='DCRat (malware)';              Exe=@('dcrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='NanoCore (malware)';           Exe=@('nanocore'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='VenomRAT (malware)';           Exe=@('venomrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='Cobalt Strike (C2)';           Exe=@('cobaltstrike'); Svc=@(); Path=@(); Signer=@(); Class='Command-and-control framework' }
)

# Keyword list for TEXT scans (registry values, scheduled-task command lines).
# Only tokens long/specific enough to avoid collisions are included.
$ratKeywords = @(
    'teamviewer','anydesk','screenconnect','connectwise','logmein','splashtop',
    'rustdesk','radmin','realvnc','tightvnc','ultravnc','tigervnc','winvnc',
    'ammyy','dameware','netsupport','supremo','ultraviewer','remotepc','zohoassist',
    'gotoassist','gotomypc','anyviewer','rutserv','bomgar','beyondtrust',
    'ngrok','cloudflared','ateraagent','ninjarmm','kaseya','pulseway',
    # additional RMM / remote tools
    'simplehelp','itarian','pdq-connect','pdqconnect','n-able','centrastage','aurora-agent',
    'syncro','kabuto','action1','level-remote','tacticalrmm','tacticalagent','meshagent',
    'meshcentral','desktopcentral','immybot','goverlan','isllight','parsec','jumpdesktop',
    'getscreen','iperius','dwagent','dwservice','distant_desktop','litemanager','romserver',
    'showmypc','aeroadmin','aweray','awesun','hoptodesk','remoting_host','fastviewer','superops',
    'mikogo','tailscale','zerotier','netbird','localxpose','localtonet','playit',
    # tunneling / reverse-shell
    'frpc','frps','loclx','plink',
    # known RAT / C2 family names
    'remcos','njrat','quasar','asyncrat','venomrat','nanocore','darkcomet','netwire',
    'xworm','dcrat','bitrat','warzonerat','orcus','limerat','cobaltstrike','bruteratel'
)

# Benign comms / cloud-sync names that must never be flagged on name alone
$benignNames = @(
    'onedrive','dropbox','googledrive','googledrivesync','gdrive','icloud',
    'zoom','webex','msteams','teams','slack','vonage','ringcentral','openphone',
    'chrome','firefox','msedge','outlook','spotify','discord'
)
function Get-WhitelistMatch([string]$text) {
    if (-not $text) { return $null }
    $t = $text.ToLower()
    return $benignNames | Where-Object { $t -like "*$_*" } | Select-Object -First 1
}

# Ports associated with remote-access / C2 traffic
$ratPorts = @{
    3389='RDP (Remote Desktop)'; 5900='VNC'; 5938='TeamViewer'; 7070='AnyDesk'
    4444='Metasploit/RAT'; 4443='Reverse Shell'; 1337='RAT port'
    5985='WinRM HTTP'; 5986='WinRM HTTPS'; 22='SSH'; 23='Telnet'
    4899='Radmin'; 6568='Remote Utilities'; 6129='DameWare'
    8040='ScreenConnect'; 55000='ScreenConnect'; 6667='IRC/Botnet C2'
    4782='Quasar RAT C2'; 1604='DarkComet C2'; 1177='njRAT C2'; 5552='njRAT C2'
    6606='AsyncRAT C2'; 7707='AsyncRAT C2'; 8808='AsyncRAT C2'; 2404='Remcos C2'
    3460='Bifrost/RAT'; 9999='RAT C2'; 5050='RAT C2'
}
# Management ports that are commonly legitimate — flagged but at MEDIUM, not HIGH
$mgmtPorts = @(22,3389,5985,5986)

# Known install folders to check on disk
$ratFolders = @(
    "$env:APPDATA\TeamViewer", "$env:APPDATA\AnyDesk", "$env:PROGRAMFILES\TeamViewer",
    "$env:PROGRAMFILES\AnyDesk", "$env:PROGRAMFILES\RealVNC", "$env:PROGRAMFILES\TightVNC",
    "$env:PROGRAMFILES\UltraVNC", "$env:PROGRAMFILES\Radmin", "$env:PROGRAMFILES\ScreenConnect",
    "$env:PROGRAMFILES\Supremo", "$env:PROGRAMFILES\UltraViewer", "$env:PROGRAMFILES\AnyViewer",
    "${env:ProgramFiles(x86)}\TeamViewer", "${env:ProgramFiles(x86)}\AnyDesk",
    "${env:ProgramFiles(x86)}\UltraViewer", "$env:LOCALAPPDATA\ngrok",
    "$env:PROGRAMFILES\SimpleHelp", "$env:PROGRAMDATA\SimpleHelpCustomer",
    "$env:PROGRAMFILES\RustDesk", "$env:APPDATA\RustDesk",
    "$env:PROGRAMFILES\Splashtop", "${env:ProgramFiles(x86)}\Splashtop",
    "$env:PROGRAMFILES\AeroAdmin", "$env:PROGRAMFILES\LiteManager Pro - Server",
    "$env:PROGRAMFILES\DWAgent", "$env:PROGRAMFILES\Getscreen.me",
    "$env:PROGRAMFILES\Mesh Agent", "$env:PROGRAMFILES\TacticalAgent",
    "$env:LOCALAPPDATA\Programs\distant-desktop", "$env:APPDATA\HopToDesk"
)

# ── Trust / catalog helpers ─────────────────────────────────────────────────
$script:TrustCache = @{}
function Get-FileTrust {
    # Authenticode + version metadata for a file, cached per path.
    param([string]$Path)
    $info = [PSCustomObject]@{ Exists=$false; Signed=$false; SignerName=''; IsMicrosoft=$false; Company=''; Product='' }
    if (-not $Path) { return $info }
    $clean = ($Path -replace '"','').Trim()
    # strip any trailing service arguments (e.g. "...\svc.exe" /run)
    if ($clean -match '^(.*\.exe)\b') { $clean = $matches[1] }
    if ($script:TrustCache.ContainsKey($clean)) { return $script:TrustCache[$clean] }
    if (-not (Test-Path -LiteralPath $clean)) { $script:TrustCache[$clean] = $info; return $info }
    $info.Exists = $true
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $clean -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $info.Signed = $true
            $cn = (($sig.SignerCertificate.Subject -split ',')[0] -replace '^CN=','').Trim('" ')
            $info.SignerName = $cn
            if ($cn -match 'Microsoft (Corporation|Windows)') { $info.IsMicrosoft = $true }
        }
    } catch {}
    try {
        $vi = (Get-Item -LiteralPath $clean -ErrorAction Stop).VersionInfo
        $info.Company = $vi.CompanyName
        $info.Product = $vi.ProductName
    } catch {}
    $script:TrustCache[$clean] = $info
    return $info
}

function Find-RemoteTool {
    # Precise catalog match. Returns the catalog entry hashtable, or $null.
    #   -Exe         executable file name (with/without .exe) -> matched EXACTLY to catalog Exe base names
    #   -ServiceName Windows service short name               -> matched to catalog Svc patterns
    #   -Display     Windows service display name             -> matched to catalog Svc patterns
    #   -Path        full path / command line                 -> matched to catalog Path patterns
    #   -Signer      Authenticode signer common name          -> matched to catalog Signer list
    # Svc patterns are matched ONLY against service name/display (never against an
    # exe name) so a broad pattern like 'level*' can't flag an unrelated level.exe.
    param([string]$Exe, [string]$ServiceName, [string]$Display, [string]$Path, [string]$Signer)
    $base = ''
    if ($Exe) { $base = ($Exe.ToLower() -replace '\.exe$',''); if ($base -match '[\\/]') { $base = ($base -split '[\\/]')[-1] } }
    $svcN = if ($ServiceName) { $ServiceName.ToLower() } else { '' }
    $disp = if ($Display)     { $Display.ToLower() }     else { '' }
    $pth  = if ($Path)        { $Path.ToLower() }        else { '' }
    $sgn  = if ($Signer)      { $Signer.ToLower() }      else { '' }
    foreach ($t in $RemoteTools) {
        if ($base) { foreach ($e in $t.Exe) { if ($e -and $base -eq $e) { return $t } } }
        foreach ($s in $t.Svc) { if ($s -and (($svcN -and $svcN -like $s) -or ($disp -and $disp -like $s))) { return $t } }
        if ($pth) { foreach ($p in $t.Path) { if ($p -and $pth -like $p.ToLower()) { return $t } } }
        if ($sgn) { foreach ($g in $t.Signer) { if ($g -and $sgn -like "*$g*") { return $t } } }
    }
    return $null
}

function Test-BadPath([string]$Path) {
    # User-writable locations where legitimate background services rarely live.
    if (-not $Path) { return $false }
    return ($Path -like '*\AppData\*' -or $Path -like '*\Temp\*' -or $Path -like '*\Users\Public\*')
}

# Well-known vendor directories — used to suppress the weak "unsigned exe buried
# deep in AppData" signal for mainstream apps (Teams, browsers, Electron apps,
# etc. all drop unsigned helper exes deep in their own folders). Catalogued tools
# and keyword matches are NOT affected by this — only the depth-only heuristic.
$benignVendorDirs = @(
    '\microsoft\','\windowsapps\','\google\','\mozilla\','\adobe\','\discord\',
    '\slack\','\spotify\','\zoom\','\webex\','\steam\','\epic games\','\jetbrains\',
    '\github\','\githubdesktop\','\postman\','\1password\','\dropbox\','\box\',
    '\nvidia\','\intel\','\amd\','\logi','\citrix\','\python','\nodejs\','\valve\',
    '\obs-studio\','\zoomus\','\whatsapp\','\signal\','\telegram desktop\'
)
function Test-TrustedVendorPath([string]$Path) {
    if (-not $Path) { return $false }
    $p = $Path.ToLower()
    foreach ($d in $benignVendorDirs) { if ($p -like "*$d*") { return $true } }
    return $false
}

# ── Helper functions ──────────────────────────────────────────────────────────
function Esc([string]$s) {
    if (-not $s) { return '' }
    $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function Badge([string]$sev) {
    $c = if ($sev -eq 'HIGH') { '#dc2626' } elseif ($sev -eq 'MEDIUM') { '#ea580c' } elseif ($sev -eq 'LOW') { '#2563eb' } else { '#d97706' }
    return "<span style='background:$c;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700'>$sev</span>"
}

function Section([string]$title, [string]$intro, $items, [string[]]$headers, [scriptblock]$rowFn) {
    $count = if ($items) { @($items).Count } else { 0 }
    $badge = if ($count -gt 0) {
        "<span style='background:#dc2626;color:#fff;padding:1px 10px;border-radius:12px;font-size:12px;margin-left:8px'>$count found</span>"
    } else {
        "<span style='background:#16a34a;color:#fff;padding:1px 10px;border-radius:12px;font-size:12px;margin-left:8px'>Clean</span>"
    }
    $out = "<div class='card'><h2>$title $badge</h2><p class='intro'>$intro</p>"
    if ($count -gt 0) {
        $ths = ($headers | ForEach-Object { "<th>$_</th>" }) -join ''
        $out += "<div class='tbl-wrap'><table><tr>$ths</tr>"
        foreach ($item in @($items)) {
            $out += (& $rowFn $item)
        }
        $out += "</table></div>"
    } else {
        $out += "<p class='clean'>&#x2714; None detected.</p>"
    }
    $out += "</div>"
    return $out
}

# ── Scan 1: Processes ─────────────────────────────────────────────────────────
Write-Host "  [1/10] Scanning running processes..." -ForegroundColor Yellow
$allProcs  = Get-Process | Select-Object Name, Id, Path, Company
$suspProcs = New-Object 'System.Collections.Generic.List[object]'
foreach ($p in $allProcs) {
    if (-not $p.Path) { continue }            # no image path = protected/system; nothing to assess
    $trust = Get-FileTrust $p.Path
    $tool  = Find-RemoteTool -Exe $p.Name -Path $p.Path -Signer $trust.SignerName
    $bad   = Test-BadPath $p.Path

    # Microsoft-signed and benign signed comms apps are never flagged on name alone
    if (-not $tool -and $trust.IsMicrosoft) { continue }
    if (-not $tool -and -not $bad -and (Get-WhitelistMatch $p.Name)) { continue }

    if ($tool -or $bad) {
        if     ($tool)               { $sev = 'HIGH';   $reason = "Known remote access tool: $($tool.Name) — $($tool.Class)" }
        elseif (-not $trust.Signed)  { $sev = 'HIGH';   $reason = 'Unsigned executable running from a user-writable location' }
        else                         { $sev = 'MEDIUM'; $reason = 'Runs from a user-writable location (AppData / Temp / Public)' }

        $signerNote = if ($trust.Signed) { "Signed by: $($trust.SignerName)" } else { 'Digital signature: UNSIGNED' }
        $suspProcs.Add([PSCustomObject]@{
            Name    = $p.Name
            PID     = $p.Id
            Path    = $p.Path
            Company = if ($trust.Company) { $trust.Company } elseif ($p.Company) { $p.Company } else { 'Unknown' }
            Sev     = $sev
            Reason  = "$reason. $signerNote."
            Fix     = "Open Task Manager, find the process, right-click and choose End Task.`nOr run in Admin PowerShell: Stop-Process -Id $($p.Id) -Force"
        })
    }
}
Write-Host "    Found: $($suspProcs.Count)" -ForegroundColor Gray

# ── Scan 2: Services ──────────────────────────────────────────────────────────
Write-Host "  [2/10] Scanning services..." -ForegroundColor Yellow
$allSvcs  = Get-WmiObject Win32_Service
$suspSvcs = New-Object 'System.Collections.Generic.List[object]'
foreach ($s in $allSvcs) {
    # Pull the bare executable path out of the service command line
    $binPath = ''
    if ($s.PathName) {
        $pn = $s.PathName.Trim()
        if     ($pn -match '^\s*"([^"]+\.exe)"') { $binPath = $matches[1] }
        elseif ($pn -match '^\s*([^\s]+\.exe)')  { $binPath = $matches[1] }
        else   { $binPath = $pn }
    }
    $trust = Get-FileTrust $binPath
    $tool  = Find-RemoteTool -Exe $binPath -ServiceName $s.Name -Display $s.DisplayName -Path $s.PathName -Signer $trust.SignerName
    $bad   = Test-BadPath $s.PathName

    if (-not $tool -and $trust.IsMicrosoft) { continue }
    if (-not $tool -and -not $bad -and (Get-WhitelistMatch $s.Name)) { continue }

    if ($tool -or $bad) {
        if     ($tool)               { $sev = 'HIGH';   $reason = "Known remote access service: $($tool.Name) — $($tool.Class)" }
        elseif (-not $trust.Signed)  { $sev = 'HIGH';   $reason = 'Unsigned service binary in a user-writable location' }
        else                         { $sev = 'MEDIUM'; $reason = 'Service binary runs from a user-writable location' }
        $signerNote = if ($trust.Signed) { "Signed by: $($trust.SignerName)" } else { 'UNSIGNED binary' }
        $suspSvcs.Add([PSCustomObject]@{
            Name    = $s.Name
            Display = $s.DisplayName
            State   = $s.State
            Start   = $s.StartMode
            Sev     = $sev
            Reason  = "$reason. $signerNote."
            Fix     = "Run in Admin PowerShell:`nStop-Service '$($s.Name)' -Force`nSet-Service '$($s.Name)' -StartupType Disabled`nsc.exe delete '$($s.Name)'"
        })
    }
}
Write-Host "    Found: $($suspSvcs.Count)" -ForegroundColor Gray

# ── Scan 3: Network connections ───────────────────────────────────────────────
Write-Host "  [3/10] Scanning network connections..." -ForegroundColor Yellow
$suspConns = New-Object 'System.Collections.Generic.List[object]'
try {
    # Try Get-NetTCPConnection first (Win8.1+/PS4+), fall back to netstat for Win8
    $netCmdAvail = $null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    if ($netCmdAvail) {
        $allConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        foreach ($c in $allConns) {
            $pNote = $ratPorts[$c.LocalPort]
            $rNote = $ratPorts[$c.RemotePort]
            $isExt = $c.RemoteAddress -and
                     $c.RemoteAddress -ne '0.0.0.0' -and
                     $c.RemoteAddress -ne '::' -and
                     $c.RemoteAddress -ne '::1' -and
                     $c.RemoteAddress -notlike '127.*'
            if (($pNote -or $rNote) -and $isExt) {
                $note   = if ($pNote) { $pNote } else { $rNote }
                $isMgmt = ($mgmtPorts -contains $c.LocalPort) -or ($mgmtPorts -contains $c.RemotePort)
                $sev    = if ($isMgmt) { 'MEDIUM' } elseif ($c.State -eq 'Established') { 'HIGH' } else { 'MEDIUM' }
                $pname  = ($allProcs | Where-Object { $_.Id -eq $c.OwningProcess } | Select-Object -First 1).Name
                $suspConns.Add([PSCustomObject]@{
                    Process = if ($pname) { $pname } else { 'Unknown' }
                    PID     = $c.OwningProcess
                    Local   = "$($c.LocalAddress):$($c.LocalPort)"
                    Remote  = "$($c.RemoteAddress):$($c.RemotePort)"
                    State   = $c.State
                    Note    = $note
                    Sev     = $sev
                    Fix     = "Kill the process: Stop-Process -Id $($c.OwningProcess) -Force`nBlock the port in Windows Firewall > Advanced Settings > Outbound Rules."
                })
            }
        }
    } else {
        # Windows 8 fallback: parse netstat -ano output
        $netstatOut = & netstat -ano 2>$null
        foreach ($line in $netstatOut) {
            if ($line -notmatch 'TCP\s+') { continue }
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -lt 5) { continue }
            $localFull  = $parts[1]
            $remoteFull = $parts[2]
            $state      = $parts[3]
            $procId     = [int]$parts[4]
            $localPort  = 0
            $remotePort = 0
            if ($localFull  -match ':(\d+)$') { $localPort  = [int]$matches[1] }
            if ($remoteFull -match ':(\d+)$') { $remotePort = [int]$matches[1] }
            $remoteIP = $remoteFull -replace ':\d+$',''
            $isExt = $remoteIP -and $remoteIP -ne '0.0.0.0' -and $remoteIP -ne '::' -and $remoteIP -ne '::1' -and $remoteIP -notlike '127.*'
            $pNote = $ratPorts[$localPort]
            $rNote = $ratPorts[$remotePort]
            if (($pNote -or $rNote) -and $isExt) {
                $note   = if ($pNote) { $pNote } else { $rNote }
                $isMgmt = ($mgmtPorts -contains $localPort) -or ($mgmtPorts -contains $remotePort)
                $sev    = if ($isMgmt) { 'MEDIUM' } elseif ($state -eq 'ESTABLISHED') { 'HIGH' } else { 'MEDIUM' }
                $pname  = ($allProcs | Where-Object { $_.Id -eq $procId } | Select-Object -First 1).Name
                $suspConns.Add([PSCustomObject]@{
                    Process = if ($pname) { $pname } else { 'Unknown' }
                    PID     = $procId
                    Local   = $localFull
                    Remote  = $remoteFull
                    State   = $state
                    Note    = $note
                    Sev     = $sev
                    Fix     = "Kill the process: Stop-Process -Id $procId -Force`nBlock the port in Windows Firewall > Advanced Settings > Outbound Rules."
                })
            }
        }
    }
} catch {
    Write-Host "    Network scan error: $_" -ForegroundColor Red
}
Write-Host "    Found: $($suspConns.Count)" -ForegroundColor Gray

# ── Scan 4: Scheduled tasks ───────────────────────────────────────────────────
Write-Host "  [4/10] Scanning scheduled tasks..." -ForegroundColor Yellow
$suspTasks = New-Object 'System.Collections.Generic.List[object]'
try {
    $schedCmdAvail = $null -ne (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)
    if ($schedCmdAvail) {
        $allTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
        foreach ($t in $allTasks) {
            $underMS = $t.TaskPath -like '\Microsoft\*'
            foreach ($a in $t.Actions) {
                if (-not $a.Execute) { continue }
                $exe   = [Environment]::ExpandEnvironmentVariables($a.Execute)
                $trust = Get-FileTrust $exe
                $kw    = $ratKeywords | Where-Object { $a.Execute -like "*$_*" -or $a.Arguments -like "*$_*" } | Select-Object -First 1
                $bad   = Test-BadPath $a.Execute
                # Random-name heuristic only for non-Microsoft, non-MS-signed tasks (pure hex)
                $rand  = (-not $underMS) -and (-not $trust.IsMicrosoft) -and ($t.TaskName -match '^[a-f0-9]{16,}$')
                if (-not $kw -and $trust.IsMicrosoft) { continue }
                if ($kw -or $bad -or $rand) {
                    $sev = if ($kw -or ($bad -and -not $trust.Signed)) { 'HIGH' } else { 'MEDIUM' }
                    $suspTasks.Add([PSCustomObject]@{
                        Name   = $t.TaskName
                        Exe    = $a.Execute
                        Args   = if ($a.Arguments) { $a.Arguments } else { '' }
                        State  = $t.State
                        Sev    = $sev
                        Reason = if ($kw) { "References remote access tool: $kw" } elseif ($bad) { 'Runs from a user-writable path' } else { 'Obfuscated / random task name' }
                        Fix    = "Open Task Scheduler, find '$($t.TaskName)', right-click and choose Disable or Delete.`nOr run: Unregister-ScheduledTask -TaskName '$($t.TaskName)' -Confirm:`$false"
                    })
                }
            }
        }
    } else {
        # Windows 8 fallback: parse schtasks /query output
        $schtasksOut = & schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
        foreach ($t in $schtasksOut) {
            $taskName = $t.'TaskName'
            $exe      = $t.'Task To Run'
            $status   = $t.'Status'
            if (-not $taskName -or -not $exe) { continue }
            if ($status -eq 'Disabled') { continue }
            $underMS = $taskName -like '\Microsoft\*'
            $trust   = Get-FileTrust $exe
            $kw      = $ratKeywords | Where-Object { $exe -like "*$_*" } | Select-Object -First 1
            $bad     = Test-BadPath $exe
            $leaf    = ($taskName -split '\\')[-1]
            $rand    = (-not $underMS) -and (-not $trust.IsMicrosoft) -and ($leaf -match '^[a-f0-9]{16,}$')
            if (-not $kw -and $trust.IsMicrosoft) { continue }
            if ($kw -or $bad -or $rand) {
                $sev = if ($kw -or ($bad -and -not $trust.Signed)) { 'HIGH' } else { 'MEDIUM' }
                $suspTasks.Add([PSCustomObject]@{
                    Name   = $taskName
                    Exe    = $exe
                    Args   = ''
                    State  = $status
                    Sev    = $sev
                    Reason = if ($kw) { "References remote access tool: $kw" } elseif ($bad) { 'Runs from a user-writable path' } else { 'Obfuscated / random task name' }
                    Fix    = "Open Task Scheduler, find '$taskName', right-click and Disable or Delete.`nOr run: schtasks /delete /tn `"$taskName`" /f"
                })
            }
        }
    }
} catch {
    Write-Host "    Task scan error: $_" -ForegroundColor Red
}
Write-Host "    Found: $($suspTasks.Count)" -ForegroundColor Gray

# ── Scan 5: Registry ──────────────────────────────────────────────────────────
Write-Host "  [5/10] Scanning registry startup keys..." -ForegroundColor Yellow
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$suspReg = New-Object 'System.Collections.Generic.List[object]'
foreach ($rp in $regPaths) {
    if (-not (Test-Path $rp)) { continue }
    try {
        $props = Get-ItemProperty -Path $rp
        if (-not $props) { continue }
        foreach ($entry in ($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            $val     = [string]$entry.Value
            $hit     = $ratKeywords | Where-Object { $val -like "*$_*" } | Select-Object -First 1
            $badPath = $val -like '*\AppData\*' -or $val -like '*\Temp\*' -or $val -like '*\Users\Public\*'
            # Resolve the target exe so we can check its signature
            $exeTarget = ''
            if     ($val -match '"([^"]+\.exe)"')            { $exeTarget = $matches[1] }
            elseif ($val -match '([A-Za-z]:\\[^\s"]+\.exe)') { $exeTarget = $matches[1] }
            elseif ($val -match '(%[^%]+%\\[^\s"]+\.exe)')   { $exeTarget = $matches[1] }
            $regTrust = Get-FileTrust ([Environment]::ExpandEnvironmentVariables($exeTarget))

            # Unless it references a known remote tool, trust normal autostart entries:
            # Microsoft-signed, benign apps by name (Teams/OneDrive/Slack/...), or any
            # validly-signed publisher. Only an UNSIGNED program auto-starting from a
            # user-writable path is suspicious.
            if (-not $hit) {
                if ($regTrust.IsMicrosoft)        { continue }
                if (Get-WhitelistMatch $val)      { continue }
                if ($regTrust.Signed)             { continue }
                if (-not $badPath)                { continue }
            }
            if ($hit -or $badPath) {
                $sev = if ($hit) { 'HIGH' } else { 'MEDIUM' }
                $suspReg.Add([PSCustomObject]@{
                    RegPath = $rp
                    Name    = $entry.Name
                    Value   = $val
                    Sev     = $sev
                    Reason  = if ($hit) { "References known remote access tool: $hit" } else { 'Unsigned program auto-starting from a user-writable path (AppData/Temp/Public)' }
                    Fix     = "Open regedit.exe, navigate to:`n$rp`nFind the entry '$($entry.Name)' and delete it.`nOr run: Remove-ItemProperty -Path '$rp' -Name '$($entry.Name)'"
                })
            }
        }
    } catch { }
}
Write-Host "    Found: $($suspReg.Count)" -ForegroundColor Gray

# ── Scan 6: Known folders ─────────────────────────────────────────────────────
Write-Host "  [6/10] Checking known RAT folders..." -ForegroundColor Yellow
$suspFolders = New-Object 'System.Collections.Generic.List[object]'
foreach ($f in $ratFolders) {
    if (Test-Path $f) {
        $suspFolders.Add([PSCustomObject]@{
            Path   = $f
            Sev    = 'HIGH'
            Reason = 'Known remote access tool installation folder found on disk'
            Fix    = "First uninstall via Settings > Apps if listed.`nThen delete leftovers: Remove-Item -Path '$f' -Recurse -Force"
        })
    }
}
Write-Host "    Found: $($suspFolders.Count)" -ForegroundColor Gray

# ── Scan 7: RDP ───────────────────────────────────────────────────────────────
Write-Host "  [7/10] Checking RDP configuration..." -ForegroundColor Yellow
$rdpEnabled = $false
$rdpPort    = 3389
$nlaOn      = $false
try {
    $rdpReg     = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpEnabled = ($rdpReg.fDenyTSConnections -eq 0)
    $rdpTcp     = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    if ($rdpTcp.PortNumber) { $rdpPort = $rdpTcp.PortNumber }
    $nlaOn = ($rdpTcp.UserAuthentication -eq 1)
} catch { }

# ── Scan 8: ScreenConnect / ConnectWise Control detection & uninstall info ───
Write-Host "  [8/11] Checking for ScreenConnect / ConnectWise Control installations..." -ForegroundColor Yellow
$scFindings = New-Object 'System.Collections.Generic.List[object]'

# Known ScreenConnect service name patterns (ConnectWise uses random-suffix names like
# "ScreenConnect Client (abc123def456)" or just "ScreenConnect" for server installs)
$scServicePatterns = @('*screenconnect*','*connectwisecontrol*','*connectwise control*')

# Known ScreenConnect install/data paths
$scKnownPaths = @(
    "$env:PROGRAMFILES\ScreenConnect",
    "$env:PROGRAMFILES\ConnectWise Control",
    "${env:ProgramFiles(x86)}\ScreenConnect",
    "${env:ProgramFiles(x86)}\ConnectWise Control",
    "$env:PROGRAMDATA\ScreenConnect",
    "$env:PROGRAMDATA\ConnectWiseControl",
    "$env:APPDATA\ScreenConnect",
    "$env:LOCALAPPDATA\ScreenConnect",
    "$env:LOCALAPPDATA\Apps",          # ClickOnce installs sometimes land here
    "C:\Windows\Temp\ScreenConnect",
    "C:\Temp\ScreenConnect"
)

# Registry uninstall keys to look for
$uninstallHives = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

try {
    # ── Step A: Check services ────────────────────────────────────────────────
    $allSvcsFull = Get-WmiObject Win32_Service
    foreach ($svc in $allSvcsFull) {
        $matchedPattern = $scServicePatterns | Where-Object { $svc.Name -like $_ -or $svc.DisplayName -like $_ } | Select-Object -First 1
        if (-not $matchedPattern) { continue }

        # Try to find uninstall string from registry
        $uninstallCmd = ''
        $installPath  = ''
        $version      = ''
        foreach ($hive in $uninstallHives) {
            if (-not (Test-Path $hive)) { continue }
            Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props -and ($props.DisplayName -like '*screenconnect*' -or $props.DisplayName -like '*connectwise control*')) {
                    if ($props.UninstallString) { $uninstallCmd = $props.UninstallString }
                    if ($props.InstallLocation) { $installPath  = $props.InstallLocation }
                    if ($props.DisplayVersion)  { $version      = $props.DisplayVersion  }
                }
            }
        }

        # Build the uninstall path from service binary if registry didn't have it
        if (-not $installPath -and $svc.PathName) {
            $installPath = Split-Path ($svc.PathName -replace '"','') -Parent
        }

        # ── Disk validation: skip ghost entries ───────────────────────────────
        # If the service is registered but nothing exists on disk, it's a stale
        # registry remnant from a previous removal. Report it as a cleanup note
        # rather than an active threat.
        $binaryExists  = $svc.PathName -and (Test-Path ($svc.PathName -replace '"','' -replace '\s+/.*$',''))
        $installExists = $installPath  -and (Test-Path $installPath)
        $isGhost       = (-not $binaryExists -and -not $installExists)

        if ($isGhost) {
            # Service key exists in registry but nothing is on disk — stale remnant
            $scFindings.Add([PSCustomObject]@{
                ServiceName    = $svc.Name
                DisplayName    = "$($svc.DisplayName) [STALE — files already removed]"
                State          = "$($svc.State) (binary missing from disk)"
                StartMode      = $svc.StartMode
                BinaryPath     = if ($svc.PathName) { $svc.PathName } else { 'N/A' }
                InstallPath    = if ($installPath) { "$installPath (NOT FOUND ON DISK)" } else { 'Not found' }
                Version        = if ($version) { $version } else { 'Unknown' }
                HasUninstaller = 'No — registry cleanup only needed'
                Sev            = 'LOW'
                Removal        = "# Files are already gone. Only the service registry key remains.`n# Run these to clean up the leftover entries:`n`n# Remove the dead service entry:`nsc.exe delete `"$($svc.Name)`"`n`n# Remove uninstall registry keys:`nforeach (`$hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {`n  Get-ChildItem `$hive -ErrorAction SilentlyContinue | ForEach-Object {`n    `$p = Get-ItemProperty `$_.PSPath -ErrorAction SilentlyContinue`n    if (`$p.DisplayName -like '*ScreenConnect*' -or `$p.DisplayName -like '*ConnectWise Control*') {`n      Remove-Item `$_.PSPath -Recurse -Force`n      Write-Host `"Removed: `$(`$_.PSPath)`"`n    }`n  }`n}`n`n# Remove any LSA auth package references:`n`$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'`n`$sp = (Get-ItemProperty `$lsaKey -Name 'Security Packages' -ErrorAction SilentlyContinue).('Security Packages')`nif (`$sp) { Set-ItemProperty `$lsaKey -Name 'Security Packages' -Value (`$sp | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' }) }`n`nWrite-Host 'Stale ScreenConnect registry entries removed.'"
            })
            continue
        }
        $removalSteps = "# STEP 1 — Stop and disable the service:`nStop-Service '$($svc.Name)' -Force -ErrorAction SilentlyContinue`nSet-Service '$($svc.Name)' -StartupType Disabled`n`n"

        if ($uninstallCmd) {
            $removalSteps += "# STEP 2 — Run the official uninstaller (found in registry):`n$uninstallCmd`n`n"
        } else {
            $removalSteps += "# STEP 2 — No uninstaller found in registry. Delete the service manually:`nsc.exe stop `"$($svc.Name)`"`nsc.exe delete `"$($svc.Name)`"`n`n"
        }

        if ($installPath -and (Test-Path $installPath)) {
            $removalSteps += "# STEP 3 — Delete install folder:`nRemove-Item -Path '$installPath' -Recurse -Force`n`n"
        }

        $removalSteps += "# STEP 4 — Remove leftover AppData folders (run for each user):`nRemove-Item -Path `"`$env:APPDATA\ScreenConnect`" -Recurse -Force -ErrorAction SilentlyContinue`nRemove-Item -Path `"`$env:LOCALAPPDATA\ScreenConnect`" -Recurse -Force -ErrorAction SilentlyContinue`n`n"

        $removalSteps += "# STEP 5 — Remove registry keys:`nRemove-Item -Path 'HKLM:\SOFTWARE\ScreenConnect' -Recurse -Force -ErrorAction SilentlyContinue`nRemove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\ScreenConnect' -Recurse -Force -ErrorAction SilentlyContinue`nRemove-Item -Path 'HKCU:\SOFTWARE\ScreenConnect' -Recurse -Force -ErrorAction SilentlyContinue`n`n"

        $removalSteps += "# STEP 6 — Remove firewall rules added by ScreenConnect:`nGet-NetFirewallRule | Where-Object { `$_.DisplayName -like '*ScreenConnect*' -or `$_.DisplayName -like '*ConnectWise*' } | Remove-NetFirewallRule`n`n"

        $removalSteps += "# STEP 7 — IMPORTANT: Remove ScreenConnect Windows Authentication Package (SSP DLL).`n# ScreenConnect registers 'ScreenConnect.WindowsAuthenticationPackage.dll' as a`n# Security Support Provider (SSP), which causes lsass.exe to hold the DLL open.`n# This is why the folder cannot be deleted — the DLL is locked by lsass.`n# You MUST do this before rebooting, then reboot to release the lock.`n`n# 7a) Remove from LSA Security Packages registry list:`n`$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'`n`$current = (Get-ItemProperty `$lsaKey -Name 'Security Packages').('Security Packages')`n`$cleaned = `$current | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' }`nSet-ItemProperty `$lsaKey -Name 'Security Packages' -Value `$cleaned`n`n# 7b) Remove from LSA Authentication Packages list (second location):`n`$authPkgs = (Get-ItemProperty `$lsaKey -Name 'Authentication Packages' -ErrorAction SilentlyContinue).('Authentication Packages')`nif (`$authPkgs) {`n  `$authCleaned = `$authPkgs | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' }`n  Set-ItemProperty `$lsaKey -Name 'Authentication Packages' -Value `$authCleaned`n}`n`n# 7c) Schedule the locked DLL for deletion on next reboot`n# (Windows will delete it before lsass loads it again):`n`$dllPaths = @(`n  `$installPath + '\ScreenConnect.WindowsAuthenticationPackage.dll',`n  `"`$env:SystemRoot\System32\ScreenConnect.WindowsAuthenticationPackage.dll`"`n)`nforeach (`$dll in `$dllPaths) {`n  if (Test-Path `$dll) {`n    # MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT flag`n    `$sig = '[DllImport(""kernel32.dll"",SetLastError=true)] public static extern bool MoveFileEx(string src, string dst, uint flags);'`n    `$t = Add-Type -MemberDefinition `$sig -Name MFE -Namespace Win32 -PassThru`n    `$t::MoveFileEx(`$dll, `$null, 4) | Out-Null  # 4 = MOVEFILE_DELAY_UNTIL_REBOOT`n    Write-Host ""  Scheduled for delete on reboot: `$dll""`n  }`n}`n`n# 7d) REBOOT THE PC after running all steps above.`n# After reboot, the DLL will be gone and you can delete the install folder:`nRemove-Item -Path '$installPath' -Recurse -Force`n`n"

        $removalSteps += "# STEP 8 — Remove registry keys:`nRemove-Item -Path 'HKLM:\SOFTWARE\ScreenConnect' -Recurse -Force -ErrorAction SilentlyContinue`nRemove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\ScreenConnect' -Recurse -Force -ErrorAction SilentlyContinue`nRemove-Item -Path 'HKCU:\SOFTWARE\ScreenConnect' -Recurse -Force -ErrorAction SilentlyContinue`n`n"

        $removalSteps += "# STEP 9 — Verify service is gone:`nGet-Service '$($svc.Name)' -ErrorAction SilentlyContinue"

        $scFindings.Add([PSCustomObject]@{
            ServiceName  = $svc.Name
            DisplayName  = $svc.DisplayName
            State        = $svc.State
            StartMode    = $svc.StartMode
            BinaryPath   = if ($svc.PathName) { $svc.PathName } else { 'N/A' }
            InstallPath  = if ($installPath)  { $installPath  } else { 'Not found in registry' }
            Version      = if ($version)      { $version      } else { 'Unknown' }
            HasUninstaller = if ($uninstallCmd) { 'Yes' } else { 'No - manual removal required' }
            Sev          = if ($svc.State -eq 'Running') { 'HIGH' } else { 'MEDIUM' }
            Removal      = $removalSteps
        })
    }

    # ── Step C: Check if the SSP DLL is registered in LSA even if service is gone
    # This catches cases where SC was partially uninstalled but left its auth package behind
    try {
        $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $secPkgs  = (Get-ItemProperty $lsaKey -Name 'Security Packages'       -ErrorAction SilentlyContinue).('Security Packages')
        $authPkgs = (Get-ItemProperty $lsaKey -Name 'Authentication Packages' -ErrorAction SilentlyContinue).('Authentication Packages')
        $allPkgs  = @($secPkgs) + @($authPkgs) | Where-Object { $_ -like '*ScreenConnect*' -or $_ -like '*ConnectWise*' }

        foreach ($pkg in $allPkgs) {
            # Only add if not already represented by a service finding
            $alreadyCaptured = $scFindings | Where-Object { $_.ServiceName -notlike '*None*' }
            if ($alreadyCaptured) { continue }

            # Validate: check if the DLL actually exists anywhere on disk
            # If not, it's a stale LSA registry entry — still needs cleaning but not an active threat
            $dllSearchPaths = @(
                "$env:SystemRoot\System32\$pkg",
                "$env:SystemRoot\System32\${pkg}.dll",
                "$pkg"  # in case it's a full path
            )
            $dllExistsOnDisk = $dllSearchPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

            if (-not $dllExistsOnDisk) {
                # Stale LSA entry — DLL is gone but registry still references it
                $scFindings.Add([PSCustomObject]@{
                    ServiceName    = 'None (stale LSA entry)'
                    DisplayName    = "Stale LSA Auth Package reference: $pkg"
                    State          = 'DLL not found on disk — registry reference only'
                    StartMode      = 'References removed auth package'
                    BinaryPath     = "LSA registry entry: $pkg (DLL NOT FOUND ON DISK)"
                    InstallPath    = 'N/A'
                    Version        = 'N/A'
                    HasUninstaller = 'No — registry cleanup only'
                    Sev            = 'LOW'
                    Removal        = "# The ScreenConnect DLL is already gone from disk.`n# Only the LSA registry reference remains. Clean it up:`n`n`$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'`n`n# Remove from Security Packages:`n`$sp = (Get-ItemProperty `$lsaKey -Name 'Security Packages' -ErrorAction SilentlyContinue).('Security Packages')`nif (`$sp) {`n  Set-ItemProperty `$lsaKey -Name 'Security Packages' -Value (`$sp | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' })`n}`n`n# Remove from Authentication Packages:`n`$ap = (Get-ItemProperty `$lsaKey -Name 'Authentication Packages' -ErrorAction SilentlyContinue).('Authentication Packages')`nif (`$ap) {`n  Set-ItemProperty `$lsaKey -Name 'Authentication Packages' -Value (`$ap | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' })`n}`n`nWrite-Host 'Stale LSA entries removed. No reboot required (DLL already gone).'"
                })
                continue
            }

            $scFindings.Add([PSCustomObject]@{
                ServiceName    = 'None (SSP orphan)'
                DisplayName    = "Orphaned LSA Auth Package: $pkg"
                State          = 'No service — DLL registered in lsass only'
                StartMode      = 'Loads at boot via LSA'
                BinaryPath     = "LSA Security Packages registry: $pkg"
                InstallPath    = 'N/A'
                Version        = 'Unknown'
                HasUninstaller = 'No — registry edit + reboot required'
                Sev            = 'HIGH'
                Removal        = "# ScreenConnect left its Authentication Package registered in LSA.`n# lsass.exe holds the DLL open, which is why the folder cannot be deleted.`n`n# STEP 1 — Remove from LSA Security Packages:`n`$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'`n`$current = (Get-ItemProperty `$lsaKey -Name 'Security Packages').('Security Packages')`n`$cleaned = `$current | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' }`nSet-ItemProperty `$lsaKey -Name 'Security Packages' -Value `$cleaned`n`n# STEP 2 — Remove from Authentication Packages:`n`$authPkgs = (Get-ItemProperty `$lsaKey -Name 'Authentication Packages' -ErrorAction SilentlyContinue).('Authentication Packages')`nif (`$authPkgs) {`n  `$authCleaned = `$authPkgs | Where-Object { `$_ -notlike '*ScreenConnect*' -and `$_ -notlike '*ConnectWise*' }`n  Set-ItemProperty `$lsaKey -Name 'Authentication Packages' -Value `$authCleaned`n}`n`n# STEP 3 — Schedule the DLL for deletion on reboot:`n`$sig = '[DllImport(""kernel32.dll"",SetLastError=true)] public static extern bool MoveFileEx(string src, string dst, uint flags);'`n`$t = Add-Type -MemberDefinition `$sig -Name MFE2 -Namespace Win32 -PassThru -ErrorAction SilentlyContinue`nif (`$t) { `$t::MoveFileEx('$pkg', `$null, 4) | Out-Null }`n`n# STEP 4 — REBOOT, then delete any remaining ScreenConnect folders.`nWrite-Host 'Reboot required to release the DLL lock.'"
            })
        }
    } catch { }

    # ── Step E: Check for portable (no-service) installs via known paths ─────
    foreach ($scPath in $scKnownPaths) {
        if (-not (Test-Path $scPath)) { continue }
        # Only add if not already captured via service scan
        $alreadyCaptured = $scFindings | Where-Object { $_.InstallPath -like "*$scPath*" }
        if ($alreadyCaptured) { continue }

        $exes = Get-ChildItem $scPath -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3
        $exeList = ($exes | ForEach-Object { $_.Name }) -join ', '

        $scFindings.Add([PSCustomObject]@{
            ServiceName  = 'None (portable/no service)'
            DisplayName  = 'ScreenConnect portable install'
            State        = 'No service installed'
            StartMode    = 'N/A'
            BinaryPath   = $scPath
            InstallPath  = $scPath
            Version      = 'Unknown (no registry entry)'
            HasUninstaller = 'No - folder delete required'
            Sev          = 'HIGH'
            Removal      = "# Portable install — no uninstaller. Kill any running processes first:`nGet-Process | Where-Object { `$_.Path -like '*ScreenConnect*' -or `$_.Path -like '$scPath*' } | Stop-Process -Force`n`n# Then delete the entire folder:`nRemove-Item -Path '$scPath' -Recurse -Force`n`n# Remove leftover AppData too:`nRemove-Item -Path `"`$env:APPDATA\ScreenConnect`" -Recurse -Force -ErrorAction SilentlyContinue`nRemove-Item -Path `"`$env:LOCALAPPDATA\ScreenConnect`" -Recurse -Force -ErrorAction SilentlyContinue`n`n# Remove firewall rules:`nGet-NetFirewallRule | Where-Object { `$_.DisplayName -like '*ScreenConnect*' -or `$_.DisplayName -like '*ConnectWise*' } | Remove-NetFirewallRule"
        })
    }

} catch {
    Write-Host "    ScreenConnect scan error: $_" -ForegroundColor Red
}
Write-Host "    Found: $($scFindings.Count) ScreenConnect/ConnectWise installation(s)" -ForegroundColor Gray

# ── Scan 9: AppData / user-profile executables ───────────────────────────────
# Scammers hide remote-access tools deep in AppData (ScreenConnect in particular
# gets buried many sub-folders down, e.g. ClickOnce-style \Apps\2.0\<hash>\... ).
# A generic "flag every exe that's deep" rule produces a false-positive storm
# because legitimate apps (browsers, Electron apps) also bury signed exes. So we
# flag, at ANY depth:
#   • catalogued remote tools (by exe name / install path / signer)        -> HIGH
#   • UNSIGNED exes whose name matches a remote-access keyword              -> MEDIUM
#   • UNSIGNED exes buried deep in AppData (legit deep exes are signed)     -> LOW
# Microsoft-signed and benign signed apps are always ignored. The scan recurses
# the full tree, so a buried ScreenConnect is found no matter how deep it sits.
Write-Host "  [9/10] Deep-scanning user AppData folders (this is the slow one)..." -ForegroundColor Yellow
$appDataFindings = New-Object 'System.Collections.Generic.List[object]'

# Catalog exe base names, for a cheap pre-filter before the costly signature check
$catalogExe = @{}
foreach ($t in $RemoteTools) { foreach ($e in $t.Exe) { if ($e) { $catalogExe[$e] = $true } } }

try {
    $userProfiles = New-Object 'System.Collections.Generic.List[string]'
    $usersRoot = Split-Path $env:USERPROFILE -Parent            # e.g. C:\Users
    if (Test-Path $usersRoot) {
        Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($sub in @('AppData\Local','AppData\Roaming')) {
                $p = Join-Path $_.FullName $sub
                if (Test-Path $p) { $userProfiles.Add($p) }
            }
        }
    }

    foreach ($adPath in ($userProfiles | Sort-Object -Unique)) {
        $rootDepth = ($adPath -split '\\').Count
        Get-ChildItem -Path $adPath -Recurse -Filter '*.exe' -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $exeName = $_.Name.ToLower()
            $base    = $exeName -replace '\.exe$',''
            $exePath = $_.FullName

            # Cheap pre-filter: catalog exe names, remote keywords, or deeply buried exes
            $kw       = $ratKeywords | Where-Object { $base -like "*$_*" } | Select-Object -First 1
            $catalogN = $catalogExe.ContainsKey($base)
            $depth    = ($exePath -split '\\').Count - $rootDepth
            $deep     = $depth -ge 5     # buried many sub-folders below AppData\Local|Roaming
            if (-not $kw -and -not $catalogN -and -not $deep) { return }

            # Confirm with signature + catalog (expensive, runs only on candidates)
            $trust = Get-FileTrust $exePath
            if ($trust.IsMicrosoft) { return }
            if (Get-WhitelistMatch $exeName) { return }
            if (Get-WhitelistMatch $exePath) { return }   # e.g. ...\Microsoft\Teams\..., ...\OneDrive\...
            $tool = Find-RemoteTool -Exe $exeName -Path $exePath -Signer $trust.SignerName

            if ($tool) {
                $sev = 'HIGH';   $reason = "Remote access tool in AppData: $($tool.Name) — $($tool.Class)"
            } elseif (-not $trust.Signed -and $kw) {
                $sev = 'MEDIUM'; $reason = "Unsigned executable in AppData whose name matches '$kw'"
            } elseif (-not $trust.Signed -and $deep -and -not (Test-TrustedVendorPath $exePath)) {
                $sev = 'LOW';    $reason = "Unsigned executable buried $depth folders deep in AppData — a common hiding spot for ScreenConnect and similar tools"
            } else {
                return   # signed (non-Microsoft) without a catalog/keyword hit — too weak to flag
            }

            $signerNote = if ($trust.Signed) { "Signed by: $($trust.SignerName)" } else { 'UNSIGNED' }
            $appDataFindings.Add([PSCustomObject]@{
                Path    = $exePath
                Company = if ($trust.Company) { $trust.Company } else { 'Unknown' }
                Product = if ($trust.Product) { $trust.Product } else { 'Unknown' }
                Sev     = $sev
                Reason  = "$reason. $signerNote."
                Fix     = "Terminate if running: Get-Process | Where-Object { `$_.Path -eq '$exePath' } | Stop-Process -Force`nThen delete: Remove-Item -Path '$exePath' -Force`nIf inside a named folder, delete the whole folder."
            })
        }
    }
} catch {
    Write-Host "    AppData scan error: $_" -ForegroundColor Red
}
Write-Host "    Found: $($appDataFindings.Count)" -ForegroundColor Gray

# ── Scan 9: Remote access users ───────────────────────────────────────────────
Write-Host "  [10/11] Checking users with remote access permissions..." -ForegroundColor Yellow
$remoteUserFindings = New-Object 'System.Collections.Generic.List[object]'

try {
    # Resolve group membership by well-known SID so localized group names and
    # localized "net user" output never break parsing.
    function Get-GroupMemberNames([string]$sid) {
        $names = @()
        if ($null -ne (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
            try {
                Get-LocalGroupMember -SID $sid -ErrorAction Stop | ForEach-Object {
                    $names += ($_.Name -replace '^.*\\','')   # strip COMPUTER\ or DOMAIN\ prefix
                }
                return $names
            } catch {}
        }
        # CIM fallback — also resolves the group by SID, locale-independent
        try {
            $grp = Get-CimInstance Win32_Group -Filter "SID='$sid'" -ErrorAction Stop
            if ($grp) {
                Get-CimInstance -Query "ASSOCIATORS OF {Win32_Group.Domain='$($grp.Domain)',Name='$($grp.Name)'} WHERE ResultClass=Win32_Account" -ErrorAction SilentlyContinue |
                    ForEach-Object { $names += $_.Name }
            }
        } catch {}
        return $names
    }

    $adminUsers = Get-GroupMemberNames 'S-1-5-32-544'   # Administrators
    $rdpUsers   = Get-GroupMemberNames 'S-1-5-32-555'   # Remote Desktop Users

    # Enumerate local users
    if ($null -ne (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
    } else {
        $localUsers = Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=true' -ErrorAction SilentlyContinue |
                      Select-Object Name, @{N='Enabled';E={ -not $_.Disabled }}
    }

    foreach ($usr in $localUsers) {
        $u = $usr.Name
        if (-not $u) { continue }
        $isRdp   = $rdpUsers   -contains $u
        $isAdmin = $adminUsers -contains $u
        if (-not ($isRdp -or $isAdmin)) { continue }

        $accessType = @()
        if ($isAdmin) { $accessType += 'Local Administrator' }
        if ($isRdp)   { $accessType += 'Remote Desktop (RDP)' }
        # Informational only — every PC has a primary admin account, so this is not a
        # risk by itself. Listed so a tech can spot an account they do not recognize.
        $sev = 'LOW'

        $active = if ($null -ne $usr.Enabled) { if ($usr.Enabled) { 'Yes' } else { 'No' } } else { 'Unknown' }
        $last   = if ($usr.PSObject.Properties['LastLogon'] -and $usr.LastLogon) { [string]$usr.LastLogon } else { 'Never / Unknown' }
        $pw     = if ($usr.PSObject.Properties['PasswordExpires']) { if ($usr.PasswordExpires) { [string]$usr.PasswordExpires } else { 'Never' } } else { 'N/A' }

        $remoteUserFindings.Add([PSCustomObject]@{
            Username   = $u
            Access     = $accessType -join ', '
            Active     = $active
            LastLogon  = $last
            PwExpires  = $pw
            Sev        = $sev
            Fix        = "To remove from Remote Desktop Users:`nnet localgroup `"Remote Desktop Users`" `"$u`" /delete`n`nTo disable account:`nnet user `"$u`" /active:no`n`nTo remove admin rights:`nnet localgroup Administrators `"$u`" /delete"
        })
    }
} catch {
    Write-Host "    Remote user scan error: $_" -ForegroundColor Red
}
Write-Host "    Found: $($remoteUserFindings.Count) accounts with elevated/remote access" -ForegroundColor Gray

# ── Scan 10: Suspicious outbound/inbound network traffic ─────────────────────
Write-Host "  [11/11] Scanning for suspicious network traffic patterns..." -ForegroundColor Yellow
$suspTraffic = New-Object 'System.Collections.Generic.List[object]'

# Known-safe process names for outbound connections (reduces noise)
$trustedProcesses = @(
    'svchost','lsass','wininit','services','spoolsv','explorer',
    'searchindexer','onedrive','dropbox','teams','slack','zoom',
    'chrome','firefox','msedge','opera','brave','iexplore',
    'outlook','thunderbird','skype','discord','spotify',
    'windows defender','mssense','msmpeng','antimalware'
)

# IPs/ranges that are always safe to ignore
$trustedCIDRs = @('10.','172.16.','172.17.','172.18.','172.19.',
                   '172.20.','172.21.','172.22.','172.23.','172.24.',
                   '172.25.','172.26.','172.27.','172.28.','172.29.',
                   '172.30.','172.31.','192.168.','127.','169.254.')

function Is-TrustedIP([string]$ip) {
    foreach ($prefix in $trustedCIDRs) {
        if ($ip.StartsWith($prefix)) { return $true }
    }
    return $false
}

try {
    $netCmdAvail = $null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    if ($netCmdAvail) {
        $allConns2 = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $_.State -eq 'Established' -and
            $_.RemoteAddress -and
            $_.RemoteAddress -ne '0.0.0.0' -and
            $_.RemoteAddress -ne '::' -and
            $_.RemoteAddress -ne '::1' -and
            $_.RemoteAddress -notlike '127.*'
        }

        # Group by owning process to detect potential beaconing (many connections from same process to different IPs)
        $procGroups = $allConns2 | Group-Object OwningProcess

        foreach ($grp in $procGroups) {
            $pid2  = $grp.Name
            $conns = $grp.Group
            $proc  = ($allProcs | Where-Object { $_.Id -eq $pid2 } | Select-Object -First 1)
            $pname = if ($proc) { $proc.Name } else { 'Unknown' }
            $ppath = if ($proc) { $proc.Path } else { '' }
            # Fallback: resolve the owning process name/path via WMI when Get-Process missed it
            if (($pname -eq 'Unknown' -or -not $ppath) -and "$pid2" -match '^\d+$') {
                $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$pid2" -ErrorAction SilentlyContinue
                if ($wp) {
                    if ($pname -eq 'Unknown' -and $wp.Name) { $pname = ($wp.Name -replace '\.exe$','') }
                    if (-not $ppath -and $wp.ExecutablePath) { $ppath = $wp.ExecutablePath }
                }
            }

            # Skip silently whitelisted processes
            $wl = Get-WhitelistMatch $pname
            if (-not $wl) { $wl = Get-WhitelistMatch $ppath }
            if ($wl) { continue }

            # Skip well-known trusted system/browser processes
            $isTrusted = $trustedProcesses | Where-Object { $pname -like "*$_*" } | Select-Object -First 1
            if ($isTrusted) { continue }

            # Skip Microsoft-signed binaries — legitimate Windows components
            $ptrust = Get-FileTrust $ppath
            if ($ptrust.IsMicrosoft) { continue }

            # Filter to only external IPs
            $extConns = $conns | Where-Object { -not (Is-TrustedIP $_.RemoteAddress) }
            if ($extConns.Count -eq 0) { continue }

            # Flag 1: Process running from AppData/Temp with ANY external connection
            $suspPath = $ppath -and (
                $ppath -like '*\AppData\*' -or
                $ppath -like '*\Temp\*' -or
                $ppath -like '*\Users\Public\*'
            )

            # Flag 2: Process has unusually many simultaneous external connections (possible beaconing/exfil)
            $manyConns = $extConns.Count -ge 5

            # Flag 3: Connecting to non-standard high ports that aren't in the known RAT port list
            # (exclude 80,443,8080,8443 which are normal web)
            $normalWebPorts = @(80,443,8080,8443,8888,8000)
            $weirdPortConns = $extConns | Where-Object {
                $_.RemotePort -notin $normalWebPorts -and
                -not $ratPorts.ContainsKey($_.RemotePort) -and
                $_.RemotePort -gt 1024
            }
            $hasWeirdPorts = $weirdPortConns.Count -gt 0

            # For validly signed (non-Microsoft) apps, only a bad image path is
            # noteworthy — high connection counts and odd ports are normal for
            # many legitimate signed apps and would otherwise be false positives.
            if ($ptrust.Signed) { $manyConns = $false; $hasWeirdPorts = $false }

            if ($suspPath -or $manyConns -or $hasWeirdPorts) {
                # Detailed, de-duplicated remote list, annotating any known remote/C2 ports
                $remoteList = $extConns | ForEach-Object {
                    $rnote = $ratPorts[[int]$_.RemotePort]
                    if ($rnote) { "$($_.RemoteAddress):$($_.RemotePort) [$rnote]" } else { "$($_.RemoteAddress):$($_.RemotePort)" }
                } | Select-Object -Unique
                $shown   = @($remoteList | Select-Object -First 8)
                $remotes = $shown -join ', '
                if ($remoteList.Count -gt 8) { $remotes += " (+$($remoteList.Count - 8) more)" }

                $reasons = @()
                if ($suspPath)     { $reasons += "Process runs from a user-writable path (AppData/Temp/Public)" }
                if ($manyConns)    { $reasons += "$($extConns.Count) simultaneous external connections (possible beaconing/exfil)" }
                if ($hasWeirdPorts){ $reasons += "Connecting to unusual high ports: $(($weirdPortConns | Select-Object -Unique -ExpandProperty RemotePort | Select-Object -First 5) -join ', ')" }

                $sev = if ($suspPath -and $manyConns) { 'HIGH' } elseif ($suspPath -or $manyConns) { 'MEDIUM' } else { 'LOW' }
                $signer = if ($ptrust.Signed) { $ptrust.SignerName } else { 'UNSIGNED' }

                $suspTraffic.Add([PSCustomObject]@{
                    Process  = $pname
                    PID      = $pid2
                    Path     = if ($ppath) { $ppath } else { 'N/A (could not resolve image path)' }
                    Signer   = $signer
                    ExtConns = $extConns.Count
                    Remotes  = $remotes
                    Sev      = $sev
                    Reason   = $reasons -join '; '
                    Fix      = "This traffic is coming from: $pname (PID $pid2)`nImage: $(if($ppath){$ppath}else{'unknown'})`nKill if suspicious: Stop-Process -Id $pid2 -Force`nSee live per-process connections: Get-NetTCPConnection -OwningProcess $pid2`nOr use TCPView (Sysinternals)."
                })
            }
        }
    } else {
        Write-Host "    (Get-NetTCPConnection unavailable; skipping advanced traffic analysis)" -ForegroundColor Gray
    }
} catch {
    Write-Host "    Traffic scan error: $_" -ForegroundColor Red
}
Write-Host "    Found: $($suspTraffic.Count)" -ForegroundColor Gray

# ── Tally findings ────────────────────────────────────────────────────────────
$allFindings = New-Object 'System.Collections.Generic.List[string]'
foreach ($p in $suspProcs)   { $allFindings.Add("PROCESS: $($p.Name) (PID $($p.PID)) - $($p.Sev) - $($p.Reason)") }
foreach ($s in $suspSvcs)    { $allFindings.Add("SERVICE: $($s.Display) [$($s.State)] - $($s.Sev)") }
foreach ($c in $suspConns)   { $allFindings.Add("NETWORK: $($c.Process) to $($c.Remote) [$($c.Note)] - $($c.Sev)") }
foreach ($t in $suspTasks)   { $allFindings.Add("TASK: $($t.Name) runs $($t.Exe) - $($t.Sev)") }
foreach ($r in $suspReg)     { $allFindings.Add("REGISTRY: $($r.Name) = $($r.Value) - $($r.Sev)") }
foreach ($f in $suspFolders) { $allFindings.Add("FOLDER: $($f.Path) - HIGH") }
foreach ($sc in $scFindings) {
    $scNote = if ($sc.ServiceName -like '*SSP orphan*') { 'SCREENCONNECT SSP DLL ORPHAN (locks folder, reboot needed)' } else { "SCREENCONNECT: $($sc.DisplayName) [$($sc.State)]" }
    $allFindings.Add("$scNote - $($sc.Sev)")
}
foreach ($a in $appDataFindings) { $allFindings.Add("APPDATA: $($a.Path) - $($a.Sev) - $($a.Reason)") }
foreach ($u in $remoteUserFindings) { if ($u.Sev -ne 'LOW') { $allFindings.Add("USER: $($u.Username) has $($u.Access) - $($u.Sev)") } }
foreach ($tr in $suspTraffic) { $allFindings.Add("TRAFFIC: $($tr.Process) (PID $($tr.PID)) - $($tr.Sev) - $($tr.Reason)") }
if ($rdpEnabled) {
    $allFindings.Add("RDP: Enabled on port $rdpPort, NLA=$(if($nlaOn){'YES - secure'}else{'NO - insecure'})")
}

$total     = $allFindings.Count
$risk      = if ($total -eq 0) { 'CLEAN' } elseif ($total -le 3) { 'LOW' } elseif ($total -le 8) { 'MEDIUM' } else { 'HIGH' }
$riskColor = switch ($risk) { 'CLEAN' {'#16a34a'} 'LOW' {'#d97706'} 'MEDIUM' {'#ea580c'} 'HIGH' {'#dc2626'} }
$riskBg    = switch ($risk) { 'CLEAN' {'#f0fdf4'} 'LOW' {'#fffbeb'} 'MEDIUM' {'#fff7ed'} 'HIGH' {'#fef2f2'} }
$riskMsg   = switch ($risk) {
    'CLEAN'  { 'No suspicious remote access activity detected on this machine.' }
    'LOW'    { 'A small number of items flagged. Review each one below.' }
    'MEDIUM' { 'Several suspicious items found. Investigate and remediate promptly.' }
    'HIGH'   { 'HIGH RISK: Multiple remote access indicators found. Take immediate action.' }
}

Write-Host ""
Write-Host "  Total findings: $total  |  Risk: $risk" -ForegroundColor Cyan
Write-Host "  Building remediation window..." -ForegroundColor Yellow

# ── Build WPF findings list ───────────────────────────────────────────────────
# Each entry: Category, Severity, Title, Detail, FixScript
$guiFindings = New-Object 'System.Collections.Generic.List[object]'

foreach ($p in $suspProcs) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Process'
        Sev        = $p.Sev
        Title      = "$($p.Name)  (PID $($p.PID))"
        Detail     = "$($p.Reason)`nPath: $($p.Path)`nCompany: $($p.Company)"
        FixScript  = $p.Fix
        FixLabel   = 'Kill Process'
    })
}
foreach ($s in $suspSvcs) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Service'
        Sev        = $s.Sev
        Title      = "$($s.Display) [$($s.State)]"
        Detail     = $s.Reason
        FixScript  = $s.Fix
        FixLabel   = 'Stop & Disable'
    })
}
foreach ($c in $suspConns) {
    $cpath = ($allProcs | Where-Object { $_.Id -eq $c.PID } | Select-Object -First 1).Path
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Network'
        Sev        = $c.Sev
        Title      = "$($c.Process)  (PID $($c.PID))  →  $($c.Remote)"
        Detail     = "From process: $($c.Process)  (PID $($c.PID))`nImage path: $(if($cpath){$cpath}else{'unknown'})`nLocal: $($c.Local)`nRemote: $($c.Remote)  [$($c.Note)]`nState: $($c.State)"
        FixScript  = $c.Fix
        FixLabel   = 'Kill & Block'
    })
}
foreach ($t in $suspTasks) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Task'
        Sev        = $t.Sev
        Title      = $t.Name
        Detail     = "$($t.Reason)`nRuns: $($t.Exe)"
        FixScript  = $t.Fix
        FixLabel   = 'Remove Task'
    })
}
foreach ($r in $suspReg) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Registry'
        Sev        = $r.Sev
        Title      = $r.Name
        Detail     = "$($r.Reason)`nValue: $($r.Value)"
        FixScript  = $r.Fix
        FixLabel   = 'Delete Key'
    })
}
foreach ($f in $suspFolders) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Folder'
        Sev        = $f.Sev
        Title      = $f.Path
        Detail     = $f.Reason
        FixScript  = $f.Fix
        FixLabel   = 'Delete Folder'
    })
}
foreach ($sc in $scFindings) {
    $label = if ($sc.Sev -eq 'LOW') { 'Clean Registry' } else { 'Full Removal' }
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'ScreenConnect'
        Sev        = $sc.Sev
        Title      = $sc.DisplayName
        Detail     = "Service: $($sc.ServiceName)  |  State: $($sc.State)`nInstall path: $($sc.InstallPath)`nUninstaller: $($sc.HasUninstaller)"
        FixScript  = $sc.Removal
        FixLabel   = $label
    })
}
foreach ($a in $appDataFindings) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'AppData'
        Sev        = $a.Sev
        Title      = Split-Path $a.Path -Leaf
        Detail     = "$($a.Reason)`nPath: $($a.Path)"
        FixScript  = $a.Fix
        FixLabel   = 'Delete File'
    })
}
foreach ($u in $remoteUserFindings) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'User'
        Sev        = $u.Sev
        Title      = "$($u.Username)  [$($u.Access)]"
        Detail     = "Active: $($u.Active)  |  Last logon: $($u.LastLogon)  |  PW expires: $($u.PwExpires)"
        FixScript  = $u.Fix
        FixLabel   = 'Remove Access'
    })
}
foreach ($tr in $suspTraffic) {
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'Traffic'
        Sev        = $tr.Sev
        Title      = "$($tr.Process)  (PID $($tr.PID))  —  $($tr.ExtConns) external connection$(if($tr.ExtConns -ne 1){'s'})"
        Detail     = "From process: $($tr.Process)  (PID $($tr.PID))`nImage path: $($tr.Path)`nSigner: $($tr.Signer)`nWhy flagged: $($tr.Reason)`nConnecting to: $($tr.Remotes)"
        FixScript  = $tr.Fix
        FixLabel   = 'Kill Process'
    })
}
if ($rdpEnabled) {
    $rdpFix = "# Disable RDP entirely:`nSet-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1`nDisable-NetFirewallRule -DisplayGroup 'Remote Desktop'`nWrite-Host 'RDP disabled.'"
    $guiFindings.Add([PSCustomObject]@{
        Category   = 'RDP'
        Sev        = if (-not $nlaOn) { 'HIGH' } else { 'MEDIUM' }
        Title      = "RDP Enabled on port $rdpPort  $(if(-not $nlaOn){'— NLA OFF (insecure)'}else{'— NLA ON'})"
        Detail     = "Network Level Authentication: $(if($nlaOn){'Enabled (secure)'}else{'DISABLED — anyone can attempt login without credentials first'})"
        FixScript  = $rdpFix
        FixLabel   = 'Disable RDP'
    })
}

# ── Launch WPF GUI ────────────────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$sevColor = @{
    'HIGH'   = '#dc2626'
    'MEDIUM' = '#ea580c'
    'LOW'    = '#2563eb'
    'CLEAN'  = '#16a34a'
}
$catColor = @{
    'Process'       = '#7c3aed'
    'Service'       = '#0369a1'
    'Network'       = '#b45309'
    'Task'          = '#0f766e'
    'Registry'      = '#be185d'
    'Folder'        = '#92400e'
    'ScreenConnect' = '#dc2626'
    'AppData'       = '#b91c1c'
    'User'          = '#1d4ed8'
    'Traffic'       = '#c2410c'
    'RDP'           = '#9f1239'
}
$riskWindowColor = @{
    'CLEAN'  = '#16a34a'
    'LOW'    = '#d97706'
    'MEDIUM' = '#ea580c'
    'HIGH'   = '#dc2626'
}

# Helper: run a fix script in a new elevated powershell window
function Invoke-Fix {
    param([string]$script, [string]$title)
    $confirm = [System.Windows.MessageBox]::Show(
        "Run fix: $title`n`nThis will execute PowerShell commands with admin rights.`nContinue?",
        "Confirm Fix",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    if ($confirm -ne 'Yes') { return }

    # Write script to temp file and run in a new visible PS window so user can see output
    $tmp = [System.IO.Path]::GetTempFileName() + '.ps1'
    $wrapped = @"
Write-Host '=== Remote Access Audit — Fix: $title ===' -ForegroundColor Cyan
Write-Host ''
try {
$script
    Write-Host ''
    Write-Host 'Fix completed.' -ForegroundColor Green
} catch {
    Write-Host "Error: `$_" -ForegroundColor Red
}
Write-Host ''
Write-Host 'Press Enter to close this window...' -ForegroundColor Gray
Read-Host
"@
    [System.IO.File]::WriteAllText($tmp, $wrapped, [System.Text.Encoding]::UTF8)
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`"" -Verb RunAs
}

# ── Build the window XAML ─────────────────────────────────────────────────────
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Remote Access Audit — $env:COMPUTERNAME"
    Width="980" Height="720" MinWidth="800" MinHeight="500"
    WindowStartupLocation="CenterScreen"
    Background="#0f172a">
  <Window.Resources>
    <Style x:Key="FlatBtn" TargetType="Button">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="FontFamily" Value="Segoe UI"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="10,4"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="4"
                    Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Opacity" Value="0.85"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter Property="Opacity" Value="0.7"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <DockPanel>
    <!-- Header -->
    <Border DockPanel.Dock="Top" Background="#1e3a5f" Padding="20,14">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0">
          <TextBlock Text="🛡 Remote Access Audit" FontSize="20" FontWeight="Bold"
                     Foreground="White" FontFamily="Segoe UI"/>
          <TextBlock FontSize="12" Foreground="#94a3b8" FontFamily="Segoe UI" Margin="0,2,0,0">
            <Run Text="$env:COMPUTERNAME"/>
            <Run Text="  ·  "/>
            <Run Text="$env:USERNAME"/>
            <Run Text="  ·  "/>
            <Run Text="$(Get-Date -Format 'MM/dd/yyyy HH:mm')"/>
          </TextBlock>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Background="$($riskWindowColor[$risk])" CornerRadius="6" Padding="14,6" Margin="0,0,10,0">
            <StackPanel>
              <TextBlock Text="RISK" FontSize="9" FontWeight="Bold" Foreground="White"
                         HorizontalAlignment="Center" FontFamily="Segoe UI"/>
              <TextBlock Text="$risk" FontSize="16" FontWeight="Bold" Foreground="White"
                         HorizontalAlignment="Center" FontFamily="Segoe UI"/>
            </StackPanel>
          </Border>
          <Border Background="#334155" CornerRadius="6" Padding="14,6">
            <StackPanel>
              <TextBlock Text="FINDINGS" FontSize="9" FontWeight="Bold" Foreground="#94a3b8"
                         HorizontalAlignment="Center" FontFamily="Segoe UI"/>
              <TextBlock Text="$total" FontSize="16" FontWeight="Bold" Foreground="White"
                         HorizontalAlignment="Center" FontFamily="Segoe UI"/>
            </StackPanel>
          </Border>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Toolbar -->
    <Border DockPanel.Dock="Top" Background="#1e293b" Padding="20,8">
      <StackPanel Orientation="Horizontal">
        <Button x:Name="btnRunAll" Content="⚡ Run ALL Fixes" Style="{StaticResource FlatBtn}"
                Background="#dc2626" Foreground="White" FontSize="12" Padding="16,6" Margin="0,0,10,0"/>
        <Button x:Name="btnViewScript" Content="📋 View Script" Style="{StaticResource FlatBtn}"
                Background="#334155" Foreground="#e2e8f0" Margin="0,0,6,0"/>
        <Button x:Name="btnClose" Content="✕ Close" Style="{StaticResource FlatBtn}"
                Background="#334155" Foreground="#e2e8f0"/>
        <TextBlock x:Name="tbStatus" Foreground="#94a3b8" FontFamily="Segoe UI" FontSize="11"
                   VerticalAlignment="Center" Margin="16,0,0,0" Text="Click a Fix button to remediate an item."/>
      </StackPanel>
    </Border>

    <!-- Status bar at bottom -->
    <Border DockPanel.Dock="Bottom" Background="#0f172a" Padding="20,6">
      <TextBlock x:Name="tbFooter"
                 Text="Remote Access Audit  ·  $(Get-Date -Format 'MMMM dd, yyyy')  ·  $env:COMPUTERNAME"
                 Foreground="#475569" FontSize="10" FontFamily="Segoe UI"/>
    </Border>

    <!-- Main scrollable findings list -->
    <ScrollViewer Background="#0f172a" Padding="16,12" VerticalScrollBarVisibility="Auto">
      <StackPanel x:Name="spFindings"/>
    </ScrollViewer>
  </DockPanel>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$spFindings  = $window.FindName('spFindings')
$btnRunAll   = $window.FindName('btnRunAll')
$btnClose    = $window.FindName('btnClose')
$btnViewScript = $window.FindName('btnViewScript')
$tbStatus    = $window.FindName('tbStatus')

# ── Populate findings ─────────────────────────────────────────────────────────
if ($guiFindings.Count -eq 0) {
    $clean = [System.Windows.Controls.Border]::new()
    $clean.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#0f3d1f')
    $clean.CornerRadius = [System.Windows.CornerRadius]::new(8)
    $clean.Padding = [System.Windows.Thickness]::new(20)
    $clean.Margin = [System.Windows.Thickness]::new(0,4,0,4)
    $tb = [System.Windows.Controls.TextBlock]::new()
    $tb.Text = '✔  No suspicious remote access activity detected. This machine appears clean.'
    $tb.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#4ade80')
    $tb.FontSize = 14
    $tb.FontFamily = [System.Windows.Media.FontFamily]::new('Segoe UI')
    $clean.Child = $tb
    $spFindings.Children.Add($clean) | Out-Null
} else {
    # Group by category for visual separation
    $grouped = $guiFindings | Group-Object Category
    foreach ($grp in $grouped) {
        # Section header
        $hdrBorder = [System.Windows.Controls.Border]::new()
        $hdrBorder.Margin = [System.Windows.Thickness]::new(0,10,0,4)
        $hdrBorder.Padding = [System.Windows.Thickness]::new(12,5)
        $hdrColor = if ($catColor.ContainsKey($grp.Name)) { $catColor[$grp.Name] } else { '#475569' }
        $hdrBorder.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString($hdrColor)
        $hdrBorder.CornerRadius = [System.Windows.CornerRadius]::new(6)
        $hdrTb = [System.Windows.Controls.TextBlock]::new()
        $hdrTb.Text = "$($grp.Name.ToUpper())  ($($grp.Group.Count) finding$(if($grp.Group.Count -ne 1){'s'}))"
        $hdrTb.Foreground = [System.Windows.Media.Brushes]::White
        $hdrTb.FontWeight = [System.Windows.FontWeights]::Bold
        $hdrTb.FontSize = 11
        $hdrTb.FontFamily = [System.Windows.Media.FontFamily]::new('Segoe UI')
        $hdrBorder.Child = $hdrTb
        $spFindings.Children.Add($hdrBorder) | Out-Null

        foreach ($f in $grp.Group) {
            # Card border
            $card = [System.Windows.Controls.Border]::new()
            $card.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#1e293b')
            $card.CornerRadius = [System.Windows.CornerRadius]::new(6)
            $card.Margin = [System.Windows.Thickness]::new(0,2,0,2)
            $card.Padding = [System.Windows.Thickness]::new(14,10)

            # Severity accent bar (left border via inner grid trick)
            $sevHex  = if ($sevColor.ContainsKey($f.Sev)) { $sevColor[$f.Sev] } else { '#475569' }

            $outerDock = [System.Windows.Controls.DockPanel]::new()

            # Left severity stripe
            $stripe = [System.Windows.Controls.Border]::new()
            $stripe.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString($sevHex)
            $stripe.Width = 4
            $stripe.CornerRadius = [System.Windows.CornerRadius]::new(4,0,0,4)
            $stripe.Margin = [System.Windows.Thickness]::new(-14,-10,10,-10)
            [System.Windows.Controls.DockPanel]::SetDock($stripe, [System.Windows.Controls.Dock]::Left)
            $outerDock.Children.Add($stripe) | Out-Null

            # Fix button on right
            $fixBtn = [System.Windows.Controls.Button]::new()
            $fixBtn.Content = $f.FixLabel
            $fixBtn.Style = $window.Resources['FlatBtn']
            $fixBtn.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString($sevHex)
            $fixBtn.Foreground = [System.Windows.Media.Brushes]::White
            $fixBtn.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            $fixBtn.Margin = [System.Windows.Thickness]::new(10,0,0,0)
            $fixBtn.MinWidth = 100
            [System.Windows.Controls.DockPanel]::SetDock($fixBtn, [System.Windows.Controls.Dock]::Right)
            # Capture for closure
            $capturedScript = $f.FixScript
            $capturedTitle  = $f.Title
            $capturedStatus = $tbStatus
            $fixBtn.Add_Click({
                $capturedStatus.Text = "Running: $capturedTitle ..."
                Invoke-Fix -script $capturedScript -title $capturedTitle
                $capturedStatus.Text = "Last run: $capturedTitle"
            }.GetNewClosure())
            $outerDock.Children.Add($fixBtn) | Out-Null

            # Text content
            $textStack = [System.Windows.Controls.StackPanel]::new()

            # Title row
            $titleDock = [System.Windows.Controls.DockPanel]::new()
            $titleDock.Margin = [System.Windows.Thickness]::new(0,0,0,3)

            $sevBadge = [System.Windows.Controls.Border]::new()
            $sevBadge.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString($sevHex)
            $sevBadge.CornerRadius = [System.Windows.CornerRadius]::new(3)
            $sevBadge.Padding = [System.Windows.Thickness]::new(5,1)
            $sevBadge.Margin = [System.Windows.Thickness]::new(0,0,8,0)
            $sevBadge.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            [System.Windows.Controls.DockPanel]::SetDock($sevBadge, [System.Windows.Controls.Dock]::Left)
            $sevTb = [System.Windows.Controls.TextBlock]::new()
            $sevTb.Text = $f.Sev
            $sevTb.Foreground = [System.Windows.Media.Brushes]::White
            $sevTb.FontSize = 9
            $sevTb.FontWeight = [System.Windows.FontWeights]::Bold
            $sevTb.FontFamily = [System.Windows.Media.FontFamily]::new('Segoe UI')
            $sevBadge.Child = $sevTb
            $titleDock.Children.Add($sevBadge) | Out-Null

            $titleTb = [System.Windows.Controls.TextBlock]::new()
            $titleTb.Text = $f.Title
            $titleTb.Foreground = [System.Windows.Media.Brushes]::White
            $titleTb.FontSize = 13
            $titleTb.FontWeight = [System.Windows.FontWeights]::SemiBold
            $titleTb.FontFamily = [System.Windows.Media.FontFamily]::new('Segoe UI')
            $titleTb.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $titleDock.Children.Add($titleTb) | Out-Null
            $textStack.Children.Add($titleDock) | Out-Null

            # Detail text
            $detailTb = [System.Windows.Controls.TextBlock]::new()
            $detailTb.Text = $f.Detail
            $detailTb.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#94a3b8')
            $detailTb.FontSize = 11
            $detailTb.FontFamily = [System.Windows.Media.FontFamily]::new('Segoe UI')
            $detailTb.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $textStack.Children.Add($detailTb) | Out-Null

            # View Script expander
            $viewScriptBtn = [System.Windows.Controls.Button]::new()
            $viewScriptBtn.Content = '▶ View fix script'
            $viewScriptBtn.Style = $window.Resources['FlatBtn']
            $viewScriptBtn.Background = [System.Windows.Media.Transparent]::Transparent
            $viewScriptBtn.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#64748b')
            $viewScriptBtn.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
            $viewScriptBtn.Padding = [System.Windows.Thickness]::new(0,4,0,0)
            $viewScriptBtn.FontSize = 10

            $scriptBox = [System.Windows.Controls.Border]::new()
            $scriptBox.Background = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#0f172a')
            $scriptBox.CornerRadius = [System.Windows.CornerRadius]::new(4)
            $scriptBox.Padding = [System.Windows.Thickness]::new(10,8)
            $scriptBox.Margin = [System.Windows.Thickness]::new(0,4,0,0)
            $scriptBox.Visibility = [System.Windows.Visibility]::Collapsed
            $scriptTb = [System.Windows.Controls.TextBlock]::new()
            $scriptTb.Text = $f.FixScript
            $scriptTb.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.ColorConverter]::ConvertFromString('#86efac')
            $scriptTb.FontFamily = [System.Windows.Media.FontFamily]::new('Consolas')
            $scriptTb.FontSize = 10
            $scriptTb.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $scriptBox.Child = $scriptTb
            $capturedScriptBox = $scriptBox
            $capturedViewBtn   = $viewScriptBtn
            $viewScriptBtn.Add_Click({
                if ($capturedScriptBox.Visibility -eq [System.Windows.Visibility]::Collapsed) {
                    $capturedScriptBox.Visibility = [System.Windows.Visibility]::Visible
                    $capturedViewBtn.Content = '▼ Hide fix script'
                } else {
                    $capturedScriptBox.Visibility = [System.Windows.Visibility]::Collapsed
                    $capturedViewBtn.Content = '▶ View fix script'
                }
            }.GetNewClosure())
            $textStack.Children.Add($viewScriptBtn) | Out-Null
            $textStack.Children.Add($scriptBox)     | Out-Null

            $outerDock.Children.Add($textStack) | Out-Null
            $card.Child = $outerDock
            $spFindings.Children.Add($card) | Out-Null
        }
    }
}

# ── Wire toolbar buttons ──────────────────────────────────────────────────────
$btnClose.Add_Click({ $window.Close() })

$btnViewScript.Add_Click({
    $allScripts = ($guiFindings | ForEach-Object { "# === $($_.Category): $($_.Title) ===`n$($_.FixScript)" }) -join "`n`n"
    $tmp = [System.IO.Path]::GetTempFileName() + '.ps1'
    [System.IO.File]::WriteAllText($tmp, $allScripts, [System.Text.Encoding]::UTF8)
    Start-Process notepad $tmp
})

$allGuiFindings = $guiFindings  # capture for closure
$btnRunAll.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show(
        "This will run ALL $($allGuiFindings.Count) fix scripts one by one.`n`nEach will open in its own PowerShell window asking for confirmation.`n`nContinue?",
        'Run All Fixes',
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    if ($confirm -ne 'Yes') { return }
    foreach ($f in $allGuiFindings) {
        Invoke-Fix -script $f.FixScript -title $f.Title
    }
})

Write-Host "  Launching remediation window..." -ForegroundColor Green
$window.ShowDialog() | Out-Null

Write-Host ""
Write-Host "  Done. Findings: $total  Risk: $risk" -ForegroundColor Cyan
Write-Host ""

# ── Save report ───────────────────────────────────────────────────────────────
$css = @'
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f1f5f9; color: #1e293b; line-height: 1.6; }
.wrap { max-width: 1150px; margin: 0 auto; padding: 28px 18px; }
.header { background: linear-gradient(135deg, #0f172a, #1e3a5f); color: #fff; padding: 30px 34px; border-radius: 12px; margin-bottom: 20px; }
.header h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
.header p { opacity: .7; font-size: 13px; }
.meta { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px; }
.meta-item { background: rgba(255,255,255,.1); border-radius: 8px; padding: 10px 14px; min-width: 130px; }
.meta-item .lbl { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; opacity: .6; }
.meta-item .val { font-size: 13px; font-weight: 600; margin-top: 2px; }
.risk-box { border-radius: 10px; padding: 16px 22px; margin-bottom: 20px; border: 2px solid; }
.risk-box .rl { font-size: 20px; font-weight: 700; }
.risk-box .rm { font-size: 13px; margin-top: 4px; }
.card { background: #fff; border-radius: 10px; padding: 22px 26px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.card h2 { font-size: 16px; font-weight: 700; color: #0f172a; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; margin-bottom: 6px; }
.intro { font-size: 12px; color: #64748b; margin-bottom: 10px; }
.clean { color: #16a34a; font-style: italic; font-size: 13px; padding: 8px 0; }
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #0f172a; color: #fff; padding: 9px 10px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; white-space: nowrap; }
td { padding: 8px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
tr:nth-child(even) td { background: #f8fafc; }
tr:hover td { background: #eff6ff; }
.fix-box { background: #0f172a; color: #86efac; font-family: Consolas, monospace; font-size: 11px; padding: 8px 12px; border-radius: 6px; margin-top: 6px; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }
.findings-list { list-style: none; padding: 0; }
.findings-list li { padding: 7px 12px; border-left: 4px solid #dc2626; background: #fef2f2; margin-bottom: 5px; border-radius: 0 6px 6px 0; font-size: 12px; }
.findings-list li.ok { border-color: #16a34a; background: #f0fdf4; color: #15803d; }
.rdp-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
.rdp-item { background: #f8fafc; border-radius: 8px; padding: 12px 16px; }
.rdp-item .lbl { font-size: 10px; text-transform: uppercase; color: #94a3b8; }
.rdp-item .val { font-size: 14px; font-weight: 700; margin-top: 4px; }
.on { color: #dc2626; } .off-good { color: #16a34a; }
.footer { text-align: center; color: #94a3b8; font-size: 11px; margin-top: 28px; padding-top: 14px; border-top: 1px solid #e2e8f0; }
@media print { body { background: #fff; } }
'@

# ── Build HTML ────────────────────────────────────────────────────────────────
Write-Host "  Building HTML report..." -ForegroundColor Yellow

$sb = New-Object System.Text.StringBuilder

$null = $sb.AppendLine('<!DOCTYPE html>')
$null = $sb.AppendLine('<html lang="en">')
$null = $sb.AppendLine('<head>')
$null = $sb.AppendLine('<meta charset="UTF-8">')
$null = $sb.AppendLine("<title>Remote Access Audit - $env:COMPUTERNAME</title>")
$null = $sb.AppendLine('<style>')
$null = $sb.AppendLine($css)
$null = $sb.AppendLine('</style>')
$null = $sb.AppendLine('</head>')
$null = $sb.AppendLine('<body><div class="wrap">')

# Header
$null = $sb.AppendLine('<div class="header">')
$null = $sb.AppendLine('<h1>&#x1F6E1; Remote Access Audit Report</h1>')
$null = $sb.AppendLine('<p>Comprehensive scan for unauthorized or hidden remote access utilities</p>')
$null = $sb.AppendLine('<div class="meta">')
$null = $sb.AppendLine("<div class='meta-item'><div class='lbl'>Computer</div><div class='val'>$(Esc $env:COMPUTERNAME)</div></div>")
$null = $sb.AppendLine("<div class='meta-item'><div class='lbl'>User</div><div class='val'>$(Esc $env:USERNAME)</div></div>")
$null = $sb.AppendLine("<div class='meta-item'><div class='lbl'>Scan Time</div><div class='val'>$(Get-Date -Format 'MM/dd/yyyy HH:mm')</div></div>")
$null = $sb.AppendLine("<div class='meta-item'><div class='lbl'>Total Findings</div><div class='val'>$total</div></div>")
$null = $sb.AppendLine("<div class='meta-item'><div class='lbl'>Risk Level</div><div class='val' style='color:$riskColor;font-size:15px'>$risk</div></div>")
$null = $sb.AppendLine('</div></div>')

# Risk banner
$null = $sb.AppendLine("<div class='risk-box' style='background:$riskBg;border-color:$riskColor'>")
$null = $sb.AppendLine("<div class='rl' style='color:$riskColor'>Risk Level: $risk</div>")
$null = $sb.AppendLine("<div class='rm'>$riskMsg</div>")
$null = $sb.AppendLine('</div>')

# Findings summary
$null = $sb.AppendLine('<div class="card">')
$null = $sb.AppendLine('<h2>&#x1F4CB; Findings Summary</h2>')
$null = $sb.AppendLine('<ul class="findings-list">')
if ($allFindings.Count -gt 0) {
    foreach ($f in $allFindings) {
        $null = $sb.AppendLine("<li>$(Esc $f)</li>")
    }
} else {
    $null = $sb.AppendLine('<li class="ok">&#x2714; No suspicious findings detected across all scan categories.</li>')
}
$null = $sb.AppendLine('</ul></div>')

# Processes section
$null = $sb.AppendLine((Section 'Suspicious Processes' `
    'Processes matching known remote access tools or running from unusual locations (AppData, Temp, Public).' `
    $suspProcs `
    @('Process','PID','Path','Company','Severity','Reason','How to Stop') `
    {
        param($p)
        "<tr><td><strong>$(Esc $p.Name)</strong></td><td>$($p.PID)</td><td style='font-size:11px;word-break:break-all'>$(Esc $p.Path)</td><td>$(Esc $p.Company)</td><td>$(Badge $p.Sev)</td><td>$(Esc $p.Reason)</td><td><div class='fix-box'>$(Esc $p.Fix)</div></td></tr>"
    }
))

# Services section
$null = $sb.AppendLine((Section 'Suspicious Services' `
    'Windows services matching known remote access tools or installed in unusual paths.' `
    $suspSvcs `
    @('Service Name','Display Name','State','Startup','Severity','Reason','How to Stop') `
    {
        param($s)
        "<tr><td><strong>$(Esc $s.Name)</strong></td><td>$(Esc $s.Display)</td><td>$(Esc $s.State)</td><td>$(Esc $s.Start)</td><td>$(Badge $s.Sev)</td><td>$(Esc $s.Reason)</td><td><div class='fix-box'>$(Esc $s.Fix)</div></td></tr>"
    }
))

# Network section
$null = $sb.AppendLine((Section 'Suspicious Network Connections' `
    'Active connections on ports used by remote access tools. Established connections are highest priority.' `
    $suspConns `
    @('Process','PID','Local','Remote','State','Port Note','Severity','How to Block') `
    {
        param($c)
        "<tr><td><strong>$(Esc $c.Process)</strong></td><td>$($c.PID)</td><td style='font-size:11px'>$(Esc $c.Local)</td><td style='font-size:11px'>$(Esc $c.Remote)</td><td>$(Esc $c.State)</td><td>$(Esc $c.Note)</td><td>$(Badge $c.Sev)</td><td><div class='fix-box'>$(Esc $c.Fix)</div></td></tr>"
    }
))

# Tasks section
$null = $sb.AppendLine((Section 'Suspicious Scheduled Tasks' `
    'Tasks pointing to remote access tools, suspicious paths, or using obfuscated/random names.' `
    $suspTasks `
    @('Task Name','Executes','Arguments','State','Severity','Reason','How to Remove') `
    {
        param($t)
        "<tr><td><strong>$(Esc $t.Name)</strong></td><td style='font-size:11px;word-break:break-all'>$(Esc $t.Exe)</td><td style='font-size:11px'>$(Esc $t.Args)</td><td>$(Esc $t.State)</td><td>$(Badge $t.Sev)</td><td>$(Esc $t.Reason)</td><td><div class='fix-box'>$(Esc $t.Fix)</div></td></tr>"
    }
))

# Registry section
$null = $sb.AppendLine((Section 'Suspicious Registry Startup Entries' `
    'Registry keys that auto-start programs at login. These should be investigated immediately if unexpected.' `
    $suspReg `
    @('Registry Path','Entry Name','Value','Severity','Reason','How to Remove') `
    {
        param($r)
        "<tr><td style='font-size:11px;word-break:break-all'>$(Esc $r.RegPath)</td><td>$(Esc $r.Name)</td><td style='font-size:11px;word-break:break-all'>$(Esc $r.Value)</td><td>$(Badge $r.Sev)</td><td>$(Esc $r.Reason)</td><td><div class='fix-box'>$(Esc $r.Fix)</div></td></tr>"
    }
))

# Folders section
$null = $sb.AppendLine((Section 'Known Remote Access Tool Folders' `
    'Installation directories of known remote access software found on this machine.' `
    $suspFolders `
    @('Path','Severity','Reason','How to Remove') `
    {
        param($f)
        "<tr><td style='word-break:break-all'>$(Esc $f.Path)</td><td>$(Badge $f.Sev)</td><td>$(Esc $f.Reason)</td><td><div class='fix-box'>$(Esc $f.Fix)</div></td></tr>"
    }
))

# ScreenConnect / ConnectWise Control section
$scCount  = $scFindings.Count
$scBadge  = if ($scCount -gt 0) {
    "<span style='background:#dc2626;color:#fff;padding:1px 10px;border-radius:12px;font-size:12px;margin-left:8px'>$scCount found</span>"
} else {
    "<span style='background:#16a34a;color:#fff;padding:1px 10px;border-radius:12px;font-size:12px;margin-left:8px'>Clean</span>"
}
$null = $sb.AppendLine('<div class="card">')
$null = $sb.AppendLine("<h2>&#x1F50C; ScreenConnect / ConnectWise Control $scBadge</h2>")
$null = $sb.AppendLine('<p class="intro">Scammers commonly use ScreenConnect to maintain persistent remote access. It registers a Windows Authentication Package DLL (<strong>ScreenConnect.WindowsAuthenticationPackage.dll</strong>) inside lsass.exe — this is why simply deleting the folder fails with a &quot;file open in isolation&quot; error. The DLL must be removed from the LSA registry and the PC rebooted before the folder can be deleted.</p>')
if ($scCount -gt 0) {
    foreach ($sc in $scFindings) {
        $isStale = $sc.Sev -eq 'LOW'
        $headerColor = if ($isStale) { '#f8fafc' } elseif ($sc.Sev -eq 'HIGH') { '#fef2f2' } else { '#fff7ed' }
        $borderColor = if ($isStale) { '#94a3b8' } else { '#dc2626' }
        $null = $sb.AppendLine("<div style='background:$headerColor;border-left:4px solid $borderColor;border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:14px'>")
        $null = $sb.AppendLine("<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:10px'>")
        $staleLabel = if ($isStale) { "<span style='background:#64748b;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-left:8px'>STALE — FILES ALREADY REMOVED</span>" } else { '' }
        $null = $sb.AppendLine("<strong style='font-size:14px'>$(Esc $sc.DisplayName)</strong> $(Badge $sc.Sev)$staleLabel")
        $null = $sb.AppendLine('</div>')
        $null = $sb.AppendLine('<div class="tbl-wrap"><table style="margin-bottom:10px">')
        $null = $sb.AppendLine('<tr><th>Service Name</th><th>State</th><th>Startup Mode</th><th>Binary Path</th><th>Install Path</th><th>Version</th><th>Official Uninstaller?</th></tr>')
        $null = $sb.AppendLine("<tr><td><strong>$(Esc $sc.ServiceName)</strong></td><td>$(Esc $sc.State)</td><td>$(Esc $sc.StartMode)</td><td style='font-size:11px;word-break:break-all'>$(Esc $sc.BinaryPath)</td><td style='font-size:11px;word-break:break-all'>$(Esc $sc.InstallPath)</td><td>$(Esc $sc.Version)</td><td>$(Esc $sc.HasUninstaller)</td></tr>")
        $null = $sb.AppendLine('</table></div>')
        $removalLabel = if ($isStale) { '&#x1F9F9; Registry Cleanup Steps (files already removed):' } else { '&#x26A0; Complete Removal Steps (run in Admin PowerShell):' }
        $removalLabelColor = if ($isStale) { '#64748b' } else { '#dc2626' }
        $null = $sb.AppendLine("<p style='font-size:12px;font-weight:700;color:$removalLabelColor;margin-bottom:6px'>$removalLabel</p>")
        $null = $sb.AppendLine("<div class='fix-box' style='white-space:pre-wrap'>$(Esc $sc.Removal)</div>")
        $null = $sb.AppendLine('</div>')
    }
} else {
    $null = $sb.AppendLine('<p class="clean">&#x2714; No ScreenConnect / ConnectWise Control installations detected.</p>')
}
$null = $sb.AppendLine('</div>')

# AppData hidden RATs section
$null = $sb.AppendLine((Section 'Hidden Remote Access Tools in AppData' `
    'Executables found in user AppData folders matching known remote access tools or suspicious patterns. Scammers often hide ScreenConnect and similar tools here to avoid detection.' `
    $appDataFindings `
    @('File Path','Company','Product','Severity','Reason','How to Remove') `
    {
        param($a)
        "<tr><td style='font-size:11px;word-break:break-all'>$(Esc $a.Path)</td><td>$(Esc $a.Company)</td><td>$(Esc $a.Product)</td><td>$(Badge $a.Sev)</td><td>$(Esc $a.Reason)</td><td><div class='fix-box'>$(Esc $a.Fix)</div></td></tr>"
    }
))

# Remote Access Users section
$null = $sb.AppendLine('<div class="card">')
$null = $sb.AppendLine('<h2>&#x1F465; Users With Remote Access Permissions')
$userCount = $remoteUserFindings.Count
$userBadge = if ($userCount -gt 0) {
    "<span style='background:#2563eb;color:#fff;padding:1px 10px;border-radius:12px;font-size:12px;margin-left:8px'>$userCount accounts (info)</span>"
} else {
    "<span style='background:#16a34a;color:#fff;padding:1px 10px;border-radius:12px;font-size:12px;margin-left:8px'>Clean</span>"
}
$null = $sb.AppendLine("$userBadge</h2>")
$null = $sb.AppendLine('<p class="intro"><strong>Informational, not a risk.</strong> Every PC has at least one administrator account, so this list is normal. It is shown only so you can scan it for an account you do not recognize (a name you did not create). Accounts here are not counted toward the risk level.</p>')
if ($remoteUserFindings.Count -gt 0) {
    $null = $sb.AppendLine('<div class="tbl-wrap"><table>')
    $null = $sb.AppendLine('<tr><th>Username</th><th>Access Type</th><th>Account Active</th><th>Last Logon</th><th>Password Expires</th><th>Severity</th><th>How to Remove/Restrict</th></tr>')
    foreach ($u in $remoteUserFindings) {
        $null = $sb.AppendLine("<tr><td><strong>$(Esc $u.Username)</strong></td><td>$(Esc $u.Access)</td><td>$(Esc $u.Active)</td><td>$(Esc $u.LastLogon)</td><td>$(Esc $u.PwExpires)</td><td>$(Badge $u.Sev)</td><td><div class='fix-box'>$(Esc $u.Fix)</div></td></tr>")
    }
    $null = $sb.AppendLine('</table></div>')
} else {
    $null = $sb.AppendLine('<p class="clean">&#x2714; No unexpected user accounts with remote access found.</p>')
}
$null = $sb.AppendLine('</div>')

# Suspicious Traffic section
$null = $sb.AppendLine((Section 'Suspicious Outbound Network Traffic' `
    'Processes making unusual external network connections — potential data exfiltration, C2 beaconing, or hidden RATs phoning home. Processes running from AppData/Temp with ANY external connection are flagged. Normal browsers and system processes are excluded.' `
    $suspTraffic `
    @('Process','PID','Path','External Connections','Remote Addresses','Severity','Reason','How to Investigate') `
    {
        param($tr)
        "<tr><td><strong>$(Esc $tr.Process)</strong></td><td>$($tr.PID)</td><td style='font-size:11px;word-break:break-all'>$(Esc $tr.Path)</td><td style='text-align:center'>$($tr.ExtConns)</td><td style='font-size:11px;word-break:break-all'>$(Esc $tr.Remotes)</td><td>$(Badge $tr.Sev)</td><td>$(Esc $tr.Reason)</td><td><div class='fix-box'>$(Esc $tr.Fix)</div></td></tr>"
    }
))

# RDP section
$rdpStatusHtml  = if ($rdpEnabled) { "<span class='on'>&#x25CF; ENABLED</span>" } else { "<span class='off-good'>&#x25CF; DISABLED</span>" }
$nlaStatusHtml  = if ($nlaOn)      { "<span class='off-good'>&#x2714; YES (Secure)</span>" } else { "<span class='on'>&#x2718; NO (Insecure)</span>" }
$portStatusHtml = if ($rdpPort -ne 3389) { "<span class='on'>$rdpPort (Non-standard!)</span>" } else { "<span>$rdpPort (Default)</span>" }

$null = $sb.AppendLine('<div class="card">')
$null = $sb.AppendLine('<h2>&#x1F5A5; Remote Desktop (RDP) Configuration</h2>')
$null = $sb.AppendLine('<p class="intro">RDP allows remote login to this PC. If enabled unexpectedly, it is a serious security risk.</p>')
$null = $sb.AppendLine('<div class="rdp-grid">')
$null = $sb.AppendLine("<div class='rdp-item'><div class='lbl'>RDP Status</div><div class='val'>$rdpStatusHtml</div></div>")
$null = $sb.AppendLine("<div class='rdp-item'><div class='lbl'>Port</div><div class='val'>$portStatusHtml</div></div>")
$null = $sb.AppendLine("<div class='rdp-item'><div class='lbl'>Network Level Auth</div><div class='val'>$nlaStatusHtml</div></div>")
$null = $sb.AppendLine('</div>')
if ($rdpEnabled) {
    $rdpFix = "# Disable RDP entirely (recommended if not needed):
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# Enable NLA if keeping RDP (makes it more secure):
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1

# See who has RDP access:
net localgroup 'Remote Desktop Users'"
    $null = $sb.AppendLine("<div class='fix-box' style='margin-top:12px'>$(Esc $rdpFix)</div>")
}
$null = $sb.AppendLine('</div>')

# Footer
$null = $sb.AppendLine("<div class='footer'>Remote Access Audit &bull; $(Get-Date -Format 'MMMM dd, yyyy HH:mm') &bull; $env:COMPUTERNAME</div>")
$null = $sb.AppendLine('</div></body></html>')

# ── Save report ───────────────────────────────────────────────────────────────
$html = $sb.ToString()
$saved = $false
$savedPath = ''

$tryPaths = @(
    $reportFile,
    (Join-Path $env:USERPROFILE "Desktop\RemoteAccessAudit_$timestamp.html"),
    "C:\Temp\RemoteAccessAudit_$timestamp.html"
)

foreach ($path in $tryPaths) {
    if ($saved) { break }
    try {
        $dir = Split-Path -Parent $path
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        [System.IO.File]::WriteAllText($path, $html, [System.Text.Encoding]::UTF8)
        $saved     = $true
        $savedPath = $path
        Write-Host "  HTML report saved (backup log): $path" -ForegroundColor Gray
    } catch {
        Write-Host "  Could not save HTML to $path : $_" -ForegroundColor Red
    }
}

# The GUI window above is the main interface; the HTML is the saved record.
# Open it automatically once the window is closed so the tech can review/print it.
if ($saved) { Start-Process $savedPath }

Write-Host ""
Write-Host "  Session complete. Findings: $total  Risk: $risk" -ForegroundColor Cyan
if ($saved) { Write-Host "  Report saved to: $savedPath" -ForegroundColor Gray }
Write-Host ""

