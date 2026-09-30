# ============================================================================
#  Remote Access Audit  -  Nerdy Neighbor / nerd industries
# ----------------------------------------------------------------------------
#  Run it (Windows PowerShell, normal or admin):
#
#    irm audit.nerdyneighbor.net | iex
#
#  Windows 7 (needs WMF 5.1; PowerShell there defaults to TLS 1.0):
#    [Net.ServicePointManager]::SecurityProtocol='Tls12'; irm audit.nerdyneighbor.net | iex
#
#  Options (set before the irm line):
#    $env:NN_AUDIT_MODE  = 'report'   # no window, no fixes: just save the HTML/JSON
#                                     # report (for RMM / SuperOps runs)
#    $env:NN_AUDIT_TRUST = 'SuperOps,OpenSSH'
#                                     # remote tools YOU deployed; reported as INFO
#                                     # instead of a threat (this is the default)
#    $env:NN_AUDIT_OUT   = 'C:\Temp'  # where to save the report
#
#  What it does:
#    - Self-elevates (one UAC prompt), runs every scan, opens the remediation
#      window. Every Fix button runs real code in-process and shows the result
#      on the finding. Files are QUARANTINED (not deleted) and registry values
#      are backed up first, under C:\ProgramData\NerdyNeighbor\RemoteAccessAudit.
#    - Saves an HTML + JSON report when the window closes.
#    - Works on Windows 7 SP1 (WMF 5.1), 8.1, 10 and 11. Every scan has a
#      Windows 7 code path; anything that could not be checked is listed in the
#      report's "Scan coverage" section instead of being silently skipped.
# ============================================================================

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

$RAA_Version = '3.0.0'
$RAA_Source  = 'https://api.github.com/repos/nerd-industries/Remote-Access-Audit/contents/RemoteAccessAudit.ps1'

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ---------------------------------------------------------------------------
#  Options
# ---------------------------------------------------------------------------
$Mode = if ($env:NN_AUDIT_MODE) { $env:NN_AUDIT_MODE.Trim().ToLower() } else { 'gui' }
$TrustList = if ($null -ne $env:NN_AUDIT_TRUST) {
    @($env:NN_AUDIT_TRUST -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
} else { @('SuperOps', 'OpenSSH') }

# ---------------------------------------------------------------------------
#  Self-elevation. Under irm | iex there is no file on disk, so relaunch the
#  same one-liner (latest commit, via the GitHub API) in an elevated window.
#  Options are passed along explicitly: an elevated process does not inherit
#  this window's environment variables.
# ---------------------------------------------------------------------------
if ($Mode -ne 'lib' -and -not (Test-IsAdmin)) {
    Write-Host ""
    Write-Host "  Remote Access Audit needs Administrator rights." -ForegroundColor Yellow
    Write-Host "  Click YES on the Windows UAC prompt..."          -ForegroundColor Yellow
    $q = { param($v) "'" + ([string]$v -replace "'", "''") + "'" }
    $pre = ''
    foreach ($n in 'NN_AUDIT_MODE', 'NN_AUDIT_TRUST', 'NN_AUDIT_OUT') {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ($null -ne $v) { $pre += "`$env:$n=$(& $q $v); " }
    }
    $selfFile = $MyInvocation.MyCommand.Path
    if ($selfFile -and (Test-Path -LiteralPath $selfFile)) {
        $relaunch = "$pre& $(& $q $selfFile)"
    } else {
        $relaunch = "[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; " +
                    "$pre irm -Headers @{Accept='application/vnd.github.raw'} '$RAA_Source' | iex"
    }
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($relaunch))
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs `
            -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-NoExit', '-EncodedCommand', $enc | Out-Null
    } catch {
        Write-Host "  Elevation cancelled - the audit cannot run without admin rights." -ForegroundColor Red
    }
    return
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "  PowerShell $($PSVersionTable.PSVersion) is too old. Install WMF 5.1 first." -ForegroundColor Red
    return
}

# ---------------------------------------------------------------------------
#  Paths, logging
# ---------------------------------------------------------------------------
$ProgressPreference = 'SilentlyContinue'
$RunStamp      = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$DataDir       = Join-Path $env:ProgramData 'NerdyNeighbor\RemoteAccessAudit'
$BackupDir     = Join-Path $DataDir "backup\$RunStamp"
$QuarantineDir = Join-Path $DataDir "quarantine\$RunStamp"
$LogFile       = Join-Path $env:ProgramData 'NerdyNeighbor\audit.log'
$OutDir = if ($env:NN_AUDIT_OUT) { $env:NN_AUDIT_OUT }
          elseif ($Mode -eq 'report') { $DataDir }
          else { [Environment]::GetFolderPath('Desktop') }
if (-not $OutDir) { $OutDir = $DataDir }
foreach ($d in @($DataDir, $OutDir)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null } }

$ActionLog = New-Object System.Collections.ArrayList

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO', [switch]$Quiet)
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -ErrorAction Stop } catch {}
    if (-not $Quiet) {
        $c = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }
        Write-Host "    $Message" -ForegroundColor $c
    }
}

# ---------------------------------------------------------------------------
#  Catalog of remote-access / remote-control tools.
#  Matching is precise: exact exe base name, service-name pattern, install-path
#  pattern or Authenticode signer. Never loose substring matching.
#  Names = product-name words used to recognise the tool in Programs and Features.
# ---------------------------------------------------------------------------
$RemoteTools = @(
    @{ Name='TeamViewer';                  Names=@('TeamViewer');   Exe=@('teamviewer','teamviewer_service','tv_w32','tv_x64','teamviewerqs'); Svc=@('teamviewer*'); Path=@('*\teamviewer*'); Signer=@('teamviewer'); Class='Commercial remote control (heavily used in tech-support scams)' }
    @{ Name='AnyDesk';                     Names=@('AnyDesk');      Exe=@('anydesk'); Svc=@('anydesk*'); Path=@('*\anydesk*'); Signer=@('anydesk','philandro'); Class='Commercial remote control (heavily used in tech-support scams)' }
    @{ Name='ScreenConnect / ConnectWise'; Names=@('ScreenConnect','ConnectWise Control'); Exe=@('screenconnect.clientservice','screenconnect.windowsclient','connectwisecontrol.client','screenconnect.clientsetup'); Svc=@('screenconnect*','connectwisecontrol*'); Path=@('*\screenconnect*','*\connectwisecontrol*','*\connectwise control*'); Signer=@('connectwise','screenconnect','elsinore'); Class='RMM / remote support (heavily used in tech-support scams)' }
    @{ Name='LogMeIn / GoTo';              Names=@('LogMeIn','GoTo Resolve','GoTo Opener'); Exe=@('logmein','lmiguardiansvc','logmeinsystray','ramaint'); Svc=@('logmein*'); Path=@('*\logmein*'); Signer=@('logmein','goto technologies'); Class='Commercial remote control' }
    @{ Name='Splashtop';                   Names=@('Splashtop');    Exe=@('sragent','srservice','strwinclt','splashtop'); Svc=@('splashtop*','sragent*'); Path=@('*\splashtop*'); Signer=@('splashtop'); Class='Commercial remote control' }
    @{ Name='RustDesk';                    Names=@('RustDesk');     Exe=@('rustdesk'); Svc=@('rustdesk*'); Path=@('*\rustdesk*'); Signer=@('rustdesk','purslane'); Class='Open-source remote control (used in scams)' }
    @{ Name='Radmin';                      Names=@('Radmin');       Exe=@('radmin','rserver3','famitrfc'); Svc=@('rserver*','radmin*'); Path=@('*\radmin*'); Signer=@('famatech'); Class='Commercial remote control' }
    @{ Name='VNC (Real/Tight/Ultra/Tiger)';Names=@('RealVNC','TightVNC','UltraVNC','TigerVNC','VNC Server'); Exe=@('winvnc','winvnc4','vncserver','vncviewer','tvnserver','uvnc_service'); Svc=@('*vnc*'); Path=@('*\realvnc*','*\tightvnc*','*\ultravnc*','*\uvnc*','*\tigervnc*'); Signer=@('realvnc','tightvnc','glavsoft'); Class='VNC remote control' }
    @{ Name='Ammyy Admin';                 Names=@('Ammyy');        Exe=@('aa_v3','ammyy'); Svc=@(); Path=@('*\ammyy*'); Signer=@(); Class='Remote control (commonly used in scams)' }
    @{ Name='DameWare';                    Names=@('DameWare');     Exe=@('dwrcs','dwrcst','dameware'); Svc=@('dwmrcs*'); Path=@('*\dameware*'); Signer=@('dameware'); Class='Commercial remote control' }
    @{ Name='NetSupport Manager';          Names=@('NetSupport');   Exe=@('client32','pcicfgui'); Svc=@('client32*'); Path=@('*\netsupport*'); Signer=@('netsupport'); Class='Remote control (abused as a RAT)' }
    @{ Name='Atera Agent';                 Names=@('Atera');        Exe=@('ateraagent','atera_agent'); Svc=@('ateraagent*'); Path=@('*\atera*'); Signer=@('atera'); Class='RMM agent' }
    @{ Name='Kaseya / VSA';                Names=@('Kaseya');       Exe=@('agentmon'); Svc=@('kaseya*'); Path=@('*\kaseya*'); Signer=@('kaseya'); Class='RMM agent' }
    @{ Name='NinjaOne / NinjaRMM';         Names=@('NinjaRMM','NinjaOne'); Exe=@('ninjarmmagent','ninjarmmagentpatcher'); Svc=@('ninjarmm*'); Path=@('*\ninjarmm*','*\ninjaone*'); Signer=@('ninjarmm','ninjaone'); Class='RMM agent' }
    @{ Name='Pulseway';                    Names=@('Pulseway');     Exe=@('pcmonitorsrv','pulseway'); Svc=@('pcmonitor*','pulseway*'); Path=@('*\pulseway*','*\pc monitor*'); Signer=@('mmsoft','pulseway'); Class='RMM agent' }
    @{ Name='Supremo';                     Names=@('Supremo');      Exe=@('supremo','supremosystem'); Svc=@('supremo*'); Path=@('*\supremo*'); Signer=@('nanosystems'); Class='Commercial remote control (used in scams)' }
    @{ Name='UltraViewer';                 Names=@('UltraViewer');  Exe=@('ultraviewer','ultraviewer_desktop'); Svc=@('ultraviewer*'); Path=@('*\ultraviewer*'); Signer=@('ductho','ultraviewer'); Class='Remote control (heavily used in scams)' }
    @{ Name='RemotePC';                    Names=@('RemotePC');     Exe=@('remotepc','rpcservice'); Svc=@('remotepc*'); Path=@('*\remotepc*'); Signer=@('remotepc','idrive'); Class='Commercial remote control' }
    @{ Name='Zoho Assist';                 Names=@('Zoho Assist');  Exe=@('zaservice','za_access'); Svc=@('zaservice*'); Path=@('*\zohoassist*','*\zoho assist*'); Signer=@('zoho'); Class='Remote support' }
    @{ Name='AnyViewer';                   Names=@('AnyViewer');    Exe=@('anyviewer'); Svc=@('anyviewer*'); Path=@('*\anyviewer*'); Signer=@('aomei'); Class='Remote control (used in scams)' }
    @{ Name='Remote Utilities';            Names=@('Remote Utilities'); Exe=@('rutserv','rfusclient'); Svc=@('rmanservice*'); Path=@('*\remote utilities*'); Signer=@('remote utilities'); Class='Remote control (abused as a RAT)' }
    @{ Name='GoToAssist / GoToMyPC';       Names=@('GoToAssist','GoToMyPC'); Exe=@('g2comm','g2svc','gotoassist','gotomypc'); Svc=@('gotoassist*','gotomypc*'); Path=@('*\gotoassist*','*\gotomypc*'); Signer=@('goto technologies'); Class='Remote support' }
    @{ Name='BeyondTrust / Bomgar';        Names=@('Bomgar','BeyondTrust Remote'); Exe=@('bomgar'); Svc=@('bomgar*','beyondtrust*'); Path=@('*\bomgar*','*\beyondtrust*'); Signer=@('bomgar','beyondtrust'); Class='Remote support' }
    @{ Name='SimpleHelp';                  Names=@('SimpleHelp');   Exe=@('simplehelpcustomer','simpleservice','simplegatewayservice'); Svc=@('simplehelp*','simpleservice*'); Path=@('*\simplehelp*','*\simple-help*'); Signer=@('simple-help','jwsoftware'); Class='Remote support (used in scams and ransomware intrusions)' }
    @{ Name='ITarian / Comodo RMM';        Names=@('ITarian');      Exe=@('itsmagent','itsmservice','rviewer'); Svc=@('itsm*'); Path=@('*\itarian*','*\comodo\*rmm*'); Signer=@('itarian'); Class='RMM agent (abused)' }
    @{ Name='PDQ Connect / Deploy';        Names=@('PDQ Connect','PDQ Deploy'); Exe=@('pdq-connect-agent','pdqconnectagent','pdqdeployrunner'); Svc=@('pdq*'); Path=@('*\pdq*'); Signer=@('pdq.com'); Class='RMM / software deployment (abused)' }
    @{ Name='N-able Take Control';         Names=@('Take Control','N-able'); Exe=@('basupsrvc','basupsrvcupdater','basuptshelper'); Svc=@('basupsrvc*','n-central*'); Path=@('*\n-able*','*\take control*','*\beanywhere*'); Signer=@('n-able'); Class='RMM / remote support (abused)' }
    @{ Name='Datto RMM (CentraStage)';     Names=@('CentraStage','Datto RMM'); Exe=@('cagservice','aurora-agent','aurora-agent-v2'); Svc=@('cagservice*'); Path=@('*\centrastage*'); Signer=@('datto','centrastage'); Class='RMM agent (abused)' }
    @{ Name='Syncro / Kabuto';             Names=@('Syncro','Kabuto'); Exe=@('syncro.service','syncro','kabuto.app.service','kabuto'); Svc=@('syncro*','kabuto*'); Path=@('*\syncro*','*\repairtech*','*\kabuto*'); Signer=@('syncromsp','servably','repairtech'); Class='RMM agent (abused)' }
    @{ Name='Action1';                     Names=@('Action1');      Exe=@('action1_agent','action1_remote','action1'); Svc=@('action1*'); Path=@('*\action1*'); Signer=@('action1'); Class='RMM agent (abused)' }
    @{ Name='Level.io';                    Names=@('Level.io');     Exe=@('level-windows-amd64','level-remote-control-ws','levelrmm'); Svc=@('level agent*','levelrmm*'); Path=@('*\level.io*','*\level\agent*'); Signer=@('level software'); Class='RMM agent (abused)' }
    @{ Name='Tactical RMM';                Names=@('Tactical RMM'); Exe=@('tacticalrmm','tacticalagent','trmm'); Svc=@('tacticalrmm*'); Path=@('*\tacticalagent*','*\tacticalrmm*'); Signer=@('amidaware'); Class='RMM agent (open-source, abused)' }
    @{ Name='MeshCentral / MeshAgent';     Names=@('Mesh Agent','MeshCentral'); Exe=@('meshagent'); Svc=@('mesh agent*','meshagent*'); Path=@('*\meshagent*','*\meshcentral*','*\mesh agent*'); Signer=@('meshcentral'); Class='Remote management (open-source, abused)' }
    @{ Name='ManageEngine Endpoint Central'; Names=@('ManageEngine','Desktop Central','Endpoint Central'); Exe=@('dcagentservice','dcagenttrayicon'); Svc=@('manageengine*','dcagent*'); Path=@('*\manageengine*','*\desktopcentral*'); Signer=@('zoho'); Class='RMM / endpoint management (abused)' }
    @{ Name='ImmyBot';                     Names=@('ImmyBot');      Exe=@('immyagent','immyupdater'); Svc=@('immy*'); Path=@('*\immybot*'); Signer=@('immense','immybot'); Class='RMM agent' }
    @{ Name='Goverlan Reach';              Names=@('Goverlan');     Exe=@('goverrmc','goverlanreach','grcagentservice'); Svc=@('grcagent*','goverlan*'); Path=@('*\goverlan*'); Signer=@('goverlan'); Class='Remote administration (abused)' }
    @{ Name='ISL Online / ISL Light';      Names=@('ISL Light','ISL Online','ISL AlwaysOn'); Exe=@('isllight','isllightclient','islalwaysonmonitor','isllightservice'); Svc=@('isl alwayson*','isllight*'); Path=@('*\isl online*','*\isllight*'); Signer=@('xlab'); Class='Remote support (abused)' }
    @{ Name='Parsec';                      Names=@('Parsec');       Exe=@('parsecd'); Svc=@('parsec*'); Path=@('*\parsec\*'); Signer=@('parsec cloud'); Class='Remote desktop (gaming; abused)' }
    @{ Name='Jump Desktop';                Names=@('Jump Desktop'); Exe=@('jumpdesktop','jumpconnect'); Svc=@('jumpconnect*'); Path=@('*\jump desktop*','*\jumpdesktop*'); Signer=@('phase five'); Class='Remote desktop' }
    @{ Name='Getscreen';                   Names=@('Getscreen');    Exe=@('getscreen'); Svc=@('getscreen*'); Path=@('*\getscreen*'); Signer=@('getscreen'); Class='Remote support (used in scams)' }
    @{ Name='Iperius Remote';              Names=@('Iperius Remote'); Exe=@('iperiusremote'); Svc=@('iperius*'); Path=@('*\iperius*'); Signer=@('enter srl'); Class='Remote support' }
    @{ Name='DWService / DWAgent';         Names=@('DWAgent','DWService'); Exe=@('dwagent','dwagsvc','dwaglnc'); Svc=@('dwagent*'); Path=@('*\dwagent*','*\dwservice*'); Signer=@('dwservice'); Class='Remote support (open-source, abused)' }
    @{ Name='Distant Desktop';             Names=@('Distant Desktop'); Exe=@('distant_desktop','distant-desktop'); Svc=@(); Path=@('*\distant desktop*','*\distant-desktop*'); Signer=@(); Class='Remote control (used in scams)' }
    @{ Name='LiteManager';                 Names=@('LiteManager');  Exe=@('romserver','romfusclient','romviewer'); Svc=@('romservice*','litemanager*'); Path=@('*\litemanager*'); Signer=@('litemanager'); Class='Remote control (abused as a RAT)' }
    @{ Name='ShowMyPC';                    Names=@('ShowMyPC');     Exe=@('showmypc'); Svc=@('showmypc*'); Path=@('*\showmypc*'); Signer=@('showmypc'); Class='Remote support (used in scams)' }
    @{ Name='AeroAdmin';                   Names=@('AeroAdmin');    Exe=@('aeroadmin'); Svc=@(); Path=@('*\aeroadmin*'); Signer=@('aeroadmin'); Class='Remote control (used in scams)' }
    @{ Name='AweRay / AweSun';             Names=@('AweSun','AweRay'); Exe=@('aweray_remote','awesun','aweray'); Svc=@('aweray*'); Path=@('*\aweray*','*\awesun*'); Signer=@('aweray'); Class='Remote control (used in scams)' }
    @{ Name='HopToDesk';                   Names=@('HopToDesk');    Exe=@('hoptodesk'); Svc=@('hoptodesk*'); Path=@('*\hoptodesk*'); Signer=@('hoptodesk'); Class='Remote control (used in scams)' }
    @{ Name='Chrome Remote Desktop';       Names=@('Chrome Remote Desktop'); Exe=@('remoting_host','remote_assistance_host'); Svc=@('chromoting*','chrome remote desktop*'); Path=@('*\chrome remote desktop*'); Signer=@(); Class='Remote desktop' }
    @{ Name='FastViewer';                  Names=@('FastViewer');   Exe=@('fastviewer','fastclient','fastmaster'); Svc=@('fastviewer*'); Path=@('*\fastviewer*'); Signer=@('fastviewer'); Class='Remote support (abused)' }
    @{ Name='SuperOps';                    Names=@('SuperOps');     Exe=@('superops','superopsticket'); Svc=@('superops*'); Path=@('*\superops*'); Signer=@('superops'); Class='RMM agent' }
    @{ Name='Mikogo';                      Names=@('Mikogo');       Exe=@('mikogo','mikogo-host','mikogo-service'); Svc=@('mikogo*'); Path=@('*\mikogo*'); Signer=@('snapview'); Class='Remote support / screen sharing' }
    @{ Name='OpenSSH Server';              Names=@('OpenSSH');      Exe=@('sshd'); Svc=@('sshd'); Path=@('*\openssh\sshd.exe'); Signer=@(); Class='SSH server (remote command-line access)' }
    @{ Name='Tailscale';                   Names=@('Tailscale');    Exe=@('tailscale','tailscaled','tailscale-ipn'); Svc=@('tailscale*'); Path=@('*\tailscale*'); Signer=@('tailscale'); Class='Mesh VPN (used by attackers for access)' }
    @{ Name='ZeroTier';                    Names=@('ZeroTier');     Exe=@('zerotier-one_x64','zerotier-one','zerotier'); Svc=@('zerotier*'); Path=@('*\zerotier*'); Signer=@('zerotier'); Class='Mesh VPN (used by attackers for access)' }
    @{ Name='NetBird';                     Names=@('NetBird');      Exe=@('netbird','netbird-ui'); Svc=@('netbird*'); Path=@('*\netbird*'); Signer=@('netbird','wiretrustee'); Class='Mesh VPN (used by attackers for access)' }
    @{ Name='ngrok (tunnel)';              Names=@('ngrok');        Exe=@('ngrok'); Svc=@('ngrok*'); Path=@('*\ngrok*'); Signer=@('ngrok'); Class='Tunnel tool (exposes remote access)' }
    @{ Name='Cloudflared (tunnel)';        Names=@('cloudflared');  Exe=@('cloudflared'); Svc=@('cloudflared*'); Path=@('*\cloudflared*'); Signer=@(); Class='Tunnel tool (exposes remote access)' }
    @{ Name='Chisel (tunnel)';             Names=@();               Exe=@('chisel'); Svc=@(); Path=@(); Signer=@(); Class='Tunnel tool (exposes remote access)' }
    @{ Name='frp (Fast Reverse Proxy)';    Names=@();               Exe=@('frpc','frps'); Svc=@(); Path=@('*\frp_*','*\frp\*'); Signer=@(); Class='Tunnel tool (exposes remote access)' }
    @{ Name='LocalXpose';                  Names=@();               Exe=@('loclx'); Svc=@(); Path=@('*\localxpose*'); Signer=@(); Class='Tunnel tool' }
    @{ Name='localtonet';                  Names=@();               Exe=@('localtonet'); Svc=@('localtonet*'); Path=@('*\localtonet*'); Signer=@(); Class='Tunnel tool' }
    @{ Name='playit.gg';                   Names=@('playit');       Exe=@('playit'); Svc=@('playit*'); Path=@('*\playit*'); Signer=@(); Class='Tunnel tool' }
    @{ Name='plink (PuTTY link)';          Names=@();               Exe=@('plink'); Svc=@(); Path=@(); Signer=@(); Class='SSH tunnel tool (used for port-forward C2)' }
    @{ Name='Netcat / Ncat';               Names=@();               Exe=@('ncat','netcat','nc64'); Svc=@(); Path=@(); Signer=@(); Class='Reverse-shell tool' }
    @{ Name='AsyncRAT (malware)';          Names=@();               Exe=@('asyncrat','asyncclient'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='Remcos (malware)';            Names=@();               Exe=@('remcos'); Svc=@(); Path=@('*\remcos*'); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='njRAT (malware)';             Names=@();               Exe=@('njrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='Quasar RAT (malware)';        Names=@();               Exe=@('quasar','quasarrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='XWorm (malware)';             Names=@();               Exe=@('xworm'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='DCRat (malware)';             Names=@();               Exe=@('dcrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='NanoCore (malware)';          Names=@();               Exe=@('nanocore'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='VenomRAT (malware)';          Names=@();               Exe=@('venomrat'); Svc=@(); Path=@(); Signer=@(); Class='Remote Access Trojan' }
    @{ Name='Cobalt Strike (C2)';          Names=@();               Exe=@('cobaltstrike','beacon'); Svc=@(); Path=@(); Signer=@(); Class='Command-and-control framework' }
)

# Keywords for TEXT scans (command lines, registry values, task actions, file names).
$RatKeywords = @(
    'teamviewer','anydesk','screenconnect','connectwise','logmein','splashtop','rustdesk','radmin',
    'realvnc','tightvnc','ultravnc','tigervnc','winvnc','ammyy','dameware','netsupport','supremo',
    'ultraviewer','remotepc','zohoassist','gotoassist','gotomypc','anyviewer','rutserv','bomgar',
    'beyondtrust','ngrok','cloudflared','ateraagent','ninjarmm','kaseya','pulseway','simplehelp',
    'itarian','pdq-connect','pdqconnect','centrastage','aurora-agent','syncro','kabuto','action1',
    'level-remote','tacticalrmm','tacticalagent','meshagent','meshcentral','desktopcentral','immybot',
    'goverlan','isllight','jumpdesktop','getscreen','iperius','dwagent','dwservice','distant_desktop',
    'litemanager','romserver','showmypc','aeroadmin','aweray','awesun','hoptodesk','remoting_host',
    'fastviewer','mikogo','zerotier','netbird','localxpose','localtonet','frpc','frps','loclx','plink',
    'remcos','njrat','quasar','asyncrat','venomrat','nanocore','darkcomet','netwire','xworm','dcrat',
    'bitrat','warzonerat','orcus','limerat','cobaltstrike','bruteratel'
)

# Ports associated with remote-access / C2 traffic. Management ports are MEDIUM.
$RatPorts = @{
    3389='RDP (Remote Desktop)'; 5900='VNC'; 5901='VNC'; 5938='TeamViewer'; 7070='AnyDesk'; 6568='AnyDesk / Remote Utilities'
    4444='Metasploit / RAT'; 4443='Reverse shell'; 1337='RAT port'; 5985='WinRM HTTP'; 5986='WinRM HTTPS'
    22='SSH'; 23='Telnet'; 4899='Radmin'; 6129='DameWare'; 8040='ScreenConnect'; 8041='ScreenConnect'
    5650='Remote Utilities'; 4782='Quasar RAT C2'; 1604='DarkComet C2'; 1177='njRAT C2'; 5552='njRAT C2'
    6606='AsyncRAT C2'; 7707='AsyncRAT C2'; 8808='AsyncRAT C2'; 2404='Remcos C2'; 6667='IRC botnet C2'
    3460='Bifrost RAT'; 9999='RAT C2'; 5050='RAT C2'
}
$MgmtPorts = @(22, 3389, 5985, 5986)

# Names of core Windows programs. Running from anywhere else = impersonation.
$SystemExeNames = @('svchost','lsass','csrss','winlogon','services','smss','wininit','spoolsv','taskhost',
                    'taskhostw','conhost','dllhost','lsm','dwm','ctfmon','rundll32','searchindexer','explorer')

# Mainstream vendor folders: suppress only the weak "unsigned + buried deep" signal.
$BenignVendorDirs = @('\microsoft\','\windowsapps\','\google\','\mozilla\','\adobe\','\discord\','\slack\',
    '\spotify\','\zoom\','\webex\','\steam\','\epic games\','\jetbrains\','\github\','\githubdesktop\',
    '\postman\','\1password\','\dropbox\','\box\','\nvidia\','\intel\','\amd\','\logi','\citrix\',
    '\python','\nodejs\','\valve\','\obs-studio\','\zoomus\','\whatsapp\','\signal\','\telegram desktop\',
    '\temporary internet files\','\inetcache\','\packages\','\assembly\','\installer\')

$SuspiciousCmdRegex = '(?i)(-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b|\biex\b|invoke-expression|net\.webclient|mshta(\.exe)?["\s]+(https?:|javascript:|vbscript:)|rundll32(\.exe)?["\s].*javascript:|regsvr32(\.exe)?["\s].*/i:https?:|certutil(\.exe)?["\s].*-urlcache|bitsadmin(\.exe)?["\s].*/transfer|-w(indowstyle)?\s+hidden.*https?:)'

# ---------------------------------------------------------------------------
#  Trust / catalog helpers
# ---------------------------------------------------------------------------
# Native helpers: MoveFileEx (delete-at-reboot) and a Windows catalog lookup.
# Windows 7's Get-AuthenticodeSignature does not check catalog signatures, so
# every in-box Windows file (cmd.exe, rundll32.exe, ...) looks "NotSigned" there.
# CatalogSigned() asks the system catalog database whether the file's hash is
# in an installed, signed catalog - the same check signtool/sigcheck do.
try {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace NNAudit {
    public static class Native {
        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
        [DllImport("wintrust.dll", SetLastError=true)]
        static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError=true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
        [DllImport("wintrust.dll")]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
        public static bool CatalogSigned(string path) {
            IntPtr ctx;
            if (!CryptCATAdminAcquireContext(out ctx, IntPtr.Zero, 0)) return false;
            try {
                using (var fs = System.IO.File.Open(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete)) {
                    IntPtr h = fs.SafeFileHandle.DangerousGetHandle();
                    uint size = 0;
                    CryptCATAdminCalcHashFromFileHandle(h, ref size, null, 0);
                    if (size == 0 || size > 256) return false;
                    byte[] hash = new byte[size];
                    if (!CryptCATAdminCalcHashFromFileHandle(h, ref size, hash, 0)) return false;
                    IntPtr cat = CryptCATAdminEnumCatalogFromHash(ctx, hash, size, 0, IntPtr.Zero);
                    if (cat == IntPtr.Zero) return false;
                    CryptCATAdminReleaseCatalogContext(ctx, cat, 0);
                    return true;
                }
            } catch { return false; }
            finally { CryptCATAdminReleaseContext(ctx, 0); }
        }
    }
}
'@
} catch {}
$CatalogCheck = [bool]('NNAudit.Native' -as [type])

$TrustCache = @{}
function Get-FileTrust {
    param([string]$Path)
    $info = [pscustomobject]@{ Path = ''; Exists = $false; Signed = $false; SignerName = ''; IsMicrosoft = $false; Company = ''; Product = ''; OriginalName = '' }
    if (-not $Path) { return $info }
    $clean = [Environment]::ExpandEnvironmentVariables(($Path -replace '"', '').Trim())
    if ($clean -match '^(.+?\.(exe|dll|scr|com|sys))(\s|,|$)') { $clean = $matches[1] }
    $clean = $clean -replace '^\\\?\?\\', ''
    if ($script:TrustCache.ContainsKey($clean)) { return $script:TrustCache[$clean] }
    $info.Path = $clean
    if (-not (Test-Path -LiteralPath $clean -PathType Leaf -ErrorAction SilentlyContinue)) { $script:TrustCache[$clean] = $info; return $info }
    $info.Exists = $true
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $clean -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $info.Signed = $true
            $cn = (($sig.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '').Trim('" ')
            $info.SignerName = $cn
            if ($cn -match '^Microsoft (Corporation|Windows)') { $info.IsMicrosoft = $true }
        }
    } catch {}
    try {
        $vi = (Get-Item -LiteralPath $clean -ErrorAction Stop).VersionInfo
        $info.Company = "$($vi.CompanyName)".Trim(); $info.Product = "$($vi.ProductName)".Trim(); $info.OriginalName = "$($vi.OriginalFilename)".Trim()
    } catch {}
    if (-not $info.Signed -and $script:CatalogCheck -and $sig -and $sig.Status -eq 'NotSigned') {
        if ([NNAudit.Native]::CatalogSigned($clean)) {
            $info.Signed = $true
            $info.SignerName = 'Windows catalog'
            if ($clean -like "$env:windir\*" -and $info.Company -like 'Microsoft*') { $info.IsMicrosoft = $true; $info.SignerName = 'Microsoft Windows (catalog)' }
        }
    }
    $script:TrustCache[$clean] = $info
    return $info
}

function Get-ExeFromCommand {
    # Pull the program path out of a command line / registry value / service path.
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c -match '^"([^"]+)"') { return $matches[1] }
    if ($c -match '^(.+?\.(exe|com|scr|bat|cmd|vbs|js|ps1|hta|dll))(\s|$|,)') { return $matches[1] }
    return ($c -split '\s+')[0]
}

function Find-RemoteTool {
    param([string]$Exe, [string]$ServiceName, [string]$Display, [string]$Path, [string]$Signer)
    $base = ''
    if ($Exe) { $base = (Split-Path $Exe -Leaf).ToLower() -replace '\.exe$', '' }
    $svcN = "$ServiceName".ToLower(); $disp = "$Display".ToLower(); $pth = "$Path".ToLower(); $sgn = "$Signer".ToLower()
    foreach ($t in $RemoteTools) {
        if ($base) { foreach ($e in $t.Exe) { if ($base -eq $e) { return $t } } }
        foreach ($s in $t.Svc) { if (($svcN -and $svcN -like $s) -or ($disp -and $disp -like $s)) { return $t } }
        if ($pth) { foreach ($p in $t.Path) { if ($pth -like $p) { return $t } } }
        if ($sgn) { foreach ($g in $t.Signer) { if ($sgn -like "*$g*") { return $t } } }
    }
    return $null
}

function Find-RemoteToolByProduct {
    # Match Programs-and-Features entries by whole product-name words.
    param([string]$DisplayName, [string]$Publisher)
    foreach ($t in $RemoteTools) {
        foreach ($n in $t.Names) {
            if ($n -and $DisplayName -match ('(?i)(^|[^a-z0-9])' + [regex]::Escape($n) + '([^a-z0-9]|$)')) { return $t }
        }
        foreach ($g in $t.Signer) { if ($g.Length -ge 6 -and $Publisher -and $Publisher.ToLower() -like "*$g*") { return $t } }
    }
    return $null
}

# Nerdy Neighbor's own RustDesk deployment: our installers point RustDesk at our
# server and write our server key into RustDesk2.toml. A RustDesk that uses our
# key is ours (INFO); any other RustDesk (public servers = scammer) stays HIGH.
$OwnRustDeskKey  = 'D11ZYHgpIWTNhltCBMe0f2MQzk+RQp4sI01KbqZj0l4='
$OwnRustDeskHost = 'rustdesk-relay.nerdyneighbor.net'
$OwnRustDesk = $null
function Reset-OwnRustDesk { $script:OwnRustDesk = $null }
function Test-OwnRustDesk {
    if ($null -ne $script:OwnRustDesk) { return $script:OwnRustDesk }
    $paths = @("$env:windir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config",
               "$env:windir\System32\config\systemprofile\AppData\Roaming\RustDesk\config",
               "$env:ProgramData\RustDesk\config")
    foreach ($p in (Get-UserProfiles)) { $paths += Join-Path $p.Path 'AppData\Roaming\RustDesk\config' }
    $script:OwnRustDesk = $false
    foreach ($d in $paths) {
        foreach ($f in 'RustDesk2.toml', 'RustDesk.toml') {
            $file = Join-Path $d $f
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $txt = ''; try { $txt = [IO.File]::ReadAllText($file) } catch {}
            if ($txt.Contains($OwnRustDeskKey) -and $txt.Contains($OwnRustDeskHost)) { $script:OwnRustDesk = $true; return $true }
        }
    }
    return $false
}

function Test-TrustedTool([string]$Name) {
    foreach ($t in $TrustList) { if ($Name -like "*$t*") { return $true } }
    if ($Name -like 'RustDesk*' -and (Test-OwnRustDesk)) { return $true }
    return $false
}

function Get-TrustReason([string]$Name) {
    if ($Name -like 'RustDesk*' -and (Test-OwnRustDesk)) { return "RustDesk is configured for Nerdy Neighbor's RustDesk server ($OwnRustDeskHost)." }
    return "$Name is in your trusted list (NN_AUDIT_TRUST)."
}

function Get-ToolSeverity {
    param($Tool, [bool]$UserPath, [bool]$Signed)
    if (Test-TrustedTool $Tool.Name) { return 'INFO' }
    if ($Tool.Class -match 'Trojan|Command-and-control|Reverse-shell') { return 'HIGH' }
    if ($UserPath -and -not $Signed) { return 'HIGH' }
    if ($Tool.Class -match 'scam|Tunnel') { return 'HIGH' }
    return 'MEDIUM'
}

function Test-UserWritablePath([string]$Path) {
    if (-not $Path) { return $false }
    return ($Path -like '*\AppData\*' -or $Path -like '*\Temp\*' -or $Path -like '*\Users\Public\*' -or
            $Path -like '*\Downloads\*' -or $Path -like '*\Desktop\*' -or $Path -like "$env:SystemDrive\ProgramData\*" -or
            $Path -like "$env:SystemDrive\PerfLogs\*" -or $Path -like '*\$Recycle.Bin\*')
}
function Test-TrustedVendorPath([string]$Path) {
    $p = "$Path".ToLower()
    foreach ($d in $BenignVendorDirs) { if ($p -like "*$d*") { return $true } }
    return $false
}
function Test-SystemImpersonation([string]$Path) {
    if (-not $Path) { return $false }
    $base = ([IO.Path]::GetFileNameWithoutExtension($Path)).ToLower()
    if ($SystemExeNames -notcontains $base) { return $false }
    $dir = (Split-Path $Path -Parent).ToLower().TrimEnd('\')
    $win = $env:windir.ToLower()
    if ($base -eq 'explorer') { return ($dir -ne $win -and $dir -ne "$win\syswow64") }
    return ($dir -ne "$win\system32" -and $dir -ne "$win\syswow64" -and $dir -notlike "$win\winsxs\*")
}
function Get-KeywordHit([string]$Text) {
    if (-not $Text) { return $null }
    $t = $Text.ToLower()
    foreach ($k in $RatKeywords) { if ($t.Contains($k)) { return $k } }
    return $null
}

# User profiles (all real users, not just the one running the audit)
function Get-UserProfiles {
    $list = @()
    try {
        Get-WmiObject Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) } | ForEach-Object {
            $list += [pscustomobject]@{ Path = $_.LocalPath; Sid = $_.SID; User = (Split-Path $_.LocalPath -Leaf); Loaded = [bool]$_.Loaded }
        }
    } catch {
        Get-ChildItem (Split-Path $env:USERPROFILE -Parent) -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $list += [pscustomobject]@{ Path = $_.FullName; Sid = ''; User = $_.Name; Loaded = $false }
        }
    }
    return $list
}
# Loaded user registry hives (HKEY_USERS\S-1-5-21-...), so HKCU data of the
# signed-in user is scanned even when the audit was elevated as another admin.
function Get-UserHives {
    $out = @()
    $profiles = Get-UserProfiles
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
        $sid = $_.PSChildName
        $u = ($profiles | Where-Object { $_.Sid -eq $sid } | Select-Object -First 1).User
        $out += [pscustomobject]@{ Root = "HKEY_USERS\$sid"; Sid = $sid; User = $(if ($u) { $u } else { $sid }) }
    }
    return $out
}

# Junction-safe recursive file enumeration. Windows PowerShell's
# Get-ChildItem -Recurse follows junctions such as "AppData\Local\Application
# Data" (which points at its own parent) and loops until the path is too long.
function Get-FilesSafe {
    param([string]$Root, [string[]]$Extensions, [int]$MaxDepth = 25, [int]$MaxFiles = 400000)
    $found = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return $found }
    $stack = New-Object System.Collections.Stack
    $stack.Push(@($Root, 0))
    $seen = 0
    while ($stack.Count -gt 0) {
        $item = $stack.Pop(); $dir = $item[0]; $depth = $item[1]
        try { $entries = (New-Object System.IO.DirectoryInfo($dir)).GetFileSystemInfos() } catch { $script:EnumErrors++; continue }
        foreach ($e in $entries) {
            if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($e -is [IO.DirectoryInfo]) {
                if ($depth -lt $MaxDepth) { $stack.Push(@($e.FullName, ($depth + 1))) }
            } else {
                $seen++
                if (-not $Extensions -or $Extensions -contains $e.Extension.ToLower()) { [void]$found.Add([pscustomobject]@{ File = $e; Depth = $depth }) }
            }
        }
        if ($seen -gt $MaxFiles) { Add-ScanNote "Stopped enumerating $Root after $MaxFiles files (limit)."; break }
    }
    return $found
}

# ---------------------------------------------------------------------------
#  Findings model
# ---------------------------------------------------------------------------
$Findings    = New-Object System.Collections.ArrayList
$FindingKeys = @{}
$ScanResults = New-Object System.Collections.ArrayList
$ScanNotes   = New-Object System.Collections.ArrayList
$EnumErrors  = 0
$SevRank     = @{ 'HIGH' = 3; 'MEDIUM' = 2; 'LOW' = 1; 'INFO' = 0 }

function Add-ScanNote([string]$Text) { [void]$script:ScanNotes.Add($Text) }

function New-FixAction {
    param([string]$Label, [string]$Description, [scriptblock]$Script, [hashtable]$Data = @{})
    [pscustomobject]@{ Label = $Label; Description = $Description; Script = $Script; Data = $Data }
}

function Add-Finding {
    param(
        [string]$Category, [ValidateSet('HIGH', 'MEDIUM', 'LOW', 'INFO')][string]$Severity, [string]$Title,
        [string]$Detail, [object]$Evidence = $null, [object[]]$Actions = @(), [string]$Key = '', [string]$Manual = ''
    )
    if (-not $Key) { $Key = "$Category|$Title" }
    if ($script:FindingKeys.ContainsKey($Key)) {
        # keep the more severe copy
        $old = $script:FindingKeys[$Key]
        if ($SevRank[$Severity] -gt $SevRank[$old.Severity]) { $old.Severity = $Severity }
        return
    }
    $ev = New-Object System.Collections.Specialized.OrderedDictionary
    if ($Evidence) { foreach ($k in $Evidence.Keys) { if ($null -ne $Evidence[$k] -and "$($Evidence[$k])" -ne '') { $ev[$k] = [string]$Evidence[$k] } } }
    $f = [pscustomobject]@{
        Id = $script:Findings.Count; Category = $Category; Severity = $Severity; Title = $Title; Detail = $Detail
        Evidence = $ev; Actions = @($Actions | Where-Object { $_ }); Manual = $Manual; Status = 'Open'; Result = ''; Key = $Key
    }
    [void]$script:Findings.Add($f)
    $script:FindingKeys[$Key] = $f
}

# ---------------------------------------------------------------------------
#  Remediation helpers. Everything is reversible where possible:
#  files are quarantined (moved + renamed), registry keys are exported first.
# ---------------------------------------------------------------------------

function ConvertTo-NativeReg([string]$Key) { return ($Key -replace '^Registry::', '' -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\', 'HKEY_CURRENT_USER\') }
function ConvertTo-PSReg([string]$Key) { if ($Key -like 'Registry::*') { return $Key }; return 'Registry::' + (ConvertTo-NativeReg $Key) }

function Backup-RegKey([string]$Key) {
    $native = ConvertTo-NativeReg $Key
    if (-not (Test-Path -LiteralPath (ConvertTo-PSReg $native))) { return }
    New-Item -ItemType Directory -Path $BackupDir -Force -ErrorAction SilentlyContinue | Out-Null
    $name = ($native -replace '[\\/:*?"<>| ]', '_')
    if ($name.Length -gt 120) { $name = $name.Substring($name.Length - 120) }
    & reg.exe export $native (Join-Path $BackupDir "$name.reg") /y 2>&1 | Out-Null
}

function Stop-ProcessesUsing([string]$Path) {
    $n = 0
    $prefix = $Path.TrimEnd('\') + '\'
    Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -eq $Path -or $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) } | ForEach-Object {
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $n++ } catch { & taskkill.exe /PID $_.ProcessId /F /T 2>&1 | Out-Null; $n++ }
    }
    return $n
}

function Invoke-Quarantine {
    # Move a file or folder into the quarantine folder and neuter executables
    # (append .quarantined). Locked files are scheduled for deletion at reboot.
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return "Already gone: $Path" }
    $killed = Stop-ProcessesUsing $Path
    if ($killed) { Start-Sleep -Milliseconds 800 }
    New-Item -ItemType Directory -Path $QuarantineDir -Force -ErrorAction SilentlyContinue | Out-Null
    $leaf = Split-Path $Path -Leaf
    $dest = Join-Path $QuarantineDir ("{0}_{1}" -f (Get-Random -Maximum 99999), $leaf)
    try {
        Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $dest -PathType Leaf) {
            Rename-Item -LiteralPath $dest -NewName ((Split-Path $dest -Leaf) + '.quarantined') -ErrorAction SilentlyContinue
        } else {
            Get-ChildItem -LiteralPath $dest -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(exe|dll|scr|com|bat|cmd|vbs|js|ps1|hta|msi)$' } |
                ForEach-Object { Rename-Item -LiteralPath $_.FullName -NewName ($_.Name + '.quarantined') -ErrorAction SilentlyContinue }
        }
        return "Quarantined $Path -> $dest" + $(if ($killed) { " (stopped $killed process(es) first)" } else { '' })
    } catch {
        $err = $_.Exception.Message
        $sched = 0
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            if ([NNAudit.Native]::MoveFileEx($Path, $null, 4)) { $sched = 1 }
        } else {
            Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $_.FullName) { if ([NNAudit.Native]::MoveFileEx($_.FullName, $null, 4)) { $sched++ } } }
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $Path) { [void][NNAudit.Native]::MoveFileEx($Path, $null, 4) }
        }
        if (-not (Test-Path -LiteralPath $Path)) { return "Deleted $Path (could not move to quarantine: $err)" }
        if ($sched) { return "PARTIAL: $Path is locked; $sched file(s) will be deleted at the next reboot" }
        throw "Could not remove $Path : $err"
    }
}

function Remove-RegValueSafe {
    param([string]$Key, [string]$Name)
    $ps = ConvertTo-PSReg $Key
    if (-not (Test-Path -LiteralPath $ps)) { return "Key already gone: $Key" }
    $item = Get-Item -LiteralPath $ps
    if ($item.GetValueNames() -notcontains $Name) { return "Value already gone: $Key\$Name" }
    Backup-RegKey $Key
    Remove-ItemProperty -LiteralPath $ps -Name $Name -Force -ErrorAction Stop
    return "Removed registry value '$Name' from $(ConvertTo-NativeReg $Key) (backup in $BackupDir)"
}

function Remove-RegKeySafe([string]$Key) {
    $ps = ConvertTo-PSReg $Key
    if (-not (Test-Path -LiteralPath $ps)) { return "Key already gone: $Key" }
    Backup-RegKey $Key
    Remove-Item -LiteralPath $ps -Recurse -Force -ErrorAction Stop
    return "Removed registry key $(ConvertTo-NativeReg $Key) (backup in $BackupDir)"
}

function Remove-ServiceSafe {
    param([string]$Name, [switch]$DisableOnly)
    $svcKey = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$Name"
    Backup-RegKey $svcKey
    & sc.exe stop "$Name" 2>&1 | Out-Null
    $pidLine = & sc.exe queryex "$Name" 2>&1 | Select-String 'PID'
    if ($pidLine -and "$pidLine" -match ':\s*(\d+)' -and [int]$matches[1] -gt 4) {
        $sp = Get-WmiObject Win32_Process -Filter "ProcessId=$($matches[1])" -ErrorAction SilentlyContinue
        if ($sp -and $sp.ExecutablePath -notlike '*\svchost.exe') { & taskkill.exe /PID $sp.ProcessId /F 2>&1 | Out-Null }
    }
    & sc.exe config "$Name" start= disabled 2>&1 | Out-Null
    if ($DisableOnly) { return "Stopped and disabled service '$Name' (backup of its settings in $BackupDir)" }
    $out = & sc.exe delete "$Name" 2>&1
    if ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath "Registry::$svcKey")) {
        Remove-Item -LiteralPath "Registry::$svcKey" -Recurse -Force -ErrorAction Stop
        return "Stopped service '$Name' and removed its registry key (sc delete said: $(($out | Out-String).Trim()))"
    }
    return "Stopped and deleted service '$Name'"
}

function Invoke-Uninstaller {
    param([hashtable]$D)
    $cmd = ''
    if ($D.MsiCode) { $cmd = "msiexec.exe /x $($D.MsiCode) /qn /norestart" }
    elseif ($D.Quiet) { $cmd = $D.Quiet }
    elseif ($D.Uninstall) { $cmd = $D.Uninstall }
    if (-not $cmd) { throw 'No uninstall command registered for this program.' }
    if ($cmd -match '(?i)msiexec(\.exe)?\s+/[ix]\s*(\{[0-9A-F-]+\})') { $cmd = "msiexec.exe /x $($matches[2]) /qn /norestart" }
    Write-Log "Running uninstaller: $cmd" -Quiet
    $p = Start-Process -FilePath "$env:windir\System32\cmd.exe" -ArgumentList '/c', "`"$cmd`"" -PassThru -WindowStyle Normal
    if (-not $p.WaitForExit(900000)) { return "Uninstaller still running after 15 minutes: $cmd" }
    $code = $p.ExitCode
    Start-Sleep -Seconds 2
    $still = $false
    if ($D.Key) { $still = Test-Path -LiteralPath (ConvertTo-PSReg $D.Key) }
    if ($code -in 0, 1605, 1614, 3010 -and -not $still) { return "Uninstalled $($D.Name) (exit code $code)" }
    if (-not $still) { return "Uninstaller finished (exit code $code); $($D.Name) no longer appears in Programs and Features" }
    throw "Uninstaller exit code $code and $($D.Name) is still listed in Programs and Features. It may need the user to click through it - try again, or remove it from Programs and Features."
}

function Remove-ScheduledTaskSafe([string]$TaskPath, [string]$File) {
    New-Item -ItemType Directory -Path $BackupDir -Force -ErrorAction SilentlyContinue | Out-Null
    if ($File -and (Test-Path -LiteralPath $File)) { Copy-Item -LiteralPath $File -Destination (Join-Path $BackupDir ('task_' + ($TaskPath -replace '[\\/:*?"<>| ]', '_') + '.xml')) -Force -ErrorAction SilentlyContinue }
    $out = & schtasks.exe /delete /tn "$TaskPath" /f 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($File -and (Test-Path -LiteralPath $File)) { throw "schtasks could not delete the task: $(($out | Out-String).Trim())" }
        return "Task already gone: $TaskPath"
    }
    return "Deleted scheduled task $TaskPath (XML backup in $BackupDir)"
}

# ---------------------------------------------------------------------------
#  Fix action builders (each returns a New-FixAction)
# ---------------------------------------------------------------------------
function Act-KillProcess([int]$ProcessId, [string]$Name) {
    New-FixAction -Label 'Stop process' -Description "Stops $Name (PID $ProcessId) and its child processes." -Data @{ Pid = $ProcessId } -Script {
        param($D)
        $out = & taskkill.exe /PID $D.Pid /F /T 2>&1
        if ($LASTEXITCODE -ne 0 -and (Get-Process -Id $D.Pid -ErrorAction SilentlyContinue)) { throw ($out | Out-String).Trim() }
        "Stopped PID $($D.Pid)"
    }
}
function Act-Quarantine([string]$Path, [string]$Label = 'Quarantine file') {
    New-FixAction -Label $Label -Description "Stops anything running from it, then moves $Path into $QuarantineDir and renames executables to .quarantined (reversible)." -Data @{ Path = $Path } -Script {
        param($D) Invoke-Quarantine $D.Path
    }
}
function Act-RemoveService([string]$Name, [string]$Binary, [bool]$QuarantineBinary) {
    $desc = "Stops, disables and deletes the service '$Name' (settings exported first)."
    if ($QuarantineBinary) { $desc += " Then quarantines its program $Binary." }
    New-FixAction -Label 'Remove service' -Description $desc -Data @{ Name = $Name; Binary = $Binary; Q = $QuarantineBinary } -Script {
        param($D)
        $r = @(Remove-ServiceSafe -Name $D.Name)
        if ($D.Q -and $D.Binary) { $r += Invoke-Quarantine $D.Binary }
        $r -join ' | '
    }
}
function Act-DisableService([string]$Name) {
    New-FixAction -Label 'Stop + disable' -Description "Stops the service '$Name' and sets it to Disabled (keeps it installed, easy to undo)." -Data @{ Name = $Name } -Script {
        param($D) Remove-ServiceSafe -Name $D.Name -DisableOnly
    }
}
function Act-Uninstall([hashtable]$Entry) {
    $what = if ($Entry.MsiCode) { "msiexec /x $($Entry.MsiCode) /qn (silent)" } elseif ($Entry.Quiet) { $Entry.Quiet } else { $Entry.Uninstall }
    New-FixAction -Label 'Uninstall' -Description "Runs the program's own uninstaller: $what. A non-silent uninstaller opens its own window - click through it." -Data $Entry -Script {
        param($D) Invoke-Uninstaller $D
    }
}
function Act-RemoveRegValue([string]$Key, [string]$Name, [string]$Label = 'Remove entry') {
    New-FixAction -Label $Label -Description "Deletes registry value '$Name' from $(ConvertTo-NativeReg $Key) (key exported to the backup folder first)." -Data @{ Key = $Key; Name = $Name } -Script {
        param($D) Remove-RegValueSafe -Key $D.Key -Name $D.Name
    }
}
function Act-RemoveTask([string]$TaskPath, [string]$File) {
    New-FixAction -Label 'Delete task' -Description "Deletes scheduled task $TaskPath (task XML copied to the backup folder first)." -Data @{ Task = $TaskPath; File = $File } -Script {
        param($D) Remove-ScheduledTaskSafe -TaskPath $D.Task -File $D.File
    }
}

# ---------------------------------------------------------------------------
#  Shared data (gathered once per scan pass)
# ---------------------------------------------------------------------------
function Get-TcpTable {
    # Get-NetTCPConnection exists on Windows 8+; Windows 7 falls back to netstat.
    $rows = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$rows.Add([pscustomobject]@{ LocalAddress = "$($_.LocalAddress)"; LocalPort = [int]$_.LocalPort; RemoteAddress = "$($_.RemoteAddress)"; RemotePort = [int]$_.RemotePort; State = "$($_.State)"; Pid = [int]$_.OwningProcess })
        }
    } else {
        Add-ScanNote 'Network: Get-NetTCPConnection is not available (Windows 7) - used netstat -ano instead.'
        foreach ($line in (& netstat.exe -ano 2>$null)) {
            if ($line -notmatch '^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') { continue }
            $l = $matches[1]; $r = $matches[2]; $st = $matches[3]; $procId = [int]$matches[4]
            $la = $l -replace ':(\d+)$', ''; $lp = if ($l -match ':(\d+)$') { [int]$matches[1] } else { 0 }
            $ra = $r -replace ':(\d+)$', ''; $rp = if ($r -match ':(\d+)$') { [int]$matches[1] } else { 0 }
            $state = switch ($st) { 'LISTENING' { 'Listen' } 'ESTABLISHED' { 'Established' } default { $st } }
            [void]$rows.Add([pscustomobject]@{ LocalAddress = $la.Trim('[]'); LocalPort = $lp; RemoteAddress = $ra.Trim('[]'); RemotePort = $rp; State = $state; Pid = $procId })
        }
    }
    return $rows
}
function Test-PrivateIP([string]$Ip) {
    if (-not $Ip) { return $true }
    if ($Ip -in '0.0.0.0', '::', '::1', '*') { return $true }
    if ($Ip -match '^(10\.|127\.|169\.254\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
    if ($Ip -match '^(fe80|fc|fd)') { return $true }
    return $false
}

$Procs = @{}
function Update-ProcessTable {
    $script:Procs = @{}
    Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $script:Procs[[int]$_.ProcessId] = [pscustomobject]@{ Pid = [int]$_.ProcessId; Name = $_.Name; Path = $_.ExecutablePath; Cmd = $_.CommandLine; Parent = [int]$_.ParentProcessId }
    }
}

# ===========================================================================
#  SCANS
# ===========================================================================
function Scan-Processes {
    foreach ($p in $script:Procs.Values) {
        if (-not $p.Path) { continue }
        $trust = Get-FileTrust $p.Path
        $tool  = Find-RemoteTool -Exe $p.Path -Path $p.Path -Signer $trust.SignerName
        $user  = Test-UserWritablePath $p.Path
        $ev = [ordered]@{ 'Path' = $p.Path; 'PID' = $p.Pid; 'Command line' = $p.Cmd; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } else { 'UNSIGNED' }); 'Company' = $trust.Company }
        if ($tool) {
            $sev = Get-ToolSeverity $tool $user $trust.Signed
            $acts = @(Act-KillProcess $p.Pid $p.Name)
            if ($user) { $acts += Act-Quarantine $p.Path 'Stop + quarantine' }
            Add-Finding -Category 'Remote access software' -Severity $sev -Title "$($tool.Name) is running ($($p.Name))" `
                -Detail $(if ($sev -eq 'INFO') { "Expected: $(Get-TrustReason $tool.Name)" } else { "$($tool.Class). If you (or the customer) did not knowingly install it, remove it - check Programs and Features too." }) `
                -Evidence $ev -Actions $acts -Key "tool-proc|$($tool.Name)|$($p.Path)"
            continue
        }
        if (Test-SystemImpersonation $p.Path) {
            Add-Finding -Category 'Processes' -Severity 'HIGH' -Title "Fake system process: $($p.Name) running from the wrong folder" `
                -Detail 'This program uses the name of a core Windows file but does not run from C:\Windows\System32. Malware does this to blend in.' `
                -Evidence $ev -Actions @((Act-Quarantine $p.Path 'Stop + quarantine'), (Act-KillProcess $p.Pid $p.Name)) -Key "proc|$($p.Path)"
            continue
        }
        if ($trust.IsMicrosoft) { continue }
        if ($user -and -not $trust.Signed) {
            $sev = if ($p.Cmd -match $SuspiciousCmdRegex) { 'HIGH' } else { 'MEDIUM' }
            Add-Finding -Category 'Processes' -Severity $sev -Title "Unsigned program running from a user folder: $($p.Name)" `
                -Detail 'Legitimate software is almost always digitally signed and installed under Program Files. Unsigned programs running from AppData/Temp/Downloads are how most remote-access trojans run.' `
                -Evidence $ev -Actions @((Act-Quarantine $p.Path 'Stop + quarantine'), (Act-KillProcess $p.Pid $p.Name)) -Key "proc|$($p.Path)"
        }
    }
}

function Scan-Services {
    foreach ($s in (Get-WmiObject Win32_Service -ErrorAction SilentlyContinue)) {
        $bin   = Get-ExeFromCommand $s.PathName
        $trust = Get-FileTrust $bin
        $tool  = Find-RemoteTool -Exe $bin -ServiceName $s.Name -Display $s.DisplayName -Path $s.PathName -Signer $trust.SignerName
        $user  = Test-UserWritablePath $bin
        $ev = [ordered]@{ 'Service name' = $s.Name; 'Display name' = $s.DisplayName; 'State' = $s.State; 'Start mode' = $s.StartMode; 'Runs as' = $s.StartName; 'Command' = $s.PathName; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } elseif ($trust.Exists) { 'UNSIGNED' } else { 'file not found' }) }
        if ($tool -and $tool.Name -like 'ScreenConnect*') { continue }   # Scan-RemoteToolFiles does the full removal
        if ($tool) {
            $sev = Get-ToolSeverity $tool $user $trust.Signed
            if (-not $trust.Exists -and $sev -ne 'INFO') {
                Add-Finding -Category 'Remote access software' -Severity 'LOW' -Title "Leftover $($tool.Name) service ($($s.Name)) - program already deleted" `
                    -Detail 'The service is still registered but its program file is gone. Harmless, but remove the leftover entry.' `
                    -Evidence $ev -Actions @(Act-RemoveService $s.Name $bin $false) -Key "svc|$($s.Name)"
                continue
            }
            Add-Finding -Category 'Remote access software' -Severity $sev -Title "$($tool.Name) service: $($s.DisplayName) [$($s.State)]" `
                -Detail $(if ($sev -eq 'INFO') { "Expected: $(Get-TrustReason $tool.Name)" } else { "$($tool.Class). A service gives it access at every boot, before anyone logs in. Prefer 'Uninstall' (Programs and Features finding) when there is one; 'Remove service' is the forceful option." }) `
                -Evidence $ev -Actions @((Act-DisableService $s.Name), (Act-RemoveService $s.Name $bin $user)) -Key "svc|$($s.Name)"
            continue
        }
        if ($trust.IsMicrosoft) { continue }
        if ($trust.Signed -and $bin -like "$env:ProgramData\*") { $user = $false }
        if (Test-SystemImpersonation $bin) {
            Add-Finding -Category 'Services' -Severity 'HIGH' -Title "Service impersonating a Windows file: $($s.DisplayName)" `
                -Detail 'The service program has the name of a core Windows file but lives outside System32.' `
                -Evidence $ev -Actions @(Act-RemoveService $s.Name $bin $true) -Key "svc|$($s.Name)"
        } elseif ($user) {
            $sev = if ($trust.Signed) { 'MEDIUM' } else { 'HIGH' }
            Add-Finding -Category 'Services' -Severity $sev -Title "Service runs from a user-writable folder: $($s.DisplayName)" `
                -Detail 'Real services are installed under Program Files or Windows. A service whose program sits in AppData/Temp/ProgramData is a classic persistence trick.' `
                -Evidence $ev -Actions @((Act-DisableService $s.Name), (Act-RemoveService $s.Name $bin $true)) -Key "svc|$($s.Name)"
        } elseif ($s.PathName -match $SuspiciousCmdRegex) {
            Add-Finding -Category 'Services' -Severity 'HIGH' -Title "Service runs a script/download command: $($s.DisplayName)" `
                -Detail 'The service command line downloads or decodes code (PowerShell -enc, mshta, certutil, ...). Typical of fileless malware.' `
                -Evidence $ev -Actions @(Act-RemoveService $s.Name '' $false) -Key "svc|$($s.Name)"
        }
    }
}

function Get-UninstallEntries {
    $roots = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
               'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in (Get-UserHives)) { $roots += "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    foreach ($r in $roots) {
        Get-ChildItem -LiteralPath "Registry::$r" -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if (-not $p.DisplayName) { return }
            [pscustomobject]@{
                Key = "$r\$($_.PSChildName)"; Name = $p.DisplayName; Publisher = $p.Publisher; Version = $p.DisplayVersion
                Uninstall = $p.UninstallString; Quiet = $p.QuietUninstallString; InstallLocation = $p.InstallLocation
                MsiCode = $(if ($p.WindowsInstaller -eq 1 -and $_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { $_.PSChildName } else { '' })
                InstallDate = $p.InstallDate
            }
        }
    }
}

function Scan-InstalledPrograms {
    foreach ($e in (Get-UninstallEntries)) {
        $tool = Find-RemoteToolByProduct $e.Name $e.Publisher
        if (-not $tool) { continue }
        $sev = Get-ToolSeverity $tool $false $true
        $ev = [ordered]@{ 'Program' = $e.Name; 'Publisher' = $e.Publisher; 'Version' = $e.Version; 'Installed' = $e.InstallDate; 'Location' = $e.InstallLocation; 'Uninstall command' = $(if ($e.Quiet) { $e.Quiet } else { $e.Uninstall }); 'Registry' = $e.Key }
        $acts = @()
        if ($e.Uninstall -or $e.Quiet -or $e.MsiCode) {
            $acts += Act-Uninstall @{ Name = $e.Name; Key = $e.Key; MsiCode = $e.MsiCode; Quiet = $e.Quiet; Uninstall = $e.Uninstall }
        }
        Add-Finding -Category 'Remote access software' -Severity $sev -Title "Installed: $($e.Name)" `
            -Detail $(if ($sev -eq 'INFO') { "Expected: $(Get-TrustReason $tool.Name)" } else { "$($tool.Class). Installed remote-access software stays usable even when it is not running. Confirm with the customer that they (not a caller) installed it." }) `
            -Evidence $ev -Actions $acts -Key "app|$($e.Key)"
    }
}

function Scan-Network {
    $table = Get-TcpTable
    $script:TcpTable = $table
    # 1) Remote-access / C2 ports: listening, or connected to an outside address
    foreach ($c in $table) {
        $pNote = $RatPorts[$c.LocalPort]; $rNote = $RatPorts[$c.RemotePort]
        if (-not $pNote -and -not $rNote) { continue }
        $proc = $script:Procs[$c.Pid]
        $pname = if ($proc) { $proc.Name } else { "PID $($c.Pid)" }
        $ppath = if ($proc) { $proc.Path } else { '' }
        $trust = Get-FileTrust $ppath
        $tool = Find-RemoteTool -Exe $ppath -Path $ppath -Signer $trust.SignerName
        $trusted = $tool -and (Test-TrustedTool $tool.Name)
        $ev = [ordered]@{ 'Process' = "$pname (PID $($c.Pid))"; 'Program' = $ppath; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } else { 'UNSIGNED / unknown' }); 'Local' = "$($c.LocalAddress):$($c.LocalPort)"; 'Remote' = "$($c.RemoteAddress):$($c.RemotePort)"; 'State' = $c.State }
        if ($c.State -eq 'Listen' -and $pNote) {
            $isMgmt = $MgmtPorts -contains $c.LocalPort
            if ($c.LocalAddress -match '^(127\.|::1$)') { continue }
            $sev = if ($trusted) { 'INFO' } elseif ($isMgmt) { 'MEDIUM' } else { 'HIGH' }
            $acts = @(); if ($c.Pid -gt 4 -and -not $trusted) { $acts += Act-KillProcess $c.Pid $pname }
            Add-Finding -Category 'Network' -Severity $sev -Title "Listening for incoming $pNote connections on port $($c.LocalPort) ($pname)" `
                -Detail $(if ($trusted) { "Expected: $(Get-TrustReason $tool.Name)" } elseif ($isMgmt) { 'A remote-management port is open to the network. Fine if you set it up; otherwise disable it (see RDP/WinRM findings or remove the program).' } else { 'This port is used by remote-control tools and trojans. Nothing legitimate on a home PC normally listens here.' }) `
                -Evidence $ev -Actions $acts -Key "listen|$($c.LocalPort)|$pname"
        } elseif ($c.State -eq 'Established' -and -not (Test-PrivateIP $c.RemoteAddress)) {
            $note = if ($rNote) { $rNote } else { $pNote }
            $isMgmt = ($MgmtPorts -contains $c.LocalPort) -or ($MgmtPorts -contains $c.RemotePort)
            $sev = if ($trusted) { 'INFO' } elseif ($isMgmt) { 'MEDIUM' } else { 'HIGH' }
            $acts = @(); if ($c.Pid -gt 4 -and -not $trusted) { $acts += Act-KillProcess $c.Pid $pname }
            Add-Finding -Category 'Network' -Severity $sev -Title "Live $note connection: $pname <-> $($c.RemoteAddress):$($c.RemotePort)" `
                -Detail 'An active connection on a remote-access / C2 port to an outside address. If nobody should be connected to this PC right now, stop the process and remove the program.' `
                -Evidence $ev -Actions $acts -Key "conn|$($c.Pid)|$($c.RemoteAddress)|$($c.RemotePort)"
        }
    }
    # 2) Per-process outside traffic heuristics (beaconing / odd ports / user-folder programs)
    $webPorts = @(80, 443, 8080, 8443)
    $groups = $table | Where-Object { $_.State -eq 'Established' -and -not (Test-PrivateIP $_.RemoteAddress) } | Group-Object Pid
    foreach ($g in $groups) {
        $procId = [int]$g.Name
        $proc = $script:Procs[$procId]
        if (-not $proc -or -not $proc.Path) { continue }
        $trust = Get-FileTrust $proc.Path
        if ($trust.IsMicrosoft) { continue }
        $user = Test-UserWritablePath $proc.Path
        $odd = @($g.Group | Where-Object { $webPorts -notcontains $_.RemotePort -and -not $RatPorts.ContainsKey($_.RemotePort) -and $_.RemotePort -gt 1024 })
        $many = $g.Count -ge 8
        if ($trust.Signed) { if (-not $user) { continue }; $odd = @(); $many = $false }
        if (-not ($user -or $odd.Count -or $many)) { continue }
        $reasons = @()
        if ($user) { $reasons += "program runs from a user-writable folder$(if (-not $trust.Signed) { ' and is UNSIGNED' })" }
        if ($many) { $reasons += "$($g.Count) simultaneous outside connections" }
        if ($odd.Count) { $reasons += "connects to unusual ports: $(($odd | Select-Object -ExpandProperty RemotePort -Unique | Select-Object -First 5) -join ', ')" }
        $sev = if ($user -and -not $trust.Signed) { 'HIGH' } elseif ($user -or $many) { 'MEDIUM' } else { 'LOW' }
        $remotes = ($g.Group | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } | Select-Object -Unique | Select-Object -First 10) -join ', '
        Add-Finding -Category 'Network' -Severity $sev -Title "Suspicious outside traffic from $($proc.Name) (PID $procId)" `
            -Detail ("Why: " + ($reasons -join '; ') + '.') `
            -Evidence ([ordered]@{ 'Program' = $proc.Path; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } else { 'UNSIGNED' }); 'Command line' = $proc.Cmd; 'Connected to' = $remotes }) `
            -Actions @((Act-KillProcess $procId $proc.Name), $(if ($user) { Act-Quarantine $proc.Path 'Stop + quarantine' })) -Key "traffic|$($proc.Path)"
    }
}

function Scan-ScheduledTasks {
    # Read the task XML files directly: works the same on Windows 7-11 and gives
    # the full command + arguments (schtasks /query output is localized and lossy).
    $root = Join-Path $env:windir 'System32\Tasks'
    if (-not (Test-Path -LiteralPath $root)) { Add-ScanNote 'Scheduled tasks: C:\Windows\System32\Tasks not readable.'; return }
    foreach ($item in (Get-FilesSafe -Root $root -Extensions @() -MaxDepth 10)) {
        $file = $item.File.FullName
        $taskPath = $file.Substring($root.Length)
        try { [xml]$x = Get-Content -LiteralPath $file -Raw -ErrorAction Stop } catch { continue }
        if (-not $x.Task) { continue }
        $enabled = -not ("$($x.Task.Settings.Enabled)" -eq 'false')
        $hidden = "$($x.Task.Settings.Hidden)" -eq 'true'
        $underMS = $taskPath -like '\Microsoft\*'
        foreach ($a in @($x.Task.Actions.Exec)) {
            if (-not $a -or -not $a.Command) { continue }
            $cmd = [Environment]::ExpandEnvironmentVariables("$($a.Command)".Trim('"'))
            $taskArgs = "$($a.Arguments)"
            $full = "$cmd $taskArgs"
            $trust = Get-FileTrust $cmd
            $tool = Find-RemoteTool -Exe $cmd -Path $cmd -Signer $trust.SignerName
            $kw = Get-KeywordHit $full
            $susp = $full -match $SuspiciousCmdRegex
            $user = Test-UserWritablePath $cmd
            $leaf = Split-Path $taskPath -Leaf
            $rand = (-not $underMS) -and (-not $trust.IsMicrosoft) -and ($leaf -match '^(\{?[0-9a-f-]{16,}\}?|[a-z0-9]{24,})$')
            $ev = [ordered]@{ 'Task' = $taskPath; 'Runs' = $cmd; 'Arguments' = $taskArgs; 'Enabled' = $enabled; 'Hidden' = $hidden; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } elseif ($trust.Exists) { 'UNSIGNED' } else { 'file not found' }); 'Author' = "$($x.Task.RegistrationInfo.Author)" }
            $acts = @(Act-RemoveTask $taskPath $file)
            if ($tool -or $kw) {
                $name = if ($tool) { $tool.Name } else { $kw }
                $sev = if ($tool) { Get-ToolSeverity $tool $user $trust.Signed } else { 'HIGH' }
                if (-not $enabled -and $sev -eq 'HIGH') { $sev = 'MEDIUM' }
                if ($user -and -not $trust.Signed -and $sev -ne 'INFO') { $acts += Act-Quarantine $cmd 'Delete task + quarantine program' }
                Add-Finding -Category 'Scheduled tasks' -Severity $sev -Title "Task launches remote-access software ($name): $taskPath" `
                    -Detail 'A scheduled task restarts the tool automatically (at logon, on a timer, or when removed).' -Evidence $ev -Actions $acts -Key "task|$taskPath"
            } elseif ($susp) {
                Add-Finding -Category 'Scheduled tasks' -Severity 'HIGH' -Title "Task runs a download/encoded command: $taskPath" `
                    -Detail 'The task runs PowerShell/mshta/certutil/rundll32 with a download or encoded payload. This is how fileless malware re-infects a PC.' -Evidence $ev -Actions $acts -Key "task|$taskPath"
            } elseif ($trust.IsMicrosoft -and $underMS) {
                continue
            } elseif ($user -and -not $trust.Signed) {
                if ($trust.Exists) { $acts += Act-Quarantine $cmd 'Delete task + quarantine program' }
                Add-Finding -Category 'Scheduled tasks' -Severity $(if ($enabled) { 'HIGH' } else { 'MEDIUM' }) -Title "Task runs an unsigned program from a user folder: $taskPath" `
                    -Detail 'Legitimate updaters are signed and live under Program Files.' -Evidence $ev -Actions $acts -Key "task|$taskPath"
            } elseif ($rand -and -not $trust.Signed) {
                Add-Finding -Category 'Scheduled tasks' -Severity 'MEDIUM' -Title "Randomly-named task: $taskPath" `
                    -Detail 'Malware often registers tasks with random/GUID names so they are hard to spot.' -Evidence $ev -Actions $acts -Key "task|$taskPath"
            } elseif ($hidden -and -not $trust.Signed -and -not $underMS) {
                Add-Finding -Category 'Scheduled tasks' -Severity 'LOW' -Title "Hidden task running unsigned program: $taskPath" `
                    -Detail 'The task is marked hidden in Task Scheduler and its program is not signed.' -Evidence $ev -Actions $acts -Key "task|$taskPath"
            }
        }
    }
}

function Test-AutorunValue {
    # Shared rules for Run keys / Startup items / Winlogon-style entries
    param([string]$Value, [string]$Where, [object[]]$Actions, [string]$Key, [string]$What = 'Startup entry')
    $exe = Get-ExeFromCommand $Value
    $trust = Get-FileTrust $exe
    $tool = Find-RemoteTool -Exe $exe -Path $Value -Signer $trust.SignerName
    $kw = Get-KeywordHit $Value
    $user = Test-UserWritablePath $exe
    $ev = [ordered]@{ 'Location' = $Where; 'Command' = $Value; 'Program' = $trust.Path; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } elseif ($trust.Exists) { 'UNSIGNED' } else { 'file not found' }); 'Company' = $trust.Company }
    $acts = @($Actions)
    if ($tool -or $kw) {
        $name = if ($tool) { $tool.Name } else { $kw }
        $sev = if ($tool) { Get-ToolSeverity $tool $user $trust.Signed } else { 'HIGH' }
        if ($user -and $trust.Exists -and -not $trust.Signed -and $sev -ne 'INFO') { $acts += Act-Quarantine $trust.Path 'Remove + quarantine program' }
        Add-Finding -Category 'Startup' -Severity $sev -Title "$What starts remote-access software ($name)" -Detail 'Starts automatically every time Windows starts or a user logs in.' -Evidence $ev -Actions $acts -Key $Key
    } elseif ($Value -match $SuspiciousCmdRegex) {
        Add-Finding -Category 'Startup' -Severity 'HIGH' -Title "$What runs a download/encoded command" -Detail 'Runs PowerShell/mshta/rundll32 with a download or encoded payload at every login. Classic fileless persistence.' -Evidence $ev -Actions $acts -Key $Key
    } elseif (Test-SystemImpersonation $exe) {
        if ($trust.Exists) { $acts += Act-Quarantine $trust.Path 'Remove + quarantine program' }
        Add-Finding -Category 'Startup' -Severity 'HIGH' -Title "$What runs a fake Windows file: $(Split-Path $exe -Leaf)" -Detail 'Uses a core Windows file name from the wrong folder.' -Evidence $ev -Actions $acts -Key $Key
    } elseif ($user -and $trust.Exists -and -not $trust.Signed) {
        $acts += Act-Quarantine $trust.Path 'Remove + quarantine program'
        Add-Finding -Category 'Startup' -Severity 'MEDIUM' -Title "$What runs an unsigned program from a user folder: $(Split-Path $exe -Leaf)" -Detail 'Unsigned programs auto-starting from AppData/Temp/ProgramData are a common way trojans survive reboots. Check the company/product and remove if unknown.' -Evidence $ev -Actions $acts -Key $Key
    } elseif ($user -and -not $trust.Exists -and $exe) {
        Add-Finding -Category 'Startup' -Severity 'LOW' -Title "$What points at a missing program: $(Split-Path $exe -Leaf)" -Detail 'Leftover entry; the program is gone. Safe to remove.' -Evidence $ev -Actions $acts -Key $Key
    }
}

function Scan-Autoruns {
    $runKeys = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    foreach ($h in (Get-UserHives)) {
        $runKeys += "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Run", "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    }
    foreach ($k in $runKeys) {
        $item = Get-Item -LiteralPath "Registry::$k" -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($n in $item.GetValueNames()) {
            if (-not $n) { continue }
            $v = [string]$item.GetValue($n)
            Test-AutorunValue -Value $v -Where "$k  [$n]" -Actions @(Act-RemoveRegValue $k $n 'Remove startup entry') -Key "run|$k|$n" -What "Startup entry '$n'"
        }
    }

    # Winlogon hijacks
    $wl = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $w = Get-ItemProperty -LiteralPath "Registry::$wl" -ErrorAction SilentlyContinue
    if ($w) {
        $defaults = @{ Shell = 'explorer.exe'; Userinit = "$env:windir\system32\userinit.exe," }
        foreach ($name in 'Shell', 'Userinit') {
            $val = "$($w.$name)".Trim()
            $ok = if ($name -eq 'Shell') { $val -match '^(explorer(\.exe)?)$' } else { $val.TrimEnd(',').ToLower() -in "$env:windir\system32\userinit.exe".ToLower(), 'userinit.exe', 'userinit' }
            if (-not $ok -and $val) {
                $d = $defaults[$name]
                Add-Finding -Category 'Backdoors' -Severity 'HIGH' -Title "Winlogon $name has been changed" `
                    -Detail "Windows runs this at every logon. It should be '$d'. Extra programs added here start with Windows and are easy to miss." `
                    -Evidence ([ordered]@{ 'Registry' = "$wl\$name"; 'Current value' = $val; 'Default' = $d }) -Key "winlogon|$name" -Actions @(
                        New-FixAction -Label 'Restore default' -Description "Sets $name back to '$d' (key exported first)." -Data @{ Key = $wl; Name = $name; Value = $d } -Script {
                            param($D) Backup-RegKey $D.Key; Set-ItemProperty -LiteralPath "Registry::$($D.Key)" -Name $D.Name -Value $D.Value -ErrorAction Stop; "Restored $($D.Name) = $($D.Value)"
                        })
            }
        }
    }

    # AppInit_DLLs (loads a DLL into every program)
    foreach ($ak in 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $a = Get-ItemProperty -LiteralPath "Registry::$ak" -ErrorAction SilentlyContinue
        if ($a -and "$($a.AppInit_DLLs)".Trim() -and $a.LoadAppInit_DLLs -ne 0) {
            Add-Finding -Category 'Backdoors' -Severity 'HIGH' -Title 'AppInit_DLLs injects a DLL into every program' `
                -Detail 'Every program that loads user32.dll also loads these DLLs. Used by spyware, adware and some old security products.' `
                -Evidence ([ordered]@{ 'Registry' = $ak; 'AppInit_DLLs' = $a.AppInit_DLLs; 'LoadAppInit_DLLs' = $a.LoadAppInit_DLLs }) -Key "appinit|$ak" -Actions @(
                    New-FixAction -Label 'Disable injection' -Description 'Sets LoadAppInit_DLLs=0 and clears AppInit_DLLs (key exported first).' -Data @{ Key = $ak } -Script {
                        param($D) Backup-RegKey $D.Key; Set-ItemProperty -LiteralPath "Registry::$($D.Key)" -Name LoadAppInit_DLLs -Value 0 -Type DWord; Set-ItemProperty -LiteralPath "Registry::$($D.Key)" -Name AppInit_DLLs -Value ''; 'AppInit_DLLs disabled'
                    })
        }
    }

    # Image File Execution Options "Debugger" hijacks
    $ifeo = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $access = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
    Get-ChildItem -LiteralPath "Registry::$ifeo" -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if (-not $dbg) { return }
        $exe = $_.PSChildName
        if ($dbg -match '(?i)vsjitdebugger|windbg|procexp|systemsettings') { return }
        $isAccess = $access -contains $exe.ToLower()
        Add-Finding -Category 'Backdoors' -Severity $(if ($isAccess) { 'HIGH' } else { 'MEDIUM' }) -Title "Program hijack: starting $exe runs '$dbg' instead" `
            -Detail $(if ($isAccess) { 'Classic backdoor: pressing Shift 5x / the Ease of Access button at the login screen opens this program with SYSTEM rights - no password needed.' } else { 'An Image File Execution Options Debugger value silently replaces a program. Used to block security tools or to hijack programs.' }) `
            -Evidence ([ordered]@{ 'Registry' = "$ifeo\$exe"; 'Debugger' = $dbg }) -Key "ifeo|$exe" -Actions @(Act-RemoveRegValue "$ifeo\$exe" 'Debugger' 'Remove hijack')
    }

    # Accessibility programs replaced on disk (e.g. cmd.exe copied over sethc.exe).
    # Detect the actual attack: the file IS a shell (by internal name or hash).
    $shellHashes = @{}
    $sha = [Security.Cryptography.SHA256]::Create()
    foreach ($sh in "$env:windir\System32\cmd.exe", "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe", "$env:windir\explorer.exe", "$env:windir\System32\taskmgr.exe", "$env:windir\regedit.exe") {
        try { $shellHashes[[BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($sh)))] = (Split-Path $sh -Leaf) } catch {}
    }
    $shellNames = @('cmd', 'powershell', 'powershell_ise', 'pwsh', 'explorer', 'taskmgr', 'regedit', 'mmc', 'wscript', 'cscript', 'mshta')
    foreach ($exe in $access) {
        $path = Join-Path "$env:windir\System32" $exe
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $t = Get-FileTrust $path
        $orig = ([IO.Path]::GetFileNameWithoutExtension(($t.OriginalName -replace '(?i)\.mui$', ''))).ToLower()
        $hashHit = $null
        try { $hashHit = $shellHashes[[BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($path)))] } catch {}
        $why = @()
        if ($shellNames -contains $orig) { $why += "its internal name is '$($t.OriginalName)'" }
        if ($hashHit) { $why += "it is byte-for-byte identical to $hashHit" }
        if ($t.Company -and $t.Company -notlike 'Microsoft*') { $why += "its company is '$($t.Company)'" }
        if ($why.Count) {
            Add-Finding -Category 'Backdoors' -Severity 'HIGH' -Title "$exe has been replaced (login-screen backdoor)" `
                -Detail "C:\Windows\System32\$exe is not the real accessibility program: $($why -join '; '). This gives anyone a SYSTEM command prompt at the login screen (press Shift 5x or click Ease of Access)." `
                -Evidence ([ordered]@{ 'File' = $path; 'Original name' = $t.OriginalName; 'Company' = $t.Company; 'Signer' = $t.SignerName }) -Key "access|$exe" -Actions @(
                    New-FixAction -Label 'Repair file' -Description "Runs 'sfc /scanfile=$path' to restore the genuine Windows file." -Data @{ Path = $path } -Script {
                        param($D) $o = & sfc.exe "/scanfile=$($D.Path)" 2>&1; ($o | Out-String) -replace '\x00', '' -replace '\s+', ' '
                    })
        }
    }

    # LSA packages (ScreenConnect and credential stealers register here)
    $lsa = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
    $known = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'msoidssp', '"', '')
    $l = Get-ItemProperty -LiteralPath "Registry::$lsa" -ErrorAction SilentlyContinue
    foreach ($vn in 'Security Packages', 'Authentication Packages', 'Notification Packages') {
        foreach ($pkg in @($l.$vn)) {
            $pk = "$pkg".Trim().Trim('"').Trim().ToLower()   # Windows 10/11 store a literal "" placeholder
            if (-not $pk) { continue }
            if ($known -contains $pk -or ($vn -eq 'Notification Packages' -and $pk -in 'scecli', 'rassfm', 'passfilt')) { continue }
            $dll = Join-Path "$env:windir\System32" ($(if ($pk -like '*.dll') { $pk } else { "$pk.dll" }))
            $t = Get-FileTrust $dll
            if ($t.IsMicrosoft) { continue }
            $isSC = $pk -match 'screenconnect|connectwise'
            Add-Finding -Category 'Backdoors' -Severity $(if ($isSC -or -not $t.Signed) { 'HIGH' } else { 'MEDIUM' }) -Title "Non-Microsoft LSA package loaded into lsass: $pkg" `
                -Detail $(if ($isSC) { 'ScreenConnect registers this so it can log in as the user. lsass keeps the DLL locked, which is why ScreenConnect folders cannot be deleted until this is removed and the PC rebooted.' } else { 'lsass.exe (which holds every password) loads this DLL at boot. Credential stealers and some remote tools install themselves here.' }) `
                -Evidence ([ordered]@{ 'Registry' = "$lsa\$vn"; 'Package' = $pkg; 'DLL' = $dll; 'Signer' = $(if ($t.Signed) { $t.SignerName } elseif ($t.Exists) { 'UNSIGNED' } else { 'file not found' }) }) -Key "lsa|$vn|$pk" -Actions @(
                    New-FixAction -Label 'Remove package' -Description "Removes '$pkg' from $vn (key exported first). Reboot afterwards to unload it." -Data @{ Key = $lsa; Name = $vn; Pkg = $pkg } -Script {
                        param($D)
                        Backup-RegKey $D.Key
                        $cur = @((Get-ItemProperty -LiteralPath "Registry::$($D.Key)").($D.Name))
                        $new = @($cur | Where-Object { "$_" -ne $D.Pkg })
                        Set-ItemProperty -LiteralPath "Registry::$($D.Key)" -Name $D.Name -Value ([string[]]$new) -Type MultiString -ErrorAction Stop
                        "Removed $($D.Pkg) from $($D.Name). Reboot to unload it."
                    })
        }
    }
}

function Scan-StartupFolders {
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($p in (Get-UserProfiles)) { $dirs += Join-Path $p.Path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    $wsh = $null; try { $wsh = New-Object -ComObject WScript.Shell } catch {}
    foreach ($sd in ($dirs | Sort-Object -Unique)) {
        Get-ChildItem -LiteralPath $sd -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $item = $_.FullName; $ext = $_.Extension.ToLower()
            if ($ext -eq '.ini') { return }
            $cmd = $item
            if ($ext -eq '.lnk' -and $wsh) { try { $sc = $wsh.CreateShortcut($item); if ($sc.TargetPath) { $cmd = ('"{0}" {1}' -f $sc.TargetPath, $sc.Arguments).Trim() } } catch {} }
            $act = New-FixAction -Label 'Remove startup item' -Description "Quarantines the startup item $item." -Data @{ Path = $item } -Script { param($D) Invoke-Quarantine $D.Path }
            if (@('.bat', '.cmd', '.vbs', '.js', '.jse', '.vbe', '.ps1', '.hta', '.wsf', '.scr') -contains $ext) {
                $content = ''
                try { $content = (Get-Content -LiteralPath $item -TotalCount 40 -ErrorAction Stop) -join "`n" } catch {}
                $sev = if ($content -match $SuspiciousCmdRegex -or (Get-KeywordHit $content)) { 'HIGH' } else { 'MEDIUM' }
                Add-Finding -Category 'Startup' -Severity $sev -Title "Script in Startup folder: $($_.Name)" -Detail 'A script runs at every login. Normal apps use programs or shortcuts, not scripts.' `
                    -Evidence ([ordered]@{ 'File' = $item; 'First lines' = ($content -split "`n" | Select-Object -First 6) -join ' | ' }) -Actions @($act) -Key "startup|$item"
            } else {
                Test-AutorunValue -Value $cmd -Where $item -Actions @($act) -Key "startup|$item" -What "Startup folder item '$($_.Name)'"
            }
        }
    }
}

function Scan-RemoteToolFiles {
    # Known install folders (for every user profile), incl. portable ScreenConnect
    $folders = @()
    $pf = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ } | Sort-Object -Unique
    $names = @('TeamViewer', 'AnyDesk', 'RealVNC', 'TightVNC', 'UltraVNC', 'Radmin', 'ScreenConnect', 'ConnectWise Control', 'ScreenConnect Client', 'Supremo',
               'UltraViewer', 'AnyViewer', 'SimpleHelp', 'SimpleHelpCustomer', 'RustDesk', 'Splashtop', 'AeroAdmin', 'LiteManager Pro - Server', 'DWAgent',
               'Getscreen.me', 'Mesh Agent', 'TacticalAgent', 'HopToDesk', 'Remote Utilities', 'NetSupport', 'Ammyy', 'ShowMyPC', 'ngrok', 'AweSun')
    foreach ($b in $pf) { foreach ($n in $names) { $folders += Join-Path $b $n } }
    foreach ($p in (Get-UserProfiles)) {
        foreach ($n in 'AnyDesk', 'TeamViewer', 'ScreenConnect', 'RustDesk', 'HopToDesk', 'SimpleHelp', 'AeroAdmin', 'UltraViewer', 'ngrok') {
            $folders += Join-Path $p.Path "AppData\Roaming\$n"; $folders += Join-Path $p.Path "AppData\Local\$n"
        }
        $folders += Join-Path $p.Path 'AppData\Local\Programs\distant-desktop'
    }
    $folders += "$env:windir\Temp\ScreenConnect", "$env:SystemDrive\Temp\ScreenConnect"
    # One finding per tool, listing all of its folders
    $byTool = [ordered]@{}
    foreach ($f in ($folders | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $f -PathType Container)) { continue }
        $tool = Find-RemoteTool -Path "$f\"
        if (-not $tool) { $tool = Find-RemoteToolByProduct (Split-Path $f -Leaf) '' }
        $tname = if ($tool) { $tool.Name } else { Split-Path $f -Leaf }
        if (-not $byTool.Contains($tname)) { $byTool[$tname] = @{ Tool = $tool; Folders = @() } }
        $byTool[$tname].Folders += $f
    }
    foreach ($tname in $byTool.Keys) {
        $tool = $byTool[$tname].Tool; $list = @($byTool[$tname].Folders)
        $sev = if ($tool) { Get-ToolSeverity $tool $false $true } else { 'MEDIUM' }
        $ev = [ordered]@{}
        $i = 0
        foreach ($f in $list) {
            $i++
            $exes = @(Get-ChildItem -LiteralPath $f -Filter *.exe -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 4 | ForEach-Object { $_.Name })
            $ev["Folder $i"] = $f + $(if ($exes.Count) { "   (programs: $($exes -join ', '))" } else { '' })
        }
        Add-Finding -Category 'Remote access software' -Severity $sev -Title "$tname files on disk ($($list.Count) folder$(if ($list.Count -ne 1) { 's' }))" `
            -Detail $(if ($sev -eq 'INFO') { "Expected: $(Get-TrustReason $tname)" } else { 'Program and settings folders of a remote-access tool. Uninstall the program first (Programs and Features finding) - then quarantine what is left.' }) `
            -Evidence $ev -Key "folders|$tname" -Actions @(
                New-FixAction -Label 'Quarantine folders' -Description "Stops anything running from them, then moves these $($list.Count) folder(s) into $QuarantineDir (reversible): $($list -join '; ')" -Data @{ Paths = $list } -Script {
                    param($D) $r = @(); foreach ($p in $D.Paths) { try { $r += Invoke-Quarantine $p } catch { $r += $_.Exception.Message } }; $r -join ' | '
                })
    }

    # ScreenConnect full removal (service + uninstaller + LSA package + folders)
    foreach ($svc in (Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*ScreenConnect*' -or $_.DisplayName -like '*ScreenConnect*' -or $_.Name -like '*ConnectWise*' })) {
        if (Test-TrustedTool 'ScreenConnect / ConnectWise') { continue }
        $bin = Get-ExeFromCommand $svc.PathName
        $dir = if ($bin) { Split-Path $bin -Parent } else { '' }
        $idMatch = if ($svc.Name -match '\(([0-9a-f]{16})\)') { $matches[1] } else { '' }
        Add-Finding -Category 'Remote access software' -Severity 'HIGH' -Title "ScreenConnect client: $($svc.DisplayName) [$($svc.State)]" `
            -Detail 'ScreenConnect (ConnectWise Control) is the most common tool in tech-support scams. "Full removal" stops the service, runs its uninstaller, removes its LSA package (the reason its folder is always locked), quarantines its folders and removes its registry keys. Reboot afterwards.' `
            -Evidence ([ordered]@{ 'Service' = $svc.Name; 'State' = $svc.State; 'Program' = $bin; 'Instance id' = $idMatch }) -Key "sc|$($svc.Name)" -Actions @(
                New-FixAction -Label 'Full removal' -Description "Stops + deletes service '$($svc.Name)', runs the ScreenConnect uninstaller silently, removes ScreenConnect LSA packages, quarantines $dir and ScreenConnect AppData folders, removes HKLM\SOFTWARE\ScreenConnect. Reboot afterwards." -Data @{ Service = $svc.Name; Dir = $dir } -Script {
                    param($D)
                    $r = New-Object System.Collections.ArrayList
                    foreach ($e in (Get-UninstallEntries | Where-Object { $_.Name -match 'ScreenConnect|ConnectWise Control' })) {
                        try { [void]$r.Add((Invoke-Uninstaller @{ Name = $e.Name; Key = $e.Key; MsiCode = $e.MsiCode; Quiet = $e.Quiet; Uninstall = $e.Uninstall })) } catch { [void]$r.Add("Uninstaller: $($_.Exception.Message)") }
                    }
                    if (Get-Service -Name $D.Service -ErrorAction SilentlyContinue) { [void]$r.Add((Remove-ServiceSafe -Name $D.Service)) }
                    $lsa = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
                    Backup-RegKey $lsa
                    foreach ($vn in 'Security Packages', 'Authentication Packages') {
                        $cur = @((Get-ItemProperty -LiteralPath "Registry::$lsa" -ErrorAction SilentlyContinue).$vn)
                        $new = @($cur | Where-Object { "$_" -notmatch 'ScreenConnect|ConnectWise' })
                        if ($new.Count -ne $cur.Count) { Set-ItemProperty -LiteralPath "Registry::$lsa" -Name $vn -Value ([string[]]$new) -Type MultiString; [void]$r.Add("Removed ScreenConnect from LSA $vn") }
                    }
                    $paths = @($D.Dir) + @(Get-UserProfiles | ForEach-Object { Join-Path $_.Path 'AppData\Local\ScreenConnect'; Join-Path $_.Path 'AppData\Roaming\ScreenConnect' })
                    foreach ($p in ($paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) { try { [void]$r.Add((Invoke-Quarantine $p)) } catch { [void]$r.Add($_.Exception.Message) } }
                    foreach ($k in 'HKEY_LOCAL_MACHINE\SOFTWARE\ScreenConnect', 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ScreenConnect') { if (Test-Path -LiteralPath "Registry::$k") { [void]$r.Add((Remove-RegKeySafe $k)) } }
                    [void]$r.Add('Reboot the PC to finish (unloads the ScreenConnect DLL from lsass).')
                    $r -join ' | '
                })
    }
}

function Scan-UserFiles {
    # Hidden/buried programs in user-writable places (junction-safe).
    $roots = @()
    foreach ($p in (Get-UserProfiles)) {
        foreach ($sub in 'AppData\Local', 'AppData\Roaming', 'AppData\LocalLow') { $roots += [pscustomobject]@{ Path = (Join-Path $p.Path $sub); Kind = 'appdata'; Max = 25 } }
        foreach ($sub in 'Downloads', 'Desktop') { $roots += [pscustomobject]@{ Path = (Join-Path $p.Path $sub); Kind = 'downloads'; Max = 3 } }
    }
    $roots += [pscustomobject]@{ Path = "$env:SystemDrive\Users\Public"; Kind = 'appdata'; Max = 8 }
    $roots += [pscustomobject]@{ Path = $env:ProgramData; Kind = 'programdata'; Max = 3 }
    $roots += [pscustomobject]@{ Path = "$env:windir\Temp"; Kind = 'appdata'; Max = 6 }
    $exts = @('.exe', '.scr', '.com', '.pif')
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r.Path)) { continue }
        $rootDepth = ($r.Path.TrimEnd('\') -split '\\').Count
        foreach ($it in (Get-FilesSafe -Root $r.Path -Extensions $exts -MaxDepth $r.Max)) {
            $file = $it.File; $path = $file.FullName
            $base = [IO.Path]::GetFileNameWithoutExtension($file.Name).ToLower()
            $kw = Get-KeywordHit $file.Name
            $catalog = $false; foreach ($t in $RemoteTools) { if ($t.Exe -contains $base) { $catalog = $true; break } }
            $deep = ($r.Kind -eq 'appdata') -and ($it.Depth -ge 4)
            $imp = $SystemExeNames -contains $base
            $installer = ($r.Kind -eq 'downloads') -and ($kw -or $catalog)
            $inTemp = $path -like '*\Temp\*'
            if (-not ($kw -or $catalog -or $deep -or $imp -or $inTemp)) { continue }
            if ($file.Length -eq 0) { continue }
            $trust = Get-FileTrust $path
            if ($trust.IsMicrosoft) { continue }
            $tool = Find-RemoteTool -Exe $path -Path $path -Signer $trust.SignerName
            $ev = [ordered]@{ 'File' = $path; 'Signer' = $(if ($trust.Signed) { $trust.SignerName } else { 'UNSIGNED' }); 'Company' = $trust.Company; 'Product' = $trust.Product; 'Size' = ('{0:N0} KB' -f ($file.Length / 1KB)); 'Modified' = $file.LastWriteTime.ToString('yyyy-MM-dd') }
            $acts = @(Act-Quarantine $path)
            $gib = ($trust.Company -and $trust.Product -and "$($trust.Company)$($trust.Product)" -notmatch '[\s\.,]' -and $trust.Company -cmatch '^[A-Z][a-z]{5,}$' -and $trust.Product -cmatch '^[A-Z][a-z]{5,}$')
            if ($imp -and (Test-SystemImpersonation $path)) {
                Add-Finding -Category 'Suspicious files' -Severity 'HIGH' -Title "Fake Windows file: $path" -Detail 'Has the name of a core Windows program but sits in a user folder. Malware uses this to look harmless in Task Manager.' -Evidence $ev -Actions $acts -Key "file|$path"
            } elseif ($installer) {
                $tn = if ($tool) { $tool.Name } else { $kw }
                if ($tool -and (Test-TrustedTool $tool.Name)) { continue }
                Add-Finding -Category 'Remote access software' -Severity 'MEDIUM' -Title "Remote-access installer/program in $($r.Path | Split-Path -Leaf): $($file.Name)" `
                    -Detail "A $tn download. Scammers walk victims through downloading exactly these. If the customer was told to download it by a caller, remove it." -Evidence $ev -Actions $acts -Key "file|$path"
            } elseif ($tool) {
                $sev = Get-ToolSeverity $tool $true $trust.Signed
                if ($sev -eq 'INFO') { continue }
                Add-Finding -Category 'Remote access software' -Severity $sev -Title "$($tool.Name) program hidden in a user folder: $($file.Name)" `
                    -Detail "$($tool.Class). Found at a user-writable location (portable copy or dropped by a scammer)." -Evidence $ev -Actions $acts -Key "file|$path"
            } elseif (-not $trust.Signed -and $kw) {
                Add-Finding -Category 'Suspicious files' -Severity 'MEDIUM' -Title "Unsigned program named like a remote tool: $($file.Name)" -Detail "Name matches '$kw' but the file is not signed by its vendor." -Evidence $ev -Actions $acts -Key "file|$path"
            } elseif (-not $trust.Signed -and $inTemp -and $gib) {
                Add-Finding -Category 'Suspicious files' -Severity 'LOW' -Title "Adware-style installer in a Temp folder: $($file.Name)" `
                    -Detail 'Unsigned, and its company/product names look randomly generated (e.g. "Fidaroma" / "Legerukob") - the fingerprint of adware/bundleware installers from download sites.' `
                    -Evidence $ev -Actions $acts -Key "file|$path"
            } elseif ($deep -and -not $trust.Signed -and -not (Test-TrustedVendorPath $path)) {
                Add-Finding -Category 'Suspicious files' -Severity 'LOW' -Title "Unsigned program buried in AppData: $($file.Name)" `
                    -Detail 'Unsigned and buried several folders deep in a user folder - a common hiding spot for ScreenConnect copies and trojans. Check the company/product and quarantine if unknown.' `
                    -Evidence $ev -Actions $acts -Key "file|$path"
            }
        }
    }
    if ($script:EnumErrors -gt 0) { Add-ScanNote "User files: $($script:EnumErrors) folder(s) could not be read (access denied or path too long)." }
}

function Scan-Antivirus {
    # Security Center (Windows 7+ client editions)
    $avs = @()
    try { $avs = @(Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -ErrorAction Stop) } catch { Add-ScanNote 'Antivirus: Security Center not available (Windows Server?) - AV status not checked.' }
    $states = @($avs | ForEach-Object {
        $hex = '{0:x6}' -f [int]$_.productState
        [pscustomobject]@{ Av = $_; On = ($hex.Substring(2, 2) -in '10', '11'); Current = ($hex.Substring(4, 2) -eq '00') }
    })
    $anyOn = [bool]@($states | Where-Object { $_.On }).Count
    foreach ($st in $states) {
        $a = $st.Av
        $ev = [ordered]@{ 'Product' = $a.displayName; 'State code' = $a.productState; 'Program' = $a.pathToSignedProductExe }
        if (-not $st.On -and -not $anyOn) {
            Add-Finding -Category 'Antivirus' -Severity 'HIGH' -Title "$($a.displayName): real-time protection is OFF" `
                -Detail 'No antivirus is actively protecting this PC. Attackers turn protection off right after installing a remote tool. Turn it back on in the antivirus program.' -Evidence $ev -Key "av|$($a.displayName)"
        } elseif ($st.On -and -not $st.Current) {
            Add-Finding -Category 'Antivirus' -Severity 'MEDIUM' -Title "$($a.displayName): definitions are out of date" `
                -Detail 'The antivirus is on but not up to date. On Windows 7 (Security Essentials) its Update button no longer works: download and run the offline definitions (mpam-fe.exe, x64: https://go.microsoft.com/fwlink/?LinkID=87341).' -Evidence $ev -Key "av|$($a.displayName)"
        }
    }
    $scMissing = @($ScanNotes | Where-Object { $_ -like 'Antivirus: Security Center not available*' }).Count
    if (-not $avs.Count -and -not $scMissing) {
        Add-Finding -Category 'Antivirus' -Severity 'HIGH' -Title 'No antivirus is registered with Windows' -Detail 'Install/enable Microsoft Defender (Windows 8+) or Microsoft Security Essentials (Windows 7).' -Key 'av|none'
    }

    # Defender policy switches that turn protection off
    $pol = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
    foreach ($pair in @(@($pol, 'DisableAntiSpyware'), @($pol, 'DisableAntiVirus'), @("$pol\Real-Time Protection", 'DisableRealtimeMonitoring'), @("$pol\Real-Time Protection", 'DisableBehaviorMonitoring'))) {
        $v = (Get-ItemProperty -LiteralPath "Registry::$($pair[0])" -ErrorAction SilentlyContinue).($pair[1])
        if ($v -eq 1) {
            Add-Finding -Category 'Antivirus' -Severity 'HIGH' -Title "Defender turned off by policy: $($pair[1])=1" -Detail 'A registry policy disables Microsoft Defender. Malware sets this so Defender cannot be switched back on from its settings page.' `
                -Evidence ([ordered]@{ 'Registry' = "$($pair[0])\$($pair[1])" }) -Actions @(Act-RemoveRegValue $pair[0] $pair[1] 'Remove policy') -Key "avpol|$($pair[1])"
        }
    }

    # Exclusions: Defender (cmdlet or registry) and Security Essentials (registry)
    $sources = @(
        @{ Name = 'Microsoft Defender'; Root = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions' },
        @{ Name = 'Defender (policy)'; Root = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' },
        @{ Name = 'Security Essentials'; Root = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions' },
        @{ Name = 'Security Essentials (policy)'; Root = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Exclusions' }
    )
    $seen = @{}
    $mp = $null
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) { try { $mp = Get-MpPreference -ErrorAction Stop } catch {} }
    if ($mp) {
        foreach ($pair in @(@('Paths', 'ExclusionPath'), @('Processes', 'ExclusionProcess'), @('Extensions', 'ExclusionExtension'))) {
            foreach ($x in @($mp.($pair[1]))) { if ($x) { $seen["Microsoft Defender|$($pair[0])|$x"] = @{ Src = 'Microsoft Defender'; Kind = $pair[0]; Value = $x; Param = $pair[1]; Key = '' } } }
        }
    }
    foreach ($s in $sources) {
        foreach ($kind in 'Paths', 'Processes', 'Extensions') {
            $item = Get-Item -LiteralPath "Registry::$($s.Root)\$kind" -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($n in $item.GetValueNames()) {
                if (-not $n) { continue }
                $k = "$($s.Name)|$kind|$n"
                if ($s.Name -eq 'Microsoft Defender' -and $seen.ContainsKey($k)) { $seen[$k].Key = "$($s.Root)\$kind"; continue }
                $seen[$k] = @{ Src = $s.Name; Kind = $kind; Value = $n; Param = ''; Key = "$($s.Root)\$kind" }
            }
        }
    }
    foreach ($e in $seen.Values) {
        $v = $e.Value
        $bad = (Test-UserWritablePath $v) -or ($v -match '^[A-Za-z]:\\?$') -or ($v -eq '*') -or ($e.Kind -eq 'Extensions' -and $v.TrimStart('.') -in 'exe', 'dll', 'ps1', 'bat', 'vbs', 'js', 'scr')
        $sbx = if ($e.Param) {
            { param($D) $p = @{ $D.Param = $D.Value }; Remove-MpPreference @p -ErrorAction Stop; "Removed $($D.Src) exclusion $($D.Value)" }
        } else {
            { param($D) Remove-RegValueSafe -Key $D.Key -Name $D.Value }
        }
        Add-Finding -Category 'Antivirus' -Severity $(if ($bad) { 'HIGH' } else { 'MEDIUM' }) -Title "$($e.Src) scan exclusion ($($e.Kind.TrimEnd('s').ToLower())): $v" `
            -Detail 'Files matching this are never scanned. Attackers add exclusions so their remote tool is never detected. Remove unless you know why it is there.' `
            -Evidence ([ordered]@{ 'Antivirus' = $e.Src; 'Type' = $e.Kind; 'Excluded' = $v; 'Registry' = $e.Key }) -Key "avx|$($e.Src)|$($e.Kind)|$v" `
            -Actions @(New-FixAction -Label 'Remove exclusion' -Description "Removes the $($e.Src) exclusion '$v'. (Tamper Protection may block this - then remove it in the antivirus settings.)" -Data $e -Script $sbx)
    }

    # Defender live status (Windows 8+)
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $ms = Get-MpComputerStatus -ErrorAction Stop
            if ($ms.PSObject.Properties['RealTimeProtectionEnabled'] -and -not $ms.RealTimeProtectionEnabled -and $ms.AMServiceEnabled) {
                Add-Finding -Category 'Antivirus' -Severity 'HIGH' -Title 'Microsoft Defender real-time protection is OFF' -Detail 'Defender is not scanning files as they are opened.' -Key 'mp|rtp' -Actions @(
                    New-FixAction -Label 'Turn on' -Description 'Set-MpPreference -DisableRealtimeMonitoring $false' -Script { param($D) Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; 'Real-time protection turned on' })
            }
        } catch {}
    }
}

function Scan-WmiPersistence {
    $consumers = @()
    try { $consumers = @(Get-WmiObject -Namespace 'root\subscription' -Class __EventConsumer -ErrorAction Stop) } catch { Add-ScanNote "WMI: could not read root\subscription ($($_.Exception.Message))."; return }
    foreach ($c in $consumers) {
        $action = if ($c.CommandLineTemplate) { [string]$c.CommandLineTemplate } elseif ($c.ExecutablePath) { [string]$c.ExecutablePath } elseif ($c.ScriptText) { 'Script: ' + (([string]$c.ScriptText) -replace '\s+', ' ') } else { '' }
        if (-not $action) { continue }
        if ($c.Name -match '^(SCM Event Log Consumer|BVTConsumer)$') { continue }
        $kw = Get-KeywordHit $action
        $bad = (Test-UserWritablePath $action) -or ($action -match $SuspiciousCmdRegex) -or ($action -match '(?i)powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32')
        Add-Finding -Category 'Backdoors' -Severity $(if ($kw -or $bad) { 'HIGH' } else { 'MEDIUM' }) -Title "WMI event subscription runs code: $($c.Name)" `
            -Detail 'Fileless persistence: Windows runs this automatically on an event (boot, logon, timer) with SYSTEM rights, without any file in Startup or Run keys.' `
            -Evidence ([ordered]@{ 'Consumer' = $c.Name; 'Type' = $c.__CLASS; 'Runs' = $action.Substring(0, [Math]::Min(400, $action.Length)) }) -Key "wmi|$($c.Name)" -Actions @(
                New-FixAction -Label 'Remove subscription' -Description "Deletes the WMI consumer '$($c.Name)', its bindings and their event filters." -Data @{ Name = $c.Name } -Script {
                    param($D)
                    $n = 0
                    foreach ($b in @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Consumer -match [regex]::Escape($D.Name) })) {
                        $filterPath = $b.Filter
                        $b.Delete(); $n++
                        try { ([wmi]"\\.\root\subscription:$($filterPath -replace '^.*?:', '')").Delete(); $n++ } catch {}
                    }
                    foreach ($c in @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $D.Name })) { $c.Delete(); $n++ }
                    "Removed $n WMI object(s) for '$($D.Name)'"
                })
    }
}

function Scan-RemoteSettings {
    $ts = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp = Get-ItemProperty -LiteralPath "Registry::$ts" -ErrorAction SilentlyContinue
    $tcp = Get-ItemProperty -LiteralPath "Registry::$ts\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
    if ($rdp -and $rdp.fDenyTSConnections -eq 0) {
        $nla = $tcp.UserAuthentication -eq 1
        $port = if ($tcp.PortNumber) { $tcp.PortNumber } else { 3389 }
        $acts = @(New-FixAction -Label 'Disable RDP' -Description 'Turns Remote Desktop off (fDenyTSConnections=1) and disables the Remote Desktop firewall rules.' -Script {
                    param($D) Backup-RegKey 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
                    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -ErrorAction Stop
                    & netsh.exe advfirewall firewall set rule group="remote desktop" new enable=No 2>&1 | Out-Null
                    'Remote Desktop disabled' })
        if (-not $nla) {
            $acts += New-FixAction -Label 'Require NLA' -Description 'Keeps RDP on but requires Network Level Authentication (password before a session is created).' -Script {
                param($D) Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -ErrorAction Stop; 'NLA required' }
        }
        $members = @(& net.exe localgroup 'Remote Desktop Users' 2>$null | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' })
        Add-Finding -Category 'Remote settings' -Severity $(if (-not $nla) { 'HIGH' } else { 'MEDIUM' }) -Title "Remote Desktop is ON (port $port, NLA $(if ($nla) { 'on' } else { 'OFF' }))" `
            -Detail 'Anyone who knows (or guesses) a password can log in remotely. Turn it off unless the customer uses it.' `
            -Evidence ([ordered]@{ 'Port' = $port; 'Network Level Authentication' = $nla; 'Remote Desktop Users group' = ($members -join ', ') }) -Actions $acts -Key 'rdp'
    }
    $ra = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
    if ($ra -and $ra.fAllowToGetHelp -eq 1) {
        Add-Finding -Category 'Remote settings' -Severity 'LOW' -Title 'Windows Remote Assistance invitations are allowed' `
            -Detail 'Scammers sometimes use Quick Assist / Remote Assistance invitations. Turn it off if the customer does not use it.' -Key 'ra' -Actions @(
                New-FixAction -Label 'Turn off' -Description 'Sets fAllowToGetHelp=0.' -Script { param($D) Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0 -ErrorAction Stop; 'Remote Assistance turned off' })
    }
    $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq 'Running') {
        $listeners = (& winrm.cmd enumerate winrm/config/listener 2>$null | Select-String 'Transport|Port' | ForEach-Object { $_.Line.Trim() }) -join '; '
        if ($listeners) {
            Add-Finding -Category 'Remote settings' -Severity 'MEDIUM' -Title 'PowerShell remoting (WinRM) is enabled' `
                -Detail 'Allows remote command execution with an admin password. Rare on home PCs; leave it only if your RMM needs it.' `
                -Evidence ([ordered]@{ 'Listeners' = $listeners }) -Key 'winrm' -Actions @(Act-DisableService 'WinRM')
        }
    }
}

function Scan-Accounts {
    $hiddenKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    $hidden = Get-Item -LiteralPath "Registry::$hiddenKey" -ErrorAction SilentlyContinue
    $admins = @()
    try {
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
        $admins = @($grp.psbase.Invoke('Members') | ForEach-Object { "$(([ADSI]$_).Name)" } | Where-Object { $_ })
    } catch {}
    foreach ($u in (Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue)) {
        if ($u.Disabled -or $u.Name -like '*$') { continue }
        $isAdmin = $admins -contains $u.Name
        $age = $null
        try { $age = [int](([ADSI]"WinNT://$env:COMPUTERNAME/$($u.Name),user").PasswordAge.Value / 86400) } catch {}
        if ($hidden -and ($hidden.GetValueNames() -contains $u.Name) -and $hidden.GetValue($u.Name) -eq 0) {
            Add-Finding -Category 'Accounts' -Severity $(if ($isAdmin) { 'HIGH' } else { 'MEDIUM' }) -Title "Hidden user account: $($u.Name)$(if ($isAdmin) { ' (administrator)' })" `
                -Detail 'This account is hidden from the Windows login screen. Attackers create hidden admin accounts to get back in. (Some tools, e.g. OpenSSH 1.0, create a hidden service account - check before disabling.)' `
                -Evidence ([ordered]@{ 'Account' = $u.Name; 'Administrator' = $isAdmin; 'Password age (days)' = $age }) -Key "hidden|$($u.Name)" -Actions @(
                    New-FixAction -Label 'Disable account' -Description "net user $($u.Name) /active:no" -Data @{ Name = $u.Name } -Script { param($D) $o = & net.exe user $D.Name /active:no 2>&1; if ($LASTEXITCODE -ne 0) { throw ($o | Out-String).Trim() }; "Disabled account $($D.Name)" })
        } elseif ($u.Name -eq 'Guest' -or $u.SID -like '*-501') {
            Add-Finding -Category 'Accounts' -Severity 'MEDIUM' -Title 'The Guest account is enabled' -Detail 'Anyone can log in without a password.' -Key 'guest' -Actions @(
                New-FixAction -Label 'Disable Guest' -Description "net user $($u.Name) /active:no" -Data @{ Name = $u.Name } -Script { param($D) & net.exe user $D.Name /active:no 2>&1 | Out-Null; "Disabled $($D.Name)" })
        } elseif ($isAdmin -and $null -ne $age -and $age -le 14) {
            Add-Finding -Category 'Accounts' -Severity 'LOW' -Title "Administrator account created or password changed recently: $($u.Name) ($age days ago)" `
                -Detail 'Scammers sometimes add an admin account or change the password. Confirm with the customer.' `
                -Evidence ([ordered]@{ 'Account' = $u.Name; 'Password age (days)' = $age }) -Key "newadmin|$($u.Name)"
        }
    }
    if ($admins.Count) {
        Add-Finding -Category 'Accounts' -Severity 'INFO' -Title "Local administrators: $($admins -join ', ')" -Detail 'For reference: every account that can change anything on this PC.' -Key 'admins'
    }
}

function Scan-NetworkConfig {
    foreach ($h in (Get-UserHives)) {
        $k = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $p = Get-ItemProperty -LiteralPath "Registry::$k" -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        if (($p.ProxyEnable -eq 1 -and $p.ProxyServer) -or $p.AutoConfigURL) {
            Add-Finding -Category 'Network settings' -Severity 'MEDIUM' -Title "Web proxy configured for $($h.User)" `
                -Detail 'All web traffic of this user goes through this proxy / PAC script. Malware and scammers use this to intercept banking sessions. Remove unless the customer uses a proxy on purpose.' `
                -Evidence ([ordered]@{ 'User' = $h.User; 'ProxyServer' = $(if ($p.ProxyEnable -eq 1) { $p.ProxyServer }); 'AutoConfigURL (PAC)' = $p.AutoConfigURL }) -Key "proxy|$($h.Sid)" -Actions @(
                    New-FixAction -Label 'Remove proxy' -Description 'Sets ProxyEnable=0 and removes ProxyServer / AutoConfigURL for this user (key exported first).' -Data @{ Key = $k } -Script {
                        param($D) Backup-RegKey $D.Key; $ps = "Registry::$($D.Key)"
                        Set-ItemProperty -LiteralPath $ps -Name ProxyEnable -Value 0 -ErrorAction Stop
                        Remove-ItemProperty -LiteralPath $ps -Name ProxyServer, AutoConfigURL -ErrorAction SilentlyContinue
                        'Proxy settings removed' })
        }
    }
    $wh = (& netsh.exe winhttp show proxy 2>$null) -join ' '
    if ($wh -match 'Proxy Server\(s\)\s*:\s*(\S+)') {
        Add-Finding -Category 'Network settings' -Severity 'LOW' -Title "System (WinHTTP) proxy set: $($matches[1])" -Detail 'Windows services send traffic through this proxy.' -Key 'winhttp' -Actions @(
            New-FixAction -Label 'Reset' -Description 'netsh winhttp reset proxy' -Script { param($D) (& netsh.exe winhttp reset proxy 2>&1 | Out-String).Trim() })
    }
    $hosts = "$env:windir\System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hosts) {
        $entries = @(Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ -and $_ -notmatch '^(127\.0\.0\.1|::1)\s+localhost$' })
        if ($entries.Count) {
            $sensitive = @($entries | Where-Object { $_ -match '(?i)microsoft|windowsupdate|google|bank|paypal|chase|wellsfargo|citi|amazon|apple|norton|mcafee|avast|malwarebytes|kaspersky|eset|bitdefender|avg' -and $_ -notmatch '^(0\.0\.0\.0|127\.0\.0\.1)\s' })
            Add-Finding -Category 'Network settings' -Severity $(if ($sensitive.Count) { 'HIGH' } else { 'LOW' }) -Title "Hosts file has $($entries.Count) custom entr$(if ($entries.Count -eq 1) { 'y' } else { 'ies' })" `
                -Detail $(if ($sensitive.Count) { 'Some entries redirect bank / security / Microsoft sites to other addresses - classic hijack.' } else { 'Custom name overrides (often ad-blocking). Reset if unexpected.' }) `
                -Evidence ([ordered]@{ 'Entries' = (($entries | Select-Object -First 15) -join ' | ') }) -Key 'hosts' -Actions @(
                    New-FixAction -Label 'Reset hosts file' -Description 'Backs up the hosts file and writes a default one.' -Script {
                        param($D) New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
                        $h = "$env:windir\System32\drivers\etc\hosts"
                        Copy-Item -LiteralPath $h -Destination (Join-Path $BackupDir 'hosts') -Force
                        Set-Content -LiteralPath $h -Value "# Default hosts file (reset by Remote Access Audit)`r`n127.0.0.1       localhost`r`n::1             localhost" -Encoding ASCII -ErrorAction Stop
                        'Hosts file reset (backup saved)' })
        }
    }
}

# ---------------------------------------------------------------------------
#  Scan runner
# ---------------------------------------------------------------------------
$ScanDefs = @(
    @{ Name = 'Running programs';           Fn = 'Scan-Processes' },
    @{ Name = 'Services';                   Fn = 'Scan-Services' },
    @{ Name = 'Installed programs';         Fn = 'Scan-InstalledPrograms' },
    @{ Name = 'Network connections';        Fn = 'Scan-Network' },
    @{ Name = 'Scheduled tasks';            Fn = 'Scan-ScheduledTasks' },
    @{ Name = 'Startup registry + backdoors'; Fn = 'Scan-Autoruns' },
    @{ Name = 'Startup folders';            Fn = 'Scan-StartupFolders' },
    @{ Name = 'Remote tool folders';        Fn = 'Scan-RemoteToolFiles' },
    @{ Name = 'User folders (deep scan)';   Fn = 'Scan-UserFiles' },
    @{ Name = 'Antivirus + exclusions';     Fn = 'Scan-Antivirus' },
    @{ Name = 'WMI persistence';            Fn = 'Scan-WmiPersistence' },
    @{ Name = 'RDP / remote settings';      Fn = 'Scan-RemoteSettings' },
    @{ Name = 'User accounts';              Fn = 'Scan-Accounts' },
    @{ Name = 'Proxy / hosts file';         Fn = 'Scan-NetworkConfig' }
)

function Invoke-AllScans {
    param([scriptblock]$OnProgress)
    $script:Findings.Clear(); $script:FindingKeys = @{}; $script:ScanResults.Clear(); $script:ScanNotes.Clear(); $script:EnumErrors = 0
    $script:ScanTime = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $script:TrustCache = @{}   # files may have been quarantined/replaced since the last pass
    Reset-OwnRustDesk
    Update-ProcessTable
    $i = 0
    foreach ($s in $ScanDefs) {
        $i++
        $label = "[{0}/{1}] {2}" -f $i, $ScanDefs.Count, $s.Name
        if ($OnProgress) { & $OnProgress $label }
        Write-Host "  $label..." -ForegroundColor Yellow -NoNewline
        $before = $script:Findings.Count; $notesBefore = $script:ScanNotes.Count
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $err = ''
        try { & $s.Fn } catch { $err = $_.Exception.Message; Write-Log "Scan '$($s.Name)' failed: $err" -Level ERROR -Quiet }
        $sw.Stop()
        $n = $script:Findings.Count - $before
        $notes = @(); for ($j = $notesBefore; $j -lt $script:ScanNotes.Count; $j++) { $notes += $script:ScanNotes[$j] }
        [void]$script:ScanResults.Add([pscustomobject]@{ Name = $s.Name; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1); Found = $n; Error = $err; Notes = ($notes -join ' ') })
        $col = if ($err) { 'Red' } elseif ($n) { 'Cyan' } else { 'DarkGray' }
        Write-Host (" {0} found ({1}s){2}" -f $n, [Math]::Round($sw.Elapsed.TotalSeconds, 1), $(if ($err) { " ERROR: $err" })) -ForegroundColor $col
    }
}

function Get-Risk {
    $open = @($script:Findings | Where-Object { $_.Status -ne 'Fixed' -and $_.Severity -ne 'INFO' })
    if ($open | Where-Object { $_.Severity -eq 'HIGH' }) { return 'HIGH' }
    if ($open | Where-Object { $_.Severity -eq 'MEDIUM' }) { return 'MEDIUM' }
    if ($open) { return 'LOW' }
    return 'CLEAN'
}

function Invoke-FindingAction {
    # Runs one fix in-process (the audit is already elevated) and records the result.
    param($Finding, $Action)
    $msg = ''
    try {
        $out = & $Action.Script $Action.Data
        $msg = (@($out) | Where-Object { $_ } | ForEach-Object { "$_" }) -join ' | '
        if (-not $msg) { $msg = 'Done' }
        $Finding.Status = if ($msg -like 'PARTIAL*') { 'Partial' } else { 'Fixed' }
        Write-Log "FIX OK  [$($Finding.Title)] $($Action.Label): $msg" -Level OK -Quiet
    } catch {
        $msg = $_.Exception.Message
        $Finding.Status = 'Failed'
        Write-Log "FIX FAIL [$($Finding.Title)] $($Action.Label): $msg" -Level ERROR -Quiet
    }
    $Finding.Result = "$($Action.Label): $msg"
    [void]$script:ActionLog.Add([pscustomobject]@{ Time = (Get-Date -Format 'HH:mm:ss'); Finding = $Finding.Title; Action = $Action.Label; Status = $Finding.Status; Result = $msg })
}

# ---------------------------------------------------------------------------
#  Report (HTML + JSON)
# ---------------------------------------------------------------------------
function Esc([string]$s) { if (-not $s) { return '' }; return [System.Security.SecurityElement]::Escape($s) }

function Get-ShortResult([string]$Result) {
    # "Label: long message -> quarantine path (backup in ...)" -> short, printable
    $r = $Result -replace '^[^:]{1,40}:\s*', ''
    $r = $r -replace '\s*->\s*C:\\ProgramData\\NerdyNeighbor[^|]*', '' -replace '\s*\((backup|XML backup)[^)]*\)', '' -replace 'HKEY_USERS\\S-1-5-21-[\d-]+', 'HKCU' -replace 'HKEY_LOCAL_MACHINE', 'HKLM'
    $r = $r -replace '(Quarantined|Deleted) \S:\\(?:[^|]*\\)?([^\\|]+?)(\s*\(|\s*\||$)', '$1 $2$3'
    $r = $r -replace '(HK[A-Z]+)\\\S*\\([^\\\s|]+)', '$1\...\$2'
    $r = ($r -replace '\s+', ' ').Trim()
    if ($r.Length -gt 120) { $r = $r.Substring(0, 117) + '...' }
    return $r
}

function Save-Report {
    param([string]$Computer = $env:COMPUTERNAME, [string]$OsName = '', [string]$ScanTime = '', [string]$RunBy = "$env:USERDOMAIN\$env:USERNAME", [string]$BaseName = '')
    $risk = Get-Risk
    if (-not $OsName) {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
        $OsName = if ($os) { "$($os.Caption.Trim()) $($os.OSArchitecture) (build $($os.BuildNumber))" } else { 'Windows' }
    }
    $osName = $OsName
    if (-not $ScanTime) { $ScanTime = if ($script:ScanTime) { $script:ScanTime } else { Get-Date -Format 'yyyy-MM-dd HH:mm' } }
    $riskColor = @{ HIGH = '#dc2626'; MEDIUM = '#ea580c'; LOW = '#2563eb'; CLEAN = '#16a34a' }[$risk]
    $sevColor = @{ HIGH = '#dc2626'; MEDIUM = '#ea580c'; LOW = '#2563eb'; INFO = '#64748b' }
    $counts = @{}; foreach ($s in 'HIGH', 'MEDIUM', 'LOW', 'INFO') { $counts[$s] = @($script:Findings | Where-Object { $_.Severity -eq $s }).Count }
    $fixed = @($script:Findings | Where-Object { $_.Status -eq 'Fixed' }).Count
    $sb = New-Object System.Text.StringBuilder
    $css = @'
*{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}.hdr{background:#0f172a;color:#fff;border-radius:12px;padding:24px 28px}
.hdr h1{margin:0 0 4px;font-size:22px}.hdr .sub{opacity:.7;font-size:13px}.meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
.m{background:rgba(255,255,255,.08);border-radius:8px;padding:8px 12px;font-size:12px}.m b{display:block;font-size:14px}
.risk{margin:16px 0;border-radius:10px;padding:14px 18px;color:#fff;font-weight:600}.card{background:#fff;border-radius:10px;padding:16px 20px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.f{border-left:5px solid #64748b;padding:10px 14px;margin:8px 0;background:#fff;border-radius:6px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.f h3{margin:0;font-size:14px}.sev{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;margin-right:6px}
.st{float:right;font-size:12px;font-weight:600}.d{font-size:13px;color:#334155;margin:4px 0}table{border-collapse:collapse;width:100%;font-size:12px}
td,th{text-align:left;padding:4px 8px;border-bottom:1px solid #e2e8f0;vertical-align:top;word-break:break-word}th{background:#f8fafc}
h2{font-size:16px;margin:22px 0 6px}.ev td:first-child{white-space:nowrap;color:#64748b;width:170px}.small{font-size:12px;color:#64748b}
.pbtn{float:right;background:#fff;color:#0f172a;border:0;border-radius:6px;padding:7px 14px;font-weight:600;cursor:pointer}
.print{display:none}
@media print{
 @page{size:letter portrait;margin:11mm}
 body{background:#fff;color:#000;font-size:12.5px;line-height:1.4;-webkit-print-color-adjust:exact;print-color-adjust:exact}
 .screen{display:none}.print{display:block}
 .ph{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:3px solid #000;padding-bottom:5px}
 .ph .t{font-size:24px;font-weight:700}.ph .s{font-size:12px;margin-top:3px}.ph .b{text-align:right;font-size:12px}
 .res{border:3px solid #000;border-radius:5px;padding:10px 14px;margin:14px 0;font-size:14px}.res b{font-size:17px}
 h3{font-size:12.5px;text-transform:uppercase;letter-spacing:.6px;border-bottom:2px solid #000;margin:16px 0 6px;padding-bottom:3px}
 table.pt{width:100%;border-collapse:collapse;font-size:12px}table.pt th{text-align:left;border-bottom:2px solid #000;padding:5px 6px;background:#fff}
 table.pt td{border-bottom:1px solid #888;padding:6px 6px;vertical-align:top;background:#fff}
 .lv{display:inline-block;border:1.5px solid #000;border-radius:2px;padding:1px 6px;font-size:10px;font-weight:700;white-space:nowrap}
 .lv.HIGH{background:#000;color:#fff}.lv.LOW{border-style:dashed}.lv.INFO{border-style:dotted}
 .ok{font-weight:700}.chk{display:grid;grid-template-columns:1fr 1fr 1fr;gap:3px 16px;font-size:11.5px}
 .pf{margin-top:18px;border-top:1px solid #000;padding-top:6px;font-size:10px;text-align:center}.ref{font-size:11px;margin-top:8px}
}
'@
    [void]$sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>Remote Access Audit - $(Esc $Computer)</title><style>$css</style></head><body><div class='wrap'>")
    [void]$sb.Append("<div class='screen'><div class='hdr'><button class='pbtn' onclick='window.print()'>Print (1 page)</button><h1>Remote Access Audit</h1><div class='sub'>Nerdy Neighbor &middot; v$RAA_Version</div><div class='meta'>")
    foreach ($m in @(@('Computer', $Computer), @('Windows', $osName), @('Scanned', $ScanTime), @('Findings', "$($counts.HIGH) high / $($counts.MEDIUM) medium / $($counts.LOW) low"), @('Fixed', $fixed))) {
        [void]$sb.Append("<div class='m'>$(Esc $m[0])<b>$(Esc ([string]$m[1]))</b></div>")
    }
    $riskMsg = @{ HIGH = 'High risk: remote-access tools or backdoors that need attention.'; MEDIUM = 'Items worth reviewing with the customer.'; LOW = 'Only low-level items found.'; CLEAN = 'No remote-access indicators found.' }[$risk]
    [void]$sb.Append("</div></div><div class='risk' style='background:$riskColor'>Risk: $risk &mdash; $riskMsg (open items only; fixed items excluded)</div>")

    $order = @{ HIGH = 0; MEDIUM = 1; LOW = 2; INFO = 3 }
    foreach ($grp in ($script:Findings | Sort-Object { $order[$_.Severity] }, Category | Group-Object Category)) {
        [void]$sb.Append("<h2>$(Esc $grp.Name) ($($grp.Count))</h2>")
        foreach ($f in $grp.Group) {
            $c = $sevColor[$f.Severity]
            $stColor = switch ($f.Status) { 'Fixed' { '#16a34a' } 'Failed' { '#dc2626' } 'Partial' { '#d97706' } default { '#64748b' } }
            $stText = if ($f.Status -ne 'Open') { $f.Status } elseif ($f.Severity -eq 'INFO') { '' } else { 'Not fixed' }
            [void]$sb.Append("<div class='f' style='border-left-color:$c'><span class='st' style='color:$stColor'>$(Esc $stText)</span><h3><span class='sev' style='background:$c'>$($f.Severity)</span>$(Esc $f.Title)</h3><div class='d'>$(Esc $f.Detail)</div>")
            if ($f.Evidence.Count) {
                [void]$sb.Append("<table class='ev'>")
                foreach ($k in $f.Evidence.Keys) { [void]$sb.Append("<tr><td>$(Esc $k)</td><td>$(Esc $f.Evidence[$k])</td></tr>") }
                [void]$sb.Append('</table>')
            }
            if ($f.Result) { [void]$sb.Append("<div class='d'><b>Result:</b> $(Esc $f.Result)</div>") }
            elseif ($f.Actions.Count) { [void]$sb.Append("<div class='small'>Available fixes: $(Esc (($f.Actions | ForEach-Object { $_.Label }) -join ', '))</div>") }
            [void]$sb.Append('</div>')
        }
    }
    if (-not $script:Findings.Count) { [void]$sb.Append("<div class='card'>No findings.</div>") }

    if ($script:ActionLog.Count) {
        [void]$sb.Append("<h2>Actions taken</h2><div class='card'><table><tr><th>Time</th><th>Finding</th><th>Action</th><th>Status</th><th>Result</th></tr>")
        foreach ($a in $script:ActionLog) { [void]$sb.Append("<tr><td>$($a.Time)</td><td>$(Esc $a.Finding)</td><td>$(Esc $a.Action)</td><td>$(Esc $a.Status)</td><td>$(Esc $a.Result)</td></tr>") }
        [void]$sb.Append("</table><p class='small'>Quarantine: $(Esc $QuarantineDir)<br>Registry backups: $(Esc $BackupDir)</p></div>")
    }
    [void]$sb.Append("<h2>Scan coverage</h2><div class='card'><table><tr><th>Check</th><th>Found</th><th>Time</th><th>Notes</th></tr>")
    foreach ($r in $script:ScanResults) {
        $note = @($r.Notes, $(if ($r.Error) { "ERROR: $($r.Error)" })) | Where-Object { $_ }
        [void]$sb.Append("<tr><td>$(Esc $r.Name)</td><td>$($r.Found)</td><td>$($r.Seconds)s</td><td>$(Esc ($note -join ' '))</td></tr>")
    }
    [void]$sb.Append("</table><p class='small'>Trusted tools (reported as INFO): $(Esc ($TrustList -join ', ')). Run by $(Esc $RunBy).</p></div></div></div>")

    # ---- one-page, black-and-white print summary (shown only when printing) ----
    $issues = @($script:Findings | Where-Object { $_.Severity -ne 'INFO' } | Sort-Object { $order[$_.Severity] }, Category, Title)
    $info = @($script:Findings | Where-Object { $_.Severity -eq 'INFO' })
    $nFixed = @($issues | Where-Object { $_.Status -eq 'Fixed' }).Count
    $nOpen = @($issues | Where-Object { $_.Status -ne 'Fixed' }).Count
    $verdict = @{ HIGH = 'HIGH RISK - remote-access tools or backdoors still need attention.'; MEDIUM = 'Items still need review.'; LOW = 'Only minor items remain.'; CLEAN = 'No remote-access threats remain on this computer.' }[$risk]
    [void]$sb.Append("<div class='print'><div class='ph'><div><div class='t'>Remote Access Audit</div><div class='s'>$(Esc $Computer) &middot; $(Esc $osName) &middot; scanned $(Esc $ScanTime)</div></div><div class='b'><b>Nerdy Neighbor</b><br>audit.nerdyneighbor.net</div></div>")
    [void]$sb.Append("<div class='res'><b>Result: $risk</b> &mdash; $verdict<br>$($issues.Count) issue$(if ($issues.Count -ne 1) { 's' }) found &middot; <b>$nFixed fixed</b> &middot; $nOpen still open &middot; 14 checks run</div>")
    [void]$sb.Append('<h3>Findings</h3>')
    if ($issues.Count) {
        [void]$sb.Append("<table class='pt'><tr><th style='width:58px'>Level</th><th>What was found</th><th style='width:42%'>Result</th></tr>")
        foreach ($f in $issues) {
            $res = switch ($f.Status) {
                'Fixed'   { "<span class='ok'>&#10003; Fixed</span> &mdash; $(Esc (Get-ShortResult $f.Result))" }
                'Partial' { "<span class='ok'>Partly fixed</span> &mdash; $(Esc (Get-ShortResult $f.Result))" }
                'Failed'  { "<b>NOT FIXED</b> &mdash; $(Esc (Get-ShortResult $f.Result))" }
                default   { '<b>Not fixed</b> &mdash; review with technician' }
            }
            [void]$sb.Append("<tr><td><span class='lv $($f.Severity)'>$($f.Severity)</span></td><td>$(Esc $f.Title)</td><td>$res</td></tr>")
        }
        [void]$sb.Append('</table>')
    } else { [void]$sb.Append('<div>No issues found.</div>') }
    if ($info.Count) { [void]$sb.Append("<div class='ref'><b>For reference (not a problem):</b> $(Esc (($info | ForEach-Object { $_.Title }) -join '; ')).</div>") }
    [void]$sb.Append("<h3>What was checked</h3><div class='chk'>")
    foreach ($r in $script:ScanResults) {
        [void]$sb.Append("<div>&#10003; $(Esc $r.Name)$(if ($r.Error) { ' (error)' })</div>")
    }
    [void]$sb.Append('</div>')
    [void]$sb.Append("<div class='pf'>Removed files are kept in quarantine (not deleted) and registry changes were backed up first: C:\ProgramData\NerdyNeighbor\RemoteAccessAudit. Run by $(Esc $RunBy) &middot; Remote Access Audit v$RAA_Version</div></div></body></html>")

    $base = if ($BaseName) { $BaseName } else { Join-Path $OutDir "RemoteAccessAudit_$($Computer)_$RunStamp" }
    [IO.File]::WriteAllText("$base.html", $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    $json = [pscustomobject]@{
        Computer = $Computer; Windows = $osName; Version = $RAA_Version; Scanned = $ScanTime; Risk = $risk
        Findings = @($script:Findings | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Category = $_.Category; Title = $_.Title; Detail = $_.Detail; Evidence = $_.Evidence; Status = $_.Status; Result = $_.Result; Fixes = @($_.Actions | ForEach-Object { $_.Label }) } })
        Actions = @($script:ActionLog); Coverage = @($script:ScanResults)
    }
    [IO.File]::WriteAllText("$base.json", ($json | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    return "$base.html"
}

# ===========================================================================
#  GUI (WPF)
# ===========================================================================
function New-Brush([string]$Hex) { return New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($Hex)) }
function New-Thick([double]$l, [double]$t, [double]$r, [double]$b) { return New-Object System.Windows.Thickness($l, $t, $r, $b) }

# --- window helpers (script scope so WPF event handlers can always see them) ---
function Set-Status {
    param([string]$Text)
    $script:UI.tbStatus.Text = $Text
    $script:Window.Dispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Update-Header {
    $risk = Get-Risk
    $script:UI.tbRisk.Text = $risk
    $script:UI.bdRisk.Background = New-Brush (@{ HIGH = '#dc2626'; MEDIUM = '#ea580c'; LOW = '#2563eb'; CLEAN = '#16a34a' }[$risk])
    $open = @($script:Findings | Where-Object { $_.Status -notin 'Fixed' })
    $script:UI.tbCounts.Text = '{0} / {1} / {2}' -f @($open | Where-Object { $_.Severity -eq 'HIGH' }).Count, @($open | Where-Object { $_.Severity -eq 'MEDIUM' }).Count, @($open | Where-Object { $_.Severity -eq 'LOW' }).Count
    $script:UI.btnFixHigh.IsEnabled = [bool](@($open | Where-Object { $_.Severity -eq 'HIGH' -and $_.Actions.Count -and $_.Status -eq 'Open' }).Count)
}

function Update-Card {
    param($f)
    $c = $script:CardUi[$f.Id]
    if (-not $c) { return }
    $color = switch ($f.Status) { 'Fixed' { '#4ade80' } 'Failed' { '#f87171' } 'Partial' { '#fbbf24' } default { '#94a3b8' } }
    $c.Status.Text = $(if ($f.Status -eq 'Open') { '' } else { "$($f.Status.ToUpper()): $($f.Result)" })
    $c.Status.Foreground = New-Brush $color
    $c.Status.Visibility = $(if ($f.Status -eq 'Open') { 'Collapsed' } else { 'Visible' })
    if ($f.Status -eq 'Fixed') { foreach ($b in $c.Buttons) { $b.IsEnabled = $false }; $c.Card.Opacity = 0.6 }
}

function Invoke-CardAction {
    param($f, $a, [bool]$Confirm)
    if ($Confirm) {
        $r = [System.Windows.MessageBox]::Show("$($a.Label): $($f.Title)`n`n$($a.Description)`n`nContinue?", 'Confirm fix', 'YesNo', 'Warning')
        if ($r -ne 'Yes') { return }
    }
    $script:Window.Cursor = [System.Windows.Input.Cursors]::Wait
    Set-Status "Working: $($a.Label) - $($f.Title) ..."
    Invoke-FindingAction $f $a
    $script:Window.Cursor = $null
    Update-Card $f
    Update-Header
    Set-Status "$($f.Status): $($f.Result)"
}

function Build-List {
    $sp = $script:UI.spList
    $sp.Children.Clear()
    $script:CardUi = @{}
    $filter = $script:UI.cbFilter.SelectedIndex
    $order = @{ HIGH = 0; MEDIUM = 1; LOW = 2; INFO = 3 }
    $items = @($script:Findings | Where-Object {
        $x = $_   # inside a switch, $_ is the switch value - keep the finding in $x
        switch ($filter) { 0 { $x.Severity -ne 'INFO' -or $x.Status -ne 'Open' } 1 { $true } 2 { $x.Severity -eq 'HIGH' } 3 { $x.Status -ne 'Open' } }
    })
    # one block per category, most severe category first
    $catRank = @{}
    foreach ($x in $items) { $r = $order[$x.Severity]; if (-not $catRank.ContainsKey($x.Category) -or $r -lt $catRank[$x.Category]) { $catRank[$x.Category] = $r } }
    $items = @($items | Sort-Object { $catRank[$_.Category] }, Category, { $order[$_.Severity] }, Title)
    if (-not $items.Count) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = $(if ($script:Findings.Count) { 'Nothing to show with this filter.' } else { 'No remote-access indicators found. This PC looks clean.' })
        $tb.Foreground = New-Brush '#4ade80'; $tb.FontSize = 15; $tb.Margin = New-Thick 6 20 6 6
        [void]$sp.Children.Add($tb)
        return
    }
    $sevHex = @{ HIGH = '#dc2626'; MEDIUM = '#ea580c'; LOW = '#2563eb'; INFO = '#64748b' }
    $lastCat = ''
    foreach ($f in $items) {
        if ($f.Category -ne $lastCat) {
            $h = New-Object System.Windows.Controls.TextBlock
            $h.Text = $f.Category.ToUpper(); $h.Foreground = New-Brush '#94a3b8'; $h.FontWeight = 'Bold'; $h.FontSize = 11; $h.Margin = New-Thick 2 12 0 4
            [void]$sp.Children.Add($h); $lastCat = $f.Category
        }
        $card = New-Object System.Windows.Controls.Border
        $card.Background = New-Brush '#1e293b'; $card.CornerRadius = New-Object System.Windows.CornerRadius 6
        $card.Margin = New-Thick 0 3 0 3; $card.Padding = New-Thick 0 0 12 0
        $card.BorderBrush = New-Brush $sevHex[$f.Severity]; $card.BorderThickness = New-Thick 5 0 0 0
        $dock = New-Object System.Windows.Controls.DockPanel
        $dock.Margin = New-Thick 12 10 0 10
        $btnPanel = New-Object System.Windows.Controls.StackPanel
        $btnPanel.VerticalAlignment = 'Top'; $btnPanel.Margin = New-Thick 10 0 0 0
        [System.Windows.Controls.DockPanel]::SetDock($btnPanel, 'Right')
        $buttons = @()
        for ($i = 0; $i -lt $f.Actions.Count; $i++) {
            $b = New-Object System.Windows.Controls.Button
            $b.Content = $f.Actions[$i].Label; $b.Style = $script:Window.Resources['Btn']; $b.Margin = New-Thick 0 0 0 4
            $b.Background = New-Brush $(if ($i -eq 0) { $sevHex[$f.Severity] } else { '#334155' }); $b.MinWidth = 130
            $b.ToolTip = $f.Actions[$i].Description
            $b.Tag = "$($f.Id)|$i"
            $b.Add_Click({
                $parts = "$($this.Tag)" -split '\|'
                $fx = $script:Findings[[int]$parts[0]]
                Invoke-CardAction $fx $fx.Actions[[int]$parts[1]] $true
            })
            [void]$btnPanel.Children.Add($b); $buttons += $b
        }
        [void]$dock.Children.Add($btnPanel)
        $stack = New-Object System.Windows.Controls.StackPanel
        $title = New-Object System.Windows.Controls.TextBlock
        $title.TextWrapping = 'Wrap'; $title.Foreground = New-Brush '#f8fafc'; $title.FontSize = 14; $title.FontWeight = 'SemiBold'
        $run1 = New-Object System.Windows.Documents.Run (" $($f.Severity) ")
        $run1.Background = New-Brush $sevHex[$f.Severity]; $run1.FontSize = 10; $run1.FontWeight = 'Bold'
        [void]$title.Inlines.Add($run1); [void]$title.Inlines.Add((New-Object System.Windows.Documents.Run ("  " + $f.Title)))
        [void]$stack.Children.Add($title)
        $det = New-Object System.Windows.Controls.TextBlock
        $det.Text = $f.Detail; $det.TextWrapping = 'Wrap'; $det.Foreground = New-Brush '#cbd5e1'; $det.FontSize = 12; $det.Margin = New-Thick 0 4 0 0
        [void]$stack.Children.Add($det)
        if ($f.Manual) {
            $man = New-Object System.Windows.Controls.TextBlock
            $man.Text = "How to fix: $($f.Manual)"; $man.TextWrapping = 'Wrap'; $man.Foreground = New-Brush '#fbbf24'; $man.FontSize = 12; $man.Margin = New-Thick 0 4 0 0
            [void]$stack.Children.Add($man)
        }
        $lines = @()
        foreach ($k in $f.Evidence.Keys) { $lines += ('{0,-22} {1}' -f ($k + ':'), $f.Evidence[$k]) }
        if ($f.Actions.Count) { $lines += ''; foreach ($a in $f.Actions) { $lines += "[$($a.Label)] $($a.Description)" } }
        if ($lines.Count) {
            $exp = New-Object System.Windows.Controls.Expander
            $exp.Header = 'Details'; $exp.Foreground = New-Brush '#94a3b8'; $exp.Margin = New-Thick 0 6 0 0; $exp.FontSize = 11
            $tbx = New-Object System.Windows.Controls.TextBox
            $tbx.Text = ($lines -join "`r`n"); $tbx.IsReadOnly = $true; $tbx.TextWrapping = 'Wrap'; $tbx.FontFamily = 'Consolas'; $tbx.FontSize = 11
            $tbx.Background = New-Brush '#0f172a'; $tbx.Foreground = New-Brush '#cbd5e1'; $tbx.BorderThickness = New-Thick 0 0 0 0; $tbx.Padding = New-Thick 8 6 8 6
            $exp.Content = $tbx
            [void]$stack.Children.Add($exp)
        }
        $st = New-Object System.Windows.Controls.TextBlock
        $st.TextWrapping = 'Wrap'; $st.FontSize = 12; $st.FontWeight = 'SemiBold'; $st.Margin = New-Thick 0 6 0 0; $st.Visibility = 'Collapsed'
        [void]$stack.Children.Add($st)
        [void]$dock.Children.Add($stack)
        $card.Child = $dock
        [void]$sp.Children.Add($card)
        $script:CardUi[$f.Id] = @{ Card = $card; Status = $st; Buttons = $buttons }
        Update-Card $f
    }
}

function Show-AuditWindow {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $esc = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Remote Access Audit - $(& $esc $env:COMPUTERNAME)" Width="1080" Height="760" MinWidth="820" MinHeight="520"
        WindowStartupLocation="CenterScreen" Background="#0f172a" FontFamily="Segoe UI">
  <Window.Resources>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Cursor" Value="Hand"/><Setter Property="Foreground" Value="White"/><Setter Property="Background" Value="#334155"/>
      <Setter Property="FontSize" Value="12"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Padding" Value="12,5"/><Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.85"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.35"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#1e3a5f" Padding="20,14">
      <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="Remote Access Audit" FontSize="21" FontWeight="Bold" Foreground="White"/>
          <TextBlock x:Name="tbSub" FontSize="12" Foreground="#94a3b8" Margin="0,2,0,0"/>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <Border x:Name="bdRisk" CornerRadius="6" Padding="14,6" Margin="0,0,8,0"><StackPanel>
            <TextBlock Text="RISK" FontSize="9" FontWeight="Bold" Foreground="White" HorizontalAlignment="Center"/>
            <TextBlock x:Name="tbRisk" FontSize="16" FontWeight="Bold" Foreground="White" HorizontalAlignment="Center"/></StackPanel></Border>
          <Border Background="#334155" CornerRadius="6" Padding="14,6"><StackPanel>
            <TextBlock Text="HIGH / MED / LOW" FontSize="9" FontWeight="Bold" Foreground="#94a3b8" HorizontalAlignment="Center"/>
            <TextBlock x:Name="tbCounts" FontSize="16" FontWeight="Bold" Foreground="White" HorizontalAlignment="Center"/></StackPanel></Border>
        </StackPanel></Grid>
    </Border>
    <Border DockPanel.Dock="Top" Background="#1e293b" Padding="20,8">
      <DockPanel>
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
          <Button x:Name="btnFixHigh" Content="Fix all HIGH" Style="{StaticResource Btn}" Background="#dc2626"/>
          <Button x:Name="btnRescan" Content="Rescan" Style="{StaticResource Btn}"/>
          <Button x:Name="btnReport" Content="Open report" Style="{StaticResource Btn}"/>
          <Button x:Name="btnQuarantine" Content="Open quarantine" Style="{StaticResource Btn}"/>
          <TextBlock Text="Show:" Foreground="#94a3b8" VerticalAlignment="Center" Margin="8,0,6,0"/>
          <ComboBox x:Name="cbFilter" Width="150" VerticalAlignment="Center" SelectedIndex="0">
            <ComboBoxItem Content="Needs attention"/><ComboBoxItem Content="Everything (incl. INFO)"/><ComboBoxItem Content="HIGH only"/><ComboBoxItem Content="Fixed / failed"/>
          </ComboBox>
        </StackPanel>
        <Button x:Name="btnClose" Content="Close + save report" Style="{StaticResource Btn}" DockPanel.Dock="Right" HorizontalAlignment="Right" Margin="0"/>
      </DockPanel>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="#020617" Padding="20,6">
      <TextBlock x:Name="tbStatus" Foreground="#cbd5e1" FontSize="12" TextTrimming="CharacterEllipsis"/>
    </Border>
    <ScrollViewer x:Name="svList" VerticalScrollBarVisibility="Auto" Padding="16,10"><StackPanel x:Name="spList"/></ScrollViewer>
  </DockPanel>
</Window>
"@
    $window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
    $ui = @{}
    foreach ($n in 'tbSub', 'bdRisk', 'tbRisk', 'tbCounts', 'btnFixHigh', 'btnRescan', 'btnReport', 'btnQuarantine', 'cbFilter', 'btnClose', 'tbStatus', 'spList', 'svList') { $ui[$n] = $window.FindName($n) }
    $script:UI = $ui; $script:Window = $window; $script:CardUi = @{}; $script:LastReport = ''

    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    $ui.tbSub.Text = "$env:COMPUTERNAME  -  $($os.Caption)  -  scanned $(Get-Date -Format 'yyyy-MM-dd HH:mm')  -  v$RAA_Version"

    $ui.cbFilter.Add_SelectionChanged({ Build-List })
    $ui.btnClose.Add_Click({ $script:Window.Close() })
    $ui.btnQuarantine.Add_Click({
        New-Item -ItemType Directory -Path $DataDir -Force -ErrorAction SilentlyContinue | Out-Null
        Start-Process explorer.exe $DataDir
    })
    $ui.btnReport.Add_Click({
        Set-Status 'Saving report...'
        $script:LastReport = Save-Report
        Set-Status "Report saved: $($script:LastReport)"
        Start-Process $script:LastReport
    })
    $ui.btnRescan.Add_Click({
        $script:Window.Cursor = [System.Windows.Input.Cursors]::Wait
        $keepLog = $script:ActionLog.Count
        Invoke-AllScans -OnProgress { param($t) Set-Status "Rescanning: $t ..." }
        $script:Window.Cursor = $null
        Build-List; Update-Header
        Set-Status "Rescan complete: $(@($script:Findings | Where-Object { $_.Severity -ne 'INFO' }).Count) item(s). ($keepLog fix action(s) this session are kept in the report.)"
    })
    $ui.btnFixHigh.Add_Click({
        $todo = @($script:Findings | Where-Object { $_.Severity -eq 'HIGH' -and $_.Status -eq 'Open' -and $_.Actions.Count })
        if (-not $todo.Count) { return }
        $list = ($todo | Select-Object -First 15 | ForEach-Object { "- $($_.Actions[0].Label): $($_.Title)" }) -join "`n"
        $r = [System.Windows.MessageBox]::Show("Run the first (recommended) fix for $($todo.Count) HIGH item(s)?`n`n$list`n`nFiles are quarantined and registry changes backed up, so this can be undone.", 'Fix all HIGH', 'YesNo', 'Warning')
        if ($r -ne 'Yes') { return }
        foreach ($f in $todo) { Invoke-CardAction $f $f.Actions[0] $false }
        Set-Status "Done: $(@($todo | Where-Object { $_.Status -eq 'Fixed' }).Count) fixed, $(@($todo | Where-Object { $_.Status -eq 'Failed' }).Count) failed. Click Rescan to verify."
    })

    Build-List
    Update-Header
    Set-Status "$(@($script:Findings | Where-Object { $_.Severity -ne 'INFO' }).Count) item(s) to review. Each Fix button shows what it will do and asks first. Close the window to save the report."
    if ($script:TestHook) { & $script:TestHook $window; return }
    [void]$window.ShowDialog()
}

# ===========================================================================
#  MAIN
# ===========================================================================
if ($Mode -eq 'lib') { return }

Write-Host ""
Write-Host "  Remote Access Audit v$RAA_Version  (Administrator)" -ForegroundColor Cyan
Write-Host "  Computer: $env:COMPUTERNAME   Mode: $Mode   Trusted: $($TrustList -join ', ')" -ForegroundColor Gray
Write-Host ""
Write-Log "Audit started (v$RAA_Version, mode $Mode) by $env:USERDOMAIN\$env:USERNAME" -Quiet

Invoke-AllScans

$risk = Get-Risk
$cnt = @{}; foreach ($s in 'HIGH', 'MEDIUM', 'LOW', 'INFO') { $cnt[$s] = @($Findings | Where-Object { $_.Severity -eq $s }).Count }
Write-Host ""
Write-Host ("  Risk: {0}   HIGH {1}  MEDIUM {2}  LOW {3}  INFO {4}" -f $risk, $cnt.HIGH, $cnt.MEDIUM, $cnt.LOW, $cnt.INFO) -ForegroundColor $(switch ($risk) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } 'LOW' { 'Cyan' } default { 'Green' } })

$sta = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
if ($Mode -eq 'gui' -and -not $sta) {
    Write-Host "  (This PowerShell window is not in STA mode - the remediation window cannot open. Saving the report only.)" -ForegroundColor Yellow
}
if ($Mode -eq 'gui' -and $sta) {
    Write-Host "  Opening the remediation window..." -ForegroundColor Green
    try { Show-AuditWindow } catch { Write-Log "Remediation window failed: $($_.Exception.Message)" -Level ERROR }
}
$reportPath = Save-Report
Write-Log "Report saved: $reportPath" -Level OK
Write-Log "Audit finished: risk $(Get-Risk), $($Findings.Count) finding(s), $($ActionLog.Count) fix action(s)" -Quiet
if ($Mode -eq 'gui') { try { Start-Process $reportPath } catch {} }
Write-Host ""
