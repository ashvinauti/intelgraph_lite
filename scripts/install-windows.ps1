<#
.SYNOPSIS
    IntelGraph Lite on Windows: watch the devices on this PC's Mobile hotspot.

.DESCRIPTION
    Windows' Mobile hotspot shares this PC's internet over Wi-Fi (clients get 192.168.137.x).
    This script sets IntelGraph Lite up to watch ONLY the devices on that hotspot:

      1. finds Python 3.11+ (installs Python 3.12 with winget if needed)
      2. checks for Wireshark's tshark and the Npcap driver (installs Wireshark with winget)
      3. finds the hotspot's network adapter (the one holding 192.168.137.1)
      4. installs IntelGraph Lite in %LOCALAPPDATA%\IntelGraphLite (its own Python environment)
      5. creates %USERPROFILE%\.iglite\.env with a dashboard token, and asks for your API keys
      6. downloads the popular-site list and Google/CloudFront address ranges
      7. allows the dashboard port through Windows Firewall (local networks only)
      8. starts IntelGraph Lite now and at every log-on, hidden, and adds a desktop shortcut

    The capture runs on the hotspot adapter only, keeps only the first packet of each new
    connection plus DNS and DHCP, and counts only 192.168.137.0/24 as devices. This PC's own
    browsing never goes through that adapter.

.EXAMPLE
    # PowerShell as Administrator, in the intelgraph_lite folder:
    powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -Keys        # change API keys only
    powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Interface,      # the hotspot adapter (default: the one holding 192.168.137.1)
    [int]$Port = 8765,
    [switch]$SkipKeys,       # don't ask for API keys
    [switch]$Keys,           # only (re)enter API keys, then restart
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Repo       = Split-Path -Parent $PSScriptRoot
$App        = Join-Path $env:LOCALAPPDATA 'IntelGraphLite'
$Venv       = Join-Path $App 'venv'
$VenvPy     = Join-Path $Venv 'Scripts\python.exe'
$VenvPyw    = Join-Path $Venv 'Scripts\pythonw.exe'
$Data       = Join-Path $env:USERPROFILE '.iglite'
$EnvFile    = Join-Path $Data '.env'
$TaskName   = 'IntelGraph Lite'
$RuleName   = 'IntelGraph Lite dashboard'
$HotspotIp  = '192.168.137.1'
$HotspotNet = '192.168.137.0/24'
$Shortcut   = Join-Path ([Environment]::GetFolderPath('Desktop')) 'IntelGraph Lite.url'

function Say($Message)  { Write-Host "==> $Message" -ForegroundColor Cyan }
function Warn($Message) { Write-Host "    $Message" -ForegroundColor Yellow }
function Stop-With($Message) { Write-Host ""; Write-Host $Message -ForegroundColor Red; exit 1 }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EnvLines {
    if (Test-Path $EnvFile) { return @(Get-Content -LiteralPath $EnvFile) }
    return @()
}

function Get-EnvValue([string]$Name) {
    foreach ($line in Get-EnvLines) {
        if ($line -match "^\s*$([regex]::Escape($Name))\s*=\s*(.*)$") { return $Matches[1].Trim() }
    }
    return ''
}

function Set-EnvValue([string]$Name, [string]$Value) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $found = $false
    foreach ($line in Get-EnvLines) {
        if ($line -match "^\s*$([regex]::Escape($Name))\s*=") { $lines.Add("$Name=$Value"); $found = $true }
        else { $lines.Add($line) }
    }
    if (-not $found) { $lines.Add("$Name=$Value") }
    Set-Content -LiteralPath $EnvFile -Value $lines -Encoding UTF8
}

function Read-ApiKeys {
    Say 'API keys (all optional: press Enter to skip or keep the current one)'
    Write-Host '    Where to get each one is in INSTALL.md, section 3. Keys are stored only in'
    Write-Host "    $EnvFile"
    $sources = @(
        @{ Name = 'OTX_API_KEY';        Label = 'AlienVault OTX';     Where = 'otx.alienvault.com > your username > Settings > OTX Key' },
        @{ Name = 'VIRUSTOTAL_API_KEY'; Label = 'VirusTotal';         Where = 'virustotal.com > profile picture > API key' },
        @{ Name = 'SHODAN_API_KEY';     Label = 'Shodan';             Where = 'account.shodan.io > API Key' },
        @{ Name = 'ABUSECH_AUTH_KEY';   Label = 'abuse.ch (URLhaus)'; Where = 'auth.abuse.ch > your profile > Auth-Key' },
        @{ Name = 'ANTHROPIC_API_KEY';  Label = 'Anthropic (AI)';     Where = 'console.anthropic.com > API Keys > Create Key' }
    )
    foreach ($s in $sources) {
        $current = Get-EnvValue $s.Name
        $state = if ($current) { 'set, Enter keeps it' } else { 'not set' }
        Write-Host ""
        Write-Host "    $($s.Label): $($s.Where)  [$state]"
        $value = (Read-Host "    $($s.Name)").Trim()
        if ($value) { Set-EnvValue $s.Name $value }
    }
}

# -- uninstall ------------------------------------------------------------------------------
if ($Uninstall) {
    Say 'Removing the IntelGraph Lite task, firewall rule and shortcut'
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Admin) { Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
    else { Warn "Not administrator: remove the firewall rule '$RuleName' by hand if you want it gone." }
    Remove-Item -LiteralPath $Shortcut -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $App -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Kept: $Data (your token, keys and database). Delete it by hand if you like."
    exit 0
}

# -- keys only ------------------------------------------------------------------------------
if ($Keys) {
    if (-not (Test-Path $EnvFile)) { Stop-With 'IntelGraph Lite is not installed yet: run this script without -Keys first.' }
    Read-ApiKeys
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Say 'Saved, and IntelGraph Lite restarted.'
    exit 0
}

if (-not (Test-Admin)) {
    Stop-With "Run this from PowerShell as Administrator (right-click PowerShell > Run as administrator).`nIt needs that once, to allow the dashboard through Windows Firewall."
}

# -- 1. Python 3.11+ -----------------------------------------------------------------------------
function Find-Python {
    $candidates = @(
        @('py', '-3'),
        @('python'),
        @("$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"),
        @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"),
        @("$env:LOCALAPPDATA\Programs\Python\Python311\python.exe")
    )
    foreach ($c in $candidates) {
        $exe = $c[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $extra = @($c | Select-Object -Skip 1)
        try {
            # no double quotes: Windows PowerShell 5.1 strips them from native arguments
            $ver = & $exe @extra -c 'import sys; print(sys.version_info[0], sys.version_info[1], sep=chr(46))' 2>$null
        } catch { continue }
        if ($LASTEXITCODE -eq 0 -and $ver -and [version]"$ver" -ge [version]'3.11') {
            return , (@($exe) + $extra)
        }
    }
    return $null
}

Say 'Looking for Python 3.11 or newer'
$Python = Find-Python
if (-not $Python) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Stop-With 'Python 3.11+ is needed: install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"), then run this again.'
    }
    Say 'Installing Python 3.12 with winget'
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
    $Python = Find-Python
    if (-not $Python) { Stop-With 'Python was installed but not found yet: close this window, open a new PowerShell as Administrator, and run the script again.' }
}
$PyExe = $Python[0]; $PyArgs = @($Python | Select-Object -Skip 1)
Write-Host "    using $(& $PyExe @PyArgs --version)"

# -- 2. tshark and Npcap ------------------------------------------------------------------------
Say 'Looking for Wireshark (tshark) and Npcap'
$Tshark = Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'
if (-not (Test-Path $Tshark)) {
    $onPath = Get-Command tshark -ErrorAction SilentlyContinue
    if ($onPath) { $Tshark = $onPath.Source }
}
if (-not (Test-Path $Tshark)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Say 'Installing Wireshark with winget'
        winget install -e --id WiresharkFoundation.Wireshark --accept-package-agreements --accept-source-agreements
    }
    if (-not (Test-Path $Tshark)) {
        Stop-With 'Wireshark is needed for its tshark tool: install it from https://www.wireshark.org/download.html, then run this again.'
    }
}
if (-not (Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
    Stop-With "The Npcap capture driver is missing. Install it from https://npcap.com/#download with the default options`n(leave 'Restrict Npcap driver's access to Administrators only' unticked), then run this again."
}
Write-Host "    tshark: $Tshark"

# -- 3. the hotspot adapter ------------------------------------------------------------------
Say 'Finding the Mobile hotspot adapter'
if (-not $Interface) {
    $addr = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $HotspotIp -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $addr) {
        Stop-With "The Mobile hotspot is off. Turn it on: Settings > Network & internet > Mobile hotspot >`nShare my internet connection from: Ethernet (or Wi-Fi) > On. Then run this again."
    }
    $Interface = $addr.InterfaceAlias
}
Write-Host "    hotspot adapter: $Interface ($HotspotNet)"

# -- 4. IntelGraph Lite in its own environment ------------------------------------------------
Say "Installing IntelGraph Lite from $Repo"
New-Item -ItemType Directory -Force -Path $App, $Data | Out-Null
if (-not (Test-Path $VenvPy)) {
    & $PyExe @PyArgs -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Stop-With 'Could not create the Python environment.' }
}
& $VenvPy -m pip install --quiet --upgrade pip
& $VenvPy -m pip install --quiet --upgrade ($Repo + '[ai]')
if ($LASTEXITCODE -ne 0) { Stop-With 'pip could not install IntelGraph Lite (see the messages above).' }
Write-Host "    $(& $VenvPy -m iglite --version)"

# -- 5. token and keys ---------------------------------------------------------------------
if (-not (Get-EnvValue 'IGLITE_API_TOKEN')) {
    $bytes = New-Object byte[] 18
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    Set-EnvValue 'IGLITE_API_TOKEN' (([Convert]::ToBase64String($bytes)) -replace '[+/=]', '')
}
$Token = Get-EnvValue 'IGLITE_API_TOKEN'
if (-not $SkipKeys) { Read-ApiKeys }

# -- 6. popular sites and address ranges -------------------------------------------------------
Say 'Downloading the popular-site list and Google/CloudFront address ranges'
& $VenvPy -m iglite common update
if ($LASTEXITCODE -ne 0) { Warn 'Could not download them now (no internet?). Run later: iglite common update' }

# -- 7. firewall --------------------------------------------------------------------------------
Say "Allowing the dashboard (TCP $Port) from local networks through Windows Firewall"
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
    -RemoteAddress LocalSubnet -Profile Any | Out-Null

# -- 8. start now and at log-on -------------------------------------------------------------------
Say 'Starting IntelGraph Lite (and at every log-on)'
$runArgs = @('serve', '--host', '0.0.0.0', '--port', "$Port", '--capture', $Interface, '--lan', $HotspotNet,
             '--tshark', $Tshark)
ConvertTo-Json -InputObject $runArgs -Compress | Set-Content -LiteralPath (Join-Path $App 'args.json') -Encoding UTF8
@'
# Started by the "IntelGraph Lite" scheduled task (pythonw: no window). Output goes to service.log.
import json, os, sys
from pathlib import Path

here = Path(__file__).resolve().parent
log = open(Path(os.environ["USERPROFILE"]) / ".iglite" / "service.log", "a", buffering=1, encoding="utf-8")
sys.stdout = sys.stderr = log
os.chdir(Path(os.environ["USERPROFILE"]) / ".iglite")  # reads .env from here
from iglite.cli import main

sys.exit(main(json.loads((here / "args.json").read_text(encoding="utf-8-sig"))))
'@ | Set-Content -LiteralPath (Join-Path $App 'run.py') -Encoding UTF8

$user = "$env:USERDOMAIN\$env:USERNAME"
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$action    = New-ScheduledTaskAction -Execute $VenvPyw -Argument "`"$(Join-Path $App 'run.py')`"" -WorkingDirectory $Data
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Set-Content -LiteralPath $Shortcut -Value @('[InternetShortcut]', "URL=http://127.0.0.1:$Port/#network") -Encoding ASCII

$up = $false
foreach ($i in 1..30) {
    Start-Sleep -Seconds 1
    try { Invoke-WebRequest "http://127.0.0.1:$Port/" -UseBasicParsing -TimeoutSec 2 | Out-Null; $up = $true; break } catch { }
}
$lan = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne $HotspotIp -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1).IPAddress

Write-Host ""
if ($up) { Write-Host 'IntelGraph Lite is running.' -ForegroundColor Green }
else { Warn "It hasn't answered yet; check $Data\service.log in a minute." }
Write-Host @"

  Dashboard on this PC:        http://127.0.0.1:$Port   (desktop shortcut: IntelGraph Lite)
  From a device on the hotspot: http://${HotspotIp}:$Port
  From your home network:      http://${lan}:$Port
  API token:                   $Token
  Settings and keys:           $EnvFile   (change keys: re-run with -Keys)
  Log:                         $Data\service.log

Connect phones and laptops to this PC's hotspot Wi-Fi; they appear under Network.
Undo: powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1 -Uninstall
"@
