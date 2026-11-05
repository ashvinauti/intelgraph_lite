<#
  IntelGraph Lite - one-time setup on Windows.

  Run from the project folder in PowerShell:
      powershell -ExecutionPolicy Bypass -File .\setup.ps1

  What it does (safe to run again; it never overwrites your .env):
    1. checks that Python 3.11+ is installed
    2. creates a private Python environment in .venv
    3. installs IntelGraph Lite into it (with the AI extra unless -NoAI)
    4. creates .env from .env.example if you don't have one yet
    5. shows which intelligence sources are enabled
#>
param(
    [switch]$NoAI  # skip the optional 'anthropic' package (AI with Claude)
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Fail([string]$Text) { Write-Host "`nSetup stopped: $Text" -ForegroundColor Red; exit 1 }

# 1. Python ------------------------------------------------------------------------
Step "Checking Python"
$py = $null
$pyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
    $py = "py"; $pyArgs = @("-3")          # the Python launcher, installed with Python
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $py = "python"
} else {
    Fail "Python was not found. Install it with:  winget install Python.Python.3.12  then open a NEW PowerShell window and run this script again."
}
& $py @pyArgs -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) {
    Fail ("Python 3.11 or newer is needed. If a Microsoft Store window opened, Windows' 'python' shortcut is in the way: " +
          "install Python with  winget install Python.Python.3.12  and turn off the 'python.exe' App execution alias " +
          "(Settings > Apps > Advanced app settings > App execution aliases).")
}
& $py @pyArgs --version

# 2. Virtual environment -----------------------------------------------------------
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path -LiteralPath $venvPython) {
    Step "Using the existing environment in .venv"
} else {
    Step "Creating a Python environment in .venv"
    & $py @pyArgs -m venv .venv
    if ($LASTEXITCODE -ne 0) { Fail "could not create .venv" }
}

# 3. Install -----------------------------------------------------------------------
$target = if ($NoAI) { "." } else { ".[ai]" }
Step "Installing IntelGraph Lite ($target)"
& $venvPython -m pip install --disable-pip-version-check --quiet --upgrade pip
& $venvPython -m pip install --disable-pip-version-check $target
if ($LASTEXITCODE -ne 0) { Fail "pip could not install the package (see the error above)" }

# 4. .env --------------------------------------------------------------------------
if (Test-Path -LiteralPath ".env") {
    Step "Keeping your existing .env"
} else {
    Step "Creating .env from .env.example (add your API keys to it)"
    Copy-Item -LiteralPath ".env.example" -Destination ".env"
}

# 5. Check -------------------------------------------------------------------------
$iglite = Join-Path $PSScriptRoot ".venv\Scripts\iglite.exe"
Step "Installed version"
& $iglite --version
Step "Intelligence sources (keys come from .env)"
& $iglite sources

Write-Host "`nSetup complete." -ForegroundColor Green
Write-Host "Next:"
Write-Host "  1. Add your API keys:     notepad .env"
Write-Host "  2. Start the dashboard:   double-click start.cmd   (or: .\.venv\Scripts\iglite.exe serve --watch --open)"
Write-Host "  Full guide: docs\WINDOWS_SETUP.md"
