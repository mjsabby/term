## uninstall-hub.ps1 — remove a Windows term-hub install.
##
## Idempotent. Preserves -ConfigDir and -DataDir by default — the data
## dir holds the agent CA, the issued-certs allowlist, registered
## passkey credentials, and the ACME cache, so wiping it is
## destructive. Use -PurgeData explicitly when you really want a
## fresh install.

[CmdletBinding()]
param(
  [string] $BinDir    = (Join-Path $env:ProgramFiles "term-hub"),
  [string] $ConfigDir = (Join-Path $env:ProgramData "term-hub"),
  [string] $DataDir   = (Join-Path $env:ProgramData "term-hub"),
  [string] $TaskName  = "term-hub",
  [switch] $PurgeConfig,
  [switch] $PurgeData,
  [switch] $KeepBinary
)

$ErrorActionPreference = "Stop"

function Note([string] $msg) {
  Write-Host "uninstall-hub: $msg"
}
function Die([string] $msg) {
  Write-Host "uninstall-hub: error: $msg" -ForegroundColor Red
  exit 1
}

$current = [System.Security.Principal.WindowsPrincipal]::new(
  [System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole(
      [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die "must run elevated (right-click PowerShell -> Run as Administrator)"
}

# --- scheduled task
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
  Note "stopping scheduled task $TaskName"
  try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
  Note "unregistering scheduled task $TaskName"
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} else {
  Note "scheduled task $TaskName not registered; skipping"
}

# Drop the system-wide TERM_HUB_CONFIG env var set by install-hub.ps1.
$cur = [Environment]::GetEnvironmentVariable("TERM_HUB_CONFIG", "Machine")
if ($cur) {
  Note "removing system env var TERM_HUB_CONFIG ($cur)"
  [Environment]::SetEnvironmentVariable("TERM_HUB_CONFIG", $null, "Machine")
}

# --- binaries
if (-not $KeepBinary) {
  if (Test-Path $BinDir) {
    Note "removing $BinDir"
    Remove-Item -Recurse -Force $BinDir -ErrorAction SilentlyContinue
  } else {
    Note "$BinDir not present; skipping"
  }
}

# install-hub.ps1 colocates hub.toml inside the data dir, so
# -ConfigDir and -DataDir may resolve to the same path. Handle that
# by tracking what we've already removed.
$removed = @{}

if ($PurgeConfig) {
  if (Test-Path $ConfigDir) {
    Note "purging $ConfigDir (hub.toml)"
    Remove-Item -Recurse -Force $ConfigDir -ErrorAction SilentlyContinue
    $removed[$ConfigDir.ToLowerInvariant()] = $true
  } else {
    Note "$ConfigDir not present; skipping"
  }
} else {
  Note "preserving $ConfigDir (use -PurgeConfig to wipe hub.toml)"
}

if ($PurgeData) {
  if (-not $removed.ContainsKey($DataDir.ToLowerInvariant())) {
    if (Test-Path $DataDir) {
      Note "purging $DataDir (CA, credentials, issued-certs, ACME cache) - DESTRUCTIVE"
      Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    } else {
      Note "$DataDir not present; skipping"
    }
  }
} else {
  Note "preserving $DataDir (use -PurgeData to wipe CA + credentials + issued-certs)"
}

Note "done."
