## uninstall-agent.ps1 — remove a Windows term-agent install.
##
## Idempotent: missing pieces are logged and skipped, not treated as
## errors. Preserves -ConfigDir by default so a re-install can reuse
## the existing cert + key — pass -PurgeConfig to wipe it.

[CmdletBinding()]
param(
  [string] $BinDir    = (Join-Path $env:ProgramFiles "term-agent"),
  [string] $ConfigDir = (Join-Path $env:ProgramData "term-agent"),
  [string] $TaskName  = "term-agent",
  [switch] $PurgeConfig,
  [switch] $KeepBinary
)

$ErrorActionPreference = "Stop"

function Note([string] $msg) {
  Write-Host "uninstall-agent: $msg"
}
function Die([string] $msg) {
  Write-Host "uninstall-agent: error: $msg" -ForegroundColor Red
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

# --- binary directory
if (-not $KeepBinary) {
  if (Test-Path $BinDir) {
    Note "removing $BinDir"
    Remove-Item -Recurse -Force $BinDir -ErrorAction SilentlyContinue
  } else {
    Note "$BinDir not present; skipping"
  }
}

# --- config dir (cert + key + agent.toml)
if ($PurgeConfig) {
  if (Test-Path $ConfigDir) {
    Note "purging $ConfigDir (cert + key + agent.toml)"
    Remove-Item -Recurse -Force $ConfigDir -ErrorAction SilentlyContinue
  } else {
    Note "$ConfigDir not present; skipping"
  }
} else {
  Note "preserving $ConfigDir (use -PurgeConfig to wipe cert+key+agent.toml)"
}

Note "done."
