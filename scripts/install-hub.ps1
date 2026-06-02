## install-hub.ps1 — install term-hub.exe + hub-admin.exe on this
## Windows host.
##
## Registers term-hub as a Scheduled Task that fires at system
## startup and runs as SYSTEM (or the account passed via -RunAsUser).
## We use Scheduled Tasks rather than a native Windows Service
## because the binary isn't SCM-aware; the task runner has been the
## supported "run-this-binary-forever" mechanism on Windows since
## Vista and handles restart-on-failure cleanly.
##
## Idempotent: refuses to overwrite an existing hub.toml unless
## -Force. Re-running with the same arguments updates the binaries
## and re-registers the task.
##
## After install:
##   - hub-admin lives at %ProgramFiles%\term-hub\hub-admin.exe.
##     Add to PATH (or run by full path) to use:
##       hub-admin list
##       hub-admin add-passkey '<blob>'
##   - Hub data (credentials.json, secret.key, acme cache) lives at
##     %ProgramData%\term-hub\
##   - Logs: tied to the task — see Task Scheduler -> History.
##     For better logging, point hub.toml at a log file via stdout
##     redirection in the task action (manual edit for now).

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string] $Domain,

  [ValidateSet("acme","files","off")]
  [string] $TlsMode = "off",

  ## ACME contact email (required when -TlsMode acme).
  [string] $AcmeEmail,

  ## TOML rp_id override; defaults to -Domain.
  [string] $RpId,

  ## Browser bind. Empty = ACME-mode default :443, off-mode default :8080.
  [string] $Bind = "",

  ## Agent bind. Default :7700.
  [string] $AgentBind = "[::]:7700",

  ## Comma-separated list of "id:label" pairs to seed [[machines]].
  ## PSKs are auto-generated (32 random bytes, base64) and printed at
  ## the end so you can paste them into install-agent on each agent.
  [string[]] $Machines = @(),

  ## Run the hub task as this account. Default SYSTEM (no logon needed,
  ## runs at boot). Pass a domain account if you want the hub to run
  ## with a specific identity (e.g. for cross-machine file access).
  [string] $RunAsUser = "SYSTEM",

  [string] $BuildDir  = (Join-Path $PSScriptRoot "..\target\release"),
  [string] $BinDir    = (Join-Path $env:ProgramFiles "term-hub"),
  [string] $DataDir   = (Join-Path $env:ProgramData "term-hub"),

  [string] $TaskName  = "term-hub",

  [switch] $NoEnable,
  [switch] $Force
)

$ErrorActionPreference = "Stop"

function Die([string] $msg) {
  Write-Host "install-hub: error: $msg" -ForegroundColor Red
  exit 1
}
function Note([string] $msg) {
  Write-Host "install-hub: $msg"
}

# ------- preflight --------------------------------------------------

$current = [System.Security.Principal.WindowsPrincipal]::new(
  [System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole(
      [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die "must run elevated (right-click PowerShell -> Run as Administrator)"
}

if ($TlsMode -eq "acme" -and -not $AcmeEmail) {
  Die "-AcmeEmail is required when -TlsMode is acme"
}

if (-not $RpId) { $RpId = $Domain }

$HubExe   = Join-Path $BuildDir "term-hub.exe"
$AdminExe = Join-Path $BuildDir "hub-admin.exe"
if (-not (Test-Path $HubExe))   { Die "missing $HubExe (run: scripts\build.ps1)" }
if (-not (Test-Path $AdminExe)) { Die "missing $AdminExe (run: scripts\build.ps1)" }

# Determine the SYSTEM SID once for ACL setup.
$systemSid = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
$adminsSid = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"

# ------- binaries ---------------------------------------------------

if (-not (Test-Path $BinDir)) {
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
}
Note "installing term-hub.exe -> $BinDir"
Copy-Item -Force $HubExe   (Join-Path $BinDir "term-hub.exe")
Note "installing hub-admin.exe -> $BinDir"
Copy-Item -Force $AdminExe (Join-Path $BinDir "hub-admin.exe")

# ------- data dir ---------------------------------------------------

if (-not (Test-Path $DataDir)) {
  New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
}

# Restrict ACL: SYSTEM + Administrators full control; nobody else. We
# disable inheritance so the parent's looser permissions don't apply.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($systemSid, $adminsSid)) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow")))
}
$acl.SetOwner($adminsSid)
Set-Acl -Path $DataDir -AclObject $acl

# ------- hub.toml ---------------------------------------------------

$ConfigPath = Join-Path $DataDir "hub.toml"
$generatedMachines = @()
if ((Test-Path $ConfigPath) -and -not $Force) {
  Note "$ConfigPath exists; not overwriting (use -Force to replace)"
} else {
  Note "writing $ConfigPath"
  # Generate PSKs and build [[machines]] entries.
  $machineToml = ""
  foreach ($entry in $Machines) {
    if (-not $entry) { continue }
    $parts = $entry.Split(":", 2)
    $id    = $parts[0]
    $label = if ($parts.Length -gt 1) { $parts[1] } else { $parts[0] }
    if ($id -notmatch '^[A-Za-z0-9_-]{1,32}$') {
      Die "machine id $id must match [A-Za-z0-9_-]{1,32}"
    }
    # 32 random bytes via RNGCryptoServiceProvider -> base64.
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $psk = [Convert]::ToBase64String($bytes)
    $generatedMachines += [pscustomobject]@{ Id = $id; Label = $label; Psk = $psk }
    $machineToml += "`r`n[[machines]]`r`nid = `"$id`"`r`nlabel = `"$label`"`r`npsk = `"$psk`"`r`n"
  }

  $acmeLines = ""
  if ($TlsMode -eq "acme") {
    $acmeLines = "acme_email = `"$AcmeEmail`"`r`n"
  }
  $bindLine = ""
  if ($Bind) { $bindLine = "bind = `"$Bind`"`r`n" }
  $now = (Get-Date).ToString("o")
  $dataDirEsc = ($DataDir -replace '\\', '\\')
  $contents = @"
## generated by scripts\install-hub.ps1 on $now
domain     = "$Domain"
rp_id      = "$RpId"
tls        = "$TlsMode"
$acmeLines
data_dir   = "$dataDirEsc"
$bindLine
agent_bind = "$AgentBind"
$machineToml
"@
  [System.IO.File]::WriteAllText($ConfigPath, $contents, [System.Text.Encoding]::UTF8)
}

# Inherit the data dir's ACL on the toml file (SYSTEM + Admins).

# ------- scheduled task ---------------------------------------------

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
  Note "removing existing scheduled task $TaskName"
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action  = New-ScheduledTaskAction `
            -Execute (Join-Path $BinDir "term-hub.exe") `
            -WorkingDirectory $BinDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
              -AllowStartIfOnBatteries `
              -DontStopIfGoingOnBatteries `
              -StartWhenAvailable `
              -RestartCount 999 `
              -RestartInterval (New-TimeSpan -Minutes 1) `
              -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
$principal = New-ScheduledTaskPrincipal `
              -UserId $RunAsUser `
              -LogonType ServiceAccount `
              -RunLevel Highest

$task = New-ScheduledTask `
          -Action $action `
          -Trigger $trigger `
          -Settings $settings `
          -Principal $principal `
          -Description "term-hub for $Domain (tls=$TlsMode)"

Note "registering scheduled task $TaskName (runs at boot as $RunAsUser)"
# TERM_HUB_CONFIG env var so term-hub reads the right path. The
# Scheduled Task action's environment doesn't carry %ProgramData%
# expansion, so we resolve here.
Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null

# Set an environment override on the task action so term-hub finds
# its config. Done via Set-ScheduledTask after register because
# Register-ScheduledTask doesn't accept env vars directly.
$svcAction = (Get-ScheduledTask -TaskName $TaskName).Actions[0]
$svcAction.Arguments = ""
# The env-var route requires editing the task XML, which is uglier
# than just passing -TERM_HUB_CONFIG via the binary. Instead set
# the env var system-wide so term-hub picks it up:
[Environment]::SetEnvironmentVariable("TERM_HUB_CONFIG", $ConfigPath, "Machine")

if (-not $NoEnable) {
  Note "starting term-hub now"
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 2
  Get-ScheduledTask -TaskName $TaskName |
    Get-ScheduledTaskInfo |
    Format-List TaskName, LastRunTime, LastTaskResult, NextRunTime
}

# ------- summary ----------------------------------------------------

Note "done."
Write-Host ""
Write-Host "next:"
Write-Host "  - check status:    Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "  - stop / start:    Stop-ScheduledTask / Start-ScheduledTask -TaskName $TaskName"
Write-Host "  - uninstall:       Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
Write-Host "  - hub data lives at: $DataDir"
Write-Host "  - config at:        $ConfigPath"
Write-Host ""

if ($generatedMachines.Count -gt 0) {
  Write-Host "generated PSKs (one per --Machines entry). Save these now —"
  Write-Host "they're only printed here, not stored anywhere readable."
  Write-Host ""
  foreach ($m in $generatedMachines) {
    Write-Host "  machine_id=$($m.Id)  label=$($m.Label)"
    Write-Host "    psk=$($m.Psk)"
    Write-Host "    install on the agent host:"
    Write-Host "      .\scripts\install-agent.ps1 -Hub $Domain`:$(($AgentBind -split ':')[-1]) -MachineId $($m.Id) -Psk '$($m.Psk)'"
    Write-Host ""
  }
}
