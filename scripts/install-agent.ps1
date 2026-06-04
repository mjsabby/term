## install-agent.ps1 — install term-agent.exe on this Windows host.
##
## Single-user model: registers a Scheduled Task that runs the agent at
## the chosen user's logon, in that user's session, with that user's
## token. One Windows user == one agent identity. If you want multiple
## users on the same machine to expose shells through term-hub, give
## each user their own per-machine cert + install invocation.
##
## As of Phase 4.6 the agent authenticates by client cert (issued via
## `hub-admin issue-cert --id <machine_id>` on the hub host). The
## machine_id is bound by the cert's SAN URN, so there is no
## -MachineId / -Psk parameter anymore.
##
## Idempotent: refuses to overwrite an existing agent.toml unless
## -Force. Re-running with the same arguments just updates the binary
## and (re-)registers the task.

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string] $Hub,
  [Parameter(Mandatory=$true)] [string] $Cert,
  [Parameter(Mandatory=$true)] [string] $Key,

  ## Optional: PEM of the CA that signed the HUB's *server* cert.
  ## Only needed for tls=files / self-signed hub deployments.
  [string] $HubCa,

  [ValidateSet("on","off")]
  [string] $Tls = "on",
  [string] $ServerName,

  ## Shell argv string passed verbatim into agent.toml's `shell` knob.
  ## Default: cmd.exe. Use "powershell -NoLogo -NoProfile" or a full
  ## path to pwsh.exe for PowerShell.
  [string] $Shell = "C:\Windows\System32\cmd.exe",

  ## User the agent (and its child shell sessions) will run as. Default
  ## is the user invoking this script — that's almost always what you
  ## want. Pass `DOMAIN\user` to install for a different account.
  [string] $RunAsUser = $env:USERNAME,
  [string] $RunAsDomain = $env:USERDOMAIN,

  [string] $BuildDir  = (Join-Path $PSScriptRoot "..\target\release"),
  [string] $BinDir    = (Join-Path $env:ProgramFiles "term-agent"),
  [string] $ConfigDir = (Join-Path $env:ProgramData "term-agent"),

  [string] $TaskName  = "term-agent",

  [switch] $NoEnable,
  [switch] $Force,
  ## Tear down any previous term-agent install before laying down the
  ## new one. Preserves $ConfigDir (cert+key+agent.toml) unless
  ## -PurgeConfig is also passed.
  [switch] $Clean,
  [switch] $PurgeConfig
)

$ErrorActionPreference = "Stop"

function Die([string] $msg) {
  Write-Host "install-agent: error: $msg" -ForegroundColor Red
  exit 1
}
function Note([string] $msg) {
  Write-Host "install-agent: $msg"
}

# ------- preflight --------------------------------------------------

$current = [System.Security.Principal.WindowsPrincipal]::new(
  [System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $current.IsInRole(
      [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die "must run elevated (right-click PowerShell -> Run as Administrator)"
}

if (-not (Test-Path $Cert)) { Die "cert file not readable: $Cert" }
if (-not (Test-Path $Key))  { Die "key file not readable: $Key" }
if ($HubCa -and -not (Test-Path $HubCa)) { Die "hub-ca file not readable: $HubCa" }

$AgentExe = Join-Path $BuildDir "term-agent.exe"
if (-not (Test-Path $AgentExe)) {
  Die "missing $AgentExe (run: scripts\build.ps1)"
}

# Optional but recommended: ship term-dl.exe alongside so users can
# `term-dl <path>` from their shell.
$DlExe = Join-Path $BuildDir "term-dl.exe"

$runAsAccount = if ($RunAsDomain) { "$RunAsDomain\$RunAsUser" } else { $RunAsUser }
try {
  $runAsSid = (New-Object System.Security.Principal.NTAccount $runAsAccount)
              .Translate([System.Security.Principal.SecurityIdentifier])
} catch {
  Die "user $runAsAccount does not exist: $_"
}
Note "agent will run as $runAsAccount (sid=$($runAsSid.Value))"

# ------- optional clean install --------------------------------------

if ($Clean) {
  $uninstall = Join-Path $PSScriptRoot "uninstall-agent.ps1"
  if (-not (Test-Path $uninstall)) {
    Die "-Clean requested but $uninstall not found"
  }
  Note "-Clean: invoking $uninstall first"
  $unArgs = @{
    BinDir      = $BinDir
    ConfigDir   = $ConfigDir
    TaskName    = $TaskName
    KeepBinary  = $true
  }
  if ($PurgeConfig) { $unArgs.PurgeConfig = $true }
  & $uninstall @unArgs
}

# ------- binary -----------------------------------------------------

if (-not (Test-Path $BinDir)) {
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
}
Note "installing binary -> $BinDir\term-agent.exe"
Copy-Item -Force $AgentExe (Join-Path $BinDir "term-agent.exe")
if (Test-Path $DlExe) {
  Note "installing helper -> $BinDir\term-dl.exe"
  Copy-Item -Force $DlExe (Join-Path $BinDir "term-dl.exe")
} else {
  Note "skipping term-dl.exe (not built)"
}

# ------- config dir + cert + key + agent.toml -----------------------

if (-not (Test-Path $ConfigDir)) {
  New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
}

# Restrict ACL: SYSTEM + Administrators full control, run-as user
# read-only. Disable inheritance so we know exactly who can read the
# private key.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)   # disable inheritance, no copy
$systemSid = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
$adminsSid = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"
foreach ($sid in @($systemSid, $adminsSid)) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow")))
}
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
  $runAsSid, "ReadAndExecute",
  "ContainerInherit,ObjectInherit", "None", "Allow")))
$acl.SetOwner($adminsSid)
Set-Acl -Path $ConfigDir -AclObject $acl

$CertDst = Join-Path $ConfigDir "agent.crt"
$KeyDst  = Join-Path $ConfigDir "agent.key"
$HubCaDst = ""
Note "installing cert -> $CertDst"
Copy-Item -Force $Cert $CertDst
Note "installing key  -> $KeyDst"
Copy-Item -Force $Key  $KeyDst
if ($HubCa) {
  $HubCaDst = Join-Path $ConfigDir "hub-server-ca.pem"
  Note "installing hub server CA -> $HubCaDst"
  Copy-Item -Force $HubCa $HubCaDst
}

$ConfigPath = Join-Path $ConfigDir "agent.toml"
if ((Test-Path $ConfigPath) -and -not $Force) {
  Note "$ConfigPath exists; not overwriting (use -Force to replace)"
} else {
  Note "writing $ConfigPath"
  $serverNameLine = ""
  if ($ServerName) { $serverNameLine = "server_name = `"$ServerName`"" }
  $hubCaLine = ""
  if ($HubCaDst) {
    $hubCaEsc = $HubCaDst -replace '\\', '\\'
    $hubCaLine = "hub_ca_path = `"$hubCaEsc`""
  }
  # Escape backslashes for TOML.
  $shellEsc = $Shell -replace '\\', '\\'
  $certEsc  = $CertDst -replace '\\', '\\'
  $keyEsc   = $KeyDst  -replace '\\', '\\'
  $now = (Get-Date).ToString("o")
  $contents = @"
## generated by scripts\install-agent.ps1 on $now
hub         = "$Hub"
cert_path   = "$certEsc"
key_path    = "$keyEsc"
tls         = "$Tls"
$hubCaLine
$serverNameLine
shell       = "$shellEsc"
"@
  # Strip multiple blank lines.
  $contents = ($contents -replace "(?ms)`r?`n`r?`n`r?`n", "`r`n`r`n")
  [System.IO.File]::WriteAllText($ConfigPath, $contents, [System.Text.Encoding]::UTF8)
}

# ------- scheduled task ---------------------------------------------

# Tear down any previous registration so re-installs pick up new args.
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
  Note "removing existing scheduled task $TaskName"
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action  = New-ScheduledTaskAction `
            -Execute (Join-Path $BinDir "term-agent.exe") `
            -WorkingDirectory $BinDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $runAsAccount
$settings = New-ScheduledTaskSettingsSet `
              -AllowStartIfOnBatteries `
              -DontStopIfGoingOnBatteries `
              -StartWhenAvailable `
              -RestartCount 999 `
              -RestartInterval (New-TimeSpan -Minutes 1) `
              -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
# RunLevel Limited (no elevation) keeps the agent in the user's normal
# token. The agent doesn't need admin once installed.
$principal = New-ScheduledTaskPrincipal `
              -UserId $runAsAccount `
              -LogonType Interactive `
              -RunLevel Limited

$task = New-ScheduledTask `
          -Action $action `
          -Trigger $trigger `
          -Settings $settings `
          -Principal $principal `
          -Description "term-agent: dials term-hub at $Hub for $runAsAccount"

Note "registering scheduled task $TaskName (runs at logon for $runAsAccount)"
Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null

if (-not $NoEnable) {
  Note "starting term-agent now"
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 2
  Get-ScheduledTask -TaskName $TaskName |
    Get-ScheduledTaskInfo |
    Format-List TaskName, LastRunTime, LastTaskResult, NextRunTime
}

Note "done."
Write-Host ""
Write-Host "next:"
Write-Host "  - check task status:   Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "  - stop / start:        Stop-ScheduledTask / Start-ScheduledTask -TaskName $TaskName"
Write-Host "  - uninstall:           Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
Write-Host "  - on the hub, you should see:"
Write-Host "      agent registered machine=<id from cert SAN> peer=..."
