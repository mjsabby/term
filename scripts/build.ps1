## Build all four workspace binaries (term-hub, term-agent, hub-admin,
## term-dl) in release mode and report where they landed.
##
## As of Phase 4.4 the whole workspace builds on Windows — the
## webauthn-rs / openssl-sys dependency is gone (replaced by a
## hand-rolled ES256 verifier in `term-common::webauthn`).
[CmdletBinding()]
param(
  [switch]$Dev,
  [int]$Jobs = 0
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo not found on PATH; install Rust first (https://rustup.rs)"
  }

  $jobsArg = @()
  if ($Jobs -gt 0) { $jobsArg = @("-j", "$Jobs") }

  if ($Dev) {
    & cargo build --workspace @jobsArg
    $outDir = "target\debug"
  } else {
    & cargo build --workspace --release @jobsArg
    $outDir = "target\release"
  }
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  Write-Host ""
  Write-Host "built:"
  foreach ($name in @("term-hub.exe", "term-agent.exe", "hub-admin.exe", "term-dl.exe")) {
    $p = Join-Path $outDir $name
    if (Test-Path $p) {
      $sz = (Get-Item $p).Length
      $kb = [math]::Round($sz / 1024, 1)
      "  {0,-15} {1}  ({2:N1} KiB)" -f $name, $p, $kb | Write-Host
    } else {
      Write-Warning "  MISSING: $p"
    }
  }
} finally {
  Pop-Location
}
