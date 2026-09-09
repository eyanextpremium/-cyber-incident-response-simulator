#!/usr/bin/env pwsh
<#
.SYNOPSIS
    CyberSim — Build & Run Script
    Builds the Rust backend and launches the SOC simulator server.

.DESCRIPTION
    This script handles the full build-and-run lifecycle:
    1. Checks Rust toolchain
    2. Builds in release mode
    3. Starts the server

.PARAMETER Release
    Build in release mode (default: debug)

.PARAMETER Port
    Override server port (default: from config)

.EXAMPLE
    .\scripts\run.ps1
    .\scripts\run.ps1 -Release -Port 9090
#>

param(
    [switch]$Release,
    [int]$Port = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colors ────────────────────────────────────────────────────
function Write-Header  { param([string]$msg) Write-Host "═══ $msg ═══" -ForegroundColor Cyan }
function Write-Success { param([string]$msg) Write-Host "✓ $msg"  -ForegroundColor Green }
function Write-Fail    { param([string]$msg) Write-Host "✗ $msg"  -ForegroundColor Red   }
function Write-Info    { param([string]$msg) Write-Host "  $msg"  -ForegroundColor Gray  }

Write-Host ""
Write-Host "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗███╗   ███╗" -ForegroundColor Magenta
Write-Host "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║████╗ ████║" -ForegroundColor Magenta
Write-Host "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║██╔████╔██║" -ForegroundColor Magenta
Write-Host "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║██║╚██╔╝██║" -ForegroundColor Magenta
Write-Host "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║██║ ╚═╝ ██║" -ForegroundColor Magenta
Write-Host "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝" -ForegroundColor Magenta
Write-Host "  Cyber Incident Response Simulator v0.1.0" -ForegroundColor DarkMagenta
Write-Host ""

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

# ── Check Rust ────────────────────────────────────────────────
Write-Header "Checking Prerequisites"
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Fail "Rust/Cargo not found. Install from https://rustup.rs"
    exit 1
}
$rustVersion = & rustc --version
Write-Success "Rust: $rustVersion"

# ── Build ─────────────────────────────────────────────────────
Write-Header "Building"

$buildArgs = @("build")
if ($Release) {
    $buildArgs += "--release"
    $buildMode = "release"
    Write-Info "Mode: Release (optimized)"
} else {
    $buildMode = "debug"
    Write-Info "Mode: Debug"
}

Write-Info "Running: cargo $($buildArgs -join ' ')"
$buildStart = Get-Date
& cargo @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Build failed. Check errors above."
    exit 1
}
$buildTime = [math]::Round(((Get-Date) - $buildStart).TotalSeconds, 1)
Write-Success "Build succeeded in ${buildTime}s"

# ── Locate Binary ─────────────────────────────────────────────
$binaryName = if ($IsWindows) { "cyber_incident_simulator.exe" } else { "cyber_incident_simulator" }
$binaryPath = Join-Path $ProjectRoot "target" $buildMode $binaryName

if (-not (Test-Path $binaryPath)) {
    Write-Fail "Binary not found at: $binaryPath"
    exit 1
}

# ── Port Override ─────────────────────────────────────────────
$env:RUST_LOG = "cyber_incident_simulator=info,tower_http=info"
if ($Port -gt 0) {
    $env:SIM_PORT = $Port.ToString()
    Write-Info "Port override: $Port"
}

# ── Launch ────────────────────────────────────────────────────
Write-Header "Starting SOC Simulator"
$defaultPort = if ($Port -gt 0) { $Port } else { 8080 }
Write-Info "Dashboard: http://localhost:$defaultPort"
Write-Info "API:       http://localhost:$defaultPort/api/health"
Write-Info "Press Ctrl+C to stop"
Write-Host ""

& $binaryPath
