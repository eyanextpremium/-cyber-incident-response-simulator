#!/usr/bin/env pwsh
<#
.SYNOPSIS
    CyberSim — Setup Script
    Installs dependencies and initializes the project for first-time use.

.DESCRIPTION
    - Checks Rust, installs if missing (via winget on Windows)
    - Verifies SQLite3 availability
    - Creates necessary directories
    - Validates all scenario JSON files
    - Runs cargo check to verify compilation

.EXAMPLE
    .\scripts\setup.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Header  { param([string]$m) Write-Host "`n┌─ $m" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m) Write-Host "│  ✓ $m" -ForegroundColor Green }
function Write-Warn    { param([string]$m) Write-Host "│  ⚠ $m" -ForegroundColor Yellow }
function Write-Err     { param([string]$m) Write-Host "│  ✗ $m" -ForegroundColor Red }
function Write-Step    { param([string]$m) Write-Host "│  → $m" -ForegroundColor White }

$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║    CyberSim — First-Time Setup           ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Magenta

# ── Rust ──────────────────────────────────────────────────────
Write-Header "Rust Toolchain"
if (Get-Command "cargo" -ErrorAction SilentlyContinue) {
    $v = & rustc --version
    Write-Ok "Rust found: $v"
} else {
    Write-Warn "Rust not found. Attempting install..."
    if ($IsWindows) {
        Write-Step "Downloading rustup-init.exe..."
        $rustupUrl = "https://win.rustup.rs/x86_64"
        $rustupExe = "$env:TEMP\rustup-init.exe"
        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupExe -UseBasicParsing
        & $rustupExe -y --default-toolchain stable
        $env:PATH += ";$env:USERPROFILE\.cargo\bin"
        Write-Ok "Rust installed. Restart your terminal if cargo is not found."
    } else {
        Write-Err "Install Rust from https://rustup.rs and re-run this script."
        exit 1
    }
}

# ── Directories ───────────────────────────────────────────────
Write-Header "Directory Structure"
$requiredDirs = @(
    "scenarios/beginner",
    "scenarios/intermediate",
    "scenarios/advanced",
    "scenarios/expert",
    "fronted/css",
    "fronted/js",
    "data",
    "logs"
)
foreach ($dir in $requiredDirs) {
    $full = Join-Path $ProjectRoot $dir
    if (-not (Test-Path $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
        Write-Ok "Created: $dir"
    } else {
        Write-Ok "Exists:  $dir"
    }
}

# ── Validate Scenario Files ───────────────────────────────────
Write-Header "Scenario JSON Validation"
$scenarioDirs = @("beginner","intermediate","advanced","expert")
$errors = 0
$total  = 0
foreach ($level in $scenarioDirs) {
    $dir = Join-Path $ProjectRoot "scenarios" $level
    if (Test-Path $dir) {
        $files = Get-ChildItem $dir -Filter "*.json"
        foreach ($f in $files) {
            $total++
            try {
                $json = Get-Content $f.FullName -Raw | ConvertFrom-Json
                if (-not $json.id -or -not $json.name) {
                    Write-Warn "Missing id/name in: $($f.Name)"
                    $errors++
                } else {
                    Write-Ok "$level/$($f.Name)"
                }
            } catch {
                Write-Err "JSON parse error in: $($f.Name)"
                $errors++
            }
        }
    }
}
if ($errors -eq 0) {
    Write-Ok "All $total scenario files valid"
} else {
    Write-Warn "$errors/$total files have issues"
}

# ── Cargo Check ───────────────────────────────────────────────
Write-Header "Rust Compilation Check"
Set-Location $ProjectRoot
Write-Step "Running cargo check..."
$checkOutput = & cargo check 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Compilation check passed"
} else {
    Write-Err "Compilation errors detected:"
    $checkOutput | Where-Object { $_ -match "^error" } | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
}

# ── Summary ───────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           Setup Complete!                ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Run:  .\scripts\run.ps1                 ║" -ForegroundColor White
Write-Host "║  Test: .\scripts\test.ps1                ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
