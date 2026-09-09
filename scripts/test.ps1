#!/usr/bin/env pwsh
<#
.SYNOPSIS
    CyberSim — Test Runner Script
    Runs all Rust unit and integration tests with pretty output.

.PARAMETER Filter
    Optional test name filter (passed to cargo test)

.PARAMETER Coverage
    Attempt to generate coverage report using cargo-llvm-cov (if installed)

.EXAMPLE
    .\scripts\test.ps1
    .\scripts\test.ps1 -Filter "test_detection"
#>

param(
    [string]$Filter   = "",
    [switch]$Coverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Header  { param([string]$m) Write-Host "`n━━━ $m ━━━" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m) Write-Host "  ✓ $m" -ForegroundColor Green }
function Write-Err     { param([string]$m) Write-Host "  ✗ $m" -ForegroundColor Red }
function Write-Info    { param([string]$m) Write-Host "  · $m" -ForegroundColor Gray }

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "┌─────────────────────────────────────────┐" -ForegroundColor Magenta
Write-Host "│       CyberSim — Test Suite             │" -ForegroundColor Magenta
Write-Host "└─────────────────────────────────────────┘" -ForegroundColor Magenta

# ── Prerequisites ─────────────────────────────────────────────
Write-Header "Prerequisites"
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Err "cargo not found. Run .\scripts\setup.ps1 first."
    exit 1
}
Write-Ok "cargo found: $(& cargo --version)"

# ── Unit Tests ────────────────────────────────────────────────
Write-Header "Running Unit Tests"

$testArgs = @("test")
if ($Filter) {
    $testArgs += $Filter
    Write-Info "Filter: $Filter"
}
$testArgs += "--", "--test-output", "immediate"

$startTime = Get-Date
$env:RUST_LOG = "error"
& cargo @testArgs 2>&1 | Tee-Object -Variable testOutput

$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)

if ($LASTEXITCODE -eq 0) {
    Write-Ok "All tests passed in ${elapsed}s"
} else {
    Write-Err "Some tests failed (exit code: $LASTEXITCODE)"
}

# ── Parse Results ─────────────────────────────────────────────
$passed = ($testOutput | Select-String "test .+ \.\.\. ok").Count
$failed = ($testOutput | Select-String "FAILED").Count
$ignored = ($testOutput | Select-String "ignored").Count

Write-Header "Test Summary"
Write-Host "  Passed:  $passed" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "  Failed:  $failed" -ForegroundColor Red
}
if ($ignored -gt 0) {
    Write-Host "  Ignored: $ignored" -ForegroundColor Yellow
}
Write-Host "  Time:    ${elapsed}s"

# ── Coverage (optional) ───────────────────────────────────────
if ($Coverage) {
    Write-Header "Code Coverage"
    if (Get-Command "cargo-llvm-cov" -ErrorAction SilentlyContinue) {
        Write-Info "Generating HTML coverage report..."
        & cargo llvm-cov --html --output-dir target/coverage
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Coverage report: target/coverage/index.html"
            if ($IsWindows) {
                Start-Process "target/coverage/index.html"
            }
        }
    } else {
        Write-Info "cargo-llvm-cov not found. Install with:"
        Write-Info "  cargo install cargo-llvm-cov"
    }
}

Write-Host ""
if ($LASTEXITCODE -eq 0) {
    Write-Host "  All tests passed! ✓" -ForegroundColor Green
    exit 0
} else {
    Write-Host "  Tests failed. See output above." -ForegroundColor Red
    exit 1
}
