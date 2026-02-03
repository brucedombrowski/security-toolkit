#Requires -Version 5.1
<#
.SYNOPSIS
    Run all PowerShell Pester tests for the Security Toolkit.

.DESCRIPTION
    Discovers and runs all *.Tests.ps1 files in the PowerShell test directory.
    Outputs results in detailed format and exits with appropriate code.

.PARAMETER OutputFormat
    Output format for results. Default is 'Detailed'.
    Options: None, Minimal, Normal, Detailed, Diagnostic

.PARAMETER Tags
    Only run tests with these tags.

.PARAMETER ExcludeTags
    Exclude tests with these tags.

.PARAMETER CI
    Run in CI mode (minimal output, fail fast).

.EXAMPLE
    ./Invoke-AllTests.ps1
    Run all tests with detailed output.

.EXAMPLE
    ./Invoke-AllTests.ps1 -CI
    Run all tests in CI mode.

.EXAMPLE
    ./Invoke-AllTests.ps1 -Tags 'Integration'
    Run only integration tests.

.EXAMPLE
    ./Invoke-AllTests.ps1 -ExcludeTags 'Known'
    Run all tests except known limitations.

.NOTES
    Requires Pester module (built into Windows 10+ or install via Install-Module Pester)
#>

[CmdletBinding()]
param(
    [ValidateSet('None', 'Minimal', 'Normal', 'Detailed', 'Diagnostic')]
    [string]$OutputFormat = 'Detailed',

    [string[]]$Tags,

    [string[]]$ExcludeTags,

    [switch]$CI
)

$ErrorActionPreference = 'Stop'

# Script paths
$TestDir = $PSScriptRoot
$RepoDir = Split-Path -Parent (Split-Path -Parent $TestDir)

# Header
Write-Host ''
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Security Toolkit - PowerShell Test Runner' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "Repository: $RepoDir"
Write-Host "Test Directory: $TestDir"
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
Write-Host ''

# Check for Pester module
$pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1

if (-not $pester) {
    Write-Host 'ERROR: Pester module not found.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Install Pester with:' -ForegroundColor Yellow
    Write-Host '  Install-Module Pester -Force -Scope CurrentUser'
    Write-Host ''
    exit 1
}

# Check Pester version (need 5.0+ for modern syntax)
if ($pester.Version.Major -lt 5) {
    Write-Host "WARNING: Pester $($pester.Version) detected. Version 5.0+ recommended." -ForegroundColor Yellow
    Write-Host 'Upgrade with: Install-Module Pester -Force -Scope CurrentUser' -ForegroundColor Yellow
    Write-Host ''
}

Write-Host "Pester Version: $($pester.Version)" -ForegroundColor Gray
Write-Host ''

# Import Pester
Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

# Build Pester configuration
$config = New-PesterConfiguration

# Discovery - Pester auto-discovers *.Tests.ps1 files in the path
$config.Run.Path = $TestDir

# Output
if ($CI) {
    $config.Output.Verbosity = 'Minimal'
    $config.Run.Exit = $true
} else {
    $config.Output.Verbosity = $OutputFormat
}

# Tags
if ($Tags) {
    $config.Filter.Tag = $Tags
}
if ($ExcludeTags) {
    $config.Filter.ExcludeTag = $ExcludeTags
}

# Run tests
Write-Host 'Running tests...' -ForegroundColor Cyan
Write-Host ''

$result = Invoke-Pester -Configuration $config

# Summary
Write-Host ''
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host 'Test Summary' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Total:   $($result.TotalCount)"
Write-Host "  Passed:  $($result.PassedCount)" -ForegroundColor Green
Write-Host "  Failed:  $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "  NotRun:  $($result.NotRunCount)" -ForegroundColor $(if ($result.NotRunCount -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ''

# Determine exit status
if ($result.FailedCount -gt 0) {
    Write-Host "$($result.FailedCount) test(s) failed" -ForegroundColor Red
    exit 1
} elseif ($result.NotRunCount -gt 0 -and $result.PassedCount -eq 0) {
    Write-Host "No tests ran ($($result.NotRunCount) not run)" -ForegroundColor Red
    exit 1
} elseif ($result.TotalCount -eq 0) {
    Write-Host 'No tests found!' -ForegroundColor Red
    exit 1
} else {
    Write-Host 'All tests passed!' -ForegroundColor Green
    exit 0
}
