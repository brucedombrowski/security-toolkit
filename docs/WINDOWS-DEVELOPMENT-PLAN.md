# Windows Development Plan

**Author:** Windows Developer Agent
**Created:** 2026-02-02
**Status:** In Progress (Priorities 1-3, 5 complete)

## Overview

This document outlines the plan for bringing Windows/PowerShell parity to the Security Verification Toolkit. The goal is to enable Windows-native scanning without requiring WSL or bash emulation.

## Priorities

| Priority | Task | Estimated Complexity | Status |
|----------|------|---------------------|--------|
| 1 | Create `scripts/lib/init.ps1` | Low | **Complete** |
| 2 | Port `check-pii.sh` to `Check-PersonalInfo.ps1` | High | **Complete** |
| 3 | Port `check-secrets.sh` to `Check-Secrets.ps1` | Medium | **Complete** |
| 4 | Enhance `Collect-HostInventory.ps1` | Medium | Planned |
| 5 | Create PowerShell test scripts | Low | **Complete** |

## Design Decisions

Decisions confirmed with project lead:

| Decision | Choice | Rationale |
|----------|--------|-----------|
| PowerShell version | Support both 5.1 and 7+ | Maximum compatibility |
| Allowlist format | Cross-platform compatible | Teams using mixed Windows/Unix |
| Audit log file | Same file as bash scripts | Unified audit trail |
| Testing approach | Pester 5.x framework | Industry standard, CI integration, code coverage |
| Security check detail | Detailed (Option B) | Matches existing inventory depth |
| Exclusion config | Same `.pii-exclude` file | One config for all platforms |
| Output styling | Match bash colors | Visual consistency across platforms |

---

## Priority 1: `scripts/lib/init.ps1`

### Purpose
PowerShell equivalent of `init.sh` - centralized initialization for all toolkit PowerShell scripts.

### Features to Implement

```powershell
# Variables to expose after initialization:
$script:LIB_DIR           # Directory containing library files
$script:SCRIPT_DIR        # Directory containing the calling script
$script:SECURITY_REPO_DIR # Root of the security toolkit repository
$script:AUDIT_AVAILABLE   # $true if audit-log.ps1 is loaded
$script:TIMESTAMPS_AVAILABLE
$script:PROGRESS_AVAILABLE
$script:TOOLKIT_AVAILABLE
$script:TIMESTAMP         # Current ISO 8601 UTC timestamp
$script:TOOLKIT_VERSION   # From git tag or config
$script:TOOLKIT_COMMIT    # Short commit hash
```

### Functions to Implement

```powershell
function Initialize-SecurityToolkit { }
function Get-TargetDirectory { param($Arguments) }
function Write-ScriptHeader { param($Name, $Target) }
function Write-LibraryStatus { }  # For debugging
```

### Version Compatibility

```powershell
# PowerShell 5.1 vs 7+ detection
if ($PSVersionTable.PSVersion.Major -ge 7) {
    # Use modern features
} else {
    # 5.1 fallback
}
```

### Template Usage

```powershell
#Requires -Version 5.1
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptDir\lib\init.ps1"
Initialize-SecurityToolkit

$TargetDir = Get-TargetDirectory $args
Write-ScriptHeader -Name "PII Verification Scan" -Target $TargetDir

# ... scan logic ...
```

### Detailed Implementation Plan (Sprint Planning 2026-02-02)

#### Full Implementation Code

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Security Toolkit Initialization Library

.DESCRIPTION
    PowerShell equivalent of init.sh - centralized boilerplate for all toolkit scripts.

.NOTES
    NIST Controls:
      - CM-8 (System Component Inventory): Consistent toolkit identification
      - AU-3 (Content of Audit Records): Standardized source attribution

    Usage:
      $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
      . "$ScriptDir\lib\init.ps1"
      Initialize-SecurityToolkit
#>

# Prevent direct execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Error "This script should be dot-sourced, not executed directly."
    Write-Error "Usage: . `"`$ScriptDir\lib\init.ps1`""
    exit 1
}

# ============================================================================
# Path Resolution
# ============================================================================

$script:LIB_DIR = $PSScriptRoot

# SCRIPT_DIR should be set by caller; provide fallback
if (-not $script:SCRIPT_DIR) {
    $script:SCRIPT_DIR = Split-Path -Parent $LIB_DIR
}

# Repository root is parent of scripts directory
$script:SECURITY_REPO_DIR = Split-Path -Parent $script:SCRIPT_DIR

# ============================================================================
# Library Availability Flags
# ============================================================================

$script:AUDIT_AVAILABLE = $false
$script:TIMESTAMPS_AVAILABLE = $false
$script:PROGRESS_AVAILABLE = $false
$script:TOOLKIT_AVAILABLE = $false

# ============================================================================
# Library Loading
# ============================================================================

$auditPath = Join-Path $LIB_DIR 'audit-log.ps1'
if (Test-Path $auditPath) {
    . $auditPath
    $script:AUDIT_AVAILABLE = $true
}

$timestampsPath = Join-Path $LIB_DIR 'timestamps.ps1'
if (Test-Path $timestampsPath) {
    . $timestampsPath
    $script:TIMESTAMPS_AVAILABLE = $true
}

$progressPath = Join-Path $LIB_DIR 'progress.ps1'
if (Test-Path $progressPath) {
    . $progressPath
    $script:PROGRESS_AVAILABLE = $true
}

$toolkitPath = Join-Path $LIB_DIR 'toolkit-info.ps1'
if (Test-Path $toolkitPath) {
    . $toolkitPath
    $script:TOOLKIT_AVAILABLE = $true
}

# ============================================================================
# Initialization Function
# ============================================================================

function Initialize-SecurityToolkit {
    <#
    .SYNOPSIS
        Initialize the security toolkit environment.
    .DESCRIPTION
        Sets up common variables: TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT
    #>

    # Initialize toolkit info
    if ($script:TOOLKIT_AVAILABLE) {
        Initialize-ToolkitInfo -RepoRoot $script:SECURITY_REPO_DIR
    } else {
        # Fallback if toolkit-info.ps1 not available
        try {
            $script:TOOLKIT_VERSION = git -C $script:SECURITY_REPO_DIR describe --tags --always 2>$null
            if (-not $script:TOOLKIT_VERSION) { $script:TOOLKIT_VERSION = 'unknown' }
        } catch {
            $script:TOOLKIT_VERSION = 'unknown'
        }

        try {
            $script:TOOLKIT_COMMIT = git -C $script:SECURITY_REPO_DIR rev-parse --short HEAD 2>$null
            if (-not $script:TOOLKIT_COMMIT) { $script:TOOLKIT_COMMIT = 'unknown' }
        } catch {
            $script:TOOLKIT_COMMIT = 'unknown'
        }
    }

    # Set timestamp (ISO 8601 UTC)
    if ($script:TIMESTAMPS_AVAILABLE) {
        $script:TIMESTAMP = Get-IsoTimestamp
    } else {
        $script:TIMESTAMP = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

# ============================================================================
# Target Directory Helper
# ============================================================================

function Get-TargetDirectory {
    <#
    .SYNOPSIS
        Parse target directory from arguments or use default.
    .PARAMETER Arguments
        Script arguments array
    .OUTPUTS
        Target directory path (defaults to SECURITY_REPO_DIR)
    #>
    param(
        [Parameter(Position = 0)]
        [string[]]$Arguments
    )

    foreach ($arg in $Arguments) {
        # Skip flags
        if ($arg -notlike '-*') {
            return $arg
        }
    }

    return $script:SECURITY_REPO_DIR
}

# ============================================================================
# Output Helpers
# ============================================================================

function Write-ScriptHeader {
    <#
    .SYNOPSIS
        Print script header with consistent formatting.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Target = $script:SECURITY_REPO_DIR
    )

    $repoName = Split-Path -Leaf $Target
    $separator = '=' * $Name.Length

    Write-Host $Name
    Write-Host $separator
    Write-Host "Timestamp: $script:TIMESTAMP"
    Write-Host "Target: $Target"
    Write-Host "Toolkit: $script:TOOLKIT_VERSION ($script:TOOLKIT_COMMIT)"
    Write-Host ''
}

function Write-LibraryStatus {
    <#
    .SYNOPSIS
        Print which libraries are loaded (for debugging).
    #>
    Write-Host 'Library Status:'
    Write-Host "  audit-log.ps1:    $(if ($script:AUDIT_AVAILABLE) { 'loaded' } else { 'not found' })"
    Write-Host "  timestamps.ps1:   $(if ($script:TIMESTAMPS_AVAILABLE) { 'loaded' } else { 'not found' })"
    Write-Host "  progress.ps1:     $(if ($script:PROGRESS_AVAILABLE) { 'loaded' } else { 'not found' })"
    Write-Host "  toolkit-info.ps1: $(if ($script:TOOLKIT_AVAILABLE) { 'loaded' } else { 'not found' })"
}
```

#### Edge Cases to Handle

| Case | Bash Behavior | PowerShell Implementation |
|------|---------------|---------------------------|
| Git not installed | Returns "unknown" | Try/catch, return "unknown" |
| Not in git repo | Returns "unknown" | Try/catch, return "unknown" |
| Library file missing | Sets flag to 0 | Sets flag to $false |
| Direct execution | Prints error, exits 1 | Same behavior |
| SCRIPT_DIR not set | Uses fallback | Uses fallback |

#### Testing Requirements

Tests for `Init-Lib.Tests.ps1`:

```powershell
Describe 'Initialize-SecurityToolkit' {
    Context 'when in a git repository' {
        It 'sets TOOLKIT_VERSION from git describe' { }
        It 'sets TOOLKIT_COMMIT from git rev-parse' { }
        It 'sets TIMESTAMP in ISO 8601 format' { }
    }

    Context 'when git is not available' {
        It 'sets TOOLKIT_VERSION to unknown' { }
        It 'sets TOOLKIT_COMMIT to unknown' { }
    }
}

Describe 'Get-TargetDirectory' {
    It 'returns first non-flag argument' { }
    It 'returns SECURITY_REPO_DIR when no args' { }
    It 'skips -flag arguments' { }
}

Describe 'Write-ScriptHeader' {
    It 'outputs formatted header' { }
}
```

#### CI Integration Requirements (for Issue #6)

The Windows CI runner needs to:

1. **Install Pester 5.x** (if not present):
   ```yaml
   - name: Install Pester
     shell: pwsh
     run: |
       if (-not (Get-Module -ListAvailable Pester | Where-Object Version -ge 5.0)) {
         Install-Module Pester -Force -Scope CurrentUser -MinimumVersion 5.0
       }
   ```

2. **Run PowerShell tests**:
   ```yaml
   - name: Run PowerShell Tests
     shell: pwsh
     run: ./tests/powershell/Invoke-AllTests.ps1 -CI
   ```

3. **Test Git availability** (Git for Windows should be pre-installed on `windows-latest`)

---

## Priority 2: `Check-PII.ps1`

### Source Analysis

Porting from `check-pii.sh` (694 lines). Key components:

| Component | Bash Implementation | PowerShell Approach |
|-----------|--------------------|--------------------|
| Pattern matching | `grep -E` | `Select-String -Pattern` |
| File discovery | `find` with exclusions | `Get-ChildItem -Recurse -Exclude` |
| SHA256 hashing | `shasum -a 256` | `[System.Security.Cryptography.SHA256]::Create()` |
| Interactive prompts | `read -r` | `Read-Host` |
| Colored output | ANSI codes | `Write-Host -ForegroundColor` |
| Exit codes | `exit $FOUND_ISSUES` | `exit $FOUND_ISSUES` |

### Patterns to Port

```powershell
$Patterns = @{
    'IPv4 Addresses' = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    'US Phone (dashed)' = '\d{3}-\d{3}-\d{4}'
    'US Phone (dotted)' = '\d{3}\.\d{3}\.\d{4}'
    'US Phone (parens)' = '\(\d{3}\)\s*\d{3}[-. ]\d{4}'
    'International Phone' = '\+\d{1,3}[ .-]?\d{1,4}[ .-]?\d{1,4}[ .-]?\d{1,4}[ .-]?\d{0,4}'
    'SSN' = '\d{3}-\d{2}-\d{4}'
    'Credit Card' = '\d{4}[-. ]?\d{4}[-. ]?\d{4}[-. ]?\d{4}'
}
```

### Luhn Algorithm Implementation

```powershell
function Test-LuhnChecksum {
    param([string]$Number)

    $Number = $Number -replace '[ .-]', ''
    if ($Number -notmatch '^\d+$') { return $false }

    $sum = 0
    $isSecond = $false

    for ($i = $Number.Length - 1; $i -ge 0; $i--) {
        $digit = [int]::Parse($Number[$i])

        if ($isSecond) {
            $digit *= 2
            if ($digit -gt 9) { $digit -= 9 }
        }

        $sum += $digit
        $isSecond = -not $isSecond
    }

    return ($sum % 10) -eq 0
}
```

### Allowlist Compatibility

```powershell
function Get-FindingHash {
    param([string]$Content)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $sha256.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace('-', '').ToLower()
}

# Produces identical hash to: echo -n "$content" | shasum -a 256
```

### File Type Filtering

```powershell
$IncludePatterns = @(
    '*.md', '*.txt', '*.tex', '*.rst',
    '*.sh', '*.bash', '*.zsh', '*.ps1', '*.psm1',
    '*.py', '*.js', '*.ts', '*.rb', '*.php', '*.go', '*.rs', '*.java', '*.cs', '*.c', '*.cpp', '*.h',
    '*.yaml', '*.yml', '*.json', '*.xml', '*.toml', '*.ini', '*.conf', '*.config',
    '*.html', '*.css', '*.scss',
    '*.sql',
    '*.env', '*.env.example'
)
```

### Exclusion Parsing (from `.pii-exclude`)

```powershell
function Get-Exclusions {
    param([string]$TargetDir)

    $excludeFile = Join-Path $TargetDir '.pii-exclude'
    $exclusions = @()

    if (Test-Path $excludeFile) {
        Get-Content $excludeFile | ForEach-Object {
            $line = $_.Trim()
            # Skip comments and empty lines
            if ($line -and -not $line.StartsWith('#')) {
                # Normalize path separators
                $exclusions += $line.Replace('\', '/')
            }
        }
    } else {
        # Defaults
        $exclusions = @('.git', '.scans')
    }

    return $exclusions
}
```

---

## Priority 3: `Check-Secrets.ps1`

### Patterns to Port

```powershell
$SecretPatterns = @{
    'AWS Access Keys' = @{
        Pattern = 'AKIA[0-9A-Z]{16}'
        Severity = 'CRITICAL'
    }
    'AWS Secret Keys' = @{
        Pattern = "['\"][A-Za-z0-9/+=]{40}['\"]"
        Severity = 'CRITICAL'
    }
    'Generic API Keys' = @{
        Pattern = "(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{16,}"
        Severity = 'HIGH'
    }
    'Private Keys' = @{
        Pattern = '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
        Severity = 'CRITICAL'
    }
    'Database Connection Strings' = @{
        Pattern = '(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@'
        Severity = 'CRITICAL'
    }
    'Hardcoded Passwords' = @{
        Pattern = "(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}"
        Severity = 'HIGH'
    }
    'Bearer Tokens' = @{
        Pattern = 'Bearer\s+[A-Za-z0-9_-]{20,}'
        Severity = 'HIGH'
    }
    'GitHub Tokens' = @{
        Pattern = 'gh[pousr]_[A-Za-z0-9_]{36,}'
        Severity = 'CRITICAL'
    }
    'Slack Tokens' = @{
        Pattern = 'xox[baprs]-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}'
        Severity = 'HIGH'
    }
    'Shell Command Injection' = @{
        Pattern = 'eval\s+"\$'
        Severity = 'MEDIUM'
    }
}
```

### Structure

Same overall structure as `Check-PII.ps1`:
- Interactive mode (`-Interactive` switch)
- Allowlist support (`.allowlists/secrets-allowlist`)
- Audit logging integration
- Colored output with severity indicators

---

## Priority 4: `Collect-HostInventory.ps1` Enhancements

### New Sections to Add

#### Windows Defender (Enhanced)

```powershell
function Get-DefenderStatus {
    if (-not $isAdmin) {
        Write-Output-Line "  Windows Defender: requires elevation for full details"
        return
    }

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $mpPrefs = Get-MpPreference -ErrorAction Stop

        Write-Output-Line "Windows Defender:"
        Write-Output-Line "  Status: $(if ($mpStatus.AntivirusEnabled) { 'Enabled' } else { 'Disabled' })"
        Write-Output-Line "  Engine Version: $($mpStatus.AMEngineVersion)"
        Write-Output-Line "  Signature Version: $($mpStatus.AntivirusSignatureVersion)"
        Write-Output-Line "  Signature Last Updated: $($mpStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        Write-Output-Line "  Real-time Protection: $($mpStatus.RealTimeProtectionEnabled)"
        Write-Output-Line "  Cloud Protection: $($mpPrefs.MAPSReporting -ne 0)"
        Write-Output-Line "  Behavior Monitoring: $($mpStatus.BehaviorMonitorEnabled)"
        Write-Output-Line "  Last Full Scan: $($mpStatus.FullScanEndTime)"
        Write-Output-Line "  Last Quick Scan: $($mpStatus.QuickScanEndTime)"

        # Recent threats
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
                   Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) }
        Write-Output-Line "  Threats Detected (30 days): $(@($threats).Count)"
    } catch {
        Write-Output-Line "  Windows Defender: unable to query ($($_.Exception.Message))"
    }
}
```

#### BitLocker Status

```powershell
function Get-BitLockerStatus {
    if (-not $isAdmin) {
        Write-Output-Line "BitLocker Encryption: requires elevation"
        return
    }

    Write-Output-Line "BitLocker Encryption:"

    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop

        foreach ($vol in $volumes) {
            $label = if ($vol.VolumeType -eq 'OperatingSystem') { 'System' } else { $vol.MountPoint }
            Write-Output-Line "  $($vol.MountPoint) ($label):"
            Write-Output-Line "    Volume Status: $($vol.VolumeStatus)"
            Write-Output-Line "    Protection Status: $($vol.ProtectionStatus)"

            if ($vol.VolumeStatus -ne 'FullyDecrypted') {
                Write-Output-Line "    Encryption Method: $($vol.EncryptionMethod)"
                Write-Output-Line "    Encryption Percentage: $($vol.EncryptionPercentage)%"

                $protectors = ($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
                Write-Output-Line "    Key Protectors: $protectors"
            }
        }
    } catch {
        Write-Output-Line "  BitLocker: unable to query ($($_.Exception.Message))"
    }
}
```

#### Windows Firewall

```powershell
function Get-FirewallStatus {
    Write-Output-Line "Windows Firewall:"

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop

        foreach ($profile in $profiles) {
            Write-Output-Line "  $($profile.Name) Profile:"
            Write-Output-Line "    Enabled: $(if ($profile.Enabled) { 'Yes' } else { 'No' })"
            Write-Output-Line "    Default Inbound: $($profile.DefaultInboundAction)"
            Write-Output-Line "    Default Outbound: $($profile.DefaultOutboundAction)"
            Write-Output-Line "    Log Allowed: $($profile.LogAllowed)"
            Write-Output-Line "    Log Blocked: $($profile.LogBlocked)"

            if ($profile.LogFileName) {
                Write-Output-Line "    Log File: $($profile.LogFileName)"
            }
        }

        # Rule summary
        $inbound = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue
        $outbound = Get-NetFirewallRule -Direction Outbound -ErrorAction SilentlyContinue

        $inboundEnabled = @($inbound | Where-Object { $_.Enabled -eq 'True' }).Count
        $outboundEnabled = @($outbound | Where-Object { $_.Enabled -eq 'True' }).Count

        Write-Output-Line "  Active Rules Summary:"
        Write-Output-Line "    Inbound: $(@($inbound).Count) ($inboundEnabled enabled)"
        Write-Output-Line "    Outbound: $(@($outbound).Count) ($outboundEnabled enabled)"
    } catch {
        Write-Output-Line "  Windows Firewall: unable to query ($($_.Exception.Message))"
    }
}
```

---

## Priority 5: PowerShell Test Scripts

**Status:** Infrastructure complete (Sprint 2026-02-02)

### Testing Framework: Pester

After research, we're using **Pester 5.x** (the standard PowerShell testing framework) instead of bash-style scripts. Benefits:

- Built into Windows 10+ (no installation required for basic use)
- Rich assertion library with `Should` syntax
- Native CI/CD integration (GitHub Actions, Azure DevOps)
- Code coverage reporting
- Tag-based test filtering

### Directory Structure (Created)

```
tests/powershell/
├── Invoke-AllTests.ps1      # Test runner (mirrors run-all-tests.sh)
├── Check-PII.Tests.ps1      # PII pattern tests (Pester)
├── Check-Secrets.Tests.ps1  # Secrets pattern tests (Pester)
├── README.md                # Usage documentation
└── fixtures/                # Test data files
```

### Pester Test Structure

```powershell
#Requires -Version 5.1

BeforeAll {
    $script:TestDir = $PSScriptRoot
    $script:RepoDir = Split-Path -Parent (Split-Path -Parent $TestDir)

    # Patterns to test
    $script:Patterns = @{
        SSN = '\d{3}-\d{2}-\d{4}'
    }
}

Describe 'SSN Detection' {
    Context 'when input contains valid SSN format' {
        It 'detects SSN (123-45-6789)' {
            '123-45-6789' | Should -Match $script:Patterns.SSN
        }
    }

    Context 'when input contains invalid format' {
        It 'rejects non-dashed SSN (123456789)' {
            '123456789' | Should -Not -Match $script:Patterns.SSN
        }
    }
}
```

### Running Tests

```powershell
# Run all tests
./tests/powershell/Invoke-AllTests.ps1

# Run with detailed output
./tests/powershell/Invoke-AllTests.ps1 -OutputFormat Detailed

# CI mode (minimal output, exit on fail)
./tests/powershell/Invoke-AllTests.ps1 -CI

# Run specific file
Invoke-Pester -Path ./tests/powershell/Check-PII.Tests.ps1 -Output Detailed

# Run by tag
./tests/powershell/Invoke-AllTests.ps1 -Tags 'Integration'
```

### Test Files to Create (Next Sprint)

| Test File | Tests For | Status |
|-----------|-----------|--------|
| Check-PersonalInfo.Tests.ps1 | Check-PersonalInfo.ps1 | **Complete** |
| Check-Secrets.Tests.ps1 | Check-Secrets.ps1 | **Complete** |
| Init-Lib.Tests.ps1 | init.ps1 | **Complete** |
| Collect-HostInventory.Tests.ps1 | Inventory enhancements | Planned |

### Pester Quick Reference

```powershell
# Assertions
$value | Should -Be 'expected'           # Exact equality
$value | Should -Match 'pattern'         # Regex match
$value | Should -Not -Match 'pattern'    # Regex non-match
$value | Should -BeTrue                  # Boolean true
{ code } | Should -Throw                 # Throws exception
Test-Path $file | Should -BeTrue         # File exists

# Tags and Skip
Describe 'Feature' -Tag 'Integration' { }
It 'known limitation' -Skip { }
```

### CI Integration

```yaml
# GitHub Actions example
- name: Run PowerShell Tests
  shell: pwsh
  run: |
    ./tests/powershell/Invoke-AllTests.ps1 -CI
```

---

## Output Styling

### Color Scheme (matching bash)

```powershell
function Write-Pass {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Header {
    param([string]$Title)
    Write-Host $Title -ForegroundColor White
    Write-Host ('=' * $Title.Length) -ForegroundColor White
}
```

### CI/CD Detection

```powershell
function Test-CIEnvironment {
    # Common CI environment variables
    return $env:CI -or $env:TF_BUILD -or $env:GITHUB_ACTIONS -or $env:JENKINS_URL
}

# Disable colors in CI if needed
if (Test-CIEnvironment) {
    $Host.UI.RawUI.ForegroundColor = 'White'
}
```

---

## Testing Matrix

### Target Platforms

| Platform | PowerShell Version | Priority |
|----------|-------------------|----------|
| Windows 10 21H2+ | 5.1 (built-in) | High |
| Windows 10 21H2+ | 7.x | Medium |
| Windows 11 22H2+ | 5.1 (built-in) | High |
| Windows 11 22H2+ | 7.x | Medium |
| Windows Server 2019 | 5.1 (built-in) | High |
| Windows Server 2022 | 5.1 (built-in) | High |

### Test Scenarios

1. **Non-elevated execution** - graceful degradation
2. **Elevated execution** - full feature access
3. **CI/CD environment** - proper exit codes, no interactive prompts
4. **Mixed team** - allowlists shared with bash users

### Bash to PowerShell Test Mapping

Tests that need PowerShell equivalents (for ported scripts):

| Bash Test | PowerShell Test | Script Being Tested | Status |
|-----------|-----------------|---------------------|--------|
| test-pii-patterns.sh | Check-PersonalInfo.Tests.ps1 | Check-PersonalInfo.ps1 | **Complete** |
| test-secrets-patterns.sh | Check-Secrets.Tests.ps1 | Check-Secrets.ps1 | **Complete** |
| test-mac-patterns.sh | Check-MAC.Tests.ps1 | (future) | Planned |
| test-audit-logging.sh | Audit-Log.Tests.ps1 | audit-log.ps1 | Planned |
| test-timestamps.sh | Timestamps.Tests.ps1 | timestamps.ps1 | Planned |
| (new) | Init-Lib.Tests.ps1 | init.ps1 | **Complete** |
| (new) | Collect-HostInventory.Tests.ps1 | Collect-HostInventory.ps1 | Planned |

Tests that remain Unix-only (no PowerShell equivalent needed):

| Bash Test | Reason |
|-----------|--------|
| test-secure-delete.sh | Uses Unix-specific shred/srm commands |
| test-run-all-scans.sh | Bash orchestration script |
| test-inventory-modules.sh | Bash-specific inventory modules |
| test-scanner-modules.sh | Unix scanner tools (Nmap, Lynis) |
| test-integration.sh | Bash integration workflow |
| test-nvd-cves.sh | Bash NVD API client |
| test-check-kev.sh | Bash KEV client |

---

## Dependencies

### Required (Built-in)
- PowerShell 5.1+ (included in Windows 10+)
- Git for Windows (for version detection)

### Optional (For enhanced features)
- Administrator privileges (for Defender/BitLocker/Firewall details)

### Not Required
- No external modules
- No package manager dependencies
- No compilation step

---

## File Deliverables

### Completed

```
scripts/
├── Check-PersonalInfo.ps1     # DONE - PII detection (Priority 2)
├── Check-Secrets.ps1          # DONE - Secrets detection (Priority 3)
├── Collect-HostInventory.ps1  # EXISTS - Windows inventory
└── lib/
    └── init.ps1               # DONE - Initialization library (Priority 1)

tests/powershell/
├── Invoke-AllTests.ps1            # DONE - Test runner
├── Init-Lib.Tests.ps1            # DONE - init.ps1 unit tests
├── Check-PersonalInfo.Tests.ps1  # DONE - PII pattern tests (Pester)
├── Check-Secrets.Tests.ps1       # DONE - Secrets pattern tests (Pester)
├── README.md                     # DONE - Usage documentation
└── fixtures/                     # DONE - Test data directory
```

### Planned (Future Sprints)

```
scripts/
├── Collect-HostInventory.ps1  # Priority 4 (enhanced security sections)
└── lib/
    ├── audit-log.ps1          # Optional (for audit integration)
    └── timestamps.ps1         # Optional (for timestamp utilities)

tests/powershell/
└── Collect-HostInventory.Tests.ps1  # Tests for inventory enhancements
```

---

## Open Questions

1. ~~PowerShell version target~~ **Resolved: Both 5.1 and 7+**
2. ~~Allowlist compatibility~~ **Resolved: Cross-platform**
3. ~~Audit log file~~ **Resolved: Same file as bash**
4. ~~Testing approach~~ **Resolved: Pester 5.x framework**
5. ~~Output styling~~ **Resolved: Match bash colors**

---

## CI Coordination (Issue #6)

Requirements for Windows CI runner (for LSE 2):

### Recommended Windows CI Job

```yaml
# Add to .github/workflows/ci.yml
windows-powershell:
  name: PowerShell Tests (Windows)
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4

    - name: Check PowerShell Version
      shell: pwsh
      run: |
        Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)"
        Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"

    - name: Check Pester Version
      shell: pwsh
      run: |
        $pester = Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1
        if ($pester.Version.Major -lt 5) {
          Write-Host "Installing Pester 5.x..."
          Install-Module Pester -Force -Scope CurrentUser -MinimumVersion 5.0
        }
        Import-Module Pester -PassThru

    - name: Run PowerShell Tests
      shell: pwsh
      run: |
        ./tests/powershell/Invoke-AllTests.ps1 -CI

    - name: Check Git Availability
      shell: pwsh
      run: |
        # Verify git works (needed for init.ps1)
        git --version
        git describe --tags --always
```

### Windows-Specific Considerations

| Item | Notes |
|------|-------|
| Shell | Use `shell: pwsh` for PowerShell Core, `shell: powershell` for 5.1 |
| Path separators | Use `Join-Path` instead of hardcoded `/` or `\` |
| Line endings | Git should handle via `.gitattributes` |
| Git for Windows | Pre-installed on `windows-latest` |
| Pester | 3.x pre-installed, need to upgrade to 5.x |

### Test Matrix (Optional Enhancement)

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    include:
      - os: windows-latest
        shell: pwsh
        test_cmd: ./tests/powershell/Invoke-AllTests.ps1 -CI
      - os: ubuntu-latest
        shell: bash
        test_cmd: ./tests/run-all-tests.sh
      - os: macos-latest
        shell: bash
        test_cmd: ./tests/run-all-tests.sh
```

---

## Next Steps

1. ~~Prepare PowerShell test infrastructure~~ **Done (Sprint 2026-02-02)**
2. ~~Implement Priority 1 (`init.ps1`)~~ **Done**
3. ~~Implement Priority 2 (`Check-PersonalInfo.ps1`)~~ **Done**
4. ~~Implement Priority 3 (`Check-Secrets.ps1`)~~ **Done**
5. ~~Create Pester tests for init.ps1, Check-PersonalInfo, Check-Secrets~~ **Done**
6. Add Windows CI runner to GitHub Actions (Issue #6) - see CI Coordination section above
7. Implement Priority 4 (`Collect-HostInventory.ps1` enhancements)
8. Test on Windows 10 and Windows 11
9. Create PR for review

---

*Document will be updated as implementation progresses.*
