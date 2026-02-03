#Requires -Version 5.1
<#
.SYNOPSIS
    Security Toolkit Initialization Library

.DESCRIPTION
    PowerShell equivalent of init.sh - centralized boilerplate for all toolkit scripts.

    After dot-sourcing, these variables are available:
      $script:SCRIPT_DIR          - Directory containing the calling script
      $script:SECURITY_REPO_DIR   - Root of the security toolkit repository
      $script:LIB_DIR             - Directory containing library files
      $script:AUDIT_AVAILABLE     - $true if audit-log.ps1 is loaded
      $script:TIMESTAMPS_AVAILABLE - $true if timestamps.ps1 is loaded
      $script:PROGRESS_AVAILABLE  - $true if progress.ps1 is loaded
      $script:TOOLKIT_AVAILABLE   - $true if toolkit-info.ps1 is loaded
      $script:TIMESTAMP           - Current ISO 8601 UTC timestamp
      $script:TOOLKIT_VERSION     - Toolkit version (from git tag or config)
      $script:TOOLKIT_COMMIT      - Toolkit commit hash (short)

.NOTES
    NIST Controls:
      - CM-8 (System Component Inventory): Consistent toolkit identification
      - AU-3 (Content of Audit Records): Standardized source attribution

    Usage:
      $script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
      . "$script:SCRIPT_DIR\lib\init.ps1"
      Initialize-SecurityToolkit
#>

# Prevent direct execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Error "This script should be dot-sourced, not executed directly."
    Write-Error 'Usage: . "$SCRIPT_DIR\lib\init.ps1"'
    exit 1
}

# ============================================================================
# Path Resolution
# ============================================================================

# Determine library directory from this file's location
$script:LIB_DIR = $PSScriptRoot

# SCRIPT_DIR should be set by the calling script before sourcing
if (-not $script:SCRIPT_DIR) {
    # Fallback: assume caller is in scripts/ directory
    $script:SCRIPT_DIR = Split-Path -Parent $script:LIB_DIR
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

# Source audit logging library
$auditPath = Join-Path $script:LIB_DIR 'audit-log.ps1'
if (Test-Path $auditPath) {
    . $auditPath
    $script:AUDIT_AVAILABLE = $true
}

# Source timestamp utilities
$timestampsPath = Join-Path $script:LIB_DIR 'timestamps.ps1'
if (Test-Path $timestampsPath) {
    . $timestampsPath
    $script:TIMESTAMPS_AVAILABLE = $true
}

# Source progress indicators
$progressPath = Join-Path $script:LIB_DIR 'progress.ps1'
if (Test-Path $progressPath) {
    . $progressPath
    $script:PROGRESS_AVAILABLE = $true
}

# Source toolkit info
$toolkitPath = Join-Path $script:LIB_DIR 'toolkit-info.ps1'
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
        Sets up common variables: TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT.
        Call this after dot-sourcing init.ps1.

    .EXAMPLE
        $script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
        . "$script:SCRIPT_DIR\lib\init.ps1"
        Initialize-SecurityToolkit
    #>

    # Initialize toolkit info (version, commit)
    if ($script:TOOLKIT_AVAILABLE) {
        Initialize-ToolkitInfo -RepoRoot $script:SECURITY_REPO_DIR
    } else {
        # Fallback if toolkit-info.ps1 not available
        try {
            $script:TOOLKIT_VERSION = & git -C $script:SECURITY_REPO_DIR describe --tags --always 2>$null
            if (-not $script:TOOLKIT_VERSION) { $script:TOOLKIT_VERSION = 'unknown' }
        } catch {
            $script:TOOLKIT_VERSION = 'unknown'
        }

        try {
            $script:TOOLKIT_COMMIT = & git -C $script:SECURITY_REPO_DIR rev-parse --short HEAD 2>$null
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
        Script arguments array (looks for first non-flag argument)

    .OUTPUTS
        Target directory path (defaults to SECURITY_REPO_DIR)

    .EXAMPLE
        $TargetDir = Get-TargetDirectory $args
    #>
    param(
        [Parameter(Position = 0)]
        [string[]]$Arguments
    )

    foreach ($arg in $Arguments) {
        # Skip flags (arguments starting with -)
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

    .PARAMETER Name
        The name/title of the script

    .PARAMETER Target
        Target directory being scanned (defaults to SECURITY_REPO_DIR)

    .EXAMPLE
        Write-ScriptHeader -Name "PII Verification Scan" -Target $TargetDir
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Target = $script:SECURITY_REPO_DIR
    )

    $separator = '=' * $Name.Length

    Write-Host $Name
    Write-Host $separator
    Write-Host "Timestamp: $script:TIMESTAMP"
    Write-Host "Target: $Target"
    Write-Host "Toolkit: $script:TOOLKIT_VERSION ($script:TOOLKIT_COMMIT)"
    Write-Host ''
}

# ============================================================================
# Library Status (for debugging)
# ============================================================================

function Write-LibraryStatus {
    <#
    .SYNOPSIS
        Print which libraries are loaded (for debugging).

    .EXAMPLE
        Write-LibraryStatus
    #>
    Write-Host 'Library Status:'
    Write-Host "  audit-log.ps1:    $(if ($script:AUDIT_AVAILABLE) { 'loaded' } else { 'not found' })"
    Write-Host "  timestamps.ps1:   $(if ($script:TIMESTAMPS_AVAILABLE) { 'loaded' } else { 'not found' })"
    Write-Host "  progress.ps1:     $(if ($script:PROGRESS_AVAILABLE) { 'loaded' } else { 'not found' })"
    Write-Host "  toolkit-info.ps1: $(if ($script:TOOLKIT_AVAILABLE) { 'loaded' } else { 'not found' })"
}

# ============================================================================
# Color Output Helpers (matching bash)
# ============================================================================

function Write-Pass {
    <#
    .SYNOPSIS
        Write a success message in green.
    #>
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Fail {
    <#
    .SYNOPSIS
        Write a failure message in red.
    #>
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Write-WarningMessage {
    <#
    .SYNOPSIS
        Write a warning message in yellow.
    #>
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Info {
    <#
    .SYNOPSIS
        Write an info message in cyan.
    #>
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

# ============================================================================
# CI/CD Detection
# ============================================================================

function Test-CIEnvironment {
    <#
    .SYNOPSIS
        Detect if running in a CI/CD environment.

    .OUTPUTS
        $true if running in CI, $false otherwise
    #>
    return [bool]($env:CI -or $env:TF_BUILD -or $env:GITHUB_ACTIONS -or $env:JENKINS_URL -or $env:GITLAB_CI)
}
