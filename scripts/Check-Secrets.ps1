#Requires -Version 5.1
<#
.SYNOPSIS
    Secrets/Vulnerability Verification Script for Windows

.DESCRIPTION
    Automated scanning for common security vulnerabilities.
    PowerShell equivalent of check-secrets.sh.

    Patterns detected:
      - AWS Access Keys and Secret Keys
      - Generic API Keys
      - Private Keys (RSA, DSA, EC, OpenSSH)
      - Database Connection Strings
      - Hardcoded Passwords
      - Bearer/JWT Tokens
      - GitHub Tokens
      - Slack Tokens
      - Shell Command Injection Patterns

.PARAMETER Target
    Directory to scan. Defaults to parent of script location.

.PARAMETER Interactive
    Prompt to accept/reject each finding.

.PARAMETER NoFile
    Output to console only, don't create scan results file.

.EXAMPLE
    .\Check-Secrets.ps1
    Scan parent directory

.EXAMPLE
    .\Check-Secrets.ps1 -Interactive C:\Projects\MyApp
    Interactive mode for specific directory

.NOTES
    NIST Control: SA-11 (Developer Testing and Evaluation)

    Exit codes:
      0 = All checks passed (no secrets found, or all reviewed/accepted)
      1 = Potential secrets detected (requires review)

    Allowlist:
      Accepted findings are stored in <target>/.allowlists/secrets-allowlist
      Format: SHA256 hash of content per line
      Allowlisted items are automatically skipped in future scans
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target,

    [Parameter()]
    [switch]$Interactive,

    [Parameter()]
    [switch]$NoFile,

    [Parameter()]
    [Alias('h')]
    [switch]$Help
)

# Show help
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Initialize using init.ps1
$script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$initPath = Join-Path $script:SCRIPT_DIR 'lib/init.ps1'
if (Test-Path $initPath) {
    . $initPath
    Initialize-SecurityToolkit
} else {
    # Fallback if init.ps1 not available
    $script:TIMESTAMP = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $script:TOOLKIT_VERSION = 'unknown'
    $script:TOOLKIT_COMMIT = 'unknown'
    $script:SECURITY_REPO_DIR = Split-Path -Parent $script:SCRIPT_DIR
    $script:AUDIT_AVAILABLE = $false
}

# Set target directory
if ($Target) {
    $TargetDir = $Target
} else {
    $TargetDir = $script:SECURITY_REPO_DIR
}

# Resolve to absolute path
$TargetDir = (Resolve-Path $TargetDir -ErrorAction Stop).Path
$RepoName = Split-Path -Leaf $TargetDir

# Allowlist configuration
$AllowlistDir = Join-Path $TargetDir '.allowlists'
$AllowlistFile = Join-Path $AllowlistDir 'secrets-allowlist'

# Counters
$script:FoundIssues = 0
$script:AcceptedCount = 0
$script:RejectedCount = 0
$script:TotalFindings = 0

# File patterns to scan
$IncludePatterns = @(
    '*.sh', '*.bash', '*.zsh', '*.ps1', '*.psm1', '*.psd1',
    '*.py', '*.js', '*.ts', '*.rb', '*.php', '*.go', '*.rs', '*.java', '*.cs', '*.c', '*.cpp', '*.h',
    '*.yaml', '*.yml', '*.json', '*.xml', '*.toml', '*.ini', '*.conf', '*.config',
    '*.env', '*.env.example', '*.env.local',
    '*.md', '*.tex', '*.txt'
)

# ============================================================================
# Secrets Pattern Definitions
# ============================================================================

$script:SecretsPatterns = [ordered]@{
    'AWS Access Keys' = @{
        Pattern = 'AKIA[0-9A-Z]{16}'
        Severity = 'CRITICAL'
        Description = 'AWS Access Key ID format'
    }
    'AWS Secret Keys' = @{
        Pattern = '[''"][A-Za-z0-9/+=]{40}[''""]'
        Severity = 'CRITICAL'
        Description = 'Potential AWS Secret Access Key - 40 char base64'
    }
    'Generic API Keys' = @{
        Pattern = '(api[_-]?key|apikey)[''"]?\s*[:=]\s*[''"][A-Za-z0-9]{16,}'
        Severity = 'HIGH'
        Description = 'Generic API key assignment'
    }
    'Private Keys' = @{
        Pattern = '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
        Severity = 'CRITICAL'
        Description = 'Private key header'
    }
    'Database Connection Strings' = @{
        Pattern = '(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@'
        Severity = 'CRITICAL'
        Description = 'Database connection string with embedded credentials'
    }
    'Hardcoded Passwords' = @{
        Pattern = '(password|passwd|pwd)[''"]?\s*[:=]\s*[''"][^''"]{8,}'
        Severity = 'HIGH'
        Description = 'Hardcoded password assignment'
    }
    'Bearer Tokens' = @{
        Pattern = 'Bearer\s+[A-Za-z0-9_-]{20,}'
        Severity = 'HIGH'
        Description = 'Bearer token in code'
    }
    'GitHub Tokens' = @{
        Pattern = 'gh[pousr]_[A-Za-z0-9_]{36,}'
        Severity = 'CRITICAL'
        Description = 'GitHub personal access token'
    }
    'Slack Tokens' = @{
        Pattern = 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'
        Severity = 'HIGH'
        Description = 'Slack API token'
    }
    'Shell Command Injection' = @{
        Pattern = 'eval\s+[''"]\$'
        Severity = 'MEDIUM'
        Description = 'Potential shell command injection via eval'
    }
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-ContentHash {
    <#
    .SYNOPSIS
        Compute SHA256 hash for allowlist comparison.
    #>
    param([string]$Content)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $sha256.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace('-', '').ToLower()
}

function Test-IsAllowlisted {
    <#
    .SYNOPSIS
        Check if a finding is in the allowlist.
    #>
    param([string]$Content)

    if (-not (Test-Path $AllowlistFile)) { return $false }

    $hash = Get-ContentHash $Content
    $allowlist = Get-Content $AllowlistFile -ErrorAction SilentlyContinue

    foreach ($line in $allowlist) {
        if ($line -match "^$hash") {
            return $true
        }
    }
    return $false
}

function Add-ToAllowlist {
    <#
    .SYNOPSIS
        Add a finding to the allowlist with reason.
    #>
    param(
        [string]$Content,
        [string]$Reason,
        [string]$FilePath,
        [int]$LineNumber
    )

    # Create directory if needed
    if (-not (Test-Path $AllowlistDir)) {
        New-Item -ItemType Directory -Path $AllowlistDir -Force | Out-Null
    }

    # Create file with header if needed
    if (-not (Test-Path $AllowlistFile)) {
        @(
            "# Secrets Scan Allowlist"
            "# Format: SHA256_HASH # REASON # LOCATION"
            "# Generated by Security Verification Toolkit"
            ""
        ) | Out-File -FilePath $AllowlistFile -Encoding UTF8
    }

    $hash = Get-ContentHash $Content
    $truncated = if ($Content.Length -gt 60) { $Content.Substring(0, 60) + '...' } else { $Content }
    $entry = "$hash # $Reason # ${FilePath}:${LineNumber}: $truncated"

    Add-Content -Path $AllowlistFile -Value $entry
}

function Test-ShouldExclude {
    <#
    .SYNOPSIS
        Check if a path should be excluded from scanning.
    #>
    param([string]$FilePath)

    $excludePatterns = @(
        '.git', '.scans', 'node_modules', '.venv', '__pycache__',
        'venv', 'obj', 'bin', 'publish', '.assessments'
    )

    $normalizedPath = $FilePath.Replace('\', '/')

    foreach ($pattern in $excludePatterns) {
        if ($normalizedPath -like "*/$pattern/*" -or
            $normalizedPath -like "*\$pattern\*" -or
            (Split-Path -Leaf $FilePath) -eq $pattern) {
            return $true
        }
    }

    # Skip scan result files and verification scripts
    $fileName = Split-Path -Leaf $FilePath
    if ($fileName -like "*Scan-Results.md" -or
        $fileName -like "check-*.sh" -or
        $fileName -eq ".secrets-allowlist") {
        return $true
    }

    return $false
}

function Show-ReviewPrompt {
    <#
    .SYNOPSIS
        Display interactive review prompt for a finding.
    #>
    param(
        [string]$CheckName,
        [string]$Severity,
        [string]$FilePath,
        [int]$LineNumber,
        [string]$Content
    )

    $relPath = $FilePath.Replace($TargetDir, '').TrimStart('\', '/')

    Write-Host ""
    Write-Host "  +---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  | REVIEW REQUIRED: $CheckName [$Severity]" -ForegroundColor Yellow
    Write-Host "  +---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  | File: $relPath" -ForegroundColor White
    Write-Host "  | Line: $LineNumber" -ForegroundColor White
    Write-Host "  |" -ForegroundColor Yellow
    Write-Host "  | Content:" -ForegroundColor Yellow
    Write-Host "  |   $Content" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ""

    # Context-aware hints
    if ($CheckName -like "*Command Injection*") {
        Write-Host "  WHY THIS MATCHED:" -ForegroundColor Gray
        Write-Host "    Pattern: eval with variable expansion detected" -ForegroundColor Gray
        Write-Host "    'eval' can be dangerous if used with untrusted input." -ForegroundColor Gray
        Write-Host "    However, 'eval' with controlled internal variables is often safe." -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "  WHY THIS MATCHED:" -ForegroundColor Gray
        Write-Host "    This pattern may indicate hardcoded credentials or secrets." -ForegroundColor Gray
        Write-Host "    Review carefully to ensure no sensitive data is exposed." -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "  OPTIONS:" -ForegroundColor White
    Write-Host "    [A]ccept  - Not a secret. Add to allowlist (custom reason)."
    Write-Host "    [R]eject  - This IS a security issue. Flag for remediation."
    Write-Host "    [S]kip    - Unsure. Leave for later review."
    Write-Host ""
    Write-Host "  QUICK ACCEPT:" -ForegroundColor White
    Write-Host "    [E]xample - Example/placeholder data"
    Write-Host "    [D]ocumentation - Documentation or comments"
    Write-Host "    [I]nternal - Internal/controlled variable (safe eval, etc.)"
    Write-Host "    [T]est - Test fixture or mock data"
    Write-Host ""

    while ($true) {
        $response = Read-Host "  Your decision [A/R/S/E/D/I/T]"

        switch -Regex ($response) {
            '^[Ee]' {
                Add-ToAllowlist -Content $Content -Reason "Example/placeholder data (not real credentials)" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  -> Added to allowlist: Example data" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Dd]' {
                Add-ToAllowlist -Content $Content -Reason "Documentation or pattern explanation" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  -> Added to allowlist: Documentation" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Ii]' {
                Add-ToAllowlist -Content $Content -Reason "Internal/controlled variable assignment" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  -> Added to allowlist: Internal variable" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Tt]' {
                Add-ToAllowlist -Content $Content -Reason "Test fixture or mock data" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  -> Added to allowlist: Test data" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Aa]' {
                $reason = Read-Host "  Reason (required for audit trail)"
                if (-not $reason) {
                    Write-Host "  X Reason is required. Please try again." -ForegroundColor Red
                    continue
                }
                Add-ToAllowlist -Content $Content -Reason $reason -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  -> Added to allowlist" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Rr]' {
                Write-Host "  -> Flagged as security issue" -ForegroundColor Red
                $script:RejectedCount++
                return 'rejected'
            }
            '^[Ss]' {
                Write-Host "  -> Skipped (will require review next time)" -ForegroundColor Yellow
                return 'skipped'
            }
            default {
                Write-Host "  Please enter A, R, S, E, D, I, or T" -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-SecretsCheck {
    <#
    .SYNOPSIS
        Run a secrets pattern check.
    #>
    param(
        [string]$CheckName,
        [string]$Pattern,
        [string]$Severity,
        [string]$Description
    )

    Write-Host "Checking: $CheckName [$Severity]"

    $totalCount = 0
    $newCount = 0
    $allowlistedCount = 0
    $issueCount = 0

    # Get files to scan
    $files = @()
    foreach ($filePattern in $IncludePatterns) {
        $files += Get-ChildItem -Path $TargetDir -Filter $filePattern -Recurse -File -ErrorAction SilentlyContinue |
                  Where-Object { -not (Test-ShouldExclude $_.FullName) }
    }
    $files = $files | Select-Object -Unique

    foreach ($file in $files) {
        try {
            $matches = Select-String -Path $file.FullName -Pattern $Pattern -AllMatches -ErrorAction SilentlyContinue

            foreach ($match in $matches) {
                $totalCount++
                $content = $match.Line.Trim()

                # Check allowlist
                if (Test-IsAllowlisted $content) {
                    $allowlistedCount++
                    continue
                }

                $newCount++
                $script:TotalFindings++

                if ($Interactive) {
                    $result = Show-ReviewPrompt -CheckName $CheckName -Severity $Severity -FilePath $file.FullName -LineNumber $match.LineNumber -Content $content
                    if ($result -ne 'accepted') {
                        $issueCount++
                    }
                } else {
                    if ($newCount -le 5) {
                        $relPath = $file.FullName.Replace($TargetDir, '').TrimStart('\', '/')
                        Write-Host "  ${relPath}:$($match.LineNumber): $content"
                    }
                    $issueCount++
                }
            }
        } catch {
            # Skip files that can't be read
        }
    }

    # Report results
    if ($totalCount -eq 0) {
        Write-Host "  Result: PASS (0 matches)" -ForegroundColor Green
    } elseif ($newCount -eq 0) {
        Write-Host "  Result: PASS ($allowlistedCount allowlisted)" -ForegroundColor Green
    } elseif ($Interactive) {
        if ($issueCount -eq 0) {
            Write-Host "  Result: PASS (all $newCount finding(s) accepted)" -ForegroundColor Green
        } else {
            Write-Host "  Result: REVIEW - $issueCount unresolved finding(s)" -ForegroundColor Yellow
            $script:FoundIssues = 1
        }
    } else {
        Write-Host "  Result: REVIEW - $newCount match(es) found" -ForegroundColor Yellow
        if ($newCount -gt 5) {
            Write-Host "  ... and $($newCount - 5) more"
        }
        if ($allowlistedCount -gt 0) {
            Write-Host "  ($allowlistedCount previously allowlisted)"
        }
        $script:FoundIssues = 1
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "Secrets/Vulnerability Verification Scan"
Write-Host "========================================"
Write-Host "Timestamp: $script:TIMESTAMP"
Write-Host "Toolkit: Security Verification Toolkit $script:TOOLKIT_VERSION ($script:TOOLKIT_COMMIT)"
Write-Host "Target: $TargetDir"
Write-Host "Repository: $RepoName"
Write-Host ""

# Run all checks
foreach ($checkName in $script:SecretsPatterns.Keys) {
    $check = $script:SecretsPatterns[$checkName]
    Invoke-SecretsCheck -CheckName $checkName -Pattern $check.Pattern -Severity $check.Severity -Description $check.Description
}

# Summary
Write-Host ""
Write-Host "========================================"

if ($Interactive) {
    Write-Host "Interactive Review Summary:"
    Write-Host "  Accepted (allowlisted): $script:AcceptedCount"
    Write-Host "  Rejected (flagged):     $script:RejectedCount"
    Write-Host ""
}

if (Test-Path $AllowlistFile) {
    $allowlistCount = (Get-Content $AllowlistFile | Where-Object { $_ -match '^[a-f0-9]' }).Count
    Write-Host "Allowlist: $AllowlistFile ($allowlistCount entries)"
    Write-Host ""
}

if ($script:FoundIssues -eq 0) {
    Write-Host "OVERALL RESULT: PASS" -ForegroundColor Green
    if ($Interactive) {
        Write-Host "All findings reviewed and accepted."
    } else {
        Write-Host "No secrets or vulnerabilities detected."
    }
} else {
    Write-Host "OVERALL RESULT: REVIEW REQUIRED" -ForegroundColor Yellow
    Write-Host "Potential secrets/vulnerabilities detected. Manual review required."
    if (-not $Interactive) {
        Write-Host ""
        Write-Host "Run with -Interactive flag for interactive review:"
        Write-Host "  .\Check-Secrets.ps1 -Interactive $TargetDir"
    }
}

exit $script:FoundIssues
