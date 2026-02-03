#Requires -Version 5.1
<#
.SYNOPSIS
    PII Verification Script for Windows

.DESCRIPTION
    Automated scanning of repository files for potential PII patterns.
    PowerShell equivalent of check-pii.sh.

    Patterns checked:
      - IP addresses (IPv4)
      - Phone numbers (US formats + international with country code)
      - Social Security Numbers
      - Credit Card Numbers (validated with Luhn algorithm to reduce false positives)

.PARAMETER Target
    Directory to scan. Defaults to parent of script location.

.PARAMETER Interactive
    Prompt to accept/reject each finding.

.PARAMETER NoFile
    Output to console only, don't create scan results file.

.EXAMPLE
    .\Check-PersonalInfo.ps1
    Scan parent directory

.EXAMPLE
    .\Check-PersonalInfo.ps1 -Interactive C:\Projects\MyApp
    Interactive mode for specific directory

.NOTES
    NIST Control: SI-12 (Information Management and Retention)

    Exit codes:
      0 = All checks passed (no PII found, or all reviewed/accepted)
      1 = Potential PII detected (requires review)

    Allowlist:
      Accepted findings are stored in <target>/.allowlists/pii-allowlist
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
$AllowlistFile = Join-Path $AllowlistDir 'pii-allowlist'

# Exclusion config file
$script:PiiExcludeFile = $null

# Counters
$script:FoundIssues = 0
$script:AcceptedCount = 0
$script:RejectedCount = 0

# File patterns to scan
$IncludePatterns = @(
    '*.md', '*.txt', '*.tex', '*.rst',
    '*.sh', '*.bash', '*.zsh', '*.ps1', '*.psm1', '*.psd1',
    '*.py', '*.js', '*.ts', '*.rb', '*.php', '*.go', '*.rs', '*.java', '*.cs', '*.c', '*.cpp', '*.h',
    '*.yaml', '*.yml', '*.json', '*.xml', '*.toml', '*.ini', '*.conf', '*.config',
    '*.html', '*.css', '*.scss',
    '*.sql',
    '*.env', '*.env.example'
)

# ============================================================================
# PII Pattern Definitions
# ============================================================================

$script:PiiPatterns = @{
    'IPv4 Addresses' = @{
        Pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        Description = 'IP address patterns that could identify network infrastructure'
    }
    'US Phone Numbers (dashed)' = @{
        Pattern = '\d{3}-\d{3}-\d{4}'
        Description = 'Phone numbers in XXX-XXX-XXXX format'
    }
    'US Phone Numbers (dotted)' = @{
        Pattern = '\d{3}\.\d{3}\.\d{4}'
        Description = 'Phone numbers in XXX.XXX.XXXX format'
    }
    'US Phone Numbers (parenthetical)' = @{
        Pattern = '\(\d{3}\)\s*\d{3}[-. ]\d{4}'
        Description = 'Phone numbers in (XXX) XXX-XXXX format'
    }
    'International Phone Numbers' = @{
        Pattern = '\+\d{1,3}[ .-]?\d{1,4}[ .-]?\d{1,4}[ .-]?\d{1,4}[ .-]?\d{0,4}'
        Description = 'International phone numbers with country code'
    }
    'Social Security Numbers' = @{
        Pattern = '\d{3}-\d{2}-\d{4}'
        Description = 'SSN patterns in XXX-XX-XXXX format'
    }
    'Credit Card Numbers' = @{
        Pattern = '\d{4}[-. ]?\d{4}[-. ]?\d{4}[-. ]?\d{4}'
        Description = '16-digit credit card numbers (Luhn validated)'
        UseLuhn = $true
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

function Test-LuhnChecksum {
    <#
    .SYNOPSIS
        Validate credit card number using Luhn algorithm.
    #>
    param([string]$Number)

    $Number = $Number -replace '[ .-]', ''
    if ($Number -notmatch '^\d+$') { return $false }

    $sum = 0
    $isSecond = $false

    for ($i = $Number.Length - 1; $i -ge 0; $i--) {
        $digit = [int]::Parse($Number[$i].ToString())

        if ($isSecond) {
            $digit *= 2
            if ($digit -gt 9) { $digit -= 9 }
        }

        $sum += $digit
        $isSecond = -not $isSecond
    }

    return ($sum % 10) -eq 0
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
            "# PII Scan Allowlist"
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

function Get-Exclusions {
    <#
    .SYNOPSIS
        Load exclusion patterns from .pii-exclude file.
    #>
    param([string]$TargetDirectory)

    $excludeFile = Join-Path $TargetDirectory '.pii-exclude'
    $exclusions = @()

    if (Test-Path $excludeFile) {
        $script:PiiExcludeFile = $excludeFile
        Get-Content $excludeFile | ForEach-Object {
            $line = $_.Trim()
            # Skip comments and empty lines
            if ($line -and -not $line.StartsWith('#')) {
                $exclusions += $line
            }
        }
    } else {
        # Defaults
        $exclusions = @('.git', '.scans', 'node_modules', '.venv', '__pycache__')
    }

    return $exclusions
}

function Test-ShouldExclude {
    <#
    .SYNOPSIS
        Check if a path should be excluded.
    #>
    param(
        [string]$FilePath,
        [string[]]$Exclusions
    )

    foreach ($exclusion in $Exclusions) {
        # Normalize path separators
        $normalizedPath = $FilePath.Replace('\', '/')
        $normalizedExclusion = $exclusion.Replace('\', '/').TrimEnd('/')

        if ($normalizedPath -like "*/$normalizedExclusion/*" -or
            $normalizedPath -like "*/$normalizedExclusion" -or
            $normalizedPath -like "$normalizedExclusion/*" -or
            (Split-Path -Leaf $FilePath) -like $exclusion) {
            return $true
        }
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
        [string]$FilePath,
        [int]$LineNumber,
        [string]$Content
    )

    $relPath = $FilePath.Replace($TargetDir, '').TrimStart('\', '/')

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "  │ REVIEW REQUIRED: $CheckName" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "  │ File: $relPath" -ForegroundColor White
    Write-Host "  │ Line: $LineNumber" -ForegroundColor White
    Write-Host "  │" -ForegroundColor Yellow
    Write-Host "  │ Content:" -ForegroundColor Yellow
    Write-Host "  │   $Content" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host ""

    # Context-aware hints
    if ($Content -match '1\.3\.6\.1\.\d') {
        Write-Host "  WHY THIS MATCHED:" -ForegroundColor Gray
        Write-Host "    This appears to be an X.509 Object Identifier (OID), not an IP address." -ForegroundColor Gray
        Write-Host ""
    } elseif ($Content -match '127\.0\.0\.1') {
        Write-Host "  WHY THIS MATCHED:" -ForegroundColor Gray
        Write-Host "    This is localhost (127.0.0.1) - the loopback address." -ForegroundColor Gray
        Write-Host ""
    }

    Write-Host "  OPTIONS:" -ForegroundColor White
    Write-Host "    [A]ccept  - Not PII. Add to allowlist (custom reason)."
    Write-Host "    [R]eject  - This IS PII or needs remediation."
    Write-Host "    [S]kip    - Unsure. Leave for later review."
    Write-Host ""
    Write-Host "  QUICK ACCEPT:" -ForegroundColor White
    Write-Host "    [E]xample - Example/placeholder data"
    Write-Host "    [O]ID     - X.509 Object Identifier"
    Write-Host "    [V]ersion - Version number"
    Write-Host "    [L]ocalhost - Loopback address"
    Write-Host "    [D]ocumentation - Documentation or comments"
    Write-Host ""

    while ($true) {
        $response = Read-Host "  Your decision [A/R/S/E/O/V/L/D]"

        switch -Regex ($response) {
            '^[Ee]' {
                Add-ToAllowlist -Content $Content -Reason "Example/placeholder data" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  → Added to allowlist: Example data" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Oo]' {
                Add-ToAllowlist -Content $Content -Reason "X.509 Object Identifier (OID)" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  → Added to allowlist: OID" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Vv]' {
                Add-ToAllowlist -Content $Content -Reason "Version number string" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  → Added to allowlist: Version number" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Ll]' {
                Add-ToAllowlist -Content $Content -Reason "Localhost/loopback address" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  → Added to allowlist: Localhost" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Dd]' {
                Add-ToAllowlist -Content $Content -Reason "Documentation or pattern explanation" -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  → Added to allowlist: Documentation" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Aa]' {
                $reason = Read-Host "  Reason (required for audit trail)"
                if (-not $reason) {
                    Write-Host "  ✗ Reason is required. Please try again." -ForegroundColor Red
                    continue
                }
                Add-ToAllowlist -Content $Content -Reason $reason -FilePath $FilePath -LineNumber $LineNumber
                Write-Host "  → Added to allowlist" -ForegroundColor Green
                $script:AcceptedCount++
                return 'accepted'
            }
            '^[Rr]' {
                Write-Host "  → Flagged as potential PII" -ForegroundColor Red
                $script:RejectedCount++
                return 'rejected'
            }
            '^[Ss]' {
                Write-Host "  → Skipped (will require review next time)" -ForegroundColor Yellow
                return 'skipped'
            }
            default {
                Write-Host "  Please enter A, R, S, E, O, V, L, or D" -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-PiiCheck {
    <#
    .SYNOPSIS
        Run a PII pattern check.
    #>
    param(
        [string]$CheckName,
        [string]$Pattern,
        [string]$Description,
        [bool]$UseLuhn = $false
    )

    Write-Host "Checking: $CheckName"

    $exclusions = Get-Exclusions $TargetDir
    $totalCount = 0
    $newCount = 0
    $allowlistedCount = 0
    $issueCount = 0

    # Get files to scan
    $files = @()
    foreach ($pattern in $IncludePatterns) {
        $files += Get-ChildItem -Path $TargetDir -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue |
                  Where-Object { -not (Test-ShouldExclude $_.FullName $exclusions) }
    }
    $files = $files | Select-Object -Unique

    foreach ($file in $files) {
        try {
            $matches = Select-String -Path $file.FullName -Pattern $Pattern -AllMatches -ErrorAction SilentlyContinue

            foreach ($match in $matches) {
                $totalCount++

                # For credit cards, validate with Luhn
                if ($UseLuhn) {
                    $matchedValue = $match.Matches[0].Value
                    if (-not (Test-LuhnChecksum $matchedValue)) {
                        continue  # Skip invalid checksums
                    }
                }

                $content = $match.Line.Trim()

                # Check allowlist
                if (Test-IsAllowlisted $content) {
                    $allowlistedCount++
                    continue
                }

                $newCount++

                if ($Interactive) {
                    $result = Show-ReviewPrompt -CheckName $CheckName -FilePath $file.FullName -LineNumber $match.LineNumber -Content $content
                    if ($result -ne 'accepted') {
                        $issueCount++
                    }
                } else {
                    if ($newCount -le 10) {
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
        Write-Host "  Result: REVIEW - $newCount new match(es) found" -ForegroundColor Yellow
        if ($newCount -gt 10) {
            Write-Host "  ... and $($newCount - 10) more"
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

Write-Host "PII Verification Scan"
Write-Host "====================="
Write-Host "Timestamp: $script:TIMESTAMP"
Write-Host "Toolkit: Security Verification Toolkit $script:TOOLKIT_VERSION ($script:TOOLKIT_COMMIT)"
Write-Host "Target: $TargetDir"
Write-Host "Repository: $RepoName"
Write-Host ""

# Run all checks
foreach ($checkName in $script:PiiPatterns.Keys) {
    $check = $script:PiiPatterns[$checkName]
    $useLuhn = if ($check.ContainsKey('UseLuhn')) { $check.UseLuhn } else { $false }
    Invoke-PiiCheck -CheckName $checkName -Pattern $check.Pattern -Description $check.Description -UseLuhn $useLuhn
}

# Summary
Write-Host ""
Write-Host "====================="

if ($Interactive) {
    Write-Host "Interactive Review Summary:"
    Write-Host "  Accepted (allowlisted): $script:AcceptedCount"
    Write-Host "  Rejected (flagged):     $script:RejectedCount"
    Write-Host ""
}

if (Test-Path $AllowlistFile) {
    $allowlistCount = (Get-Content $AllowlistFile | Where-Object { $_ -match '^[a-f0-9]' }).Count
    Write-Host "Allowlist: $AllowlistFile ($allowlistCount entries)"
}
if ($script:PiiExcludeFile -and (Test-Path $script:PiiExcludeFile)) {
    $excludeCount = (Get-Content $script:PiiExcludeFile | Where-Object { $_ -and -not $_.StartsWith('#') }).Count
    Write-Host "Exclusions: $script:PiiExcludeFile ($excludeCount patterns)"
}
Write-Host ""

if ($script:FoundIssues -eq 0) {
    Write-Host "OVERALL RESULT: PASS" -ForegroundColor Green
    if ($Interactive) {
        Write-Host "All findings reviewed and accepted."
    } else {
        Write-Host "No PII patterns detected."
    }
} else {
    Write-Host "OVERALL RESULT: REVIEW REQUIRED" -ForegroundColor Yellow
    Write-Host "Potential PII patterns detected. Manual review required."
    if (-not $Interactive) {
        Write-Host ""
        Write-Host "Run with -Interactive flag for interactive review:"
        Write-Host "  .\Check-PersonalInfo.ps1 -Interactive $TargetDir"
    }
}

exit $script:FoundIssues
