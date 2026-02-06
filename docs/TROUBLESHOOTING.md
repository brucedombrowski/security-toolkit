# Troubleshooting Guide

Advanced diagnostics for Security Verification Toolkit issues. For common questions, see [FAQ.md](FAQ.md).

## Quick Diagnostics

Run this command to check toolkit health:

**Bash (macOS/Linux):**
```bash
./scripts/run-all-scans.sh --check-deps
```

**PowerShell (Windows):**
```powershell
# Check PowerShell version and execution policy
$PSVersionTable.PSVersion
Get-ExecutionPolicy

# Test script availability
Test-Path ".\scripts\Collect-HostInventory.ps1"
Test-Path ".\scripts\lib\init.ps1"
```

## Exit Codes Reference

Scripts use these exit codes:

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success/Pass | No action needed |
| 1 | Findings require review | Check `.scans/` output for details |
| 2 | Missing dependency | Install required tool (e.g., ClamAV) |

**Note:** Exit code 1 means "review required" - the scan completed successfully but found items that need human review. This is not an error.

---

## ClamAV Issues

### Virus database outdated

**Symptom:** Warning about outdated virus definitions.

**Diagnostic:**
```bash
# Check database age
ls -la /opt/homebrew/var/lib/clamav/*.cvd  # macOS
ls -la /var/lib/clamav/*.cvd               # Linux

# Check freshclam log
cat /var/log/clamav/freshclam.log
```

**Fix:**
```bash
sudo freshclam
```

### ClamAV daemon not responding

**Symptom:** `clamd` connection refused errors.

**Diagnostic:**
```bash
# Check if daemon is running
pgrep -l clamd

# Test daemon connection
clamdscan --ping
```

**Fix:**
```bash
# macOS
brew services restart clamav

# Linux (systemd)
sudo systemctl restart clamav-daemon
```

### ClamAV path resolution failures

**Symptom:** "ClamAV not found" despite installation.

**Diagnostic:**
```bash
# Check installation paths
which clamscan
which freshclam

# Check Homebrew paths (macOS)
brew --prefix clamav
```

**Fix:** The toolkit searches these paths in order:
1. `$PATH` lookup
2. `/opt/homebrew/bin/` (macOS ARM)
3. `/usr/local/bin/` (macOS Intel)
4. `/usr/bin/` (Linux)

Add the correct path to your shell profile if needed.

---

## NVD API Issues

### Rate limiting (HTTP 429)

**Symptom:** `Too Many Requests` errors.

**Diagnostic:**
```bash
# Check cache status
ls -la ~/.cache/nvd-api/
```

**Fix:**
1. Wait 30 seconds between API calls (automatic)
2. Set `NVD_API_KEY` for higher rate limits:
   ```bash
   export NVD_API_KEY="your-api-key"
   ```
3. Get API key at: https://nvd.nist.gov/developers/request-an-api-key

### API connection failures

**Symptom:** Network timeouts or connection refused.

**Diagnostic:**
```bash
# Test API connectivity
curl -I "https://services.nvd.nist.gov/rest/json/cves/2.0"
```

**Fix:**
1. Check firewall rules for `services.nvd.nist.gov`
2. Check proxy settings: `$HTTP_PROXY`, `$HTTPS_PROXY`
3. Use offline mode with cached data

### Cache corruption

**Symptom:** JSON parse errors from cached responses.

**Fix:**
```bash
# Clear NVD cache
rm -rf ~/.cache/nvd-api/
```

---

## Allowlist Issues

### Hash mismatch on allowlisted entry

**Symptom:** Entry not suppressed despite being allowlisted.

**Cause:** The matched content changed since the allowlist entry was created.

**Diagnostic:**
```bash
# View allowlist entry
cat .allowlists/pii-allowlist

# Entry format: SHA256 # REASON # TRUNCATED_FINDING
# The SHA256 is computed from the matched CONTENT ONLY (not file path or line number)
# This allows entries to survive when code moves between lines
```

**Fix:**
1. Re-add the entry using interactive mode:
   ```bash
   ./scripts/check-pii.sh -i .
   ```
2. Or manually compute the hash from the matched content:
   ```bash
   # Hash is of the content portion only (after file:line:)
   echo -n "192.168.1.1" | shasum -a 256
   ```

### Allowlist file not detected

**Symptom:** Allowlisted entries still flagged.

**Diagnostic:**
```bash
# Check allowlist exists and has correct permissions
ls -la .allowlists/

# Verify format (one entry per line)
head .allowlists/pii-allowlist
```

**Fix:** Ensure allowlist files are in `.allowlists/` directory at the target root.

---

## PDF Generation Issues

### LaTeX compilation errors

**Symptom:** PDF generation fails with LaTeX errors.

**Diagnostic:**
```bash
# Check for .log file
cat .scans/*.log

# Common error patterns:
# - "Missing $ inserted" = unescaped special chars
# - "Undefined control sequence" = missing package
```

**Fix:**
1. Ensure all LaTeX packages are installed:
   ```bash
   sudo tlmgr install fancyhdr lastpage geometry xcolor hyperref
   ```
2. Check for special characters in input (& % $ # _ { } ~ ^)

### Logo not found

**Symptom:** Warning about missing logo.png.

**Diagnostic:**
```bash
ls -la templates/logo.png
```

**Fix:** Place a logo.png file in `templates/` or the script will continue without it.

---

## Audit Log Issues

### Log file not created

**Symptom:** No audit log in `.scans/` directory.

**Cause:** `init_audit_log` not called or directory permissions.

**Diagnostic:**
```bash
# Check .scans directory permissions
ls -la .scans/

# Verify audit log initialization
grep -r "init_audit_log" scripts/
```

**Fix:** Ensure target directory is writable and `.scans/` can be created.

### Invalid JSON in audit log

**Symptom:** JSON parse errors when reading audit log.

**Diagnostic:**
```bash
# Validate JSON Lines format (each line is valid JSON)
while read -r line; do
    echo "$line" | jq . > /dev/null || echo "Invalid: $line"
done < .scans/audit-*.jsonl
```

**Fix:** Audit logs use JSON Lines format (one JSON object per line). Ensure log wasn't truncated mid-write.

---

## Integration Test Failures

### Tests pass locally but fail in CI

**Diagnostic checklist:**
1. Shell version: `bash --version` (requires 4.0+)
2. Available tools: `which nmap lynis clamscan`
3. File permissions: `ls -la tests/`
4. Environment variables: `env | grep -E "^(PATH|HOME|USER)="`

### Test timeout

**Symptom:** Test hangs then fails.

**Diagnostic:**
```bash
# Run with verbose output
bash -x ./tests/test-integration.sh
```

**Fix:**
1. Reduce test data size in `tests/fixtures/`
2. Increase timeout in test script
3. Check for infinite loops in test logic

---

## macOS-Specific Issues

### System Integrity Protection (SIP) blocking scans

**Symptom:** Permission denied on system directories.

**Diagnostic:**
```bash
csrutil status
```

**Note:** This is expected. The toolkit cannot scan SIP-protected directories (`/System`, `/usr/bin`, etc.). These are excluded by design.

### Gatekeeper blocking script execution

**Symptom:** "cannot be opened because the developer cannot be verified"

**Fix:**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine scripts/*.sh
```

### ARM vs Intel path differences

**Symptom:** Tools not found on Apple Silicon.

**Diagnostic:**
```bash
# Check architecture
uname -m  # arm64 or x86_64

# Check Homebrew prefix
brew --prefix  # /opt/homebrew (ARM) or /usr/local (Intel)
```

**Fix:** The toolkit auto-detects paths, but ensure `PATH` includes:
- ARM: `/opt/homebrew/bin`
- Intel: `/usr/local/bin`

---

## Linux-Specific Issues

### AppArmor/SELinux blocking scans

**Symptom:** Permission denied despite correct file permissions.

**Diagnostic:**
```bash
# Check SELinux (RHEL/CentOS)
getenforce
ausearch -m avc -ts recent

# Check AppArmor (Ubuntu)
aa-status
```

**Fix:** Create policy exceptions or run in permissive mode for testing.

### Missing GNU coreutils

**Symptom:** `timeout`, `realpath`, or other commands not found.

**Fix:**
```bash
# Debian/Ubuntu
sudo apt install coreutils

# Alpine
apk add coreutils
```

---

## Windows-Specific Issues

### PowerShell execution policy blocking scripts

**Symptom:** "Running scripts is disabled on this system" or "cannot be loaded because the execution of scripts is disabled"

**Diagnostic:**
```powershell
Get-ExecutionPolicy -List
```

**Fix:**
```powershell
# Option 1: Set for current user (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Option 2: Bypass for single session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Option 3: Run script with bypass flag
powershell -ExecutionPolicy Bypass -File ".\scripts\Check-PersonalInfo.ps1"
```

**Note:** `RemoteSigned` allows local scripts to run while requiring signatures on downloaded scripts.

### Windows Defender interference

**Symptom:** Scripts run slowly, files quarantined, or "Access denied" errors during scans.

**Diagnostic:**
```powershell
# Check Defender status
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled

# Check exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**Fix:**
```powershell
# Add toolkit directory to exclusions (run as Administrator)
Add-MpPreference -ExclusionPath "C:\Path\To\security-toolkit"

# Or temporarily disable real-time protection for testing
Set-MpPreference -DisableRealtimeMonitoring $true
# Re-enable after testing:
Set-MpPreference -DisableRealtimeMonitoring $false
```

**Note:** Adding exclusions is preferred over disabling protection entirely.

### Path and encoding issues

**Symptom:** File not found errors, garbled output, or `???` characters in results.

**Diagnostic:**
```powershell
# Check current encoding
[Console]::OutputEncoding
$OutputEncoding

# Check for BOM in files
Format-Hex -Path "file.txt" -Count 4
```

**Fix:**
```powershell
# Set UTF-8 encoding for session
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Or set in PowerShell profile (~\Documents\PowerShell\Microsoft.PowerShell_profile.ps1)
```

**Path issues:**
```powershell
# Use Join-Path for cross-platform paths
$outputPath = Join-Path $PSScriptRoot ".scans"

# Convert Unix paths if needed
$windowsPath = $unixPath -replace '/', '\'
```

### Line ending issues (CRLF vs LF)

**Symptom:** Scripts fail with "unexpected token" or patterns don't match.

**Diagnostic:**
```powershell
# Check file line endings
(Get-Content -Raw "file.sh") -match "`r`n"  # True = CRLF
```

**Fix:**
```powershell
# Configure Git to handle line endings
git config --global core.autocrlf true   # Windows
git config --global core.autocrlf input  # WSL/Linux

# Convert existing file
(Get-Content "file.txt") | Set-Content "file.txt"  # Normalizes to Windows CRLF
```

### ClamAV on Windows

**Symptom:** ClamAV commands not found or daemon won't start.

**Diagnostic:**
```powershell
# Check if ClamAV is installed
Get-Command clamscan -ErrorAction SilentlyContinue
Get-Command freshclam -ErrorAction SilentlyContinue

# Check service status
Get-Service -Name "ClamAV" -ErrorAction SilentlyContinue
```

**Installation:**
```powershell
# Option 1: Chocolatey
choco install clamav

# Option 2: Download from https://www.clamav.net/downloads#otherversions
# Install to C:\Program Files\ClamAV and add to PATH
```

**Fix for database issues:**
```powershell
# Update virus definitions
& "C:\Program Files\ClamAV\freshclam.exe"

# Run scan manually
& "C:\Program Files\ClamAV\clamscan.exe" --recursive "C:\Path\To\Scan"
```

### WSL vs native PowerShell

**When to use WSL:**
- Running the Bash scripts directly (`check-pii.sh`, `run-all-scans.sh`)
- When you need Unix tools (`grep`, `sed`, `awk`)
- CI/CD pipelines targeting Linux

**When to use native PowerShell:**
- Running PowerShell scripts (`Check-PersonalInfo.ps1`, `Collect-HostInventory.ps1`)
- When scanning Windows-native paths
- For host inventory collection (Windows system info)

**Diagnostic:**
```powershell
# Check if running in WSL
if ($env:WSL_DISTRO_NAME) { "Running in WSL" } else { "Native Windows" }

# Check PowerShell version
$PSVersionTable.PSVersion
```

**Path translation between WSL and Windows:**
```bash
# WSL: Convert Windows path to WSL
wslpath "C:\Users\Name\project"  # Returns /mnt/c/Users/Name/project

# WSL: Convert WSL path to Windows
wslpath -w "/mnt/c/Users/Name/project"  # Returns C:\Users\Name\project
```

```powershell
# PowerShell: Access WSL filesystem
Get-ChildItem "\\wsl$\Ubuntu\home\user\project"
```

### PowerShell version compatibility

**Symptom:** Script fails with syntax errors or missing cmdlets.

**Diagnostic:**
```powershell
$PSVersionTable.PSVersion
```

**Requirements:**
- PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+ (PowerShell Core)
- Recommended: PowerShell 7+ for cross-platform compatibility

**Fix:**
```powershell
# Install PowerShell 7 via winget
winget install Microsoft.PowerShell

# Or via Chocolatey
choco install pwsh

# Run scripts with PowerShell 7 explicitly
pwsh -File ".\scripts\Check-PersonalInfo.ps1"
```

### Windows Terminal tab naming

**For multi-agent workflows**, set descriptive tab titles:

```powershell
$Host.UI.RawUI.WindowTitle = "Lead Systems Engineer"
```

Or in Windows Terminal settings, configure profiles with distinct names and colors.

---

## Network Scanning Issues (Nmap)

### Nmap requires root for SYN scan

**Symptom:** "TCP/IP fingerprinting requires root privileges"

**Fix:**
```bash
sudo ./scripts/scan-vulnerabilities.sh --nmap-only localhost
```

### Nmap OS fingerprinting requires sudo

**Symptom:** OS detection results are missing or incomplete.

**Fix:** Nmap OS fingerprinting requires elevated privileges:
```bash
sudo ./scripts/scan-vulnerabilities.sh localhost
```

---

## Getting Debug Output

### Bash scripts

Enable verbose output for any script:

```bash
# Method 1: Set DEBUG variable
DEBUG=1 ./scripts/check-pii.sh .

# Method 2: Use bash -x
bash -x ./scripts/check-pii.sh .

# Method 3: Check audit log
cat .scans/audit-*.jsonl | jq .
```

### PowerShell scripts

```powershell
# Method 1: Use -Verbose flag
.\scripts\Check-PersonalInfo.ps1 -Target . -Verbose

# Method 2: Set preference variable
$VerbosePreference = "Continue"
.\scripts\Check-PersonalInfo.ps1 -Target .

# Method 3: Use Set-PSDebug for tracing
Set-PSDebug -Trace 1
.\scripts\Check-PersonalInfo.ps1 -Target .
Set-PSDebug -Off

# Method 4: Check audit log
Get-Content .scans\audit-*.jsonl | ConvertFrom-Json
```

## Reporting Issues

When reporting issues, include:

1. **Command run:** Full command with arguments
2. **Exit code:** `echo $?` (Bash) or `$LASTEXITCODE` (PowerShell)
3. **Error output:** Full error message
4. **Environment:**

   **Bash/macOS/Linux:**
   ```bash
   uname -a
   bash --version
   ./scripts/run-all-scans.sh --version
   ```

   **PowerShell/Windows:**
   ```powershell
   $PSVersionTable
   [System.Environment]::OSVersion
   Get-ComputerInfo | Select-Object WindowsVersion, OsBuildNumber
   ```

5. **Relevant logs:** `.scans/audit-*.jsonl`

Open issues at: https://github.com/brucedombrowski/security-toolkit/issues
