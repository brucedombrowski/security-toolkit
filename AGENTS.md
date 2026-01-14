# Security - AI Agent Instructions

## Project Purpose

This repository contains security analysis and compliance documentation tools for scanning software projects against federal security standards (NIST 800-53, FIPS).

## Repository Structure

```
Security/
├── README.md           # Usage documentation
├── AGENTS.md           # This file (AI agent instructions)
├── LICENSE             # MIT License
├── .gitignore          # Excludes .scans/ and result files
└── scripts/
    ├── run-all-scans.sh       # Master orchestrator
    ├── check-pii.sh           # PII pattern detection
    ├── check-malware.sh       # ClamAV malware scanning
    ├── check-secrets.sh       # Secrets/credentials detection
    ├── check-mac-addresses.sh # IEEE 802.3 MAC address scan
    └── check-host-security.sh # Host OS security verification
```

## Script Design Patterns

All scripts follow these conventions:

### Arguments
- First argument (optional): Target directory to scan
- If not provided, defaults to parent directory of script

### Exit Codes
- `0` = Pass (no issues found)
- `1` = Fail (issues detected)

### Output
- Results go to stdout only
- No files written to target repository
- Suitable for CI/CD pipeline integration

### NIST Control Mapping
Each script maps to specific NIST 800-53 controls:
- `check-pii.sh` → SI-12 (Information Management)
- `check-malware.sh` → SI-3 (Malicious Code Protection)
- `check-secrets.sh` → SA-11 (Developer Testing)
- `check-mac-addresses.sh` → SC-8 (Transmission Confidentiality)
- `check-host-security.sh` → CM-6 (Configuration Settings)

## Adding New Scans

When adding new security checks:

1. Create script in `scripts/` directory
2. Follow naming convention: `check-<category>.sh`
3. Accept target directory as first argument
4. Use exit code 0 for pass, 1 for fail
5. Map to appropriate NIST 800-53 control
6. Update `run-all-scans.sh` to include new scan
7. Update README.md with new script documentation

### Template for new scans

```bash
#!/bin/bash
#
# <Description> Verification Script
#
# Purpose: <What this script checks>
# NIST Control: <Control ID and name>
#
# Exit codes:
#   0 = Pass
#   1 = Fail

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "$1" ]; then
    TARGET_DIR="$1"
else
    TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
REPO_NAME=$(basename "$TARGET_DIR")

echo "<Scan Name>"
echo "==========="
echo "Timestamp: $TIMESTAMP"
echo "Target: $TARGET_DIR"
echo ""

# ... scan logic ...

exit $EXIT_CODE
```

## Integration Patterns

### With SpeakUp-style attestation

If a project wants to produce attestation files (public proof of passing scans):

1. Run scans with this toolkit
2. On success, generate attestation markdown
3. On failure, remove any existing attestation

### With build scripts

Projects can call these scripts from their build process:

```bash
SECURITY_TOOLKIT="$HOME/Security"
"$SECURITY_TOOLKIT/scripts/run-all-scans.sh" "$(pwd)" || exit 1
```

## Future Enhancements

Potential additions to the toolkit:

1. **Dependency vulnerability scanning**
   - `npm audit` for Node.js
   - `pip-audit` for Python
   - `dotnet list package --vulnerable` for .NET

2. **FIPS cryptographic compliance**
   - Check for FIPS-approved algorithms
   - Detect weak crypto usage

3. **Static code analysis**
   - Language-specific security linters
   - OWASP pattern detection

4. **PDF report generation**
   - LaTeX templates for formal reports
   - Integration with LaTeX/ExportCompliance templates

## Dependencies

- **Required**: grep (with -E extended regex)
- **Required for malware scan**: ClamAV (`clamscan`)
- **macOS specific**: Various system commands for host security checks
- **Linux specific**: ufw/iptables, SELinux/AppArmor for host security checks
