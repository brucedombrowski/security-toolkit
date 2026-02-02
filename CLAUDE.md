# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and AI agents working with code in this repository.

## Project Overview

Security verification toolkit for scanning software projects against federal security standards (NIST 800-53, NIST 800-171, FIPS 199/200). Pure Bash implementation with no build system.

## Core Values (TIA Principles)

All changes must maintain:
- **Transparency** - Document all findings, exceptions, and decisions clearly
- **Inspectability** - Output includes file:line references for verification
- **Accountability** - Allowlist entries require SHA256 integrity hash + justification
- **Traceability** - Checksums, toolkit version, and commit hashes link attestations to sources

## Commands

```bash
# Run all tests
./tests/run-all-tests.sh

# Run specific test suite
./tests/test-pii-patterns.sh
./tests/test-secrets-patterns.sh
./tests/test-mac-patterns.sh
./tests/test-audit-logging.sh

# Run all scans on a target project
./scripts/run-all-scans.sh /path/to/project

# Non-interactive mode (CI/CD)
./scripts/run-all-scans.sh -n /path/to/project

# Release workflow (maintainers only)
./scripts/release.sh              # Test release
./scripts/release.sh 1.16.0       # Specific version

# Upgrade toolkit
./scripts/upgrade.sh
```

**Release Policy:** Only the latest release is kept on GitHub. Old releases are automatically deleted by `release.sh`, but all tags are preserved for version history.

## Development Workflow

This project uses **git worktrees** to separate development from releases:

```
~/Security/        # main branch - always release-ready
~/security-dev/    # dev branch - active development
```

### Worktree Setup (One-Time)

```bash
# From the main repo
cd ~/Security
git worktree add ../security-dev -b dev
```

### Terminal Tab Naming

When working in multiple terminal tabs (especially with multiple agents), set a descriptive tab title immediately on session start:

```bash
echo -ne "\033]0;Lead Systems Engineer\007"
```

This helps distinguish between agent contexts and worktrees at a glance.

### Development Process

1. **All development happens in the dev worktree:**
   ```bash
   cd ~/security-dev
   # Make changes, commit frequently
   git add <files>
   git commit -m "feat: Add new feature"
   ```

2. **Run tests before proposing changes:**
   ```bash
   ./tests/run-all-tests.sh
   ```

3. **Push dev branch and create PR:**
   ```bash
   git push -u origin dev
   gh pr create --base main --head dev
   ```

4. **After PR is merged, sync and release from main:**
   ```bash
   cd ~/Security
   git pull
   ./scripts/release.sh X.Y.Z
   ```

5. **Reset dev branch after release:**
   ```bash
   cd ~/security-dev
   git fetch origin
   git reset --hard origin/main
   ```

### Branch Rules

| Branch | Purpose | Direct Commits | Force Push |
|--------|---------|----------------|------------|
| `main` | Releases only | No (PR required) | Never |
| `dev` | Active development | Yes | After release only |
| `feature/*` | Isolated features | Yes | Yes |

### CI/CD Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push to main, PRs | Tests, linting, security scans |
| `pr.yml` | Pull requests | Auto-labeling, title validation |
| `release.yml` | Version tags (`v*.*.*`) | Automated releases |

See [docs/BRANCH-PROTECTION.md](docs/BRANCH-PROTECTION.md) for recommended GitHub settings.

## Repository Structure

```
Security/
├── README.md                    # Usage documentation
├── CLAUDE.md                    # This file (AI agent instructions)
├── CHANGELOG.md                 # Version history
├── INSTALLATION.md              # Platform-specific setup
├── SECURITY.md                  # Vulnerability reporting
├── LICENSE                      # MIT License
├── scripts/
│   ├── run-all-scans.sh         # Master orchestrator
│   ├── release.sh               # Release workflow
│   ├── collect-host-inventory.sh # System inventory (CUI)
│   ├── Collect-HostInventory.ps1 # Windows PowerShell inventory
│   ├── check-pii.sh             # PII pattern detection
│   ├── check-malware.sh         # ClamAV malware scanning
│   ├── check-secrets.sh         # Secrets/credentials detection
│   ├── check-mac-addresses.sh   # MAC address scan
│   ├── check-host-security.sh   # Host OS security
│   ├── check-kev.sh             # CISA KEV cross-reference
│   ├── scan-vulnerabilities.sh  # Nmap/OpenVAS/Lynis
│   ├── harden-system.sh         # System hardening
│   ├── secure-delete.sh         # NIST SP 800-88 deletion
│   ├── purge-git-history.sh     # Remove sensitive files from git
│   ├── generate-compliance.sh   # Compliance statement PDF
│   ├── generate-scan-attestation.sh # PDF attestation
│   ├── upgrade.sh               # Toolkit upgrade helper
│   └── lib/
│       ├── audit-log.sh         # JSON Lines audit logging
│       ├── progress.sh          # Spinners, progress bars
│       ├── timestamps.sh        # ISO 8601 UTC timestamps
│       ├── toolkit-info.sh      # Version, commit, config management
│       ├── inventory/           # Host inventory modules
│       │   ├── detect.sh        # Platform detection helpers
│       │   ├── output.sh        # CUI-safe file output
│       │   └── collectors/      # 13 modular collectors
│       ├── scanners/            # Vulnerability scanner modules
│       │   ├── common.sh        # Shared scanner utilities
│       │   ├── nist-controls.sh # NIST control definitions
│       │   ├── nmap.sh          # Nmap integration
│       │   ├── lynis.sh         # Lynis integration
│       │   └── report.sh        # Report generation
│       └── nvd/                 # NVD CVE lookup modules
│           ├── api.sh           # NVD API client with caching
│           └── matcher.sh       # Package-to-CPE mapping
├── data/                        # Bundled resources for offline use
│   ├── kev-catalog.json         # CISA KEV catalog snapshot
│   └── kev-catalog.json.sha256  # Integrity hash
├── requirements/                # Requirements documentation (JSON)
│   ├── controls/                # NIST 800-53, 800-171 mappings
│   ├── functional/              # Functional requirements (FR-XXX)
│   └── mapping.json             # Traceability matrix
├── verification/                # Verification evidence
│   └── templates/               # LaTeX templates for PDFs
├── templates/                   # LaTeX templates for PDFs
├── tests/                       # Unit tests
├── docs/
│   ├── COMPLIANCE.md            # NIST control mapping
│   ├── MAINTENANCE.md           # Maintenance schedules
│   ├── THREAT-INTELLIGENCE.md   # CISA KEV, DHS MARs
│   ├── FAQ.md                   # Frequently asked questions
│   ├── PERFORMANCE.md           # Performance baselines
│   └── false-positives-macos.md # macOS-specific guidance
├── examples/                    # Redacted example outputs
├── .scans/                      # Raw scan output (gitignored)
├── .assessments/                # Security assessments (PRIVATE)
├── .allowlists/                 # Reviewed exceptions
└── .cache/                      # Threat intelligence cache
```

## Script Design Patterns

All scripts follow these conventions:

**Arguments:** First argument (optional) is target directory; defaults to parent of script

**Exit Codes:** `0` = Pass, `1` = Fail

**Output:**
- Console output for real-time feedback
- Results saved to `<target>/.scans/` with timestamps
- All outputs include toolkit version and commit hash

**Shared Libraries:** Source with `source "$SCRIPT_DIR/lib/audit-log.sh"`

| Library | Purpose |
|---------|---------|
| `audit-log.sh` | JSON Lines audit logging (NIST AU-2/AU-3) |
| `progress.sh` | Spinners, progress bars, ETA, TTY detection |
| `timestamps.sh` | ISO 8601 UTC timestamp utilities |
| `toolkit-info.sh` | Toolkit version, commit hash, configuration |

### NIST Control Mapping

| Script | NIST Control |
|--------|--------------|
| `collect-host-inventory.sh` | CM-8 (System Component Inventory) |
| `check-pii.sh` | SI-12 (Information Management) |
| `check-malware.sh` | SI-3 (Malicious Code Protection) |
| `check-secrets.sh` | SA-11 (Developer Testing) |
| `check-mac-addresses.sh` | SC-8 (Transmission Confidentiality) |
| `check-host-security.sh` | CM-6 (Configuration Settings) |
| `check-kev.sh` | RA-5, SI-5 (Vulnerability/Security Alerts) |
| `check-nvd-cves.sh` | RA-5, SI-2 (Vulnerability Monitoring) |
| `scan-vulnerabilities.sh` | RA-5, SI-2, SI-4, CA-2 |
| `secure-delete.sh` | MP-6 (Media Sanitization) |
| `purge-git-history.sh` | MP-6, SI-12 |

## Adding New Scans

1. Create `scripts/check-<category>.sh`
2. Map to appropriate NIST 800-53 control
3. Add to `run-all-scans.sh` orchestrator
4. Create test file `tests/test-<category>-patterns.sh`
5. Update README.md

### Template

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

## Adding Scanner Modules to scan-vulnerabilities.sh

The vulnerability scanner uses a modular architecture. To add a new scanner (e.g., Trivy):

### 1. Create the Scanner Module

Create `scripts/lib/scanners/<scanner>.sh`:

```bash
#!/bin/bash
#
# <Scanner Name> Module
#
# Purpose: <What this scanner does>
# NIST Controls: <Relevant controls, e.g., RA-5, SI-2>
#
# Functions:
#   run_<scanner>_scan() - Execute the scan
#   summarize_<scanner>_results() - Parse and summarize results (optional)
#
# Dependencies: common.sh, nist-controls.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Run <scanner> scan
# Usage: run_<scanner>_scan "target" "output_dir" "timestamp" "scan_mode"
# Returns: 0 on success, 1 on failure
run_<scanner>_scan() {
    local target="$1"
    local output_dir="$2"
    local timestamp="$3"
    local scan_mode="${4:-full}"
    local output_file="$output_dir/<scanner>-$timestamp.txt"

    print_scanner_section "<SCANNER NAME> SCAN"
    print_nist_controls_header "<scanner>"  # After adding to nist-controls.sh

    echo "Target: $target"
    echo ""

    # Check if scanner is available
    if ! command -v <scanner-cmd> &>/dev/null; then
        log_error "<Scanner> not installed"
        return 1
    fi

    log_info "Running <scanner> scan..."

    # Run the scan
    if <scanner-cmd> <args> "$target" > "$output_file" 2>&1; then
        log_success "<Scanner> scan completed"
        echo "Results saved to: $output_file"
        return 0
    else
        log_error "<Scanner> scan failed"
        return 1
    fi
}
```

### 2. Add NIST Control Mapping

Edit `scripts/lib/scanners/nist-controls.sh`:

```bash
# In get_scanner_controls_800_53():
"<scanner>") echo "RA-5 SI-2" ;;  # Add relevant controls

# In get_scanner_controls_800_171():
"<scanner>") echo "3.11.2 3.14.1" ;;  # Add relevant controls
```

### 3. Add Dependency Check

Edit `scripts/lib/scanners/common.sh` in `check_scanner_deps()`:

```bash
# <Scanner> check
if ! command -v <scanner-cmd> &>/dev/null; then
    optional_tools+=("<scanner>")
    SCANNER_RUN_<SCANNER>=false
else
    log_success "<scanner>: found"
fi
```

### 4. Integrate into Main Script

Edit `scripts/scan-vulnerabilities.sh`:

```bash
# Add source line
source "$SCRIPT_DIR/lib/scanners/<scanner>.sh"

# Add command-line option in argument parsing
-t|--<scanner>-only)
    RUN_NMAP=false
    RUN_OPENVAS=false
    RUN_LYNIS=false
    RUN_<SCANNER>=true
    shift
    ;;

# Add scan execution
if $RUN_<SCANNER> && ! $REPORT_ONLY; then
    scan_count=$((scan_count + 1))
    if run_<scanner>_scan "$TARGET" "$SCANNER_OUTPUT_DIR" "$TIMESTAMP" "$SCAN_MODE" 2>&1 | tee -a "$SCANNER_REPORT_FILE"; then
        pass_count=$((pass_count + 1))
    else
        overall_status=1
    fi
fi
```

### Example: Adding Trivy Container Scanner

```bash
# scripts/lib/scanners/trivy.sh
run_trivy_scan() {
    local target="$1"
    local output_dir="$2"
    local timestamp="$3"
    local scan_mode="${4:-full}"
    local output_file="$output_dir/trivy-$timestamp.json"

    print_scanner_section "TRIVY CONTAINER VULNERABILITY SCAN"

    if ! command -v trivy &>/dev/null; then
        log_error "Trivy not installed. Install with: brew install trivy"
        return 1
    fi

    local trivy_args="--format json --output $output_file"
    if [ "$scan_mode" = "quick" ]; then
        trivy_args="$trivy_args --severity HIGH,CRITICAL"
    fi

    log_info "Running Trivy scan on $target..."

    if trivy image $trivy_args "$target" 2>&1; then
        log_success "Trivy scan completed"
        # Parse results
        local vuln_count=$(jq '.Results[].Vulnerabilities | length' "$output_file" 2>/dev/null | paste -sd+ | bc)
        echo "Vulnerabilities found: ${vuln_count:-0}"
        return 0
    else
        log_error "Trivy scan failed"
        return 1
    fi
}
```

## Integration Patterns

### With build scripts

```bash
SECURITY_TOOLKIT="$HOME/Security"
"$SECURITY_TOOLKIT/scripts/run-all-scans.sh" "$(pwd)" || exit 1
```

## Output Directories

| Directory | Contents | Sensitivity |
|-----------|----------|-------------|
| `.scans/` | Raw scan results, checksums, PDFs | Shareable (transient) |
| `.assessments/` | Analysis reports, recommendations | Private (never commit) |
| `.allowlists/` | Reviewed exceptions with SHA256 hashes | Project-specific |
| `.cache/` | Threat intelligence (KEV catalog) | Auto-managed |

## Security Model

### Trust Boundaries

| Boundary | Trust Level | Rationale |
|----------|-------------|-----------|
| Local filesystem | Trusted | Scripts operate on user-accessible files |
| Target directory | Semi-trusted | May contain malicious files (why we scan) |
| Network (localhost) | Trusted | Vulnerability scans target local machine |
| Network (remote) | Untrusted | Remote scans require explicit authorization |

### Data Handling

| Category | Examples | Handling |
|----------|----------|----------|
| CUI | Host inventory, MAC addresses, serial numbers | Mode 600, CUI banner, secure delete |
| PII | SSNs, phone numbers found in scans | Displayed for remediation only |
| Secrets | API keys, passwords found in scans | Never logged in plaintext |

### Security Guarantees

1. **No Data Exfiltration**: Scripts do not transmit data externally
2. **No Code Execution from Targets**: Scans read files, never execute them
3. **Audit Trail**: All scan results are timestamped and checksummed
4. **Fail-Safe Defaults**: Destructive operations require explicit confirmation

## Key Considerations

### Pattern Changes
Regex pattern modifications affect detection accuracy across all scanned projects. Test thoroughly with `./tests/run-all-tests.sh`.

### Allowlist System
Allowlist entries use SHA256 hash of `file:line:content` for integrity verification. Never modify allowlist format without updating verification logic.

### CUI Sensitivity
Host inventory contains Controlled Unclassified Information (MAC addresses, serial numbers, software versions). Never expose in logs, tests, or examples.

### Known Limitations

1. **False Positives**: Use `.allowlists/` to suppress known-good matches
2. **False Negatives**: Cannot detect obfuscated malware, encrypted secrets, novel patterns
3. **Platform-Specific**: Some checks are macOS or Linux specific
4. **Point-in-Time**: Code changes invalidate prior attestations

## Dependencies

- **Required**: Bash 4.0+, grep, git
- **Required for malware scan**: ClamAV (`clamscan`, `freshclam`)
- **Optional**: pdflatex, Nmap, Lynis

## Key Documentation

- [INSTALLATION.md](INSTALLATION.md) - Platform-specific setup
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) - NIST control mapping details
- [docs/MAINTENANCE.md](docs/MAINTENANCE.md) - Maintenance schedules
- [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md) - CISA KEV integration
- [docs/FAQ.md](docs/FAQ.md) - Frequently asked questions
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - Performance baselines
- [requirements/README.md](requirements/README.md) - Requirements framework and traceability
- [verification/README.md](verification/README.md) - Verification evidence workflow
