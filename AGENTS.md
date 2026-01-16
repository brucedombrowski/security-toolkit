# Security - AI Agent Instructions

## Core Values

This toolkit is built on TIA principles:

- **Transparency** - All scan findings, exceptions, and decisions are documented clearly
- **Inspectability** - Output includes file:line references enabling verification of any finding
- **Accountability** - Each allowlist entry requires reviewer justification with SHA256 integrity hash
- **Traceability** - Host inventory checksums, toolkit version, and commit hashes link every attestation to its source

## Project Purpose

This repository contains security analysis and compliance documentation tools for scanning software projects against federal security standards (NIST 800-53, FIPS).

## Repository Structure

```
Security/
├── README.md           # Usage documentation
├── AGENTS.md           # This file (AI agent instructions)
├── CHANGELOG.md        # Version history
├── LICENSE             # MIT License
├── .gitignore          # Excludes .scans/, .assessments/, and result files
├── scripts/
│   ├── run-all-scans.sh         # Master orchestrator (inventory + scans + PDF)
│   ├── collect-host-inventory.sh # System inventory (SENSITIVE: MAC addresses, etc.)
│   ├── check-pii.sh             # PII pattern detection
│   ├── check-malware.sh         # ClamAV malware scanning (with DB auto-update)
│   ├── check-secrets.sh         # Secrets/credentials detection
│   ├── check-mac-addresses.sh   # IEEE 802.3 MAC address scan
│   ├── check-host-security.sh   # Host OS security verification
│   ├── scan-vulnerabilities.sh  # Comprehensive vuln scanning (Nmap/OpenVAS/Lynis)
│   ├── secure-delete.sh         # NIST SP 800-88 secure file deletion
│   └── purge-git-history.sh     # Remove sensitive files from git history
├── templates/
│   ├── scan_attestation.tex         # Generic attestation LaTeX template
│   ├── security_compliance_statement.tex  # Project-specific compliance template
│   └── logo.png                     # Logo for PDF headers
├── .scans/             # Raw scan output (gitignored, auto-generated)
└── .assessments/       # Security assessment reports (gitignored, PRIVATE)
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
- Console output for real-time feedback
- **Raw scan output** saved to `<target>/.scans/` directory:
  - **Host inventory**: `host-inventory-YYYY-MM-DD.txt` (SENSITIVE - contains MAC addresses)
  - Individual scan logs: `*-scan-YYYY-MM-DD.txt` (reference inventory checksum)
  - Consolidated report: `security-scan-report-YYYY-MM-DD.txt`
  - Checksums file: `checksums.md` (SHA256 of all outputs + inventory reference)
  - PDF attestation: `scan-attestation-YYYY-MM-DD.pdf` (if pdflatex available)
  - ClamAV metadata: `malware-metadata-YYYY-MM-DD/` (JSON with file hashes)
  - ClamAV log: `clamav-log-YYYY-MM-DD.txt`
  - Vulnerability scans: `nmap-*.txt`, `lynis-*.txt`, etc.
- **Security assessments** saved to `<target>/.assessments/` directory (PRIVATE):
  - Assessment reports: `security-assessment-report-YYYY-MM-DD.md`
  - These contain analysis, recommendations, and findings interpretation
  - Never commit to version control - contains sensitive system details
- All outputs include toolkit version and commit hash for traceability
- Scan results can be shared without exposing sensitive machine data (they only reference inventory checksum)
- Suitable for CI/CD pipeline integration

### NIST Control Mapping
Each script maps to specific NIST 800-53 controls:
- `collect-host-inventory.sh` → CM-8 (System Component Inventory)
- `check-pii.sh` → SI-12 (Information Management)
- `check-malware.sh` → SI-3 (Malicious Code Protection)
- `check-secrets.sh` → SA-11 (Developer Testing)
- `check-mac-addresses.sh` → SC-8 (Transmission Confidentiality)
- `check-host-security.sh` → CM-6 (Configuration Settings)
- `scan-vulnerabilities.sh` → RA-5, SI-2, SI-4, CA-2 (Vulnerability Assessment)
- `secure-delete.sh` → MP-6 (Media Sanitization, NIST SP 800-88)
- `purge-git-history.sh` → MP-6, SI-12 (Sanitization of version control)

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

## Templates

### scan_attestation.tex
Generic attestation document generated automatically by `run-all-scans.sh`:
- Substitution variables: `\UniqueID`, `\DocumentDate`, `\TargetName`, `\PIIScanResult`, etc.
- NIST control mapping table
- Scan results table with PASS/FAIL color coding
- Verification instructions for checksums

### security_compliance_statement.tex
Project-specific compliance document requiring manual curation:
- Cryptographic implementation details
- Certificate handling documentation
- Security controls description
- Formal certification statement

## Vulnerability Scanning (scan-vulnerabilities.sh)

The `scan-vulnerabilities.sh` script provides comprehensive vulnerability assessment using open-source tools with full NIST compliance mapping.

### Supported Tools

| Tool | Purpose | NIST Controls |
|------|---------|---------------|
| **Nmap** | Network scanning, port discovery, service detection | RA-5, SI-4, CM-8, SC-7 |
| **OpenVAS/GVM** | Vulnerability assessment, CVE detection | RA-5, SI-2, RA-3 |
| **Lynis** | System security auditing, configuration review | SI-7, CM-6, CA-2 |

### NIST SP 800-53 Rev 5 Control Mapping

| Control | Family | Description | Implementation |
|---------|--------|-------------|----------------|
| CA-2 | Assessment | Control Assessments | Lynis system audit |
| CA-7 | Assessment | Continuous Monitoring | Scheduled scan capability |
| CM-6 | Configuration Mgmt | Configuration Settings | Lynis configuration audit |
| CM-8 | Configuration Mgmt | System Component Inventory | Nmap service inventory |
| RA-3 | Risk Assessment | Risk Assessment | All tools contribute to risk assessment |
| RA-5 | Risk Assessment | Vulnerability Monitoring and Scanning | Nmap + OpenVAS network/vuln scanning |
| SA-11 | Services Acquisition | Developer Testing | All tools for security testing |
| SC-7 | Comms Protection | Boundary Protection | Nmap firewall/port analysis |
| SI-2 | System Integrity | Flaw Remediation | OpenVAS CVE identification |
| SI-4 | System Integrity | System Monitoring | Nmap service monitoring |
| SI-7 | System Integrity | Software/Firmware Integrity | Lynis integrity checks |

### NIST SP 800-171 Rev 2 Control Mapping

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| 3.11.1 | Periodically assess risk | All scan tools |
| 3.11.2 | Scan for vulnerabilities periodically | Nmap + OpenVAS |
| 3.11.3 | Remediate vulnerabilities per risk | OpenVAS findings |
| 3.12.1 | Assess security controls periodically | Lynis audit |
| 3.12.3 | Monitor security controls ongoing | All tools |
| 3.14.1 | Identify, report, correct flaws | OpenVAS + Lynis |
| 3.14.6 | Monitor to detect attacks | Nmap monitoring |
| 3.14.7 | Identify unauthorized system use | Nmap service detection |

### FIPS 199/200 Alignment

**FIPS 199 Impact Assessment:**
- Confidentiality: Scan results may reveal network topology (handle as sensitive)
- Integrity: Verifies system configuration integrity via Lynis
- Availability: Identifies services affecting system availability

**FIPS 200 Minimum Security Requirements:**
- Risk Assessment (RA) - Verified
- Security Assessment and Authorization (CA) - Verified
- System and Information Integrity (SI) - Verified
- Configuration Management (CM) - Verified

### Usage Examples

```bash
# Full scan of localhost (all available tools)
./scripts/scan-vulnerabilities.sh

# Network scan of specific target
./scripts/scan-vulnerabilities.sh 192.168.1.0/24

# Quick scan (reduced thoroughness)
./scripts/scan-vulnerabilities.sh -q 10.0.0.1

# Nmap only
./scripts/scan-vulnerabilities.sh -n 192.168.1.1

# Lynis system audit only
./scripts/scan-vulnerabilities.sh -l

# Full scan with sudo (recommended for comprehensive results)
sudo ./scripts/scan-vulnerabilities.sh
```

### Output Files

Scan results are saved to `.scans/` with timestamps:
- `vulnerability-scan-TIMESTAMP.txt` - Consolidated report with NIST mapping
- `nmap-TIMESTAMP.txt` - Nmap text output
- `nmap-TIMESTAMP.xml` - Nmap XML output (for further processing)
- `lynis-TIMESTAMP.txt` - Lynis audit log
- `lynis-TIMESTAMP-report.dat` - Lynis machine-readable report
- `openvas-TIMESTAMP.xml` - OpenVAS results (when available)

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

4. **OpenVAS/GVM full integration**
   - Currently documented but marked optional due to infrastructure requirements
   - OpenVAS requires: PostgreSQL database, Redis cache, multiple daemon services
   - Full integration would provide comprehensive CVE vulnerability detection
   - Consider for environments with dedicated security scanning infrastructure

5. **Multi-interface vulnerability scanning**
   - Currently scans localhost (127.0.0.1) only for development testing
   - Future: Auto-detect all network interfaces with IP addresses
   - Scan all interfaces + loopback for comprehensive coverage
   - Support for `-a|--all-interfaces` flag
   - Consider network segmentation (scan internal vs external interfaces separately)

6. **Agentic AI-Driven Compliance Orchestration** (Long-term Vision)
   - **End-to-end workflow automation**: Agentic AI orchestrates the complete compliance pipeline from scanning through attestation and submission
   - **PDFSigner integration**: Automatically digitally signs compliance statements with proper X.509 certificates
   - **Distributed ledger submission**: Uploads signed compliance attestations to blockchain or distributed ledger systems for immutability
   - **Automated compliance verification**: Triggers upstream compliance checks against submitted attestations
   - **Cryptographic integrity**: Leverages digital signatures + distributed ledgers to create tamper-proof audit trails
   - **Real-time compliance status**: Enables continuous compliance monitoring and automated status updates to governance systems
   - **Requirements**: Sophisticated AI agent with organizational trust, certificate management capabilities, and blockchain integration

## Security Model & Assumptions

### Trust Boundaries

This toolkit operates with the following trust model:

| Boundary | Trust Level | Rationale |
|----------|-------------|-----------|
| Local filesystem | Trusted | Scripts operate on user-accessible files |
| Target directory | Semi-trusted | May contain malicious files (why we scan) |
| Network (localhost) | Trusted | Vulnerability scans target local machine |
| Network (remote) | Untrusted | Remote scans require explicit authorization |
| ClamAV databases | Trusted | Downloaded from official ClamAV mirrors |
| External tools | Trusted | Nmap, Lynis installed via package managers |

### Data Handling

**Sensitive Data Categories:**

| Category | Examples | Handling |
|----------|----------|----------|
| CUI (Controlled Unclassified Information) | Host inventory, MAC addresses, serial numbers | Mode 600, CUI banner, secure delete required |
| PII (Personally Identifiable Information) | SSNs, phone numbers found in scans | Displayed for remediation, not persisted beyond scan logs |
| Secrets | API keys, passwords found in scans | Displayed for remediation, never logged in plaintext |
| Network Topology | Open ports, services, IP addresses | Vulnerability scans contain this; treat as sensitive |

**Data Flow:**
```
Target Directory → Scan Scripts → .scans/ Directory → PDF Attestation
                                       ↓
                              (gitignored, transient)

                   Analysis/Review → .assessments/ Directory
                                       ↓
                              (gitignored, persistent, worth storing)
```

**Directory Lifecycle:**
- `.scans/` - **Transient**: Raw scan output, deleted frequently, regenerated on each scan run
- `.assessments/` - **Persistent**: Curated assessment reports worth storing for compliance records, audits, and historical reference

### Privilege Requirements

| Script | Requires sudo | Why |
|--------|---------------|-----|
| `run-all-scans.sh` | No | Orchestration only |
| `check-pii.sh` | No | File content scanning |
| `check-secrets.sh` | No | File content scanning |
| `check-malware.sh` | No* | ClamAV runs unprivileged |
| `check-mac-addresses.sh` | No | File content scanning |
| `check-host-security.sh` | Partial | Some checks need root |
| `scan-vulnerabilities.sh` | Recommended | Nmap/Lynis more thorough with root |
| `collect-host-inventory.sh` | No | Uses system_profiler |
| `harden-system.sh` | Yes (--apply) | Modifies system config |
| `secure-delete.sh` | No | User file deletion |
| `purge-git-history.sh` | No | Git operations only |

*ClamAV database updates (`freshclam`) may require sudo on first run.

### Known Limitations

1. **False Positives**: Pattern-based scanning (PII, secrets) has inherent false positive rates
   - Use `<target>/.allowlists/pii-allowlist` and `<target>/.allowlists/secrets-allowlist` to suppress known-good matches
   - Allowlist files are created in the `.allowlists/` subdirectory of the scanned project (gitignored by default)
   - Each allowlist entry requires justification and includes SHA256 hash for integrity

2. **False Negatives**: Scans cannot detect:
   - Obfuscated malware (ClamAV limitation)
   - Encrypted secrets
   - Novel attack patterns
   - Logic vulnerabilities

3. **Platform-Specific**: Some checks are macOS or Linux specific
   - `check-host-security.sh` has platform-specific code paths
   - Lynis findings vary by platform (see `docs/false-positives-macos.md`)

4. **Point-in-Time**: Scans reflect state at execution time
   - Code changes invalidate prior attestations
   - Re-scan after any modification

5. **Network Scanning**: Requires authorization
   - Only scan systems you own or have permission to test
   - Remote scans may trigger security alerts

### Threat Model

**What This Toolkit Detects:**
- Accidental PII/secret commits
- Known malware signatures
- Common misconfigurations
- Network service exposures
- Hardcoded credentials

**What This Toolkit Does NOT Detect:**
- Zero-day vulnerabilities
- Sophisticated APT techniques
- Social engineering vectors
- Supply chain attacks
- Business logic flaws

### Security Guarantees

1. **No Data Exfiltration**: Scripts do not transmit data externally
2. **No Code Execution from Targets**: Scans read files, never execute them
3. **Audit Trail**: All scan results are timestamped and checksummed
4. **Fail-Safe Defaults**: Destructive operations require explicit confirmation

---

## Dependencies

- **Required**: grep (with -E extended regex), git (for version identification)
- **Required for malware scan**: ClamAV (`clamscan`, `freshclam`, `sigtool`)
- **Optional for PDF generation**: pdflatex (from TeX Live or BasicTeX)
- **macOS specific**: Various system commands for host security checks
- **Linux specific**: ufw/iptables, SELinux/AppArmor for host security checks

### Installing Dependencies

**macOS:**
```bash
brew install clamav
brew install basictex  # For PDF generation (optional)
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install clamav clamav-daemon
sudo apt install texlive-latex-base  # For PDF generation (optional)
```
