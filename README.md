# Security Toolkit

IT security analysis and compliance documentation tools for software projects.

## Quick Start

### Option 1: Homebrew (macOS/Linux)

```bash
brew tap brucedombrowski/security-toolkit
brew install security-toolkit

# Run scans
security-scan /path/to/project
security-tui  # Interactive mode
```

### Option 2: Clone Repository

```bash
git clone https://github.com/brucedombrowski/security-toolkit.git
cd security-toolkit
./scripts/run-all-scans.sh /path/to/project
```

### Review Results

Results are saved in `.scans/` directory of your target project.

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALLATION.md](INSTALLATION.md) | Setup and prerequisites |
| [CLAUDE.md](CLAUDE.md) | AI agent instructions and architecture |
| [docs/TESTING.md](docs/TESTING.md) | Test architecture and contributor guide |
| [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | NIST control mapping |
| [docs/MAINTENANCE.md](docs/MAINTENANCE.md) | Maintenance schedules and procedures |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md) | CISA KEV, DHS MARs, NASA SOC-MARs integration |
| [docs/FALSE-POSITIVES-MACOS.md](docs/FALSE-POSITIVES-MACOS.md) | macOS-specific guidance |

## Overview

This toolkit provides automated security verification scripts aligned with federal security standards:

| Standard | Title |
|----------|-------|
| FIPS 199 | Standards for Security Categorization |
| FIPS 200 | Minimum Security Requirements |
| NIST SP 800-53 Rev 5 | Security and Privacy Controls |
| NIST SP 800-171 | Protecting CUI in Nonfederal Systems |

## Scripts

| Script | NIST Control | Description |
|--------|--------------|-------------|
| `backup-guidance.sh` | CP-9, CP-10 | Display backup guidance before scans/remediation |
| `check-containers.sh` | CM-8, RA-5 | Scan Docker/Podman/nerdctl containers for vulnerabilities |
| `check-host-security.sh` | CM-6 | Host OS security posture verification |
| `check-kev.sh` | RA-5, SI-5 | Cross-reference CVEs against CISA KEV catalog |
| `check-mac-addresses.sh` | SC-8 | IEEE 802.3 MAC address detection |
| `check-malware.sh` | SI-3 | Malware scanning (ClamAV, future: Windows Defender) |
| `check-nvd-cves.sh` | RA-5, SI-2 | Cross-reference installed software against NVD |
| `check-pii.sh` | SI-12 | Scan for PII patterns (SSN, phone, IP, credit card) |
| `check-secrets.sh` | SA-11 | Detect hardcoded credentials and API keys |
| `collect-host-inventory.sh` | CM-8 | System component inventory (CUI-marked) |
| `Collect-HostInventory.ps1` | CM-8 | Windows PowerShell host inventory |
| `generate-compliance.sh` | - | Generate security compliance statement PDF |
| `generate-scan-attestation.sh` | - | Generate PDF attestation from scan results |
| `generate-verification-report.sh` | CA-2 | Generate verification package PDF |
| `harden-system.sh` | CM-6, SC-7 | Apply security hardening configurations |
| `pre-scan-cleanup.sh` | SI-14 | Clean temp files/caches before scanning |
| `purge-git-history.sh` | SP 800-88 | Remove sensitive files from git history |
| `redact-examples.sh` | - | Strip sensitive data for public examples |
| `release.sh` | - | Release workflow (maintainers only) |
| `run-all-scans.sh` | - | Run all scans with consolidated report |
| `scan-vulnerabilities.sh` | RA-5, SI-2 | Comprehensive vulnerability scanning (Nmap/OpenVAS/Lynis) |
| `secure-delete.sh` | SP 800-88 | Securely delete files (NIST Clear method) |
| `tui.sh` | - | Interactive TUI for scan selection |
| `upgrade.sh` | - | Upgrade toolkit to latest version |

### Security Validation Scripts

These scripts validate the toolkit's own security controls:

| Script | NIST Control | Description |
|--------|--------------|-------------|
| `test-cui-data-exposure.sh` | AC-3, MP-2, MP-6 | Verify CUI protection in host inventory |
| `test-git-purge-dry-run.sh` | SI-12, CM-3 | Verify safe git history purge with dry-run |
| `test-latex-injection.sh` | SI-10 | Test LaTeX special character escaping |
| `test-rm-rf-validation.sh` | SI-10 | Test destructive command validation |
| `test-symlink-attacks.sh` | SI-4, SI-10 | Verify symlink attack prevention |

## Usage

```bash
# Run all scans on a target directory (interactive mode)
./scripts/run-all-scans.sh /path/to/project

# Run in non-interactive mode (for CI/CD)
./scripts/run-all-scans.sh -n /path/to/project

# Run individual scans
./scripts/check-pii.sh /path/to/project
./scripts/check-secrets.sh /path/to/project
./scripts/check-malware.sh /path/to/project

# Securely delete scan artifacts (NIST SP 800-88)
./scripts/secure-delete.sh -rf .scans/
```

### Interactive TUI Mode

For a menu-driven experience, use the TUI:

```bash
./scripts/tui.sh /path/to/project
```

Features:
- **Run All Scans** - Execute complete scan suite with progress spinner
- **Select Individual Scans** - Toggle specific scans (PII, secrets, malware, etc.)
- **View Scan Results** - Browse and open result files
- **Generate Verification Report** - Create PDF compliance package
- **Change Target Directory** - Switch projects without restarting

The TUI shows elapsed time during long-running scans (like malware scanning) so you know it's still working. Works with Bash 3.2+ (macOS default).

### Container Security Scanning

Scan running Docker, Podman, or nerdctl containers for known vulnerabilities:

```bash
# Scan all running containers (auto-detects runtime)
./scripts/check-containers.sh

# Use specific runtime
./scripts/check-containers.sh --runtime podman

# Via Homebrew
security-containers
```

The scanner:
- Auto-detects container runtime (Docker, Podman, nerdctl)
- Extracts software versions from running containers
- Cross-references against NVD CVE database
- Checks for CISA KEV (Known Exploited Vulnerabilities) matches

**Vulnerable Lab Demo:**

Test the scanner with intentionally vulnerable containers:

```bash
./scripts/scan-containers.sh  # Starts 5 vulnerable containers and scans them
```

See [demo/vulnerable-lab/README.md](demo/vulnerable-lab/README.md) for details.

### Integrate into CI/CD

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    git clone https://github.com/brucedombrowski/security-toolkit.git /tmp/security-toolkit
    /tmp/security-toolkit/scripts/run-all-scans.sh ${{ github.workspace }}
```

### Integrate into build script

```bash
# In your project's build.sh
SECURITY_TOOLKIT="/path/to/security-toolkit"
if [ -x "$SECURITY_TOOLKIT/scripts/run-all-scans.sh" ]; then
    "$SECURITY_TOOLKIT/scripts/run-all-scans.sh" "$(pwd)"
fi
```

### Generate Compliance Documentation

Generate a formal security compliance statement PDF for a project:

```bash
# Generate PDF and place in project directory
./scripts/generate-compliance.sh /path/to/project

# Specify custom output location
./scripts/generate-compliance.sh /path/to/project /path/to/output
```

See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for detailed documentation on the compliance workflow.

### Vulnerability Scanning

Run comprehensive vulnerability assessments using open-source tools:

```bash
# Quick scan mode (recommended for localhost without sudo)
./scripts/scan-vulnerabilities.sh -q

# Lynis system audit only (fast, no network scan)
./scripts/scan-vulnerabilities.sh -l

# Full scan with elevated privileges (recommended for comprehensive results)
sudo ./scripts/scan-vulnerabilities.sh

# Scan specific network target
./scripts/scan-vulnerabilities.sh 192.168.1.0/24

# Quick scan of specific host
./scripts/scan-vulnerabilities.sh -q 10.0.0.1

# Nmap network scan only
./scripts/scan-vulnerabilities.sh -n 192.168.1.1
```

**Note:** Unprivileged Nmap scans of localhost may show "Strange read error" messages - this is a known Nmap issue with TCP connect scans. Use `-q` (quick) mode or run with `sudo` for best results.

**NIST Controls Assessed:**
- RA-5: Vulnerability Monitoring and Scanning
- SI-2: Flaw Remediation
- SI-4: System Monitoring
- CM-6: Configuration Settings
- CA-2: Control Assessments

See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for complete NIST control mapping.

## Homebrew Commands

When installed via Homebrew, these commands are available:

| Command | Description |
|---------|-------------|
| `security-scan` | Run all security scans on a directory |
| `security-tui` | Interactive menu interface |
| `security-inventory` | Collect host system inventory |
| `security-pii` | Scan for PII patterns |
| `security-secrets` | Scan for hardcoded secrets |
| `security-malware` | Run malware scan |
| `security-kev` | Check against CISA KEV catalog |
| `security-containers` | Scan running containers |

## Prerequisites

- **Bash** - Required to execute all security scripts (included by default on macOS/Linux)

- **Malware Scanner** - Required for malware scanning (SI-3 compliance)
  - **macOS/Linux:** ClamAV recommended
    ```bash
    # macOS
    brew install clamav

    # Ubuntu/Debian
    sudo apt install clamav
    ```
  - **Windows:** Windows Defender (built-in) - native support planned

- **pdflatex** - Required for compliance PDF generation (TeX Live or MiKTeX)
  ```bash
  # macOS
  brew install --cask mactex-no-gui

  # Ubuntu/Debian
  sudo apt install texlive-latex-base texlive-latex-recommended
  ```

- **grep** - Standard grep with extended regex support (included in macOS/Linux)

- **Nmap** - Required for network vulnerability scanning
  ```bash
  # macOS
  brew install nmap

  # Ubuntu/Debian
  sudo apt install nmap
  ```

- **Lynis** - Required for system security auditing
  ```bash
  # macOS
  brew install lynis

  # Ubuntu/Debian
  sudo apt install lynis
  ```

- **OpenVAS/GVM** - Optional for comprehensive vulnerability assessment
  ```bash
  # See: https://greenbone.github.io/docs/latest/
  # OpenVAS requires dedicated setup and daemon configuration
  ```

## Exit Codes

All scripts follow standard exit code conventions:
- `0` = Pass (no issues found)
- `1` = Fail (issues detected or scan error)

## Scan Output

Scan results are saved to `<target_project>/.scans/` for submittal purposes:

```
.scans/
├── security-scan-report-2026-01-14.txt  # Consolidated report
├── pii-scan-2026-01-14.txt              # PII pattern scan
├── malware-scan-2026-01-14.txt          # ClamAV malware scan
├── secrets-scan-2026-01-14.txt          # Secrets/credentials scan
├── mac-address-scan-2026-01-14.txt      # MAC address scan
└── host-security-scan-2026-01-14.txt    # Host security scan
```

Add `.scans/` to your project's `.gitignore`:

```bash
echo ".scans/" >> /path/to/project/.gitignore
```

## Scan Philosophy

**"You are only as good as your last scan."**

Scan results are point-in-time attestations. Each run of `run-all-scans.sh` overwrites previous results because:

- Any code change invalidates prior scans
- The only relevant attestation is the current one
- Stale scan results provide false assurance

If you need to preserve scan results for a specific release or submittal, copy the `.scans/` directory contents before re-running. The timestamped PDF attestation (`scan-attestation-YYYY-MM-DDTHHMMSSZ.pdf`) provides a unique artifact for each scan run.

## Security Policy

- Detailed vulnerability information is displayed for remediation
- Scan results are saved locally for audit/submittal purposes
- Add `.scans/` to `.gitignore` to prevent committing scan artifacts

## NIST Control Mapping

| Control | Family | Description | Script |
|---------|--------|-------------|--------|
| CA-2 | Assessment, Authorization | Control Assessments | `scan-vulnerabilities.sh` |
| CM-6 | Configuration Management | Configuration Settings | `check-host-security.sh`, `scan-vulnerabilities.sh` |
| CM-8 | Configuration Management | System Component Inventory | `collect-host-inventory.sh`, `scan-vulnerabilities.sh` |
| MP-6 | Media Protection | Media Sanitization | `secure-delete.sh`, `purge-git-history.sh` |
| RA-5 | Risk Assessment | Vulnerability Monitoring and Scanning | `scan-vulnerabilities.sh`, `check-nvd-cves.sh`, `check-kev.sh` |
| SA-11 | System and Services Acquisition | Developer Testing and Evaluation | `check-secrets.sh` |
| SC-8 | System and Communications Protection | Transmission Confidentiality and Integrity | `check-mac-addresses.sh` |
| SI-2 | System and Information Integrity | Flaw Remediation | `scan-vulnerabilities.sh`, `check-nvd-cves.sh` |
| SI-3 | System and Information Integrity | Malicious Code Protection | `check-malware.sh` |
| SI-4 | System and Information Integrity | System Monitoring | `scan-vulnerabilities.sh` |
| SI-12 | System and Information Integrity | Information Management and Retention | `check-pii.sh` |

## Requirements & Verification Framework

The toolkit includes a machine-readable requirements framework for compliance documentation:

```
requirements/
├── controls/
│   ├── nist-800-53.json      # NIST SP 800-53 Rev 5 control definitions
│   └── nist-800-171.json     # NIST SP 800-171 Rev 2 control definitions
├── functional/
│   └── functional-requirements.json  # Toolkit functional requirements (FR-001 to FR-014)
├── mapping.json              # Traceability matrix (Requirement → Control → Script → Test)
└── project-requirements-template.json  # Template for your project's requirements
```

### For Your Project

If your project has compliance requirements that reference NIST controls, you can:

1. **Define your requirements** in JSON using the template
2. **Link to NIST controls** that your requirements satisfy
3. **Run toolkit scans** to generate verification evidence
4. **Use the PDF attestation** for compliance submittals

Example traceability chain:
```
Your Requirement     →  NIST Control  →  Toolkit Script    →  Evidence
────────────────────────────────────────────────────────────────────────
"No hardcoded creds" →  SA-11         →  check-secrets.sh  →  secrets-scan.txt
"Vuln monitoring"    →  RA-5, SI-2    →  check-nvd-cves.sh →  nvd-cve-scan.txt
```

See [`requirements/README.md`](requirements/README.md) for detailed documentation.

## CUI Handling

The `collect-host-inventory.sh` script generates output marked as **Controlled Unclassified Information (CUI)** per:

| Reference | Title |
|-----------|-------|
| 32 CFR Part 2002 | Controlled Unclassified Information |
| NIST SP 800-171 | Protecting CUI in Nonfederal Systems |
| CUI Registry | CTI (Controlled Technical Information) |

Host inventory output contains:
- MAC addresses (network infrastructure identifiers)
- Serial numbers (asset tracking data)
- Installed software versions (configuration data)

**Handling requirements:**
- Store on encrypted media or NIST 800-171 compliant systems
- Limit access to authorized personnel
- Do not post to public repositories
- Destroy securely when no longer needed: `./scripts/secure-delete.sh -rf .scans/`

### Removing CUI from Git History

If CUI-marked files (like host inventory) are accidentally committed to a repository, removing them from the current commit is **not sufficient**. Git preserves the file in history, making it recoverable.

**To completely remove sensitive files from git history:**

```bash
# 1. Preview affected commits (dry run)
./scripts/purge-git-history.sh --dry-run 'path/to/sensitive-file.txt'

# 2. Remove file from all commits
./scripts/purge-git-history.sh 'path/to/sensitive-file.txt'

# 3. Force push to remote (rewrites history)
git push origin --force --all

# 4. Clean up local repository
rm -rf .git/refs/original/
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# 5. Notify collaborators to re-clone
```

**Why this matters:**
- `git rm` only removes from current state, not history
- Anyone with repository access can checkout old commits
- GitHub/GitLab retain commit history even after deletion
- NIST SP 800-88 requires sanitization of all copies

This applies the NIST SP 800-88 "Clear" sanitization method to version control systems.

## License

MIT License - see [LICENSE](LICENSE) file.
