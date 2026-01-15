# Security

IT security analysis and compliance documentation tools for software projects.

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
| `check-host-security.sh` | CM-6 | Host OS security posture verification |
| `check-mac-addresses.sh` | SC-8 | IEEE 802.3 MAC address detection |
| `check-malware.sh` | SI-3 | ClamAV malware scanning |
| `check-pii.sh` | SI-12 | Scan for PII patterns (SSN, phone, IP, credit card) |
| `check-secrets.sh` | SA-11 | Detect hardcoded credentials and API keys |
| `collect-host-inventory.sh` | CM-8 | System component inventory (CUI-marked) |
| `generate-compliance.sh` | - | Generate security compliance statement PDF |
| `generate-scan-attestation.sh` | - | Generate PDF attestation from scan results |
| `purge-git-history.sh` | SP 800-88 | Remove sensitive files from git history |
| `redact-examples.sh` | - | Strip sensitive data for public examples |
| `run-all-scans.sh` | - | Run all scans with consolidated report |
| `scan-vulnerabilities.sh` | RA-5, SI-2 | Comprehensive vulnerability scanning (Nmap/OpenVAS/Lynis) |
| `secure-delete.sh` | SP 800-88 | Securely delete files (NIST Clear method) |

## Usage

### Release Workflow (Recommended)

The recommended workflow for releasing the toolkit:

1. **Run `release.sh`** - Executes non-interactive scans and prepares release
   ```bash
   ./release.sh                    # Generate test release (0.0.0-test.TIMESTAMP)
   ./release.sh 1.12.0             # Prepare specific version release
   ./release.sh --skip-tests       # Skip scans (not recommended)
   ```

2. **Review output** - If scans report findings, review and address them

3. **Run interactive scans** - If findings need review, run scans interactively
   ```bash
   ./scripts/run-all-scans.sh      # Interactive mode (default)
   ```

4. **Review artifacts** - Verify generated files in `.scans/`:
   - `scan-attestation-*.pdf` - PDF attestation document
   - `checksums.md` - SHA256 checksums for verification
   - Individual scan logs

### Scan a specific project

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

### Integrate into CI/CD

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    git clone https://github.com/brucedombrowski/Security.git /tmp/security
    /tmp/security/scripts/run-all-scans.sh ${{ github.workspace }}
```

### Integrate into build script

```bash
# In your project's build.sh
SECURITY_REPO="/path/to/Security"
if [ -x "$SECURITY_REPO/scripts/run-all-scans.sh" ]; then
    "$SECURITY_REPO/scripts/run-all-scans.sh" "$(pwd)"
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

See [COMPLIANCE.md](COMPLIANCE.md) for detailed documentation on the compliance workflow.

### Vulnerability Scanning

Run comprehensive vulnerability assessments using open-source tools:

```bash
# Full vulnerability scan (Nmap + Lynis)
./scripts/scan-vulnerabilities.sh

# Scan specific network target
./scripts/scan-vulnerabilities.sh 192.168.1.0/24

# Quick scan mode
./scripts/scan-vulnerabilities.sh -q 10.0.0.1

# Nmap network scan only
./scripts/scan-vulnerabilities.sh -n 192.168.1.1

# Lynis system audit only
./scripts/scan-vulnerabilities.sh -l

# Full scan with elevated privileges (recommended)
sudo ./scripts/scan-vulnerabilities.sh
```

**NIST Controls Assessed:**
- RA-5: Vulnerability Monitoring and Scanning
- SI-2: Flaw Remediation
- SI-4: System Monitoring
- CM-6: Configuration Settings
- CA-2: Control Assessments

See [AGENTS.md](AGENTS.md#vulnerability-scanning-scan-vulnerabilitiessh) for complete NIST 800-53, 800-171, and FIPS 199/200 control mapping.

## Prerequisites

- **Bash** - Required to execute all security scripts (included by default on macOS/Linux)

- **ClamAV** - Required for malware scanning
  ```bash
  # macOS
  brew install clamav

  # Ubuntu/Debian
  sudo apt install clamav
  ```

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
| RA-5 | Risk Assessment | Vulnerability Monitoring and Scanning | `scan-vulnerabilities.sh` |
| SA-11 | System and Services Acquisition | Developer Testing and Evaluation | `check-secrets.sh` |
| SC-8 | System and Communications Protection | Transmission Confidentiality and Integrity | `check-mac-addresses.sh` |
| SI-2 | System and Information Integrity | Flaw Remediation | `scan-vulnerabilities.sh` |
| SI-3 | System and Information Integrity | Malicious Code Protection | `check-malware.sh` |
| SI-4 | System and Information Integrity | System Monitoring | `scan-vulnerabilities.sh` |
| SI-12 | System and Information Integrity | Information Management and Retention | `check-pii.sh` |

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
