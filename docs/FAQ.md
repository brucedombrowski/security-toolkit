# Frequently Asked Questions & Troubleshooting

Security Verification Toolkit - Common Questions and Solutions

## Table of Contents

- [General Questions](#general-questions)
- [Installation Issues](#installation-issues)
- [Scan Problems](#scan-problems)
- [False Positives](#false-positives)
- [Performance](#performance)
- [CI/CD Integration](#cicd-integration)
- [CUI Handling](#cui-handling)

---

## General Questions

### What does this toolkit do?

The Security Verification Toolkit automates security scanning aligned with federal standards:
- **PII Detection** - Finds personal data (SSNs, credit cards, phone numbers)
- **Secrets Detection** - Finds API keys, passwords, private keys
- **Malware Scanning** - Uses ClamAV to detect malicious files
- **Vulnerability Assessment** - Nmap, Lynis, OpenVAS integration
- **System Inventory** - Collects hardware and software inventory

All scans map to NIST SP 800-53 and NIST SP 800-171 controls.

### Which NIST controls does this implement?

| Control | Description | Scanner |
|---------|-------------|---------|
| SI-3 | Malware Protection | check-malware.sh |
| SI-12 | Information Management | check-pii.sh |
| SA-11 | Developer Testing | check-secrets.sh |
| RA-5 | Vulnerability Scanning | scan-vulnerabilities.sh |
| CM-8 | System Component Inventory | collect-host-inventory.sh |
| MP-6 | Media Sanitization | secure-delete.sh |

See [COMPLIANCE.md](COMPLIANCE.md) for complete control mapping.

### What platforms are supported?

- **macOS** (Intel and Apple Silicon) - Full support
- **Linux** (Ubuntu, Debian, CentOS, RHEL) - Full support
- **Windows** - PowerShell script for host inventory (`Collect-HostInventory.ps1`)

---

## Installation Issues

### ClamAV not found

**Error:**
```
SKIPPED: ClamAV (clamscan) not found
```

**Solution:**
```bash
# macOS
brew install clamav
sudo freshclam  # Download virus definitions

# Ubuntu/Debian
sudo apt install clamav clamav-daemon
sudo freshclam

# CentOS/RHEL
sudo yum install clamav clamav-update
sudo freshclam
```

### freshclam fails with permission error

**Error:**
```
ERROR: Can't create freshclam.dat in /opt/homebrew/var/lib/clamav
```

**Solution:**
```bash
# macOS - Fix permissions
sudo chown -R $(whoami) /opt/homebrew/var/lib/clamav

# Linux - Run as root or with proper group
sudo freshclam
```

### pdflatex not found (PDF attestation fails)

**Error:**
```
pdflatex not found. Install TeX Live or MiKTeX.
```

**Solution:**
```bash
# macOS
brew install --cask basictex
# Restart terminal, then:
sudo tlmgr update --self
sudo tlmgr install collection-latexrecommended

# Ubuntu/Debian
sudo apt install texlive-latex-base texlive-latex-recommended

# CentOS/RHEL
sudo yum install texlive-latex
```

### timeout command not found (Linux)

**Error:**
```
timeout: command not found
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install coreutils

# macOS (uses gtimeout)
brew install coreutils
```

---

## Scan Problems

### Scan hangs or takes too long

**Possible causes:**
1. Large repository with many files
2. ClamAV database update running
3. Scanning network drives or symlinks

**Solutions:**
1. Use `.pii-exclude` to skip large directories:
   ```
   node_modules/
   .git/
   vendor/
   ```

2. Skip malware scan for quick checks:
   ```bash
   ./scripts/run-all-scans.sh --skip-malware .
   ```

3. Run scans on local filesystem, not network mounts

### Scan exits with code 1 but shows "PASS"

This is expected behavior. Exit code 1 means "review required" even if individual scans pass. Check the full report in `.scans/` for details.

### "Permission denied" errors during scan

**Solution:**
```bash
# Run with appropriate permissions
sudo ./scripts/run-all-scans.sh /path/to/scan

# Or fix file permissions
chmod -R u+r /path/to/scan
```

### Docker warning but scan continues

**Message:**
```
WARNING: Docker is installed but the Docker daemon is not running.
```

This is informational only. Docker is optional for advanced scanning features. The scan will continue with native tools.

---

## False Positives

### IP addresses in documentation flagged

**Problem:** Example IPs like `192.168.1.1` in README files are flagged.

**Solution:** Add to `.pii-exclude`:
```
docs/
README.md
examples/
```

Or add specific matches to `.allowlists/pii-allowlist` using interactive mode:
```bash
./scripts/check-pii.sh -i .
```

### Version numbers flagged as IPs

**Problem:** Patterns like `1.2.3.4` (version numbers) flagged as IPs.

**Solution:** This is a known limitation. Use the allowlist to accept specific matches. See [FALSE-POSITIVES-MACOS.md](FALSE-POSITIVES-MACOS.md) for macOS-specific issues.

### Credit card test numbers flagged

**Problem:** Test card numbers like `4111111111111111` are detected.

**Solution:** The Luhn algorithm validates these as real card patterns. If they're intentional test data:
1. Add to `.pii-exclude` if in test directories
2. Use interactive mode to allowlist specific matches

### API key patterns in comments

**Problem:** Example API keys in documentation are flagged.

**Solution:** Add to `.pii-exclude`:
```
# Documentation with example keys
docs/api-reference.md
examples/
```

---

## Performance

### How long do scans take?

Typical scan times (varies by hardware and repository size):

| Scan Type | Small Repo (<1000 files) | Medium (1000-10000) | Large (>10000) |
|-----------|--------------------------|---------------------|----------------|
| PII | 5-10 seconds | 30-60 seconds | 2-5 minutes |
| Secrets | 5-10 seconds | 30-60 seconds | 2-5 minutes |
| Malware | 1-2 minutes | 5-10 minutes | 15-30 minutes |
| Full Suite | 2-3 minutes | 10-15 minutes | 30-60 minutes |

### How to speed up scans?

1. **Exclude unnecessary directories** in `.pii-exclude`:
   ```
   node_modules/
   .git/
   vendor/
   build/
   dist/
   ```

2. **Skip malware scan** for quick development checks:
   ```bash
   ./scripts/run-all-scans.sh --skip-malware .
   ```

3. **Run specific scans** instead of full suite:
   ```bash
   ./scripts/check-pii.sh .
   ./scripts/check-secrets.sh .
   ```

4. **Update ClamAV database** during off-hours to avoid slowdowns

### Memory usage during scans

- PII/Secrets scans: ~50-100 MB
- Malware scan: ~500 MB - 1 GB (ClamAV database)
- Host inventory: ~20-50 MB

---

## CI/CD Integration

### GitHub Actions example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clamav
          sudo freshclam

      - name: Run security scans
        run: ./scripts/run-all-scans.sh -n .

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: .scans/
```

### Scan fails in CI but passes locally

**Common causes:**
1. Missing dependencies in CI environment
2. Different file permissions
3. Symlinks not preserved in checkout

**Solutions:**
1. Ensure dependencies are installed (see workflow above)
2. Use `chmod +x scripts/*.sh` if needed
3. Check `actions/checkout` settings for symlink handling

### How to fail CI on findings?

The scan scripts return:
- Exit code 0 = All scans passed
- Exit code 1 = Findings require review
- Exit code 2 = Missing dependencies (skipped)

Use exit code to fail the build:
```yaml
- name: Run security scans
  run: ./scripts/run-all-scans.sh -n .
  # Build fails if exit code != 0
```

---

## CUI Handling

### What is CUI?

Controlled Unclassified Information (CUI) is sensitive but unclassified government information requiring safeguarding per 32 CFR Part 2002 and NIST SP 800-171.

### Which scan outputs contain CUI?

| File | CUI Content | Handling |
|------|-------------|----------|
| host-inventory-*.txt | MAC addresses, serial numbers, software versions | Store encrypted, limit distribution |
| vulnerability-scan-*.txt | Network topology, open ports | Store encrypted, limit distribution |

### How to securely delete CUI files?

```bash
# Single file
./scripts/secure-delete.sh .scans/host-inventory-*.txt

# Multiple files (dry-run first)
./scripts/secure-delete.sh --dry-run .scans/*.txt
./scripts/secure-delete.sh .scans/*.txt
```

### Why does host inventory show a big warning?

The warning ensures operators understand the file contains CUI:
```
⚠️  SECURITY WARNING: CONTROLLED UNCLASSIFIED INFORMATION (CUI)
```

This is required by NIST SP 800-171 control 3.1.22 (Security Awareness).

---

## Getting Help

### Where to report bugs?

Open an issue at: https://github.com/brucedombrowski/Security/issues

### Where to request features?

Open a feature request issue with the `enhancement` label.

### Security vulnerabilities?

See [SECURITY.md](../SECURITY.md) for responsible disclosure procedures.
