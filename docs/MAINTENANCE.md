# Maintenance Plan

Security Verification Toolkit - Maintenance and Operations Guide

## Overview

This document defines the maintenance procedures, update schedules, and operational responsibilities for the Security Verification Toolkit. Following NIST SP 800-53 SI-2 (Flaw Remediation) and CM-3 (Configuration Change Control).

## Maintenance Schedule

### Daily Tasks

| Task | Description | Script/Command |
|------|-------------|----------------|
| Virus Definition Updates | Update ClamAV signatures | `freshclam` (automatic via cron) |
| Log Review | Check scan logs for anomalies | Review `.scans/` directory |

### Weekly Tasks

| Task | Description | Script/Command |
|------|-------------|----------------|
| Full System Scan | Run complete security scan on development systems | `./scripts/run-all-scans.sh` |
| Allowlist Review | Review PII/secrets allowlist for expired entries | Check `.allowlists/` directory |
| Backup Verification | Verify backup systems are operational | `./scripts/backup-guidance.sh` |

### Monthly Tasks

| Task | Description | Script/Command |
|------|-------------|----------------|
| Vulnerability Assessment | Run full vulnerability scan | `./scripts/scan-vulnerabilities.sh` |
| Host Inventory Update | Collect updated system inventory | `./scripts/collect-host-inventory.sh` |
| Dependency Updates | Update toolkit dependencies | See [Dependency Updates](#dependency-updates) |
| Test Suite Execution | Run all unit tests | `./tests/run-all-tests.sh` |
| Documentation Review | Review and update documentation | Manual review |

### Quarterly Tasks

| Task | Description | Script/Command |
|------|-------------|----------------|
| Pattern Updates | Review and update detection patterns | See [Pattern Maintenance](#pattern-maintenance) |
| Security Audit | Internal security review of toolkit | Manual audit |
| Performance Review | Assess scan times and optimize | Benchmark testing |
| Compliance Review | Verify NIST control alignment | Review COMPLIANCE.md |

### Annual Tasks

| Task | Description | Script/Command |
|------|-------------|----------------|
| Major Version Review | Evaluate major version upgrade needs | Architecture review |
| Standards Update | Review NIST/FIPS standard updates | Update COMPLIANCE.md |
| Training | Team training on toolkit updates | Training session |
| Disaster Recovery Test | Test toolkit recovery procedures | DR drill |

---

## Dependency Updates

### ClamAV Virus Definitions

**Automatic Updates (Recommended):**
```bash
# macOS - Configure freshclam to run automatically
sudo freshclam

# Linux - Enable freshclam daemon
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-freshclam
```

**Manual Update:**
```bash
sudo freshclam
```

**Verification:**
```bash
clamscan --version
# Shows database version and signature count
```

### System Dependencies

| Dependency | Update Command (macOS) | Update Command (Linux) |
|------------|------------------------|------------------------|
| ClamAV | `brew upgrade clamav` | `apt update && apt upgrade clamav` |
| OpenSSL | `brew upgrade openssl` | `apt upgrade openssl` |
| LaTeX (BasicTeX) | `sudo tlmgr update --all` | `apt upgrade texlive` |
| Nmap | `brew upgrade nmap` | `apt upgrade nmap` |
| Lynis | `brew upgrade lynis` | `apt upgrade lynis` |
| BleachBit | `brew upgrade --cask bleachbit` | `apt upgrade bleachbit` |

### Toolkit Updates

```bash
# Update from GitHub
cd /path/to/Security
git pull origin main

# Verify integrity
git log --oneline -5
git status
```

---

## Pattern Maintenance

### PII Detection Patterns

Location: `scripts/check-pii.sh`

**Review Criteria:**
- False positive rate > 5% indicates pattern needs refinement
- New PII types identified in regulations
- Industry-specific patterns needed

**Update Process:**
1. Document the new pattern requirement
2. Add pattern to `check-pii.sh`
3. Add test case to `tests/test-pii-patterns.sh`
4. Run tests: `./tests/test-pii-patterns.sh`
5. Update examples with `./scripts/redact-examples.sh`

**Current Patterns:**
- Social Security Numbers (XXX-XX-XXXX)
- Phone Numbers (various formats)
- Credit Card Numbers (major card formats)
- IP Addresses (IPv4, IPv6)
- Email Addresses
- Date of Birth patterns

### Secrets Detection Patterns

Location: `scripts/check-secrets.sh`

**Review Criteria:**
- New API key formats from major providers
- New credential storage patterns
- CVE-related secret exposure patterns

**Update Process:**
1. Research new secret format
2. Add pattern with severity level
3. Add test case
4. Document in CLAUDE.md

**Current Patterns:**
- AWS Access Keys / Secret Keys
- Generic API Keys
- Private Keys (PEM format)
- Database Connection Strings
- Hardcoded Passwords
- Bearer Tokens
- GitHub/Slack Tokens
- Shell Command Injection

### Host Inventory Categories

Location: `scripts/collect-host-inventory.sh` (Bash), `scripts/Collect-HostInventory.ps1` (PowerShell)

**Review Criteria:**
- New software categories relevant to security
- Deprecated software detection
- Platform-specific updates

**Current Categories:**
- Security Tools
- Programming Languages (22)
- Web Browsers
- Backup and Restore Software
- Remote Desktop / Control Software
- Productivity Software
- Containers and Virtualization
- Web Servers
- Database Servers

---

## Allowlist Management

### Location
```
.allowlists/
├── pii-allowlist        # Reviewed PII false positives
└── secrets-allowlist    # Reviewed secrets false positives
```

### Allowlist Entry Format
```
# Hash | Reason | Date | Reviewer
abc123def456... | Example data in documentation | 2026-01-15 | jsmith
```

### Review Process

**Weekly Review:**
1. Check allowlist file modification dates
2. Remove entries older than 90 days (re-review required)
3. Verify entries still valid in codebase

**Removal Criteria:**
- Source file no longer exists
- Pattern changed in source
- Entry older than 90 days without re-review
- False positive confirmed as true positive

**Audit Trail:**
- All allowlist changes tracked in git history
- PDF attestation includes allowlist summary

---

## Backup and Recovery

### Toolkit Backup

**What to Back Up:**
- `.allowlists/` directory (contains reviewed exceptions)
- Custom patterns or modifications
- Local configuration files

**What NOT to Back Up:**
- `.scans/` directory (regenerated on each scan)
- Host inventory files (CUI - regenerate as needed)

### Recovery Procedure

1. **Clone from GitHub:**
   ```bash
   git clone https://github.com/brucedombrowski/Security.git
   ```

2. **Restore Allowlists:**
   ```bash
   cp /backup/.allowlists/* Security/.allowlists/
   ```

3. **Verify Installation:**
   ```bash
   cd Security
   ./tests/run-all-tests.sh
   ```

4. **Update Dependencies:**
   ```bash
   # macOS
   brew install clamav nmap lynis

   # Linux
   apt install clamav nmap lynis
   ```

---

## Incident Response

### Security Finding in Toolkit

1. **Assess Severity:**
   - Critical: Toolkit itself contains malware or backdoor
   - High: False negative allowing real secrets/PII through
   - Medium: False positive rate significantly increased
   - Low: Documentation or minor functionality issue

2. **Containment:**
   ```bash
   # Stop using affected version
   git checkout <last-known-good-tag>
   ```

3. **Investigation:**
   - Review git history for unauthorized changes
   - Run `./tests/run-all-tests.sh`
   - Check file integrity against release checksums

4. **Remediation:**
   - Apply fix to main branch
   - Create new release with fix
   - Update all deployed instances

5. **Documentation:**
   - Create issue in GitHub
   - Update SECURITY.md if needed
   - Notify affected users

### ClamAV Detection in Scanned Project

1. **Quarantine:** ClamAV automatically quarantines (if configured)
2. **Verify:** Check if false positive using VirusTotal
3. **Report:** If true positive, follow organization incident response
4. **Document:** Record in scan attestation PDF

---

## Performance Monitoring

### Scan Time Benchmarks

| Scan Type | Small Project (<1000 files) | Medium (1000-10000) | Large (>10000) |
|-----------|----------------------------|---------------------|----------------|
| PII Scan | < 30 seconds | < 2 minutes | < 10 minutes |
| Secrets Scan | < 30 seconds | < 2 minutes | < 10 minutes |
| Malware Scan | < 2 minutes | < 10 minutes | < 30 minutes |
| Full Suite | < 5 minutes | < 15 minutes | < 1 hour |

### Performance Optimization

**If scans exceed benchmarks:**

1. **Run Pre-Scan Cleanup:**
   ```bash
   ./scripts/pre-scan-cleanup.sh --dry-run
   ./scripts/pre-scan-cleanup.sh
   ```

2. **Exclude Large Binary Directories:**
   - Add to `.gitignore` (scans respect gitignore)
   - Or use scan-specific exclusions

3. **Update ClamAV:**
   - Newer versions often have performance improvements
   - Ensure signature database is not corrupted

4. **Hardware:**
   - SSD improves scan times significantly
   - More RAM helps with large file scanning

---

## Version History Maintenance

### Release Process

1. **Update CHANGELOG.md** with new features/fixes
2. **Run test suite:** `./tests/run-all-tests.sh`
3. **Run security scan on toolkit:** `./scripts/run-all-scans.sh .`
4. **Update version in scripts** (if hardcoded)
5. **Create git tag:** `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
6. **Push:** `git push origin main --tags`
7. **Create GitHub release** with release notes

### Versioning Scheme

Following [Semantic Versioning](https://semver.org/):

- **MAJOR (X):** Breaking changes to script interfaces
- **MINOR (Y):** New features, new scan types, new patterns
- **PATCH (Z):** Bug fixes, pattern updates, documentation

---

## Contacts and Escalation

### Repository
- GitHub: https://github.com/brucedombrowski/security-toolkit
- Issues: https://github.com/brucedombrowski/security-toolkit/issues

### Security Vulnerabilities
- Report via: SECURITY.md process
- Do not create public issues for security vulnerabilities

---

## Compliance Checklist

### NIST SP 800-53 Maintenance Controls

| Control | Description | Toolkit Implementation |
|---------|-------------|------------------------|
| SI-2 | Flaw Remediation | Dependency updates, pattern updates |
| SI-3 | Malicious Code Protection | ClamAV signature updates |
| CM-2 | Baseline Configuration | Host inventory collection |
| CM-3 | Configuration Change Control | Git version control |
| CM-8 | System Component Inventory | `collect-host-inventory.sh` |
| AU-6 | Audit Record Review | Log review, attestation PDFs |
| CA-7 | Continuous Monitoring | Scheduled scan execution |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-16 | Security Team | Initial release |

**Review Schedule:** Quarterly
**Next Review:** 2026-04-16
