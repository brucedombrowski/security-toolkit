# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-01-15

### Added

- **ClamAV Database Management**
  - Automatic virus database update attempt via `freshclam` before scan
  - Detailed virus database information in scan output:
    - Database location
    - Main, Daily, and Bytecode database versions
    - Build timestamps for each database
    - Signature counts
  - Automatic detection of `freshclam.conf` location
  - Helpful guidance when config file is missing

## [1.3.0] - 2026-01-15

### Added

- **Enhanced Malware Scan with File Hashes**
  - Verbose file-by-file scan output
  - JSON metadata with MD5, SHA1, SHA256 hashes for every scanned file
  - Native ClamAV log file saved to `.scans/clamav-log-YYYY-MM-DD.txt`
  - Metadata directory with per-file JSON: `.scans/malware-metadata-YYYY-MM-DD/`
  - File hash manifest displayed in scan output
  - Excludes `.scans/` and `.git/` directories from scanning

## [1.2.0] - 2026-01-15

### Added

- **Scan Output Checksums**
  - `checksums.md` file generated in `.scans/` directory
  - SHA256 checksums for all scan output files
  - Enables integrity verification of scan results with `shasum -a 256 -c checksums.md`

## [1.1.0] - 2026-01-15

### Added

- **Scan Output Persistence**
  - Scan results now saved to `<target>/.scans/` directory for submittal purposes
  - Individual scan files: `pii-scan-YYYY-MM-DD.txt`, `malware-scan-YYYY-MM-DD.txt`, etc.
  - Consolidated report: `security-scan-report-YYYY-MM-DD.txt`

- **Toolkit Identification in Scan Output**
  - All scan outputs now include toolkit version and commit hash
  - GitHub source URL included for traceability
  - Example: `Toolkit: Security Verification Toolkit v1.1.0 (abc1234)`

- **Release Checksums**
  - `checksums.txt` attached to GitHub releases for integrity verification
  - Enables `sha256sum -c checksums.txt` verification workflow

### Changed

- Updated README with scan output documentation
- Individual scan scripts now report toolkit version in headers

## [1.0.0] - 2026-01-14

### Added

- **Security Scanning Scripts**
  - `check-pii.sh` - PII pattern detection (SSN, phone numbers, credit cards, IP addresses)
  - `check-malware.sh` - ClamAV-based malware scanning
  - `check-secrets.sh` - Secrets and credential detection (API keys, tokens, passwords)
  - `check-mac-addresses.sh` - IEEE 802.3 MAC address detection
  - `check-host-security.sh` - Host OS security posture verification (macOS/Linux)
  - `run-all-scans.sh` - Consolidated scan runner with summary report

- **Compliance Documentation Generator**
  - `generate-compliance.sh` - Automated security compliance statement PDF generation
  - LaTeX template integration for professional PDF output
  - NIST SP 800-53 control mapping in generated documents

- **Documentation**
  - `README.md` - Project overview and usage instructions
  - `AGENTS.md` - AI agent development guide
  - `COMPLIANCE.md` - Compliance workflow documentation
  - `LICENSE` - MIT License

### NIST Control Coverage

| Control | Family | Script |
|---------|--------|--------|
| SI-3 | System and Information Integrity | `check-malware.sh` |
| SI-12 | System and Information Integrity | `check-pii.sh` |
| SA-11 | System and Services Acquisition | `check-secrets.sh` |
| SC-8 | System and Communications Protection | `check-mac-addresses.sh` |
| CM-6 | Configuration Management | `check-host-security.sh` |

### Standards Alignment

- NIST SP 800-53 Rev 5 (Security and Privacy Controls)
- NIST SP 800-171 (Protecting CUI in Nonfederal Systems)
- FIPS 199 (Standards for Security Categorization)
- FIPS 200 (Minimum Security Requirements)

[1.4.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.4.0
[1.3.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.3.0
[1.2.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.2.0
[1.1.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.1.0
[1.0.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.0.0
