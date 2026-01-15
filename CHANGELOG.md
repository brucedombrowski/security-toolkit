# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.10.0] - 2026-01-15

### Added

- **CUI Markings for Host Inventory**
  - `collect-host-inventory.sh` output now includes CUI banner and footer
  - CUI Category: CTI (Controlled Technical Information)
  - References 32 CFR Part 2002 and NIST SP 800-171
  - Handling notice with specific guidance for sensitive data

- **CUI Handling Documentation**
  - New CUI Handling section in README.md
  - Documents CUI category, references, and handling requirements
  - CM-8 (System Component Inventory) added to NIST Control Mapping

- **Security Compliance Statement Template**
  - New LaTeX template for security compliance PDF
  - NIST control mapping for automated scans
  - Cryptographic implementation documentation
  - Certificate handling and security controls
  - CUI handling section

### Changed

- All scan scripts now use UTC timestamps in ISO 8601 format
- Format: `YYYY-MM-DDTHH:MM:SSZ` (e.g., `2026-01-15T14:30:00Z`)
- Consistent timestamps across all output files

## [1.9.0] - 2026-01-15

### Added

- **Reviewed Exceptions in PDF Attestation**
  - New section showing allowlisted items with their justifications
  - Total exception count displayed in attestation
  - References `.pii-allowlist` file for audit trail

### Changed

- `run-all-scans.sh` now runs in interactive mode by default
- Added `-n|--non-interactive` flag to skip interactive prompts
- Interactive flag (`$INTERACTIVE_FLAG`) applied consistently to all supporting scans
- Updated OID explanation to clarify certificate filtering usage

## [1.8.0] - 2026-01-15

### Added

- **Interactive PII Review Mode**
  - New `-i` flag for `check-pii.sh` enables interactive review of findings
  - Prompts user to Accept, Reject, or Skip each potential PII match
  - Accepted findings stored in `.pii-allowlist` with reason and hash
  - Allowlisted items automatically skipped in future scans
  - Non-interactive mode suggests `-i` flag when findings detected

## [1.7.0] - 2026-01-15

### Added

- **Enhanced PDF Attestation**
  - Host Inventory Reference section with SHA256 checksum
  - Scan Output Checksums section listing all generated files
  - CM-8 (System Component Inventory) added to NIST Control Mapping table
  - Privacy note explaining inventory checksum reference design
  - Date-stamped file references in checksums table

### Changed

- PDF attestation template now includes complete audit trail
- `run-all-scans.sh` substitutes inventory checksum and date stamp into PDF

## [1.6.0] - 2026-01-15

### Added

- **Host Inventory Collection**
  - New `collect-host-inventory.sh` script for comprehensive system inventory
  - Captures OS version, kernel, architecture, hardware model, serial number
  - Network interfaces with MAC addresses, IP addresses, and status
  - Installed software packages (Homebrew, dpkg, rpm)
  - Security-relevant software versions (ClamAV, OpenSSL, SSH, GPG, etc.)
  - NIST SP 800-53 CM-8 (System Component Inventory) aligned

- **Inventory-Referenced Scans**
  - Host inventory collected first, creating a verifiable system thumbprint
  - All scan outputs include inventory SHA256 checksum reference
  - Enables sharing scan results without exposing sensitive machine data
  - Checksums.md documents the inventory reference with privacy note

### Changed

- `run-all-scans.sh` now collects host inventory before running scans
- Individual scan outputs include inventory reference header
- `check-host-security.sh` simplified to reference separate inventory script

## [1.5.0] - 2026-01-15

### Added

- **PDF Scan Attestation Generation**
  - Automatic PDF attestation document generated after scans complete
  - Professional LaTeX template with NIST control mapping
  - Dynamic substitution of scan results, timestamps, and toolkit version
  - PASS/FAIL color-coded results table
  - Includes verification instructions for scan output checksums
  - Output: `.scans/scan-attestation-YYYY-MM-DD.pdf`

- **Templates Directory**
  - `templates/scan_attestation.tex` - Generic attestation template for any project
  - `templates/logo.png` - Logo for PDF header

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

[1.10.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.10.0
[1.9.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.9.0
[1.8.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.8.0
[1.7.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.7.0
[1.6.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.6.0
[1.5.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.5.0
[1.4.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.4.0
[1.3.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.3.0
[1.2.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.2.0
[1.1.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.1.0
[1.0.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.0.0
