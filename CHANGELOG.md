# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Fix jq injection in container and KEV scripts** (#133)
  - Replaced string interpolation with `--arg` in `jq` calls in `check-containers.sh` (4 calls) and `check-kev.sh` (1 call)
  - Prevented potential data exfiltration via crafted package names or CVE IDs

- **Fix eval injection in inventory detection** (#136)
  - Replaced `eval "$filter"` with safe case-based dispatch function in `detect.sh`
  - Only accepts known filter values (`cat`, `head -1`); unknown filters fall back safely

- **Fix predictable SSH control socket path** (#135)
  - Replaced hardcoded `/tmp` socket path with `mktemp -d` in `remote.sh`
  - Prevents local attacker from hijacking SSH multiplexed connections

### Fixed

- **Fix pipe subshell variable loss in PII and secrets scans** (#131)
  - Converted pipe-fed `while` loops to process substitution in `check-pii.sh` and `check-secrets.sh`
  - Prevents scan counters from being silently reset in subshells

- **Fix -newer logic error in host scan file selection** (#143)
  - Replaced `find -newer` with direct filename match in `host-scan.sh`
  - Previous logic referenced a file that hadn't been created yet

- **Fix `((var++))` set -e crash across 6 files** (#132)
  - Replaced `((count++))` with `count=$((count + 1))` in `check-malware.sh`, `check-power-settings.sh`, `generate-malware-attestation.sh`, `generate-scan-attestation.sh`, `content-scan.sh`, `local.sh`
  - Arithmetic returning zero caused silent script termination under `set -e`

- **Nmap Scan Failure Detection**
  - Failed nmap scans are now properly detected instead of counting as passed
  - Nmap OS fingerprinting correctly requires sudo

- **Attestation and Host Scan Fixes**
  - Handle host scans in attestation and fix grep integer error

- **macOS Compatibility**
  - Remove Bash 4.3+ namerefs for macOS compatibility (Bash 3.2 safe)

- **Bug Fixes (#110-115)**
  - Address multiple bugs discovered during testing

### Added

- **Spinner Progress Indicators**
  - All scans now show animated spinner progress during execution

- **Malware/KEV Scans in Host Menu**
  - Added malware and KEV scans to QuickStart host scan menu
  - Cleanup after remote scans

- **pdflatex Dependency Check**
  - Added pdflatex to dependency check with install prompt

### Fixed

- **Interactive Prompt Safety**
  - Add `</dev/tty` to all interactive prompts in local.sh and remote.sh
  - Fix Lynis/ClamAV install prompts on remote hosts

## [2.4.0] - 2026-02-05

*Major release - OpenVAS removal and comprehensive stability fixes.*

### Removed

- **OpenVAS/GVM Support** (PR #107)
  - Removed OpenVAS scanner module (`scripts/lib/scanners/openvas.sh`)
  - Removed QuickStart OpenVAS integration (`scripts/lib/quickstart/openvas.sh`)
  - Simplified scanner dependency checks
  - Nmap and Lynis remain as the supported vulnerability scanners

### Added

- **SSH Troubleshooting Guide** (`docs/SSH-TROUBLESHOOTING.md`)
  - Comprehensive guide for remote scan SSH connection issues
  - Platform-specific setup for Kali, Ubuntu, RHEL, macOS, Windows
  - SSH key-based authentication instructions

- **Power Settings Verification** (`scripts/check-power-settings.sh`)
  - New script to verify system power settings for security compliance

- **Target Reachability Verification**
  - Verify target is reachable before starting vulnerability scans

### Fixed

- **set -e Safety Fixes** (Issue #104)
  - Prevent script exit on conditional assignments
  - Add `|| true` to all arithmetic increments in remote.sh
  - Add `|| true` to ALL ssh_cmd calls in compound blocks
  - Prevent set -e exit from compound command blocks

- **Input Validation** (Issue #105)
  - Validate f/Q input for scan type selection

- **Windows Credential Prompts** (Issue #94)
  - Updated Windows credential prompts after OpenVAS removal

- **SSH Connection Handling**
  - Skip SSH connection when no SSH-based scans selected
  - Prevent script exit on SSH failure skip counting

- **OpenVAS Progress Protection**
  - Protect OpenVAS progress indicator from user input (before removal)

## [2.3.0] - 2026-02-05

*QuickStart architecture refactor with modular scan system.*

### Changed

- **QuickStart Architecture Refactor**
  - Complete rewrite of QuickStart subsystem for modularity
  - Windows scanning fixes and improvements
  - Removed dialog/whiptail dependency, use gum or CLI mode only

- **Modular QuickStart System**
  - Extracted content scanning, host scanning, menus, session management into separate modules
  - New `scripts/lib/quickstart/scans/lynis.sh` module
  - New `scripts/lib/quickstart/scans/malware.sh` module

### Fixed

- **OpenVAS Integration** (pre-removal)
  - OpenVAS polling includes Queued and New statuses
  - OpenVAS target creation requires port list
  - OpenVAS Docker and XML parsing issues

- **Configuration**
  - Remote config prompts before scan selection
  - Changed all scan selection defaults to No

## [2.2.1] - 2026-02-04

*QuickStart UX improvements and Lynis integration enhancements.*

### Added

- **gum TUI Support**
  - Added gum-based TUI with dialog/whiptail fallback
  - Dynamically centered version banner

- **Config File Support**
  - QuickStart config file support with preserved variables
  - Config file can specify scans to run
  - Auto-find config files in `.scans/` directory

- **Lynis Enhancements**
  - Quick vs full Lynis audit option
  - Progress indicator for Lynis audit
  - Lynis privileged mode support

- **Remote Scan Improvements**
  - Prompt to install missing Lynis/ClamAV on remote host
  - Real-time progress during remote package install
  - SSH TTY allocation for sudo commands
  - Actual inventory checksum for remote scans

### Fixed

- **Lynis Execution**
  - Use tee for lynis output (show AND save)
  - Run lynis with TTY for sudo, capture output directly
  - Separate sudo auth from Lynis scan execution
  - Revert to simple synchronous Lynis audit
  - Use background process for Lynis progress indicator

- **ClamAV**
  - Skip freshclam if service already running

## [2.2.0] - 2026-02-04

*Remote scanning and PDF attestation enhancements.*

### Added

- **Remote ClamAV Scanning**
  - Remote ClamAV scanning and PDF field cleanup

- **PDF Attestation in QuickStart**
  - PDF attestation generation integrated into QuickStart workflow
  - PDF appendices with detailed findings

- **SSH Connection Multiplexing**
  - SSH connection multiplexing for faster remote scan execution

- **Unique Scan Sessions**
  - Each scan session now gets a unique folder (`Scan<timestamp>`)

### Fixed

- **Nmap**
  - Add `-Pn` to nmap to skip host discovery

- **Security**
  - Remove IP addresses from filenames

- **SSH**
  - Remove default username for remote SSH scans

## [2.1.9] - 2026-02-04

### Added

- **Remote Scan Execution**
  - Complete remote scan execution logic for QuickStart

## [2.1.8] - 2026-02-04

### Changed

- **QuickStart Menu Refactor** (Issue #59)
  - Improved menu structure and navigation

## [2.1.7] - 2026-02-04

### Added

- **Lynis Privileged Mode**
  - Added Lynis privileged mode option to QuickStart

## [2.1.6] - 2026-02-03

### Added

- **ClamAV Progress Display**
  - Compact ClamAV progress display during scans

- **Dependency Management**
  - QuickStart prompts to install missing dependencies

### Fixed

- **ClamAV Warning Capture**
  - Capture ClamAV warnings in verification report

## [2.1.5] - 2026-02-03

### Fixed

- **Malware Scan False Positive**
  - Fixed malware scan false positive when ClamAV has minor errors

## [2.1.4] - 2026-02-03

*Sprint 2.1.3 stabilization release - airgapped systems and malware scanning improvements.*

### Added

- **ClamAV Bundling for Air-Gapped Systems** (Issue #50)
  - Air-gap bundle creator for offline malware scanning
  - ClamAV bundling for systems without internet access

- **Full-System Malware Scan** (Issue #45)
  - Added full-system malware scan option to QuickStart

### Fixed

- **QuickStart Reliability**
  - QuickStart scan reliability and TUI support improvements
  - Capture exit code before if-test in QuickStart
  - Resolve ClamAV hanging in QuickStart (Issue #47)

- **ClamAV Compatibility**
  - Make ClamAV JSON features optional for older versions
  - Check for `--json-store-extra-hashes` support separately

- **Build System**
  - Make build-release.sh compatible with Bash 3.2

- **Sprint 2.1.3 Bug Fixes**
  - Multiple bug fixes and enhancements from sprint testing

## [2.1.3] - 2026-02-03

*Windows PowerShell scanning and QuickStart introduction.*

### Added

- **PowerShell Scanning Scripts**
  - `Check-PersonalInfo.ps1` - PII scanning for Windows (PR #24)
  - `Check-Secrets.ps1` - Secrets scanning for Windows (PR #42)

- **QuickStart** (PR #34, Issues #28, #29)
  - New QuickStart scripts for guided scan setup
  - Sprint issue templates for project management

- **Executive Brief** (`docs/EXECUTIVE-BRIEF.md`, PR #40)
  - High-level overview document for stakeholders

### Fixed

- **ClamAV Test Robustness** (PR #48)
  - Improved ClamAV test robustness in CI environment

- **File Naming**
  - Rename false-positives-macos.md to UPPERCASE convention

### Changed

- **Documentation**
  - Add Windows troubleshooting section (PR #21, #41)
  - Add Windows instructions to INSTALLATION.md (PR #38)
  - Broaden malware scanner documentation (PR #37, Issue #15)
  - Add PowerShell command equivalents to CLAUDE.md (PR #36)

- **Tests**
  - Add integration test for check-malware.sh (PR #25)

## [2.1.2] - 2026-02-03

*Sprint review release - Windows CI and expanded test coverage.*

### Added

- **Windows CI Runner** (PR #18, Issue #6)
  - PowerShell tests now run on Windows in GitHub Actions
  - 67 Pester tests passing on Windows Server 2022
  - Pester 5.x with proper test discovery

- **Cloud Provider Secret Patterns** (PR #22, Issue #3)
  - Stripe live/test key detection
  - Twilio API key detection
  - SendGrid API key detection
  - Google Cloud API key detection
  - DigitalOcean access token detection
  - NPM/PyPI token detection

- **International Phone Format Tests** (PR #22)
  - Japan, China, India, Brazil, Mexico, UK formats
  - Pattern boundary edge case tests

### Fixed

- **Pester Test Runner** (`tests/powershell/Invoke-AllTests.ps1`)
  - Fixed `Filter.FullName` misconfiguration causing 0 tests to run
  - Added `NotRun` count to test summary
  - Improved exit logic for edge cases

- **GitHub Token Test Length**
  - Corrected test tokens to 36 characters (was 34)

## [2.1.1] - 2026-02-03

### Added

- **Testing Documentation** (`docs/TESTING.md`)
  - Test architecture and contributor guide
  - Test helper function reference
  - Guidelines for adding new tests

- **Agent Role Management** (`scripts/lib/agent.sh`)
  - Role assignment helper for multi-agent sessions
  - Terminal tab naming automation
  - Environment variable exports for scripts

- **Expanded Test Coverage**
  - `tests/test-containers.sh` - Container scanning tests
  - `tests/test-edge-cases.sh` - Edge case coverage
  - Enhanced PII and secrets pattern tests
  - 14 → 16 test suites (+746 lines)

### Changed

- **Refactored All Scan Scripts**
  - Applied `lib/init.sh` to remaining 6 scripts
  - Net reduction of ~80 lines of boilerplate

- **Multi-Agent Context Awareness** (`CLAUDE.md`)
  - Added rules for distinguishing task delegation from status updates
  - Improved agent coordination guidelines

### Fixed

- **GitHub Push Protection**
  - Obfuscated test tokens to avoid false positives in `test-secrets-patterns.sh`

## [2.1.0] - 2026-02-02

*Multi-agent integration release - first version developed collaboratively by multiple AI agents.*

### Added

- **Multi-Agent Development Workflow**
  - Git worktree-based development separating `main` (releases) from `dev` (active work)
  - Terminal tab naming convention for agent identification in concurrent sessions
  - Documented coordination process for multiple AI agents working on the codebase
  - Branch protection enforcing PR-based workflow (no direct pushes to main)

- **Branch Protection** (Active on GitHub)
  - Require pull request with 1 approval before merge
  - Require CI status checks (ShellCheck, syntax, tests on Ubuntu + macOS)
  - Dismiss stale approvals on new commits
  - Enforce for administrators

- **Dependencies Documentation** (`docs/DEPENDENCIES.md`)
  - Complete version requirements for all toolkit dependencies
  - Platform compatibility matrix (macOS, Linux, Windows WSL)
  - Version check script for quick dependency audit
  - Upgrade instructions per package manager

- **Troubleshooting Guide** (`docs/TROUBLESHOOTING.md`)
  - Exit codes reference
  - ClamAV, NVD API, allowlist, PDF generation diagnostics
  - macOS and Linux-specific issues
  - Debug output instructions

- **Initialization Library** (`scripts/lib/init.sh`)
  - Centralized boilerplate for script initialization
  - Library availability flags
  - Common variable setup (TIMESTAMP, TOOLKIT_VERSION, etc.)
  - Reduces ~20 lines of boilerplate per script

### Fixed

- **ShellCheck Compliance** (`scripts/check-containers.sh`)
  - Use `awk` for numeric version comparison instead of bash string comparison (SC2072)

- **KEV Catalog Checksum** (`data/kev-catalog.json.sha256`)
  - Use relative path for portability across environments
  - Fixed `release.sh` to generate relative paths in checksum files

### Changed

- **Test Helpers**
  - Added `test_known()` function to test scripts for documenting known limitations

## [2.0.6] - 2026-02-02

### Added

- **Automated Release Workflow** (`.github/workflows/release.yml`)
  - Triggers on version tags (`v*.*.*`)
  - Runs full CI test suite before release
  - Downloads fresh CISA KEV catalog
  - Extracts release notes from CHANGELOG.md
  - Creates GitHub Release with auto-generated notes
  - Computes SHA256 of release tarball
  - Auto-updates Homebrew tap formula (if configured)
  - Deletes old releases (keeps only latest)

- **PR Enhancement Workflow** (`.github/workflows/pr.yml`)
  - Auto-labeling based on changed files (scripts, tests, docs, ci, templates)
  - Size labels (XS, S, M, L, XL) based on lines changed
  - Conventional commit title validation
  - Welcome message for first-time contributors

- **GitHub Release Notes Configuration** (`.github/release.yml`)
  - Categorizes PRs into Features, Bug Fixes, Security, Documentation, Tests, CI/CD

- **PR Labeler Configuration** (`.github/labeler.yml`)
  - Label rules for auto-labeling PRs by changed files

- **Branch Protection Guide** (`docs/BRANCH-PROTECTION.md`)
  - Recommended settings for main branch protection
  - Required status checks documentation
  - Setup instructions via UI and CLI

### Changed

- **CI Workflow** (`.github/workflows/ci.yml`)
  - Added `workflow_call` trigger to make it reusable by release workflow

- **Moved `scan-containers.sh` to `scripts/`**
  - Relocated from `demo/vulnerable-lab/` to `scripts/`
  - Updated path references in README.md and demo documentation

## [2.0.5] - 2026-01-31

### Added

- **Container Security Scanning** (`scripts/check-containers.sh`)
  - Scan running Docker, Podman, or nerdctl containers
  - Auto-detect container runtime
  - Extract software versions from container images
  - Cross-reference with NVD CVE database and CISA KEV catalog
  - NIST Controls: CM-8 (Inventory), RA-5 (Vulnerability Scanning)

- **Vulnerable Lab Demo** (`demo/vulnerable-lab/`)
  - Docker Compose setup with 5 KEV-listed vulnerabilities:
    - Grafana 8.3.0 (CVE-2021-43798)
    - Jenkins 2.441 (CVE-2024-23897)
    - Elasticsearch 1.4.2 (CVE-2015-1427)
    - Tomcat 9.0.30 (CVE-2020-1938)
    - ActiveMQ 5.11.1 (CVE-2023-46604)
  - Vagrant VM for full host simulation (VirtualBox/VMware/Parallels)
  - Wrapper script for quick demo: `./scan-containers.sh --lab`

- **Homebrew Tap** (`brucedombrowski/homebrew-security-toolkit`)
  - Install via: `brew tap brucedombrowski/security-toolkit && brew install security-toolkit`
  - Commands: `security-scan`, `security-tui`, `security-pii`, `security-secrets`, etc.

### Changed

- Repository renamed from `Security` to `security-toolkit`

## [2.0.4] - 2026-01-30

### Fixed

- **CI Test Compatibility**
  - KEV catalog checksum now uses relative path (works on CI runners)
  - Platform-aware `stat` command (macOS `-f "%OLp"` vs Linux `-c "%a"`)
  - Git tag test handles shallow clones (CI environments)
  - Fixed ShellCheck SC2144: use `ls` instead of `[ -f ]` with glob patterns

## [2.0.3] - 2026-01-30

### Changed

- **Documentation Reorganization**
  - Split THREAT-INTELLIGENCE.md into two focused documents
  - New ASSESSOR-QUALIFICATIONS.md for certification requirements (CISSP, CISM, CEH)
  - THREAT-INTELLIGENCE.md now focused on data feeds (CISA KEV, DHS MARs, NASA SOC-MARs)
  - Cross-references between documents

## [2.0.2] - 2026-01-30

### Added

- **NVD CVE Check in TUI**
  - Added check-nvd-cves.sh as 8th scan option
  - Cross-references installed software against NVD vulnerability database

### Changed

- **Documentation Review**
  - Updated SECURITY.md last updated date
  - Verified all documentation current through v2.0.2

## [2.0.1] - 2026-01-30

### Fixed

- **TUI Bash 3.2 Compatibility**
  - Replaced associative arrays with indexed variables for macOS default bash
  - Works on Bash 3.2+ (macOS ships with 3.2 due to licensing)

- **Version Display**
  - Fixed double "v" prefix in TUI header (was showing "vv2.0.0")

### Added

- **TUI Progress Indicator**
  - Spinner with elapsed time during scans (e.g., `[-] 2m34s`)
  - Shows scan is active during long-running operations like malware scanning

### Changed

- **README Documentation**
  - Added dedicated "Interactive TUI Mode" section
  - Documented all TUI features and menu options

## [2.0.0] - 2026-01-29

### Added

- **Interactive TUI Mode** (`scripts/tui.sh`)
  - Menu-driven interface for scan selection and execution
  - Supports dialog/whiptail when available, falls back to bash menu
  - Features: run all/individual scans, view results, generate reports
  - Change target directory on the fly
  - Keyboard navigation and visual feedback

- **GitHub Actions CI Workflow** (`.github/workflows/ci.yml`)
  - Comprehensive CI pipeline with 7 parallel jobs
  - ShellCheck linting for all scripts
  - Bash syntax validation for scripts and libraries
  - Unit and integration tests on Ubuntu and macOS
  - Security self-scan (PII, secrets, malware checks)
  - Documentation and CHANGELOG format verification
  - KEV catalog integrity verification

- **Expanded CPE Mappings** (`scripts/lib/nvd/matcher.sh`)
  - Increased from ~50 to 200+ package mappings for NVD vulnerability matching
  - New categories: Security Tools (24), Programming Languages (25),
    Web Servers (15), Databases (25), Message Queues (10),
    Container/Orchestration (15), Infrastructure/DevOps (22),
    Package Managers (13), CLI Tools (25), Browsers (10),
    Compression (10), Email (10), Virtualization (10),
    Networking (15), OS Components (10), Logging/Monitoring (10),
    File Sharing (11)

### Changed

- **Major Version Bump**: 2.0 reflects significant new features
  - Interactive TUI mode for improved user experience
  - CI/CD integration for automated testing
  - Comprehensive NVD vulnerability coverage

## [1.19.0] - 2026-01-29

### Added

- **Verification Package Generation** (`scripts/generate-verification-report.sh`)
  - Comprehensive PDF verification packages for compliance submittals
  - Includes executive summary, requirements traceability, test results, scan results
  - NIST 800-53 control implementation mapping
  - Formal attestation with SHA256 checksums
  - Supports external projects with their own requirements.json
  - Tests-only mode for faster generation (--tests-only)

- **Advanced Integration Tests** (`tests/test-integration-advanced.sh`)
  - 30 new integration tests covering cross-component interactions
  - KEV catalog integration and hash verification
  - NVD CVE offline mode and CPE mapping
  - PDF generation, error handling, concurrent execution
  - Library dependency chains and version consistency
  - NIST control coverage verification

### Changed

- **External Project Support**
  - Projects can create their own requirements.json linking to NIST controls
  - Verification reports include project-specific requirements
  - Output goes to project's .verification/ directory

- **Documentation**
  - Updated verification/README.md with usage guide
  - Added generate-verification-report.sh to README.md scripts table

## [1.18.1] - 2026-01-29

### Added

- **Library API Documentation** (`docs/LIBRARY-API.md`)
  - Comprehensive API reference for all 27 shell library modules
  - Documents 90+ functions across 4 subsystems (Core, Inventory, Scanners, NVD)
  - Usage examples and contributing guidelines

- **Security Validation Scripts in README**
  - Added 5 security test scripts to documentation (test-cui-data-exposure,
    test-git-purge-dry-run, test-latex-injection, test-rm-rf-validation, test-symlink-attacks)

### Changed

- **Complete Script Documentation**
  - All 26 scripts now documented in README.md
  - Added backup-guidance.sh, harden-system.sh, pre-scan-cleanup.sh, release.sh
  - Added docs/README.md and templates/README.md directory indexes

## [1.18.0] - 2026-01-29

### Added

- **Offline KEV Support for Air-Gapped Systems**
  - Bundled CISA KEV catalog in `data/kev-catalog.json` (1,501 known exploited vulnerabilities)
  - SHA256 integrity hash in `data/kev-catalog.json.sha256`
  - `check-kev.sh` automatically falls back to bundled catalog when network unavailable
  - `release.sh` downloads and bundles latest KEV catalog with each release

- **Upgrade Helper Script** (`scripts/upgrade.sh`)
  - Interactive upgrade process showing pending changes
  - Warns about uncommitted local changes before upgrade
  - Shows if KEV catalog will be updated
  - Displays what's preserved during upgrades (project-specific data)

- **KEV Unit Tests** (`tests/test-kev.sh`)
  - 72 comprehensive unit tests for check-kev.sh functionality
  - Tests for CVE extraction, JSON parsing, offline fallback, and more

### Changed

- **Documentation Updates**
  - Added upgrade guide to INSTALLATION.md
  - Documented offline KEV mode in docs/THREAT-INTELLIGENCE.md
  - Added upgrade.sh and data/ directory to CLAUDE.md structure
  - Added upgrade.sh to README.md scripts table

### Removed

- Deprecated test fixtures (replaced with inline test data)

## [1.17.15] - 2026-01-30

### Added

- **Requirements Documentation Framework** (`requirements/`)
  - `controls/nist-800-53.json` - NIST SP 800-53 Rev 5 control definitions with implementation status
  - `controls/nist-800-171.json` - NIST SP 800-171 Rev 2 control definitions
  - `functional/functional-requirements.json` - 14 functional requirements (FR-001 to FR-014)
  - `mapping.json` - Traceability matrix (FR → NIST → Script → Test)
  - `schema.json` - JSON Schema for validation
  - `project-requirements-template.json` - Template for other projects to define their requirements

- **Verification Framework** (`verification/`)
  - Directory structure for PDF verification evidence
  - Templates for compliance attestation documents
  - README documenting verification workflow

### Changed

- **Documentation Updates**
  - Updated CLAUDE.md with complete lib/ structure (inventory/, scanners/, nvd/)
  - Added toolkit-info.sh to library documentation
  - Added FAQ.md and PERFORMANCE.md to key documentation section
  - Updated INSTALLATION.md last updated date
  - Added requirements/ and verification/ to repository structure

## [1.17.14] - 2026-01-30

### Changed

- **Integrated NVD CVE scan into run-all-scans.sh**
  - NVD vulnerability lookup now runs automatically as part of the standard scan suite
  - Uses offline mode with host inventory for consistent, reproducible scans
  - Total scans increased from 6 to 7
  - Scan order: PII → Malware → Secrets → MAC → NVD CVE → Host Security → Vulnerability

## [1.17.13] - 2026-01-30

### Added

- **NVD CVE Vulnerability Lookup** (`scripts/check-nvd-cves.sh`)
  - Cross-reference installed software against National Vulnerability Database
  - Automatic CPE (Common Platform Enumeration) mapping for 50+ common packages
  - CVSS score parsing (supports v2.0, v3.0, v3.1)
  - Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
  - Caching system with 24-hour TTL for API responses
  - Offline mode for air-gapped environments
  - Priority-only mode for faster scans of critical packages
  - NIST Controls: RA-5 (Vulnerability Monitoring), SI-2 (Flaw Remediation), 3.11.2 (800-171)

- **NVD Integration Libraries** (`scripts/lib/nvd/`)
  - `api.sh` - NVD API 2.0 client with rate limiting and caching
  - `matcher.sh` - Package-to-CPE mapping (Bash 3.2+ compatible)

- **NVD CVE Unit Tests** (`tests/test-nvd-cves.sh`)
  - 41 tests covering API, matcher, and main script functionality
  - Mock NVD responses for testing without network
  - CVSS parsing verification

- **Test Runner Updates**
  - Added `test-nvd-cves.sh` to `run-all-tests.sh`
  - Total test suite now includes 14 test suites

## [1.17.12] - 2026-01-30

### Added

- **Scanner Module Unit Tests** (`tests/test-scanner-modules.sh`)
  - 74 unit tests covering all scanner library modules:
    - `common.sh` - Logging functions, dependency checking, output initialization
    - `nist-controls.sh` - Control lookups, family lookups, scanner-to-control mapping
    - `report.sh` - Header generation, compliance reports, usage output
    - `nmap.sh` - Module sourcing, result summarization with mock data
    - `lynis.sh` - Module sourcing, result summarization with mock data
    - `openvas.sh` - Module sourcing, function existence
  - Integration tests verifying all modules work together
  - Mock nmap/lynis output for testing without real scanners

- **Test Runner Updates**
  - Added `test-scanner-modules.sh` to `run-all-tests.sh`
  - Added `test-integration.sh` to `run-all-tests.sh`
  - Total test suite now includes 13 test suites

## [1.17.11] - 2026-01-30

### Added

- **Comprehensive Integration Tests**
  - Expanded `tests/test-integration.sh` from 307 to 750 lines (61 tests total)
  - New test sections:
    - Multi-language secret detection (Python, JavaScript, Go)
    - Multi-format PII detection (SSNs, phones, credit cards)
    - MAC address format detection (colon, dash, Cisco)
    - Audit log format verification (JSON Lines, required fields)
    - Host inventory end-to-end testing
    - Output file verification with timestamps
    - False positive verification with clean code fixtures
    - Host security scanner validation
    - Scanner module library sourcing tests
    - Inventory module library sourcing tests

- **Test Fixtures for Multi-Language Scanning**
  - `tests/fixtures/vulnerable-code/python-secrets.py` - AWS keys, private keys, passwords
  - `tests/fixtures/vulnerable-code/javascript-secrets.js` - Firebase, Stripe, Twilio tokens
  - `tests/fixtures/vulnerable-code/go-secrets.go` - Hardcoded credentials, connection strings
  - `tests/fixtures/vulnerable-code/pii-data.txt` - SSNs, phones, credit cards, IPs
  - `tests/fixtures/config-files/network-config.conf` - MAC addresses in multiple formats
  - `tests/fixtures/clean-code/clean-python.py` - Environment variable patterns
  - `tests/fixtures/clean-code/clean-javascript.js` - Safe configuration patterns
  - `tests/fixtures/clean-code/clean-config.yaml` - Secret manager references

## [1.17.10] - 2026-01-30

### Changed

- **Modularized Vulnerability Scanner**
  - Refactored `scan-vulnerabilities.sh` from 930 to 295 lines (68% reduction)
  - Extracted scanner modules into `lib/scanners/`:
    - `common.sh` - Logging helpers, dependency checking
    - `nist-controls.sh` - NIST 800-53/171 control definitions (reusable)
    - `nmap.sh` - Nmap network vulnerability scanning
    - `openvas.sh` - OpenVAS/GVM vulnerability assessment
    - `lynis.sh` - Lynis system security auditing
    - `report.sh` - Compliance report generation
  - Maintain identical output and full backward compatibility

### Added

- **Scanner Module Documentation**
  - Step-by-step guide in CLAUDE.md for adding new scanner modules
  - Complete template with required functions and structure
  - NIST control mapping instructions
  - Full Trivy container scanner example

## [1.17.9] - 2026-01-29

### Added

- **Unit Tests for Inventory Modules**
  - New `tests/test-inventory-modules.sh` with 31 comprehensive tests
  - Tests for output library: `output()`, `init_output()`, CUI functions
  - Tests for detection library: `detect_tool()`, `detect_macos_app()`, `section_header()`
  - Tests for all 13 collector modules (verifies each runs without error)
  - Integration tests for full inventory collection
  - Test runner now executes 11 test suites

## [1.17.8] - 2026-01-29

### Changed

- **Modularized Host Inventory Collection**
  - Refactored `collect-host-inventory.sh` from 1,642 lines to 129 lines (92% reduction)
  - Extracted reusable detection helpers into `lib/inventory/detect.sh`
  - Extracted output/CUI handling into `lib/inventory/output.sh`
  - Split data collection into 13 focused collector modules:
    - `os-info.sh` - OS, kernel, hardware
    - `network.sh` - Interfaces, MACs, IPs
    - `packages.sh` - Homebrew, dpkg, rpm
    - `security-tools.sh` - ClamAV, OpenSSL, SSH, GPG
    - `languages.sh` - Programming language runtimes
    - `ides.sh` - Development environments
    - `browsers.sh` - Web browsers
    - `backup.sh` - Backup software
    - `remote-desktop.sh` - Remote access tools
    - `productivity.sh` - Office, chat apps
    - `containers.sh` - Docker, Podman, K8s, VMs
    - `web-servers.sh` - Apache, Nginx, etc.
    - `databases.sh` - PostgreSQL, MySQL, etc.
  - New reusable functions: `detect_tool()`, `detect_macos_app()`, `detect_linux_tool()`
  - Output and behavior remain identical (full backward compatibility)

## [1.17.7] - 2026-01-29

### Added

- **Integration Test Suite**
  - New `tests/test-integration.sh` with 16 comprehensive integration tests
  - Tests end-to-end scan execution, output file creation, exit codes
  - Validates scan orchestration and report generation

- **Enhanced PII Detection**
  - Luhn algorithm validation for credit card numbers (reduces false positives)
  - International phone number patterns (supports country codes, various formats)

- **Documentation**
  - `docs/FAQ.md` - Troubleshooting guide for common issues
  - `docs/PERFORMANCE.md` - Performance baselines and benchmarks

### Changed

- **Improved Exit Codes**
  - `check-malware.sh` now returns exit code 2 when ClamAV is not installed
  - Distinguishes between scan failures (1) and missing dependencies (2)

- **Better Scan Summary**
  - `run-all-scans.sh` now tracks and displays skipped scan count
  - Summary shows Passed/Failed/Skipped counts

## [1.17.6] - 2026-01-29

### Added

- **Configurable PII Scan Exclusions**
  - New `.pii-exclude` config file with gitignore-style syntax
  - Directory exclusions (patterns ending with `/`)
  - Wildcard patterns (containing `*`)
  - Specific file exclusions
  - Comment support (lines starting with `#`)
  - Replaces hardcoded exclusion paths in `check-pii.sh`

## [1.17.5] - 2026-01-29

### Fixed

- **Browser Detection Compatibility**
  - Improved recursive directory scanning for browser detection on Linux
  - Better handling of non-standard browser installation paths

## [1.17.4] - 2026-01-29

### Added

- **GitHub Actions CI Workflow**
  - ShellCheck static analysis for scripts/ and tests/
  - Test suites run on Ubuntu and macOS
  - Bash syntax validation for all scripts
  - Triggers on push to main and pull requests

### Fixed

- **Cross-Platform Compatibility for `set -eu`**
  - Fixed `stat` command using platform-specific syntax (macOS: `-f "%OLp"`, Linux: `-c "%a"`)
  - Added safe variable defaults with `${VAR:-}` syntax for:
    - Script arguments (`$1`)
    - Toolkit variables (`TOOLKIT_NAME`, `TOOLKIT_VERSION`, etc.)
    - OS release variables (`NAME`, `VERSION`, `VERSION_ID`)
  - Fixed arithmetic increment `((VAR++))` returning exit code 1 when incrementing from 0
    - Changed to `VAR=$((VAR + 1))` which always succeeds
  - Added `|| true` to browser detection functions that legitimately return non-zero
  - Tests now pass on both Ubuntu and macOS CI runners

## [1.17.3] - 2026-01-29

### Changed

- **Added Undefined Variable Checking**
  - All 31 scripts now use `set -eu` instead of just `set -e`
  - Catches typos in variable names at runtime
  - Errors on uninitialized or missing variables
  - Improves script robustness and debugging

## [1.17.2] - 2026-01-29

### Changed

- **Enhanced Podman Version Output**
  - Captures complete `podman version` output (Client and Server details)
  - Includes Version, API Version, Go Version, Build date, OS/Arch, Git Commit

- **Enhanced Rootless Networking Tool Versions**
  - `slirp4netns --version` now captures full output (version, commit, libslirp, libseccomp)
  - `pasta --version` captures full output with fallback to package manager (rpm/dpkg) when `--version` produces no output

## [1.17.1] - 2026-01-29

### Changed

- **Complete Podman Version Output**
  - Now captures full `podman version` instead of just `podman --version`
  - Shows both Client and Server information

## [1.17.0] - 2026-01-29

### Added

- **Podman Container Details in Host Inventory**
  - Running container count
  - Container details: name, image, and IP address
  - Podman networks list (name and driver)
  - pasta and slirp4netns versions (Linux rootless networking tools)
  - Graceful handling when podman machine not running

### Fixed

- **Release Version in Examples**
  - Examples now show release version (e.g., v1.17.0) instead of git describe output
  - Added `TOOLKIT_VERSION_OVERRIDE` environment variable support
  - Release script exports version before running scans

- **Examples Committed Before Tagging**
  - Release script now commits staged examples before creating tag
  - Ensures examples in release match the tagged version

## [1.16.0] - 2026-01-29

### Added

- **Toolkit Info Shared Library**
  - New `scripts/lib/toolkit-info.sh` centralizes toolkit identification
  - Provides `TOOLKIT_NAME`, `TOOLKIT_VERSION`, `TOOLKIT_COMMIT`, `TOOLKIT_SOURCE`
  - Auto-detects source URL with priority: release.config.json → git remote → default

- **Configurable Release Script**
  - `release.config.json` stores GitHub owner/repo configuration
  - Projects using toolkit can configure their own repository

### Changed

- **Generic Toolkit Configuration**
  - Removed all hardcoded repository URLs from scripts
  - Scripts now use `toolkit-info.sh` library for source attribution
  - PowerShell script (`Collect-HostInventory.ps1`) also reads from config
  - Enables toolkit to be used by any project with their own GitHub repo

## [1.15.2] - 2026-01-29

### Added

- **Automatic GitHub Release Creation**
  - `release.sh` now creates GitHub releases automatically (not just tags)
  - Uses `gh release create` after pushing tags
  - Falls back gracefully if GitHub CLI not installed

## [1.15.1] - 2026-01-29

### Fixed

- **Host Inventory Script Exit Code**
  - Fixed `collect-host-inventory.sh` exiting with code 1 when macOS apps not installed
  - Added `|| true` to `find_macos_ide` and `find_macos_browser` calls to prevent `set -e` from triggering

### Changed

- **Documentation Reorganization**
  - Merged `AGENTS.md` into `CLAUDE.md` (single AI agent instructions file)
  - Moved `COMPLIANCE.md` to `docs/COMPLIANCE.md`
  - Moved `MAINTENANCE.md` to `docs/MAINTENANCE.md`
  - Moved `release.sh` to `scripts/release.sh`
  - Removed toolkit-specific release workflow from README.md

- **Release Automation**
  - `release.sh` now auto-deletes old GitHub releases (keeps only latest)
  - Git tags are preserved for version history

### Added

- `CLAUDE.md` created for Claude Code guidance

## [1.15.0] - 2026-01-16

### Added

- **Expanded Host Inventory Categories**
  - Programming Languages: Added Bash, Zsh, Lua, R, Swift, Kotlin, Scala, Groovy, TypeScript, Elixir, Haskell (GHC), Julia (13 new languages, 22 total)
  - Productivity Software: Microsoft Office (Word, Excel, PowerPoint, Outlook, Teams), Apple iWork (Pages, Numbers, Keynote), LibreOffice, Slack, Cisco Webex, Discord, Skype
  - Containers and Virtualization: Docker, Podman, kubectl, Minikube, Helm, Vagrant, VirtualBox, VMware Fusion/Workstation, Parallels Desktop, QEMU, libvirt, LXC/LXD
  - Web Servers: Apache (httpd), Nginx, Caddy, Lighttpd, Traefik
  - Database Servers: PostgreSQL, MySQL, SQLite, MongoDB, Redis

### Changed

- Updated redact script to handle all new inventory categories
- Regenerated example files with expanded inventory

## [1.14.1] - 2026-01-16

### Fixed

- grep `-H` flag added to always output filename in PII and secrets scan findings
- Fixes file/line field swap in interactive review display

### Added

- `checksums-EXAMPLE.md` example file showing scan output checksums format

### Changed

- Regenerated example files with new host inventory categories (Programming Languages, Web Browsers, Backup and Restore, Remote Desktop/Control)

## [1.14.0] - 2026-01-16

### Added

- **Progress Indicator Library**
  - New `scripts/lib/progress.sh` shared library for progress display
  - Animated spinner for indeterminate operations (Braille character animation)
  - Progress bar with visual indicator, percentage, and ETA calculation
  - Step progress for multi-step operations (`[1/6] Running scan...`)
  - Elapsed time tracking and formatting
  - TTY detection for non-interactive environments (falls back to milestone updates)
  - NIST SP 800-53: AU-3 (Content of Audit Records) - user feedback during operations

- **Progress in Scan Scripts**
  - `run-all-scans.sh`: Step indicators for all 6 scans with elapsed time display
  - `check-malware.sh`: Spinner during ClamAV scan operation

- **Progress Library Unit Tests**
  - New `tests/test-progress.sh` with 14 tests covering all progress functions
  - Tests TTY detection, time formatting, function existence, and edge cases

- **Enhanced .gitignore for Spillage Prevention**
  - CUI (Controlled Unclassified Information) pattern exclusions
  - PII (Personally Identifiable Information) pattern exclusions
  - Host inventory file exclusions
  - Secrets and credentials patterns (*.pem, *.key, .env, etc.)
  - SSH and GPG key exclusions
  - AWS credential exclusions
  - Database dump exclusions
  - Log file exclusions

## [1.13.0] - 2026-01-16

### Added

- **Pre-Scan Cleanup Script**
  - New `pre-scan-cleanup.sh` using BleachBit for system cleanup before scans
  - Reduces scan time by eliminating temporary files and caches
  - Modes: `--dry-run` (preview), `--aggressive` (deep clean), `--browsers`, `--system`
  - Cleans browser caches/cookies/history (Chrome, Firefox, Safari, Edge)
  - Cleans system temp files, thumbnails, trash, package manager caches
  - Aggressive mode clears shell history, logs, recent documents (with confirmation)
  - Full audit logging integration
  - NIST SP 800-53: SI-14 (Non-Persistence), NIST SP 800-88 (Media Sanitization)

- **Enhanced Host Inventory Categories**
  - Security Tools: ClamAV, OpenSSL, SSH, GPG, Git
  - Programming Languages: Python, Node.js, Java, .NET, Ruby, Go, Rust, Perl, PHP
  - Web Browsers: Chrome, Firefox, Safari, Edge, Brave
  - Backup and Restore: Time Machine, Arq, Carbon Copy Cloner, Backblaze, rsync, Borg, Restic
  - Remote Desktop / Control: Screen Sharing, TeamViewer, AnyDesk, Zoom, VNC, Microsoft Remote Desktop
  - All items now show "not installed" when missing (comprehensive list)

### Changed

- **Allowlist Location Migration**
  - Moved from repo root to `.allowlists/` directory (gitignored)
  - PII allowlist: `.allowlists/pii-allowlist`
  - Secrets allowlist: `.allowlists/secrets-allowlist`
  - Updated all scripts, templates, and documentation

- Updated redact script to handle new software categories

## [1.12.0] - 2026-01-15

### Added

- **Vulnerability Scanning Script**
  - New `scan-vulnerabilities.sh` for comprehensive vulnerability assessment
  - Nmap network scanning with port discovery and service detection
  - Lynis system security auditing and configuration review
  - Quick mode (`-q`) for fast localhost scans without sudo
  - NIST SP 800-53 controls: RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation), SI-4 (System Monitoring), CA-2 (Control Assessments)
  - NIST SP 800-171 controls: 3.11.1, 3.11.2, 3.11.3, 3.12.1, 3.12.3, 3.14.1, 3.14.6, 3.14.7

- **Vulnerability Scan in PDF Attestation**
  - Scan attestation now includes vulnerability scan results
  - New RA-5, SI-2, SI-4 controls in NIST Control Mapping table
  - Vulnerability scan row in Scan Results table with PASS/FAIL/SKIP status
  - Vulnerability scan checksum in Scan Output Checksums table
  - SKIP status for when vulnerability scan was not run

### Removed

- Removed `examples/` directory - examples are generated dynamically during scans

### Changed

- Updated AGENTS.md with vulnerability scanning documentation
- OpenVAS documented as future consideration due to infrastructure requirements

## [1.11.0] - 2026-01-15

### Added

- **Interactive Secrets Review Mode**
  - New `-i` flag for `check-secrets.sh` enables interactive review of findings
  - Allowlist support with `.secrets-allowlist` file
  - Quick-accept shortcuts for common false positives:
    - [E]xample - Example/placeholder data
    - [D]ocumentation - Documentation or pattern explanations
    - [I]nternal - Internal/controlled variable assignment (safe eval)
    - [T]est - Test fixture or mock data
  - Integrated into `run-all-scans.sh` interactive mode

- **Quick-Accept Shortcuts for PII Scanner**
  - [E]xample - Example/placeholder data (example.com, 192.0.2.x)
  - [O]ID - X.509 Object Identifiers
  - [V]ersion - Version number strings
  - [L]ocalhost - Loopback addresses (127.0.0.1)
  - [D]ocumentation - Documentation or comments

### Fixed

- PDF attestation generation now checks for output file instead of exit code
- Allowlist entries properly escaped for LaTeX in PDF attestation
- Multiline content replacement uses perl for reliability

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

[Unreleased]: https://github.com/brucedombrowski/security-toolkit/compare/v2.4.0...HEAD
[2.4.0]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.4.0
[2.3.0]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.3.0
[2.2.1]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.2.1
[2.2.0]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.2.0
[2.1.9]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.9
[2.1.8]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.8
[2.1.7]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.7
[2.1.6]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.6
[2.1.5]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.5
[2.1.4]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.4
[2.1.3]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.3
[2.1.2]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.2
[2.1.1]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.1
[2.1.0]: https://github.com/brucedombrowski/security-toolkit/releases/tag/v2.1.0
[2.0.6]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.6
[2.0.5]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.5
[2.0.4]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.4
[2.0.3]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.3
[2.0.2]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.2
[2.0.1]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.1
[2.0.0]: https://github.com/brucedombrowski/Security/releases/tag/v2.0.0
[1.19.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.19.0
[1.18.1]: https://github.com/brucedombrowski/Security/releases/tag/v1.18.1
[1.18.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.18.0
[1.17.15]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.15
[1.17.14]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.14
[1.17.13]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.13
[1.17.12]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.12
[1.17.11]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.11
[1.17.10]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.10
[1.17.9]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.9
[1.17.8]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.8
[1.17.7]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.7
[1.17.6]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.6
[1.17.5]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.5
[1.17.4]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.4
[1.17.3]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.3
[1.17.2]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.2
[1.17.1]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.1
[1.17.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.17.0
[1.16.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.16.0
[1.15.2]: https://github.com/brucedombrowski/Security/releases/tag/v1.15.2
[1.15.1]: https://github.com/brucedombrowski/Security/releases/tag/v1.15.1
[1.15.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.15.0
[1.14.1]: https://github.com/brucedombrowski/Security/releases/tag/v1.14.1
[1.14.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.14.0
[1.13.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.13.0
[1.12.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.12.0
[1.11.0]: https://github.com/brucedombrowski/Security/releases/tag/v1.11.0
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
