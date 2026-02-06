# Library API Reference

This document describes the shell library modules in `scripts/lib/` for contributors and integrators.

## Overview

The toolkit provides shell library modules organized into 4 subsystems:

| Subsystem | Location | Purpose |
|-----------|----------|---------|
| Core Utilities | `lib/*.sh` | Shared functionality (logging, progress, timestamps) |
| Inventory | `lib/inventory/` | Host inventory collection |
| Scanners | `lib/scanners/` | Vulnerability scanner integration |
| NVD | `lib/nvd/` | National Vulnerability Database lookup |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MAIN ENTRY POINTS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  run-all-scans.sh    tui.sh    scan-vulnerabilities.sh    check-*.sh        │
└────────┬────────────────┬──────────────┬───────────────────────┬────────────┘
         ▼                ▼              ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CORE UTILITIES (lib/*.sh)                           │
├──────────────────┬──────────────────┬──────────────────┬────────────────────┤
│   audit-log.sh   │   progress.sh    │  timestamps.sh   │  toolkit-info.sh   │
│  (NIST AU-2/3)   │  (TTY-aware)     │  (ISO 8601 UTC)  │  (version info)    │
└──────────────────┴──────────────────┴──────────────────┴────────────────────┘
         │                                      │
         ▼                                      ▼
┌────────────────────────────┐    ┌────────────────────────────────────────────┐
│  INVENTORY SUBSYSTEM       │    │           SCANNER SUBSYSTEM                │
│  lib/inventory/            │    │           lib/scanners/                    │
│  ┌─────────────────────┐   │    │  common.sh → nmap.sh / lynis.sh            │
│  │ 13 collectors for   │   │    │              ↓                             │
│  │ OS, network, pkgs,  │   │    │         report.sh                          │
│  │ browsers, DBs, etc. │   │    └────────────────────────────────────────────┘
│  └─────────────────────┘   │                     │
└────────────────────────────┘                     ▼
                              ┌────────────────────────────────────────────┐
                              │         NVD SUBSYSTEM (lib/nvd/)           │
                              │   api.sh (NVD 2.0 client with caching)     │
                              │   matcher.sh (package → CPE mapping)       │
                              └────────────────────────────────────────────┘
```

### Data Flow

```
Target Directory → Scanners → .scans/ (output) → PDF Attestation
                      ↓
                 Audit Log (JSON Lines)
```

## Usage

Source libraries in your scripts:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/audit-log.sh"
source "$SCRIPT_DIR/lib/progress.sh"
```

---

## Core Utilities

### init.sh

Centralized boilerplate for script initialization. Reduces ~20 lines of boilerplate per script.

| Function / Variable | Description |
|---------------------|-------------|
| `SCRIPT_DIR` | Auto-detected script directory |
| `TIMESTAMP` | Current ISO 8601 UTC timestamp |
| `TOOLKIT_VERSION` | Toolkit version (from git tag) |
| `TOOLKIT_COMMIT` | Short commit hash |
| `AUDIT_AVAILABLE` | `true` if audit-log.sh loaded |
| `TIMESTAMPS_AVAILABLE` | `true` if timestamps.sh loaded |
| `PROGRESS_AVAILABLE` | `true` if progress.sh loaded |
| `TOOLKIT_AVAILABLE` | `true` if toolkit-info.sh loaded |

**Example:**
```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"
```

### audit-log.sh

JSON Lines audit logging for NIST AU-2/AU-3 compliance.

| Function | Description |
|----------|-------------|
| `init_audit_log` | Initialize audit log file with session metadata |
| `audit_log` | Write generic audit log entry |
| `audit_log_finding` | Log a security finding with severity |
| `audit_log_error` | Log an error event |
| `audit_log_file_skipped` | Log skipped file (symlink, permission, etc.) |
| `audit_log_allowlist_match` | Log allowlisted finding |
| `audit_log_config_change` | Log configuration change |
| `finalize_audit_log` | Close audit log with summary |
| `get_audit_log_path` | Return current audit log path |
| `is_audit_log_enabled` | Check if audit logging is active |

**Example:**
```bash
init_audit_log "/path/to/.scans" "check-secrets"
audit_log_finding "HIGH" "Hardcoded API key" "src/config.js" "42"
finalize_audit_log "FAIL" "3"
```

### progress.sh

Terminal progress indicators with TTY detection.

| Function | Description |
|----------|-------------|
| `spinner_start` | Start animated spinner with message |
| `spinner_stop` | Stop spinner, show result (pass/fail) |
| `progress_bar` | Display progress bar (current/total) |
| `progress_start` | Begin progress tracking |
| `progress_step` | Increment progress |
| `progress_end` | Complete progress display |
| `status_line` | Update status line (TTY-aware) |
| `status_clear` | Clear status line |

**Example:**
```bash
spinner_start "Scanning files"
# ... do work ...
spinner_stop 0  # 0=success, 1=failure
```

### timestamps.sh

ISO 8601 UTC timestamp utilities.

| Function | Description |
|----------|-------------|
| `get_iso_timestamp` | Current UTC timestamp (2026-01-29T12:34:56Z) |
| `get_compact_timestamp` | Compact format (20260129T123456Z) |
| `get_filename_timestamp` | Filename-safe format (2026-01-29-T123456Z) |
| `get_date_stamp` | Date only (2026-01-29) |
| `get_unix_timestamp` | Unix epoch seconds |
| `get_human_date` | Human-readable format |
| `validate_iso_timestamp` | Validate timestamp format |
| `calculate_elapsed_seconds` | Calculate duration between timestamps |
| `format_elapsed_time` | Format seconds as "Xm Ys" |

**Example:**
```bash
START=$(get_unix_timestamp)
# ... do work ...
ELAPSED=$(calculate_elapsed_seconds "$START" "$(get_unix_timestamp)")
echo "Completed in $(format_elapsed_time "$ELAPSED")"
```

### toolkit-info.sh

Version, commit, and configuration management.

| Function | Description |
|----------|-------------|
| `init_toolkit_info` | Initialize toolkit metadata |
| `get_toolkit_id` | Get toolkit version and commit hash |
| `get_toolkit_source` | Get toolkit source path |
| `print_toolkit_header` | Print standard header with version info |

---

## Inventory Subsystem

### lib/inventory/detect.sh

Platform detection helpers for software inventory.

| Function | Description |
|----------|-------------|
| `detect_tool` | Detect CLI tool and version |
| `detect_tool_stderr` | Detect tool with stderr version output |
| `detect_macos_app` | Detect macOS .app bundle version |
| `detect_macos_app_paths` | Detect app from multiple possible paths |
| `detect_linux_tool` | Detect Linux package version |
| `section_header` | Print section header |

**Example:**
```bash
detect_tool "Python" "python3" "--version"
# Output: Python: Python 3.11.4

detect_macos_app "Safari" "/Applications/Safari.app"
# Output: Safari: 17.2
```

### lib/inventory/output.sh

CUI-safe file output with proper permissions.

| Function | Description |
|----------|-------------|
| `init_output` | Initialize output file with mode 600 |
| `output` | Write line to output (file and/or console) |
| `output_cui_header` | Print CUI warning header |
| `output_cui_footer` | Print CUI handling instructions |
| `show_cui_warning` | Display console CUI warning |

### lib/inventory/collectors/*.sh

13 modular collectors for different software categories:

| Collector | Function | Categories |
|-----------|----------|------------|
| `os-info.sh` | `collect_os_info` | OS, kernel, hardware, uptime |
| `network.sh` | `collect_network` | Interfaces, IPs, MACs, DNS |
| `packages.sh` | `collect_packages` | Homebrew, apt, rpm, snap |
| `security-tools.sh` | `collect_security_tools` | ClamAV, OpenSSL, SSH, GPG |
| `languages.sh` | `collect_languages` | Python, Node, Ruby, Go, Rust, Java |
| `ides.sh` | `collect_ides` | VS Code, Xcode, JetBrains, vim |
| `browsers.sh` | `collect_browsers` | Chrome, Firefox, Safari, Edge |
| `databases.sh` | `collect_databases` | PostgreSQL, MySQL, SQLite, Redis |
| `web-servers.sh` | `collect_web_servers` | Apache, Nginx, Caddy |
| `containers.sh` | `collect_containers` | Docker, Podman, containerd, K8s |
| `remote-desktop.sh` | `collect_remote_desktop` | SSH, VNC, RDP, TeamViewer |
| `productivity.sh` | `collect_productivity` | Office, Slack, Zoom, Teams |
| `backup.sh` | `collect_backup` | Time Machine, rsync, Borg |

Each collector follows the pattern:
```bash
collect_<category>() {
    section_header "<Category Name>"
    # Platform-specific detection
    if [[ "$(uname)" == "Darwin" ]]; then
        _collect_<category>_macos
    else
        _collect_<category>_linux
    fi
}
```

---

## Scanners Subsystem

### lib/scanners/common.sh

Shared scanner utilities for logging and dependency checking.

| Function | Description |
|----------|-------------|
| `log_info` | Log info message (blue `[INFO]`) |
| `log_success` | Log success message (green `[PASS]`) |
| `log_warning` | Log warning message (yellow `[WARN]`) |
| `log_error` | Log error message (red `[FAIL]`) |
| `check_root` | Check if running as root |
| `check_scanner_deps` | Verify scanner dependencies (nmap, lynis) |
| `init_scanner_output` | Initialize output directory and report file |
| `print_scanner_section` | Print section divider with title |

### lib/scanners/nist-controls.sh

NIST control definitions and mapping.

| Function | Description |
|----------|-------------|
| `get_nist_control` | Get control description by ID |
| `print_nist_controls_header` | Print NIST controls summary |

### lib/scanners/nmap.sh

Nmap network scanner integration.

| Function | Description |
|----------|-------------|
| `run_nmap_scan` | Execute Nmap scan with options |
| `summarize_nmap_results` | Parse and summarize Nmap output |

### lib/scanners/lynis.sh

Lynis security auditing integration.

| Function | Description |
|----------|-------------|
| `run_lynis_audit` | Execute Lynis audit |
| `summarize_lynis_results` | Parse and summarize Lynis output |

### lib/scanners/report.sh

Report generation and display utilities.

| Function | Description |
|----------|-------------|
| `print_scan_header` | Print scanner header with target info and timestamp |
| `init_report_file` | Initialize report file with header |
| `generate_compliance_report` | Generate NIST compliance report |
| `print_scan_summary` | Print scan summary with pass/fail counts |
| `print_scanner_usage` | Print usage information for scan-vulnerabilities.sh |

---

## NVD Subsystem

### lib/nvd/api.sh

NVD API 2.0 client with rate limiting and caching.

| Function | Description |
|----------|-------------|
| `init_nvd_cache` | Initialize 24-hour cache directory |
| `query_nvd_by_cpe` | Query CVEs by CPE string |
| `query_nvd_by_cve` | Query specific CVE details |
| `query_nvd_by_keyword` | Search CVEs by keyword |
| `extract_cvss_score` | Extract CVSS score from response |
| `extract_severity` | Extract severity level |
| `extract_cve_description` | Extract CVE description |
| `check_nvd_api` | Verify API connectivity |
| `nvd_rate_limit` | Enforce rate limiting |
| `nvd_api_headers` | Get API headers (with optional key) |
| `nvd_cache_stats` | Show cache statistics |
| `clear_nvd_cache` | Clear cached responses |

**Example:**
```bash
init_nvd_cache
RESULT=$(query_nvd_by_cpe "cpe:2.3:a:openssl:openssl:1.1.1")
SCORE=$(extract_cvss_score "$RESULT")
```

### lib/nvd/matcher.sh

Package name to CPE (Common Platform Enumeration) mapping.

| Function | Description |
|----------|-------------|
| `get_cpe_mapping` | Get CPE vendor:product for package |
| `get_cpe_vendor` | Extract vendor from mapping |
| `get_cpe_product` | Extract product from mapping |
| `package_to_cpe` | Build full CPE string |
| `parse_version` | Normalize version string |
| `version_gte` | Compare versions (>=) |
| `is_priority_package` | Check if package is high-priority |
| `get_priority_packages` | List priority packages |
| `filter_known_packages` | Filter to known CPE mappings |
| `parse_inventory_packages` | Parse host inventory for packages |

**Supported Packages (50+):**
- Security: openssl, openssh, gnupg, sudo
- Languages: python, node, ruby, go, rust, java, php, perl
- Databases: postgresql, mysql, sqlite, redis, mongodb
- Web: apache, nginx, curl, wget
- Containers: docker, podman, containerd, kubernetes

---

## Error Handling

All libraries use `set -eu` for strict error handling:
- `set -e`: Exit on error
- `set -u`: Error on undefined variables

Functions return exit codes:
- `0`: Success
- `1`: Failure/error
- `2`: Missing dependency

---

## PowerShell Libraries

The toolkit includes PowerShell equivalents of core Bash libraries for Windows compatibility.

### lib/init.ps1

PowerShell equivalent of init.sh - centralized boilerplate for all toolkit scripts.

**Usage:**
```powershell
$script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$script:SCRIPT_DIR\lib\init.ps1"
Initialize-SecurityToolkit
```

**Variables (after dot-sourcing):**

| Variable | Description |
|----------|-------------|
| `$script:SCRIPT_DIR` | Directory containing the calling script |
| `$script:SECURITY_REPO_DIR` | Root of the security toolkit repository |
| `$script:LIB_DIR` | Directory containing library files |
| `$script:AUDIT_AVAILABLE` | `$true` if audit-log.ps1 is loaded |
| `$script:TIMESTAMPS_AVAILABLE` | `$true` if timestamps.ps1 is loaded |
| `$script:PROGRESS_AVAILABLE` | `$true` if progress.ps1 is loaded |
| `$script:TOOLKIT_AVAILABLE` | `$true` if toolkit-info.ps1 is loaded |
| `$script:TIMESTAMP` | Current ISO 8601 UTC timestamp |
| `$script:TOOLKIT_VERSION` | Toolkit version (from git tag or config) |
| `$script:TOOLKIT_COMMIT` | Toolkit commit hash (short) |

**Functions:**

| Function | Description |
|----------|-------------|
| `Initialize-SecurityToolkit` | Initialize toolkit environment (timestamp, version, commit) |
| `Get-TargetDirectory` | Parse target directory from arguments or use default |
| `Write-ScriptHeader` | Print script header with consistent formatting |
| `Write-LibraryStatus` | Print which libraries are loaded (for debugging) |
| `Write-Pass` | Write success message in green |
| `Write-Fail` | Write failure message in red |
| `Write-WarningMessage` | Write warning message in yellow |
| `Write-Info` | Write info message in cyan |
| `Test-CIEnvironment` | Detect if running in a CI/CD environment |

**Example:**
```powershell
$script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$script:SCRIPT_DIR\lib\init.ps1"
Initialize-SecurityToolkit

$TargetDir = Get-TargetDirectory $args
Write-ScriptHeader -Name "Security Scan" -Target $TargetDir
```

### PowerShell Script Inventory

| Script | Description | Bash Equivalent |
|--------|-------------|-----------------|
| `Check-PersonalInfo.ps1` | PII detection (SSN, phone, etc.) | `check-pii.sh` |
| `Check-Secrets.ps1` | Secrets/credentials detection | `check-secrets.sh` |
| `Collect-HostInventory.ps1` | Windows system inventory (CM-8) | `collect-host-inventory.sh` |

**Test Files:**
- `tests/powershell/Invoke-AllTests.ps1` - Master test runner
- `tests/powershell/Init-Lib.Tests.ps1` - init.ps1 unit tests
- `tests/powershell/Check-Secrets.Tests.ps1` - Check-Secrets tests
- `tests/powershell/Check-PersonalInfo.Tests.ps1` - Check-PersonalInfo tests

---

## Contributing

When adding new library functions:

### Bash Libraries
1. Follow naming conventions (`lowercase_with_underscores`)
2. Add function to appropriate module
3. Document in this file
4. Add tests in `tests/test-*.sh`
5. Use `local` for function variables
6. Return meaningful exit codes

### PowerShell Libraries
1. Follow naming conventions (`Verb-Noun` with PascalCase)
2. Add function to appropriate module
3. Include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`)
4. Document in this file
5. Add tests in `tests/powershell/*.Tests.ps1`
6. Use `param()` blocks with types
