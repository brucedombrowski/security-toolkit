#!/bin/bash
#
# Vulnerability Scanning Script
#
# Purpose: Comprehensive vulnerability assessment using open-source security tools
# Tools: Nmap (network scanning), Lynis (system audit)
#
# ============================================================================
# NIST SP 800-53 Rev 5 Control Mapping
# ============================================================================
#
# This script implements the following NIST controls:
#
# | Control | Family                        | Description                          | Tool     |
# |---------|-------------------------------|--------------------------------------|----------|
# | CA-2    | Assessment, Authorization     | Control Assessments                  | All      |
# | CA-7    | Assessment, Authorization     | Continuous Monitoring                | All      |
# | RA-3    | Risk Assessment               | Risk Assessment                      | All      |
# | RA-5    | Risk Assessment               | Vulnerability Monitoring and Scanning| Nmap     |
# | SA-11   | System & Services Acquisition | Developer Testing and Evaluation     | All      |
# | SI-2    | System & Info Integrity       | Flaw Remediation                     | Lynis    |
# | SI-4    | System & Info Integrity       | System Monitoring                    | Nmap     |
# | SI-7    | System & Info Integrity       | Software, Firmware, Info Integrity   | Lynis    |
# | CM-6    | Configuration Management      | Configuration Settings               | Lynis    |
# | CM-8    | Configuration Management      | System Component Inventory           | Nmap     |
# | SC-7    | System & Comms Protection     | Boundary Protection                  | Nmap     |
#
# ============================================================================
# NIST SP 800-171 Rev 2 Control Mapping (CUI Protection)
# ============================================================================
#
# | Control   | Description                                    | Tool     |
# |-----------|------------------------------------------------|----------|
# | 3.11.1    | Periodically assess risk                       | All      |
# | 3.11.2    | Scan for vulnerabilities periodically          | All      |
# | 3.11.3    | Remediate vulnerabilities per risk assessments | Lynis    |
# | 3.12.1    | Assess security controls periodically          | All      |
# | 3.12.3    | Monitor security controls on ongoing basis     | All      |
# | 3.14.1    | Identify, report, correct system flaws         | Lynis    |
# | 3.14.6    | Monitor system to detect attacks               | Nmap     |
# | 3.14.7    | Identify unauthorized use of systems           | Nmap     |
#
# ============================================================================
# FIPS 199/200 Security Categorization
# ============================================================================
#
# FIPS 199 - Impact Levels Assessed:
#   - Confidentiality: Scan results may contain sensitive network topology
#   - Integrity: Scan verifies system configuration integrity
#   - Availability: Identifies services that could affect availability
#
# FIPS 200 - Minimum Security Requirements Verified:
#   - Risk Assessment (RA)
#   - Security Assessment and Authorization (CA)
#   - System and Information Integrity (SI)
#   - Configuration Management (CM)
#
# ============================================================================
# Exit Codes
# ============================================================================
#   0 = All scans completed successfully, no critical vulnerabilities
#   1 = Scans completed with findings requiring attention
#   2 = Missing required dependencies
#   3 = Scan execution error
#
# ============================================================================
# Usage
# ============================================================================
#   ./scan-vulnerabilities.sh [options] [target]
#
#   Options:
#     -n, --nmap-only      Run only Nmap scans
#     -l, --lynis-only     Run only Lynis audit
#     -q, --quick          Quick scan (reduced thoroughness)
#     -f, --full           Full comprehensive scan (default)
#     -r, --report-only    Generate report from existing scan data
#     -d, --output-dir DIR Output directory (default: .scans/)
#     -h, --help           Show this help message
#
#   Target:
#     IP address, hostname, or CIDR range for network scans
#     Default: localhost (127.0.0.1)
#
#   NOTE: Currently defaults to localhost only. Future enhancement will add
#   -a|--all-interfaces to auto-detect and scan all network interfaces.
#   See AGENTS.md "Future Enhancements" for details.
#

set -eu

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ============================================================================
# SOURCE LIBRARIES
# ============================================================================

# Source shared libraries
AUDIT_AVAILABLE=0
TIMESTAMPS_AVAILABLE=0

if [ -f "$SCRIPT_DIR/lib/audit-log.sh" ]; then
    source "$SCRIPT_DIR/lib/audit-log.sh"
    AUDIT_AVAILABLE=1
fi

if [ -f "$SCRIPT_DIR/lib/timestamps.sh" ]; then
    source "$SCRIPT_DIR/lib/timestamps.sh"
    TIMESTAMPS_AVAILABLE=1
fi

if [ -f "$SCRIPT_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPT_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SECURITY_REPO_DIR"
fi

# Ensure toolkit variables have defaults
TOOLKIT_NAME="${TOOLKIT_NAME:-Security Verification Toolkit}"
TOOLKIT_VERSION="${TOOLKIT_VERSION:-unknown}"
TOOLKIT_COMMIT="${TOOLKIT_COMMIT:-unknown}"
TOOLKIT_SOURCE="${TOOLKIT_SOURCE:-unknown}"

# Source scanner modules
source "$SCRIPT_DIR/lib/scanners/common.sh"
source "$SCRIPT_DIR/lib/scanners/nist-controls.sh"
source "$SCRIPT_DIR/lib/scanners/nmap.sh"
source "$SCRIPT_DIR/lib/scanners/lynis.sh"
source "$SCRIPT_DIR/lib/scanners/report.sh"

# ============================================================================
# INITIALIZATION
# ============================================================================

# Use standardized timestamps (UTC for consistency across time zones)
if [ "$TIMESTAMPS_AVAILABLE" -eq 1 ]; then
    TIMESTAMP=$(get_filename_timestamp)
else
    TIMESTAMP=$(date -u "+%Y-%m-%dT%H%M%SZ")
fi
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)

# Default settings
TARGET="127.0.0.1"
SCAN_MODE="full"
RUN_NMAP=true
RUN_LYNIS=true
REPORT_ONLY=false
OUTPUT_DIR_ARG=""

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--nmap-only)
                RUN_LYNIS=false
                shift
                ;;
            -l|--lynis-only)
                RUN_NMAP=false
                shift
                ;;
            -q|--quick)
                SCAN_MODE="quick"
                shift
                ;;
            -f|--full)
                SCAN_MODE="full"
                shift
                ;;
            -r|--report-only)
                REPORT_ONLY=true
                shift
                ;;
            -d|--output-dir)
                OUTPUT_DIR_ARG="$2"
                shift 2
                ;;
            -h|--help)
                print_scanner_usage "$0"
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                print_scanner_usage "$0"
                exit 2
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done

    # Print header
    print_scan_header "$TIMESTAMP" "$TARGET" "$SCAN_MODE" "$HOSTNAME_SHORT" \
        "$TOOLKIT_NAME" "$TOOLKIT_VERSION" "$TOOLKIT_COMMIT" "$TOOLKIT_SOURCE"

    # Check dependencies
    if ! check_scanner_deps; then
        exit 2
    fi

    # Update run flags from dependency check (only disable if tool not found)
    # Don't enable if explicitly disabled by command-line options
    $RUN_NMAP && RUN_NMAP=$SCANNER_RUN_NMAP
    $RUN_LYNIS && RUN_LYNIS=$SCANNER_RUN_LYNIS

    # Initialize output directory
    init_scanner_output "$OUTPUT_DIR_ARG" "$TIMESTAMP" "$SECURITY_REPO_DIR"

    # Initialize audit logging
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        init_audit_log "$SECURITY_REPO_DIR" "vulnerability-scan" || true
    fi

    # Initialize report file
    init_report_file "$SCANNER_REPORT_FILE" "$TIMESTAMP" "$TARGET" \
        "$TOOLKIT_NAME" "$TOOLKIT_VERSION" "$TOOLKIT_COMMIT" "$TOOLKIT_SOURCE"

    # Track overall status
    local overall_status=0
    local scan_count=0
    local pass_count=0

    echo ""

    # Run Nmap if enabled
    if $RUN_NMAP && ! $REPORT_ONLY; then
        scan_count=$((scan_count + 1))
        if run_nmap_scan "$TARGET" "$SCANNER_OUTPUT_DIR" "$TIMESTAMP" "$SCAN_MODE" 2>&1 | tee -a "$SCANNER_REPORT_FILE"; then
            pass_count=$((pass_count + 1))
        else
            overall_status=1
        fi
    fi

    # Run Lynis if enabled (always local)
    if $RUN_LYNIS && ! $REPORT_ONLY; then
        scan_count=$((scan_count + 1))
        if run_lynis_audit "$SCANNER_OUTPUT_DIR" "$TIMESTAMP" "$SCAN_MODE" 2>&1 | tee -a "$SCANNER_REPORT_FILE"; then
            pass_count=$((pass_count + 1))
        else
            overall_status=1
        fi
    fi

    # Generate compliance mapping
    generate_compliance_report "$SCANNER_REPORT_FILE" "$TIMESTAMP" "$TARGET" "$HOSTNAME_SHORT" \
        "$SCAN_MODE" "$TOOLKIT_VERSION" "$TOOLKIT_COMMIT" "$RUN_NMAP" "$RUN_LYNIS"

    # Print summary
    print_scan_summary "$scan_count" "$pass_count" "$SCANNER_REPORT_FILE" "$overall_status"

    # Finalize audit log
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        if [ $overall_status -eq 0 ]; then
            finalize_audit_log "PASS" "scans=$scan_count passed=$pass_count"
        else
            finalize_audit_log "FAIL" "scans=$scan_count passed=$pass_count"
        fi
    fi

    return $overall_status
}

# Run main
main "$@"
