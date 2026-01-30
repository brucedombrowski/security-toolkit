#!/bin/bash
#
# Scanner Report Generation Module
#
# Purpose: Generate compliance reports for vulnerability scanning
# NIST Controls: CA-2 (Control Assessments), RA-3 (Risk Assessment)
#
# Functions:
#   print_scan_header()          - Print scan header to console
#   generate_compliance_report() - Generate NIST compliance report
#   print_scan_summary()         - Print scan completion summary
#
# Dependencies: common.sh, nist-controls.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Print scan header to console
# Usage: print_scan_header "timestamp" "target" "scan_mode" "hostname" "toolkit_name" "toolkit_version" "toolkit_commit" "toolkit_source"
print_scan_header() {
    local timestamp="$1"
    local target="$2"
    local scan_mode="$3"
    local hostname="$4"
    local toolkit_name="$5"
    local toolkit_version="$6"
    local toolkit_commit="$7"
    local toolkit_source="$8"

    echo ""
    echo "================================================================================"
    echo "                    VULNERABILITY SCANNING REPORT"
    echo "================================================================================"
    echo ""
    echo "  Scan Timestamp:  $timestamp"
    echo "  Target:          $target"
    echo "  Scan Mode:       $scan_mode"
    echo "  Hostname:        $hostname"
    echo "  Toolkit:         $toolkit_name $toolkit_version ($toolkit_commit)"
    echo "  Source:          $toolkit_source"
    echo ""
    echo "================================================================================"
    echo ""
}

# Initialize report file
# Usage: init_report_file "report_file" "timestamp" "target" "toolkit_name" "toolkit_version" "toolkit_commit" "toolkit_source"
init_report_file() {
    local report_file="$1"
    local timestamp="$2"
    local target="$3"
    local toolkit_name="$4"
    local toolkit_version="$5"
    local toolkit_commit="$6"
    local toolkit_source="$7"

    {
        echo "================================================================================"
        echo "                    VULNERABILITY SCANNING REPORT"
        echo "================================================================================"
        echo ""
        echo "Generated: $timestamp"
        echo "Target: $target"
        echo "Toolkit: $toolkit_name $toolkit_version ($toolkit_commit)"
        echo "Source: $toolkit_source"
        echo ""
    } > "$report_file"
}

# Generate NIST compliance mapping in report
# Usage: generate_compliance_report "report_file" "timestamp" "target" "hostname" "scan_mode" "toolkit_version" "toolkit_commit" "run_nmap" "run_openvas" "run_lynis"
generate_compliance_report() {
    local report_file="$1"
    local timestamp="$2"
    local target="$3"
    local hostname="$4"
    local scan_mode="$5"
    local toolkit_version="$6"
    local toolkit_commit="$7"
    local run_nmap="$8"
    local run_openvas="$9"
    local run_lynis="${10}"

    {
        echo ""
        echo "================================================================================"
        echo "                    NIST COMPLIANCE MAPPING SUMMARY"
        echo "================================================================================"
        echo ""

        echo "NIST SP 800-53 Rev 5 Controls Assessed:"
        echo "----------------------------------------"
        for control in $NIST_800_53_CONTROLS; do
            printf "  %-8s %s\n" "$control" "$(get_nist_800_53_control "$control")"
        done

        echo ""
        echo "NIST SP 800-171 Rev 2 Controls Assessed:"
        echo "-----------------------------------------"
        for control in $NIST_800_171_CONTROLS; do
            printf "  %-10s %s\n" "$control" "$(get_nist_800_171_control "$control")"
        done

        echo ""
        echo "FIPS Requirements:"
        echo "------------------"
        echo "  FIPS 199: Security categorization impact levels assessed"
        echo "  FIPS 200: Minimum security requirements verified"

        echo ""
        echo "================================================================================"
        echo "                         SCAN EXECUTION DETAILS"
        echo "================================================================================"
        echo ""
        echo "Scan Timestamp:  $timestamp"
        echo "Target:          $target"
        echo "Hostname:        $hostname"
        echo "Scan Mode:       $scan_mode"
        echo "Toolkit Version: $toolkit_version ($toolkit_commit)"
        echo ""
        echo "Tools Executed:"
        if [ "$run_nmap" = "true" ]; then
            echo "  [X] Nmap network scanning"
        else
            echo "  [ ] Nmap (not available)"
        fi
        if [ "$run_openvas" = "true" ]; then
            echo "  [X] OpenVAS vulnerability assessment"
        else
            echo "  [ ] OpenVAS (not available)"
        fi
        if [ "$run_lynis" = "true" ]; then
            echo "  [X] Lynis system audit"
        else
            echo "  [ ] Lynis (not available)"
        fi

        echo ""
    } >> "$report_file"
}

# Print scan completion summary
# Usage: print_scan_summary "scan_count" "pass_count" "report_file" "overall_status"
print_scan_summary() {
    local scan_count="$1"
    local pass_count="$2"
    local report_file="$3"
    local overall_status="$4"

    echo ""
    echo "================================================================================"
    echo "                         SCAN COMPLETION SUMMARY"
    echo "================================================================================"
    echo ""
    echo "Scans executed: $scan_count"
    echo "Scans passed:   $pass_count"
    echo ""
    echo "Report saved to: $report_file"
    echo ""

    if [ "$overall_status" -eq 0 ]; then
        log_success "All scans completed successfully"
    else
        log_warning "Scans completed with findings - review report for details"
    fi

    echo ""
    echo "NIST Compliance Status:"
    echo "  RA-5 (Vulnerability Scanning): Executed"
    echo "  CA-2 (Control Assessment): Executed"
    echo "  SI-2 (Flaw Remediation): Findings documented"
    echo ""
}

# Print usage information
# Usage: print_scanner_usage "script_name"
print_scanner_usage() {
    local script_name="$1"

    cat << EOF
Vulnerability Scanning Script - NIST Compliance Assessment

Usage: $script_name [options] [target]

Options:
  -n, --nmap-only      Run only Nmap network scans
  -o, --openvas-only   Run only OpenVAS vulnerability scans
  -l, --lynis-only     Run only Lynis system audit
  -q, --quick          Quick scan (reduced thoroughness)
  -f, --full           Full comprehensive scan (default)
  -r, --report-only    Generate report from existing scan data
  -d, --output-dir DIR Output directory (default: .scans/)
  -h, --help           Show this help message

Target:
  IP address, hostname, or CIDR range (default: 127.0.0.1)

NIST Controls Assessed:
  RA-5   Vulnerability Monitoring and Scanning
  RA-3   Risk Assessment
  CA-2   Control Assessments
  SI-2   Flaw Remediation
  CM-6   Configuration Settings
  SC-7   Boundary Protection

Examples:
  $script_name                           # Scan localhost with all tools
  $script_name 192.168.1.0/24            # Scan network range
  $script_name -n 10.0.0.1               # Nmap only on specific host
  $script_name -l                        # Lynis audit only (local system)
  $script_name -q 192.168.1.1            # Quick scan of specific host

EOF
}
