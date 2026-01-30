#!/bin/bash
#
# OpenVAS/GVM Scanner Module
#
# Purpose: Vulnerability assessment using OpenVAS/Greenbone Vulnerability Management
# NIST Controls: RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation),
#                RA-3 (Risk Assessment)
#
# Functions:
#   run_openvas_scan() - Execute OpenVAS/GVM scan
#   run_gvm_scan()     - GVM-specific scanning
#   run_omp_scan()     - OMP-specific scanning (legacy)
#
# Dependencies: common.sh, nist-controls.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Run OpenVAS/GVM vulnerability assessment
# Usage: run_openvas_scan "target" "output_dir" "timestamp"
# Returns: 0 on success, 1 on failure
run_openvas_scan() {
    local target="$1"
    local output_dir="$2"
    local timestamp="$3"
    local output_prefix="$output_dir/openvas-$timestamp"

    print_scanner_section "OPENVAS VULNERABILITY ASSESSMENT"

    print_nist_controls_header "openvas"

    echo "Target: $target"
    echo ""

    # Check if GVM/OpenVAS daemon is running
    if command -v gvm-cli &> /dev/null; then
        log_info "Using Greenbone Vulnerability Management (GVM)"
        run_gvm_scan "$target" "$output_prefix" "$timestamp"
    elif command -v omp &> /dev/null; then
        log_info "Using OpenVAS Management Protocol (OMP)"
        run_omp_scan "$target" "$output_prefix" "$timestamp"
    else
        log_error "No OpenVAS/GVM client available"
        return 1
    fi
}

# Run GVM scan
# Usage: run_gvm_scan "target" "output_prefix" "timestamp"
run_gvm_scan() {
    local target="$1"
    local output_prefix="$2"
    local timestamp="$3"

    log_warning "GVM scanning requires a running GVM daemon and proper authentication."
    echo ""
    echo "To run a GVM scan manually:"
    echo ""
    echo "  1. Start GVM services:"
    echo "     sudo gvm-start"
    echo ""
    echo "  2. Create a target:"
    echo "     gvm-cli --gmp-username admin --gmp-password <pass> \\"
    echo "       tls --hostname localhost socket \\"
    echo "       --xml '<create_target><name>Scan-$timestamp</name><hosts>$target</hosts></create_target>'"
    echo ""
    echo "  3. Create and start a task with appropriate scan config"
    echo ""
    echo "  4. Export results to: $output_prefix.xml"
    echo ""

    # Check if we can connect to GVM
    if gvm-cli --help &>/dev/null; then
        log_info "GVM CLI available. Configure credentials in /etc/gvm/ or use --gmp-username/--gmp-password"
    fi

    return 0
}

# Run OMP scan (legacy OpenVAS)
# Usage: run_omp_scan "target" "output_prefix" "timestamp"
run_omp_scan() {
    local target="$1"
    local output_prefix="$2"
    local timestamp="$3"

    log_warning "OMP scanning requires OpenVAS daemon running and credentials configured."
    echo ""
    echo "To run an OMP scan manually:"
    echo ""
    echo "  1. Ensure OpenVAS services are running"
    echo "  2. Configure ~/.omp (username, password, host, port)"
    echo "  3. Create target and task via OMP commands"
    echo "  4. Export results to: $output_prefix.xml"
    echo ""

    return 0
}
