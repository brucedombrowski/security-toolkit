#!/bin/bash
#
# Nmap Scanner Module
#
# Purpose: Network vulnerability scanning using Nmap
# NIST Controls: RA-5 (Vulnerability Scanning), SI-4 (System Monitoring),
#                CM-8 (System Inventory), SC-7 (Boundary Protection)
#
# Functions:
#   run_nmap_scan()         - Execute Nmap scan
#   summarize_nmap_results() - Parse and summarize scan results
#
# Dependencies: common.sh, nist-controls.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Run Nmap network vulnerability scan
# Usage: run_nmap_scan "target" "output_dir" "timestamp" "scan_mode"
# Returns: 0 on success, 1 on failure
run_nmap_scan() {
    local target="$1"
    local output_dir="$2"
    local timestamp="$3"
    local scan_mode="${4:-full}"
    local output_prefix="$output_dir/nmap-$timestamp"

    print_scanner_section "NMAP NETWORK VULNERABILITY SCAN"

    print_nist_controls_header "nmap"

    echo "Target: $target"
    echo ""

    local nmap_args=""
    local is_localhost=false

    # Check if target is localhost
    if [ "$target" = "127.0.0.1" ] || [ "$target" = "localhost" ] || [ "$target" = "::1" ]; then
        is_localhost=true
    fi

    if [ "$scan_mode" = "quick" ]; then
        # Quick scan: Top 100 ports, no scripts
        nmap_args="-sV -T4 --top-ports 100"
        log_info "Running quick Nmap scan (top 100 ports)..."
    else
        # Full scan: version detection, common ports
        # Note: -p- (all ports) is too slow for unprivileged localhost scans
        if $is_localhost && [[ $EUID -ne 0 ]]; then
            nmap_args="-sV -T4 --top-ports 1000"
            log_info "Running Nmap scan (top 1000 ports - localhost unprivileged mode)..."
        else
            nmap_args="-sV -sC -T4 -p-"
            log_info "Running comprehensive Nmap scan (all ports)..."
        fi
    fi

    # Check if we can run privileged scans
    if [[ $EUID -eq 0 ]]; then
        nmap_args="$nmap_args -sS -O"  # SYN scan + OS detection
        log_info "Running privileged scan (SYN + OS detection)"
    else
        nmap_args="$nmap_args -sT"  # TCP connect scan
        log_warning "Running unprivileged scan (TCP connect only)"
        if $is_localhost; then
            log_warning "Localhost TCP connect scan may show 'Strange read error' - this is a known Nmap issue"
        fi
    fi

    # Add timeout for scans to prevent hanging
    if [ "$scan_mode" = "quick" ]; then
        nmap_args="$nmap_args --host-timeout 300s"
    else
        nmap_args="$nmap_args --host-timeout 900s --stats-every 10s"
    fi

    # Run Nmap
    local nmap_output="$output_prefix.txt"
    local nmap_xml="$output_prefix.xml"

    echo ""
    if nmap $nmap_args -oN "$nmap_output" -oX "$nmap_xml" "$target" 2>&1; then
        log_success "Nmap scan completed"
        echo ""
        echo "Results saved to:"
        echo "  Text: $nmap_output"
        echo "  XML:  $nmap_xml"

        # Parse and summarize results
        summarize_nmap_results "$nmap_output"
        return 0
    else
        log_error "Nmap scan failed"
        return 1
    fi
}

# Summarize Nmap scan results
# Usage: summarize_nmap_results "nmap_output_file"
summarize_nmap_results() {
    local nmap_output="$1"

    echo ""
    echo "--- Nmap Scan Summary ---"
    echo ""

    # Count open ports
    local open_ports filtered_ports
    open_ports=$(grep -c "^[0-9].*open" "$nmap_output" 2>/dev/null || echo "0")
    filtered_ports=$(grep -c "^[0-9].*filtered" "$nmap_output" 2>/dev/null || echo "0")

    echo "Open ports found: $open_ports"
    echo "Filtered ports: $filtered_ports"
    echo ""

    # List open ports with services
    if [ "$open_ports" -gt 0 ]; then
        echo "Open ports and services:"
        grep "^[0-9].*open" "$nmap_output" | head -20
        if [ "$open_ports" -gt 20 ]; then
            echo "... and $((open_ports - 20)) more"
        fi
    fi

    # Check for common vulnerable services
    echo ""
    echo "Security assessment:"

    local vuln_count=0

    # Check for telnet (insecure)
    if grep -q "23/tcp.*open.*telnet" "$nmap_output" 2>/dev/null; then
        log_warning "Telnet service detected (insecure, use SSH instead)"
        vuln_count=$((vuln_count + 1))
    fi

    # Check for FTP (often insecure)
    if grep -q "21/tcp.*open.*ftp" "$nmap_output" 2>/dev/null; then
        log_warning "FTP service detected (consider SFTP/FTPS)"
        vuln_count=$((vuln_count + 1))
    fi

    # Check for unencrypted HTTP
    if grep -q "80/tcp.*open.*http" "$nmap_output" 2>/dev/null; then
        log_info "HTTP (port 80) detected - verify HTTPS redirect"
    fi

    # Check for SMB
    if grep -q "445/tcp.*open" "$nmap_output" 2>/dev/null; then
        log_warning "SMB service detected - ensure latest patches applied"
        vuln_count=$((vuln_count + 1))
    fi

    # Check for RDP
    if grep -q "3389/tcp.*open" "$nmap_output" 2>/dev/null; then
        log_warning "RDP service detected - ensure NLA enabled"
        vuln_count=$((vuln_count + 1))
    fi

    if [ "$vuln_count" -eq 0 ]; then
        log_success "No obviously vulnerable services detected"
    else
        log_warning "$vuln_count potential security concern(s) identified"
    fi

    echo ""
    return 0
}
