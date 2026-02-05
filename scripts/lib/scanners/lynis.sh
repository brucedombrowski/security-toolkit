#!/bin/bash
#
# Lynis Scanner Module
#
# Purpose: System security auditing using Lynis
# NIST Controls: SI-7 (Software/Firmware Integrity), CM-6 (Configuration Settings),
#                CA-2 (Control Assessments)
#
# Functions:
#   run_lynis_audit()       - Execute Lynis system audit
#   summarize_lynis_results() - Parse and summarize audit results
#
# Dependencies: common.sh, nist-controls.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Run Lynis system security audit
# Usage: run_lynis_audit "output_dir" "timestamp" "scan_mode"
# Returns: 0 on success, 1 on failure
run_lynis_audit() {
    local output_dir="$1"
    local timestamp="$2"
    local scan_mode="${3:-full}"
    local output_prefix="$output_dir/lynis-$timestamp"

    print_scanner_section "LYNIS SYSTEM SECURITY AUDIT"

    print_nist_controls_header "lynis"

    echo "FIPS 200 Requirements:"
    echo "  - Configuration Management (CM)"
    echo "  - System and Information Integrity (SI)"
    echo ""

    local lynis_args="--quick"

    if [ "$scan_mode" = "full" ]; then
        lynis_args=""
        log_info "Running comprehensive Lynis audit..."
    else
        log_info "Running quick Lynis audit..."
    fi

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_warning "Running without root - some checks will be skipped"
        lynis_args="$lynis_args --pentest"
    fi

    local lynis_output="$output_prefix.txt"
    local lynis_report="$output_prefix-report.dat"

    echo ""

    # Run Lynis
    if lynis audit system $lynis_args --report-file "$lynis_report" 2>&1 | tee "$lynis_output"; then
        log_success "Lynis audit completed"
        echo ""
        echo "Results saved to:"
        echo "  Log:    $lynis_output"
        echo "  Report: $lynis_report"

        # Parse and summarize results
        summarize_lynis_results "$lynis_output" "$lynis_report"
        return 0
    else
        log_error "Lynis audit encountered errors"
        return 1
    fi
}

# Summarize Lynis audit results
# Usage: summarize_lynis_results "lynis_output" "lynis_report"
summarize_lynis_results() {
    local lynis_output="$1"
    local lynis_report="$2"

    echo ""
    echo "--- Lynis Audit Summary ---"
    echo ""

    # Extract hardening index if available
    if [ -f "$lynis_report" ]; then
        local hardening_index
        hardening_index=$(grep "hardening_index=" "$lynis_report" 2>/dev/null | cut -d= -f2)
        if [ -n "$hardening_index" ]; then
            echo "Hardening Index: $hardening_index / 100"
            echo ""

            if [ "$hardening_index" -ge 80 ]; then
                log_success "System hardening: GOOD"
            elif [ "$hardening_index" -ge 60 ]; then
                log_warning "System hardening: MODERATE (improvements recommended)"
            else
                log_error "System hardening: NEEDS IMPROVEMENT"
            fi
        fi
    fi

    # Count warnings and suggestions (use tr to strip any whitespace/newlines)
    local warnings suggestions
    warnings=$(grep -c "\[ warning \]" "$lynis_output" 2>/dev/null | tr -d '[:space:]')
    suggestions=$(grep -c "\[ suggestion \]" "$lynis_output" 2>/dev/null | tr -d '[:space:]')
    # Default to 0 if empty
    warnings="${warnings:-0}"
    suggestions="${suggestions:-0}"

    echo ""
    echo "Findings:"
    echo "  Warnings:    $warnings"
    echo "  Suggestions: $suggestions"
    echo ""

    # Show top warnings (use numeric comparison with default)
    if [ "${warnings:-0}" -gt 0 ] 2>/dev/null; then
        echo "Top warnings:"
        grep "\[ warning \]" "$lynis_output" | head -5
        echo ""
    fi

    return 0
}
