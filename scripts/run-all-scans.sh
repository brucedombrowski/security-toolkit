#!/bin/bash
#
# Master Security Verification Script
#
# Purpose: Run all security verification scans and produce consolidated report
# Standards Reference:
#   - NIST SP 800-53 Rev 5: Security and Privacy Controls
#   - NIST SP 800-171: Protecting CUI in Nonfederal Systems
#   - FIPS 199: Standards for Security Categorization
#   - FIPS 200: Minimum Security Requirements
#
# Exit codes:
#   0 = All scans passed
#   1 = One or more scans failed
#
# Usage: ./run-all-scans.sh [target_directory]
#        If no target specified, uses parent directory of script location

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Allow target directory to be specified as argument
if [ -n "$1" ]; then
    TARGET_DIR="$1"
else
    TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
REPO_NAME=$(basename "$TARGET_DIR")

echo "========================================================"
echo "Security Verification Suite"
echo "========================================================"
echo "Timestamp: $TIMESTAMP"
echo "Target: $TARGET_DIR"
echo "Repository: $REPO_NAME"
echo ""
echo "========================================================"
echo ""

# Track overall status
OVERALL_STATUS="PASS"
FAIL_COUNT=0
PASS_COUNT=0

# Run each scan
run_scan() {
    local scan_name="$1"
    local script="$2"
    local control_ref="$3"

    echo "Running: $scan_name"
    echo "  Control: $control_ref"

    if [ -x "$script" ]; then
        if "$script" "$TARGET_DIR" 2>&1; then
            echo "  Status: PASS"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            OVERALL_STATUS="FAIL"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo "  Status: FAIL"
        fi
    else
        echo "  Status: SKIPPED (script not found or not executable)"
    fi
    echo ""
    echo "--------------------------------------------------------"
    echo ""
}

# Run all scans with NIST control references
run_scan "PII Pattern Scan" \
    "$SCRIPT_DIR/check-pii.sh" \
    "NIST 800-53: SI-12 (Information Management)"

run_scan "Malware Scan (ClamAV)" \
    "$SCRIPT_DIR/check-malware.sh" \
    "NIST 800-53: SI-3 (Malicious Code Protection)"

run_scan "Secrets/Credentials Scan" \
    "$SCRIPT_DIR/check-secrets.sh" \
    "NIST 800-53: SA-11 (Developer Testing)"

run_scan "IEEE 802.3 MAC Address Scan" \
    "$SCRIPT_DIR/check-mac-addresses.sh" \
    "NIST 800-53: SC-8 (Transmission Confidentiality)"

run_scan "Host Security Configuration" \
    "$SCRIPT_DIR/check-host-security.sh" \
    "NIST 800-53: CM-6 (Configuration Settings)"

echo "========================================================"
echo ""
echo "SCAN SUMMARY"
echo "============"
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"
echo ""

if [ "$OVERALL_STATUS" = "PASS" ]; then
    echo "OVERALL RESULT: PASS"
    echo ""
    echo "All security scans passed."
    exit 0
else
    echo "OVERALL RESULT: FAIL"
    echo ""
    echo "$FAIL_COUNT scan(s) require attention."
    echo "Review the output above for details."
    exit 1
fi
