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
#
# Output:
#   Results are saved to <target_directory>/.scans/ for submittal purposes
#   Add .scans/ to your .gitignore

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Allow target directory to be specified as argument
if [ -n "$1" ]; then
    TARGET_DIR="$1"
else
    TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
DATE_STAMP=$(date "+%Y-%m-%d")

# Create .scans directory for output
SCANS_DIR="$TARGET_DIR/.scans"
mkdir -p "$SCANS_DIR"

# Consolidated report file
REPORT_FILE="$SCANS_DIR/security-scan-report-$DATE_STAMP.txt"
REPO_NAME=$(basename "$TARGET_DIR")

# Function to output to both console and file
log() {
    echo "$1"
    echo "$1" >> "$REPORT_FILE"
}

# Start fresh report
echo "" > "$REPORT_FILE"

log "========================================================"
log "Security Verification Suite"
log "========================================================"
log "Timestamp: $TIMESTAMP"
log "Target: $TARGET_DIR"
log "Repository: $REPO_NAME"
log "Report: $REPORT_FILE"
log ""
log "========================================================"
log ""

# Track overall status
OVERALL_STATUS="PASS"
FAIL_COUNT=0
PASS_COUNT=0

# Run each scan
run_scan() {
    local scan_name="$1"
    local script="$2"
    local control_ref="$3"
    local output_file="$4"

    log "Running: $scan_name"
    log "  Control: $control_ref"

    if [ -x "$script" ]; then
        # Run scan and capture output to both console and individual file
        local scan_output
        local exit_code=0
        scan_output=$("$script" "$TARGET_DIR" 2>&1) || exit_code=$?

        # Display output to console and append to consolidated report
        echo "$scan_output"
        echo "$scan_output" >> "$REPORT_FILE"

        # Save individual scan output
        if [ -n "$output_file" ]; then
            echo "$scan_output" > "$SCANS_DIR/$output_file"
        fi

        if [ $exit_code -eq 0 ]; then
            log "  Status: PASS"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            OVERALL_STATUS="FAIL"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            log "  Status: FAIL"
        fi
    else
        log "  Status: SKIPPED (script not found or not executable)"
    fi
    log ""
    log "--------------------------------------------------------"
    log ""
}

# Run all scans with NIST control references
run_scan "PII Pattern Scan" \
    "$SCRIPT_DIR/check-pii.sh" \
    "NIST 800-53: SI-12 (Information Management)" \
    "pii-scan-$DATE_STAMP.txt"

run_scan "Malware Scan (ClamAV)" \
    "$SCRIPT_DIR/check-malware.sh" \
    "NIST 800-53: SI-3 (Malicious Code Protection)" \
    "malware-scan-$DATE_STAMP.txt"

run_scan "Secrets/Credentials Scan" \
    "$SCRIPT_DIR/check-secrets.sh" \
    "NIST 800-53: SA-11 (Developer Testing)" \
    "secrets-scan-$DATE_STAMP.txt"

run_scan "IEEE 802.3 MAC Address Scan" \
    "$SCRIPT_DIR/check-mac-addresses.sh" \
    "NIST 800-53: SC-8 (Transmission Confidentiality)" \
    "mac-address-scan-$DATE_STAMP.txt"

run_scan "Host Security Configuration" \
    "$SCRIPT_DIR/check-host-security.sh" \
    "NIST 800-53: CM-6 (Configuration Settings)" \
    "host-security-scan-$DATE_STAMP.txt"

log "========================================================"
log ""
log "SCAN SUMMARY"
log "============"
log "Passed: $PASS_COUNT"
log "Failed: $FAIL_COUNT"
log ""

if [ "$OVERALL_STATUS" = "PASS" ]; then
    log "OVERALL RESULT: PASS"
    log ""
    log "All security scans passed."
else
    log "OVERALL RESULT: FAIL"
    log ""
    log "$FAIL_COUNT scan(s) require attention."
    log "Review the output above for details."
fi

log ""
log "========================================================"
log "SCAN ARTIFACTS"
log "========================================================"
log ""
log "Results saved to: $SCANS_DIR/"
log ""
ls -1 "$SCANS_DIR"/*.txt 2>/dev/null | while read f; do
    log "  $(basename "$f")"
done
log ""

if [ "$OVERALL_STATUS" = "PASS" ]; then
    exit 0
else
    exit 1
fi
