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
# Usage: ./run-all-scans.sh [-n|--non-interactive] [target_directory]
#        -n  Non-interactive mode: skip interactive prompts
#        If no target specified, uses parent directory of script location
#
# Output:
#   Results are saved to <target_directory>/.scans/ for submittal purposes
#   Add .scans/ to your .gitignore

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Toolkit identification
TOOLKIT_VERSION=$(git -C "$SECURITY_REPO_DIR" describe --tags --always 2>/dev/null || echo "unknown")
TOOLKIT_COMMIT=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Default to interactive mode
INTERACTIVE=1
INTERACTIVE_FLAG="-i"
TARGET_DIR=""

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--non-interactive)
            INTERACTIVE=0
            INTERACTIVE_FLAG=""
            shift
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

# Default target to security repo if not specified
if [ -z "$TARGET_DIR" ]; then
    TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    # Convert relative path to absolute for consistent behavior
    TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
fi

# Use UTC for consistent timestamps across time zones
TIMESTAMP=$(date -u "+%Y-%m-%dT%H:%M:%SZ")
DATE_STAMP=$(date -u "+%Y-%m-%d")
# Filesystem-safe timestamp for unique filenames (no colons)
# Format: YYYY-MM-DD-THHMMSSZ (e.g., 2026-01-15-T154452Z)
FILE_TIMESTAMP=$(date -u "+%Y-%m-%d-T%H%M%SZ")

# Get hostname for attestation
TARGET_HOST=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")

# Create .scans directory for output (delete previous results first)
SCANS_DIR="$TARGET_DIR/.scans"
if [ -d "$SCANS_DIR" ]; then
    echo "Removing previous scan results: $SCANS_DIR"
    rm -rf "$SCANS_DIR"
fi
mkdir -p "$SCANS_DIR"

# Consolidated report file (using FILE_TIMESTAMP for unique UTC-timestamped filenames)
REPORT_FILE="$SCANS_DIR/security-scan-report-$FILE_TIMESTAMP.txt"
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

# ============================================================================
# HOST INVENTORY COLLECTION (First step - creates verifiable thumbprint)
# ============================================================================
INVENTORY_FILE="$SCANS_DIR/host-inventory-$FILE_TIMESTAMP.txt"
INVENTORY_SCRIPT="$SCRIPT_DIR/collect-host-inventory.sh"

log "Collecting Host Inventory..."
log "-----------------------------"

if [ -x "$INVENTORY_SCRIPT" ]; then
    "$INVENTORY_SCRIPT" "$INVENTORY_FILE" 2>&1

    # Calculate checksum of inventory file
    INVENTORY_CHECKSUM=$(shasum -a 256 "$INVENTORY_FILE" | awk '{print $1}')

    log "  Host inventory collected: host-inventory-$FILE_TIMESTAMP.txt"
    log "  Inventory SHA256: $INVENTORY_CHECKSUM"
    log ""
    log "  All subsequent scans reference this inventory snapshot."
else
    log "  WARNING: collect-host-inventory.sh not found or not executable"
    INVENTORY_CHECKSUM="NOT_COLLECTED"
fi

log ""
log "========================================================"
log ""

# Track overall status
OVERALL_STATUS="PASS"
FAIL_COUNT=0
PASS_COUNT=0

# Track individual scan results for PDF generation
PII_RESULT="PASS"
PII_FINDINGS="No PII detected"
MALWARE_RESULT="PASS"
MALWARE_FINDINGS="No malware detected"
SECRETS_RESULT="PASS"
SECRETS_FINDINGS="No secrets detected"
MAC_RESULT="PASS"
MAC_FINDINGS="No MAC addresses detected"
HOST_RESULT="PASS"
HOST_FINDINGS="All checks passed"
VULN_RESULT="SKIP"
VULN_FINDINGS="Not run"

# Run each scan
# Arguments: scan_name script_cmd control_ref output_file result_var findings_var
# Note: script_cmd can include flags (e.g., "check-pii.sh -i")
run_scan() {
    local scan_name="$1"
    local script_cmd="$2"
    local control_ref="$3"
    local output_file="$4"
    local result_var="$5"
    local findings_var="$6"

    # Extract just the script path (first word) for executable check
    local script_path="${script_cmd%% *}"

    log "Running: $scan_name"
    log "  Control: $control_ref"
    log "  Host Inventory Reference: $INVENTORY_CHECKSUM"

    if [ -x "$script_path" ]; then
        # Run scan and capture output
        local scan_output
        local exit_code=0

        # Check if this is an interactive scan (needs TTY access)
        if echo "$script_cmd" | grep -q "\-i"; then
            # Interactive mode: run directly (not captured) so TTY works
            # Use tee to capture output while still showing it
            local temp_output=$(mktemp)
            $script_cmd "$TARGET_DIR" 2>&1 | tee "$temp_output" || exit_code=$?
            scan_output=$(cat "$temp_output")
            rm -f "$temp_output"
        else
            # Non-interactive: capture output normally
            scan_output=$($script_cmd "$TARGET_DIR" 2>&1) || exit_code=$?
            echo "$scan_output"
        fi

        # Append to consolidated report
        echo "$scan_output" >> "$REPORT_FILE"

        # Save individual scan output with inventory reference header
        if [ -n "$output_file" ]; then
            {
                echo "# Host Inventory Reference: $INVENTORY_CHECKSUM"
                echo "# Scan Timestamp: $TIMESTAMP"
                echo ""
                echo "$scan_output"
            } > "$SCANS_DIR/$output_file"
        fi

        if [ $exit_code -eq 0 ]; then
            log "  Status: PASS"
            PASS_COUNT=$((PASS_COUNT + 1))
            # Update result variable if provided
            if [ -n "$result_var" ]; then
                eval "$result_var=PASS"
            fi
        else
            OVERALL_STATUS="FAIL"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            log "  Status: FAIL"
            # Update result variable if provided
            if [ -n "$result_var" ]; then
                eval "$result_var=FAIL"
                # Extract findings count from output if possible
                local finding_count=$(echo "$scan_output" | grep -E "(found|detected|flagged)" -i | head -1)
                if [ -n "$findings_var" ] && [ -n "$finding_count" ]; then
                    eval "$findings_var=\"Issues detected\""
                fi
            fi
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
    "$SCRIPT_DIR/check-pii.sh $INTERACTIVE_FLAG" \
    "NIST 800-53: SI-12 (Information Management)" \
    "pii-scan-$FILE_TIMESTAMP.txt" \
    "PII_RESULT" "PII_FINDINGS"

run_scan "Malware Scan (ClamAV)" \
    "$SCRIPT_DIR/check-malware.sh" \
    "NIST 800-53: SI-3 (Malicious Code Protection)" \
    "malware-scan-$FILE_TIMESTAMP.txt" \
    "MALWARE_RESULT" "MALWARE_FINDINGS"

run_scan "Secrets/Credentials Scan" \
    "$SCRIPT_DIR/check-secrets.sh $INTERACTIVE_FLAG" \
    "NIST 800-53: SA-11 (Developer Testing)" \
    "secrets-scan-$FILE_TIMESTAMP.txt" \
    "SECRETS_RESULT" "SECRETS_FINDINGS"

run_scan "IEEE 802.3 MAC Address Scan" \
    "$SCRIPT_DIR/check-mac-addresses.sh" \
    "NIST 800-53: SC-8 (Transmission Confidentiality)" \
    "mac-address-scan-$FILE_TIMESTAMP.txt" \
    "MAC_RESULT" "MAC_FINDINGS"

run_scan "Host Security Configuration" \
    "$SCRIPT_DIR/check-host-security.sh" \
    "NIST 800-53: CM-6 (Configuration Settings)" \
    "host-security-scan-$FILE_TIMESTAMP.txt" \
    "HOST_RESULT" "HOST_FINDINGS"

# Run vulnerability scan (quick mode, scans localhost)
# Note: This scans the HOST system, not the codebase - uses different invocation
# The script creates its own output files in .scans/ directory
log "Running: Vulnerability Scan (Nmap/Lynis)"
log "  Control: NIST 800-53: RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation)"
log "  Host Inventory Reference: $INVENTORY_CHECKSUM"

VULN_SCRIPT="$SCRIPT_DIR/scan-vulnerabilities.sh"
if [ -x "$VULN_SCRIPT" ]; then
    # Vulnerability scan targets localhost and outputs to .scans/ directly
    # Pass -d to specify our output directory
    vuln_exit=0
    "$VULN_SCRIPT" -q -d "$SCANS_DIR" 2>&1 | tee -a "$REPORT_FILE" || vuln_exit=$?

    # Find the vulnerability scan report created by the script
    VULN_SCAN_FILE=$(ls -t "$SCANS_DIR"/vulnerability-scan-*.txt 2>/dev/null | head -1)
    if [ -n "$VULN_SCAN_FILE" ] && [ -f "$VULN_SCAN_FILE" ]; then
        # Prepend inventory reference header
        {
            echo "# Host Inventory Reference: $INVENTORY_CHECKSUM"
            echo "# Scan Timestamp: $TIMESTAMP"
            echo ""
            cat "$VULN_SCAN_FILE"
        } > "$VULN_SCAN_FILE.tmp"
        mv "$VULN_SCAN_FILE.tmp" "$VULN_SCAN_FILE"
    fi

    if [ $vuln_exit -eq 0 ]; then
        log "  Status: PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
        VULN_RESULT="PASS"
        VULN_FINDINGS="No critical vulnerabilities"
    else
        log "  Status: FAIL"
        OVERALL_STATUS="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        VULN_RESULT="FAIL"
        VULN_FINDINGS="Vulnerabilities detected"
    fi
else
    log "  Status: SKIPPED (scan-vulnerabilities.sh not found)"
    VULN_RESULT="SKIP"
    VULN_FINDINGS="Not run"
fi
log ""
log "--------------------------------------------------------"
log ""

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

# Generate checksums.md for all scan output files
CHECKSUMS_FILE="$SCANS_DIR/checksums.md"
{
    echo "# Scan Output Checksums"
    echo ""
    echo "Generated: $TIMESTAMP"
    echo "Toolkit: Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
    echo "Source: https://github.com/brucedombrowski/Security"
    echo "Target: $TARGET_DIR"
    echo ""
    echo "## Host Inventory Reference"
    echo ""
    echo "All scan outputs reference this host inventory snapshot:"
    echo ""
    echo "\`\`\`"
    echo "SHA256: $INVENTORY_CHECKSUM"
    echo "File:   host-inventory-$FILE_TIMESTAMP.txt"
    echo "\`\`\`"
    echo ""
    echo "**Note:** The host inventory contains sensitive information (MAC addresses,"
    echo "serial numbers, installed software). Scan results can be shared without"
    echo "exposing this data - they only reference the inventory checksum."
    echo ""
    echo "## SHA256 Checksums"
    echo ""
    echo "\`\`\`"
    cd "$SCANS_DIR"
    for f in *.txt; do
        if [ -f "$f" ]; then
            shasum -a 256 "$f"
        fi
    done
    echo "\`\`\`"
    echo ""
    echo "## Verification"
    echo ""
    echo "To verify integrity of scan results:"
    echo ""
    echo "\`\`\`bash"
    echo "cd .scans && shasum -a 256 -c checksums.md"
    echo "\`\`\`"
} > "$CHECKSUMS_FILE"

log "Checksums: checksums.md"
log ""
ls -1 "$SCANS_DIR"/*.txt 2>/dev/null | while read f; do
    log "  $(basename "$f")"
done

# Generate PDF attestation using external script
# Export all required variables for the attestation script
export TARGET_DIR FILE_TIMESTAMP TIMESTAMP DATE_STAMP INVENTORY_CHECKSUM
export TOOLKIT_VERSION TOOLKIT_COMMIT
export PII_RESULT PII_FINDINGS MALWARE_RESULT MALWARE_FINDINGS
export SECRETS_RESULT SECRETS_FINDINGS MAC_RESULT MAC_FINDINGS
export HOST_RESULT HOST_FINDINGS VULN_RESULT VULN_FINDINGS
export OVERALL_STATUS PASS_COUNT FAIL_COUNT

ATTESTATION_SCRIPT="$SCRIPT_DIR/generate-scan-attestation.sh"
if [ -x "$ATTESTATION_SCRIPT" ]; then
    # Capture output for logging
    attestation_output=$("$ATTESTATION_SCRIPT" "$SCANS_DIR" 2>&1) || true
    echo "$attestation_output"
    echo "$attestation_output" >> "$REPORT_FILE"
else
    log "Note: generate-scan-attestation.sh not found, skipping PDF attestation"
fi

log ""

# Update report checksum in checksums.md (report file was modified after initial checksum)
FINAL_REPORT_CHECKSUM=$(shasum -a 256 "$REPORT_FILE" 2>/dev/null | awk '{print $1}')
if [ -n "$FINAL_REPORT_CHECKSUM" ]; then
    # Replace the report checksum line in checksums.md
    sed -i.bak "s/^[a-f0-9]*  security-scan-report-.*\.txt$/$FINAL_REPORT_CHECKSUM  $(basename "$REPORT_FILE")/" "$CHECKSUMS_FILE"
    rm -f "$CHECKSUMS_FILE.bak"
fi

if [ "$OVERALL_STATUS" = "PASS" ]; then
    exit 0
else
    exit 1
fi
