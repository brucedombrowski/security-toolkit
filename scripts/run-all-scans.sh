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
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Toolkit identification
TOOLKIT_VERSION=$(git -C "$SECURITY_REPO_DIR" describe --tags --always 2>/dev/null || echo "unknown")
TOOLKIT_COMMIT=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

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

# ============================================================================
# HOST INVENTORY COLLECTION (First step - creates verifiable thumbprint)
# ============================================================================
INVENTORY_FILE="$SCANS_DIR/host-inventory-$DATE_STAMP.txt"
INVENTORY_SCRIPT="$SCRIPT_DIR/collect-host-inventory.sh"

log "Collecting Host Inventory..."
log "-----------------------------"

if [ -x "$INVENTORY_SCRIPT" ]; then
    "$INVENTORY_SCRIPT" "$INVENTORY_FILE" 2>&1

    # Calculate checksum of inventory file
    INVENTORY_CHECKSUM=$(shasum -a 256 "$INVENTORY_FILE" | awk '{print $1}')

    log "  Host inventory collected: host-inventory-$DATE_STAMP.txt"
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

# Run each scan
# Arguments: scan_name script control_ref output_file result_var findings_var
run_scan() {
    local scan_name="$1"
    local script="$2"
    local control_ref="$3"
    local output_file="$4"
    local result_var="$5"
    local findings_var="$6"

    log "Running: $scan_name"
    log "  Control: $control_ref"
    log "  Host Inventory Reference: $INVENTORY_CHECKSUM"

    if [ -x "$script" ]; then
        # Run scan and capture output to both console and individual file
        local scan_output
        local exit_code=0
        scan_output=$("$script" "$TARGET_DIR" 2>&1) || exit_code=$?

        # Display output to console and append to consolidated report
        echo "$scan_output"
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
    "$SCRIPT_DIR/check-pii.sh" \
    "NIST 800-53: SI-12 (Information Management)" \
    "pii-scan-$DATE_STAMP.txt" \
    "PII_RESULT" "PII_FINDINGS"

run_scan "Malware Scan (ClamAV)" \
    "$SCRIPT_DIR/check-malware.sh" \
    "NIST 800-53: SI-3 (Malicious Code Protection)" \
    "malware-scan-$DATE_STAMP.txt" \
    "MALWARE_RESULT" "MALWARE_FINDINGS"

run_scan "Secrets/Credentials Scan" \
    "$SCRIPT_DIR/check-secrets.sh" \
    "NIST 800-53: SA-11 (Developer Testing)" \
    "secrets-scan-$DATE_STAMP.txt" \
    "SECRETS_RESULT" "SECRETS_FINDINGS"

run_scan "IEEE 802.3 MAC Address Scan" \
    "$SCRIPT_DIR/check-mac-addresses.sh" \
    "NIST 800-53: SC-8 (Transmission Confidentiality)" \
    "mac-address-scan-$DATE_STAMP.txt" \
    "MAC_RESULT" "MAC_FINDINGS"

run_scan "Host Security Configuration" \
    "$SCRIPT_DIR/check-host-security.sh" \
    "NIST 800-53: CM-6 (Configuration Settings)" \
    "host-security-scan-$DATE_STAMP.txt" \
    "HOST_RESULT" "HOST_FINDINGS"

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
    echo "File:   host-inventory-$DATE_STAMP.txt"
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
log ""

# Generate PDF attestation if pdflatex is available
PDFLATEX=$(which pdflatex 2>/dev/null || echo "")
TEMPLATE_FILE="$SECURITY_REPO_DIR/templates/scan_attestation.tex"

if [ -n "$PDFLATEX" ] && [ -x "$PDFLATEX" ] && [ -f "$TEMPLATE_FILE" ]; then
    log "Generating PDF attestation..."

    # Create temp directory for LaTeX build
    PDF_BUILD_DIR=$(mktemp -d)

    # Generate unique ID
    UNIQUE_ID="SCAN-$(date +%Y)-$(printf '%03d' $((RANDOM % 1000)))"
    FORMATTED_DATE=$(date "+%B %d, %Y")

    # Copy template and substitute variables
    cp "$TEMPLATE_FILE" "$PDF_BUILD_DIR/scan_attestation.tex"

    # Copy logo if available
    if [ -f "$SECURITY_REPO_DIR/templates/logo.png" ]; then
        cp "$SECURITY_REPO_DIR/templates/logo.png" "$PDF_BUILD_DIR/"
    fi

    # Perform substitutions using sed
    # Escape special characters in paths for sed
    ESCAPED_TARGET_PATH=$(echo "$TARGET_DIR" | sed 's/[&/\]/\\&/g')

    # Truncate inventory checksum for display (first 16 chars)
    INVENTORY_CHECKSUM_SHORT="${INVENTORY_CHECKSUM:0:16}..."

    sed -i.bak \
        -e "s/SCAN-YYYY-NNN/$UNIQUE_ID/g" \
        -e "s/January 15, 2026/$FORMATTED_DATE/g" \
        -e "s/2026-01-15 08:00:00/$TIMESTAMP/g" \
        -e "s/2026-01-15/$DATE_STAMP/g" \
        -e "s/ProjectName/$REPO_NAME/g" \
        -e "s|/path/to/project|$ESCAPED_TARGET_PATH|g" \
        -e "s/v1.0.0/$TOOLKIT_VERSION/g" \
        -e "s/abc1234/$TOOLKIT_COMMIT/g" \
        -e "s/0000000000000000000000000000000000000000000000000000000000000000/$INVENTORY_CHECKSUM_SHORT/g" \
        -e "s/host-inventory-2026-01-15.txt/host-inventory-$DATE_STAMP.txt/g" \
        -e "s/\\\\newcommand{\\\\PIIScanResult}{PASS}/\\\\newcommand{\\\\PIIScanResult}{$PII_RESULT}/g" \
        -e "s/\\\\newcommand{\\\\PIIScanFindings}{No PII detected}/\\\\newcommand{\\\\PIIScanFindings}{$PII_FINDINGS}/g" \
        -e "s/\\\\newcommand{\\\\MalwareScanResult}{PASS}/\\\\newcommand{\\\\MalwareScanResult}{$MALWARE_RESULT}/g" \
        -e "s/\\\\newcommand{\\\\MalwareScanFindings}{No malware detected}/\\\\newcommand{\\\\MalwareScanFindings}{$MALWARE_FINDINGS}/g" \
        -e "s/\\\\newcommand{\\\\SecretsScanResult}{PASS}/\\\\newcommand{\\\\SecretsScanResult}{$SECRETS_RESULT}/g" \
        -e "s/\\\\newcommand{\\\\SecretsScanFindings}{No secrets detected}/\\\\newcommand{\\\\SecretsScanFindings}{$SECRETS_FINDINGS}/g" \
        -e "s/\\\\newcommand{\\\\MACScanResult}{PASS}/\\\\newcommand{\\\\MACScanResult}{$MAC_RESULT}/g" \
        -e "s/\\\\newcommand{\\\\MACScanFindings}{No MAC addresses detected}/\\\\newcommand{\\\\MACScanFindings}{$MAC_FINDINGS}/g" \
        -e "s/\\\\newcommand{\\\\HostSecurityResult}{PASS}/\\\\newcommand{\\\\HostSecurityResult}{$HOST_RESULT}/g" \
        -e "s/\\\\newcommand{\\\\HostSecurityFindings}{All checks passed}/\\\\newcommand{\\\\HostSecurityFindings}{$HOST_FINDINGS}/g" \
        -e "s/\\\\newcommand{\\\\OverallResult}{PASS}/\\\\newcommand{\\\\OverallResult}{$OVERALL_STATUS}/g" \
        -e "s/\\\\newcommand{\\\\PassCount}{5}/\\\\newcommand{\\\\PassCount}{$PASS_COUNT}/g" \
        -e "s/\\\\newcommand{\\\\FailCount}{0}/\\\\newcommand{\\\\FailCount}{$FAIL_COUNT}/g" \
        "$PDF_BUILD_DIR/scan_attestation.tex"

    # Run pdflatex (twice for references)
    cd "$PDF_BUILD_DIR"
    if $PDFLATEX -interaction=nonstopmode scan_attestation.tex > /dev/null 2>&1; then
        $PDFLATEX -interaction=nonstopmode scan_attestation.tex > /dev/null 2>&1

        if [ -f "scan_attestation.pdf" ]; then
            cp "scan_attestation.pdf" "$SCANS_DIR/scan-attestation-$DATE_STAMP.pdf"
            log "  scan-attestation-$DATE_STAMP.pdf"
        else
            log "  PDF generation failed (no output file)"
        fi
    else
        log "  PDF generation failed (pdflatex error)"
    fi

    # Cleanup
    rm -rf "$PDF_BUILD_DIR"
    cd "$SCANS_DIR"
else
    if [ ! -f "$TEMPLATE_FILE" ]; then
        log "Note: PDF attestation template not found at $TEMPLATE_FILE"
    elif [ -z "$PDFLATEX" ] || [ ! -x "$PDFLATEX" ]; then
        log "Note: pdflatex not found, skipping PDF attestation generation"
        log "      Install with: brew install basictex (macOS) or apt install texlive-latex-base (Linux)"
    fi
fi

log ""

if [ "$OVERALL_STATUS" = "PASS" ]; then
    exit 0
else
    exit 1
fi
