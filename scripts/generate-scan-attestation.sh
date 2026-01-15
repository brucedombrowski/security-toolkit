#!/bin/bash
#
# Scan Attestation PDF Generator
#
# Purpose: Generate PDF attestation document from scan results
# Usage: ./generate-scan-attestation.sh <scans_dir> [options]
#
# Required arguments:
#   scans_dir           Path to .scans directory containing scan results
#
# Required environment variables (set by run-all-scans.sh):
#   TARGET_DIR          Target directory that was scanned
#   FILE_TIMESTAMP      Timestamp for output files (YYYY-MM-DD-THHMMSSZ)
#   TIMESTAMP           Human-readable timestamp
#   DATE_STAMP          Date stamp (YYYY-MM-DD)
#   INVENTORY_CHECKSUM  SHA256 of host inventory file
#   TOOLKIT_VERSION     Version of security toolkit
#   TOOLKIT_COMMIT      Git commit hash of toolkit
#   PII_RESULT          PII scan result (PASS/FAIL/EXCEPT)
#   PII_FINDINGS        PII scan findings text
#   MALWARE_RESULT      Malware scan result
#   MALWARE_FINDINGS    Malware scan findings text
#   SECRETS_RESULT      Secrets scan result
#   SECRETS_FINDINGS    Secrets scan findings text
#   MAC_RESULT          MAC address scan result
#   MAC_FINDINGS        MAC address scan findings text
#   HOST_RESULT         Host security scan result
#   HOST_FINDINGS       Host security scan findings text
#   VULN_RESULT         Vulnerability scan result (PASS/FAIL/SKIP)
#   VULN_FINDINGS       Vulnerability scan findings text
#   OVERALL_STATUS      Overall scan status (PASS/FAIL)
#   PASS_COUNT          Number of passed scans
#   FAIL_COUNT          Number of failed scans
#
# Exit codes:
#   0 = PDF generated successfully
#   1 = PDF generation failed
#   2 = Missing dependencies or arguments
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <scans_dir>" >&2
    echo "  scans_dir: Path to .scans directory containing scan results" >&2
    exit 2
fi

SCANS_DIR="$1"

# Verify scans directory exists
if [ ! -d "$SCANS_DIR" ]; then
    echo "Error: Scans directory not found: $SCANS_DIR" >&2
    exit 2
fi

# Check for required environment variables
REQUIRED_VARS="TARGET_DIR FILE_TIMESTAMP TIMESTAMP DATE_STAMP INVENTORY_CHECKSUM TOOLKIT_VERSION TOOLKIT_COMMIT OVERALL_STATUS PASS_COUNT FAIL_COUNT"
for var in $REQUIRED_VARS; do
    if [ -z "${!var}" ]; then
        echo "Error: Required environment variable $var is not set" >&2
        exit 2
    fi
done

# Check for pdflatex
PDFLATEX=$(which pdflatex 2>/dev/null || echo "")
if [ -z "$PDFLATEX" ] || [ ! -x "$PDFLATEX" ]; then
    echo "Note: pdflatex not found, skipping PDF attestation generation"
    echo "      Install with: brew install basictex (macOS) or apt install texlive-latex-base (Linux)"
    exit 0
fi

# Check for template
TEMPLATE_FILE="$SECURITY_REPO_DIR/templates/scan_attestation.tex"
if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "Note: PDF attestation template not found at $TEMPLATE_FILE"
    exit 0
fi

echo "Generating PDF attestation..."

# Delete previous attestation PDFs to avoid conflicts
rm -f "$SCANS_DIR"/scan-attestation-*.pdf 2>/dev/null

# Create temp directory for LaTeX build
PDF_BUILD_DIR=$(mktemp -d)

# Generate unique ID based on UTC timestamp (unique to the second)
UNIQUE_ID="SCAN-$(date -u +%Y%m%d-%H%M%S)"
FORMATTED_DATE=$(date "+%B %d, %Y")

# Get repo name from target dir
REPO_NAME=$(basename "$TARGET_DIR")

# Calculate individual scan file checksums (first 16 chars)
PII_SCAN_CHECKSUM=$(shasum -a 256 "$SCANS_DIR/pii-scan-$FILE_TIMESTAMP.txt" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
MALWARE_SCAN_CHECKSUM=$(shasum -a 256 "$SCANS_DIR/malware-scan-$FILE_TIMESTAMP.txt" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
SECRETS_SCAN_CHECKSUM=$(shasum -a 256 "$SCANS_DIR/secrets-scan-$FILE_TIMESTAMP.txt" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
MAC_SCAN_CHECKSUM=$(shasum -a 256 "$SCANS_DIR/mac-address-scan-$FILE_TIMESTAMP.txt" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
HOST_SECURITY_SCAN_CHECKSUM=$(shasum -a 256 "$SCANS_DIR/host-security-scan-$FILE_TIMESTAMP.txt" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
# Vuln scan file may have different timestamp format - find most recent
VULN_SCAN_FILE=$(ls -t "$SCANS_DIR"/vulnerability-scan-*.txt 2>/dev/null | head -1)
VULN_SCAN_CHECKSUM=$(shasum -a 256 "$VULN_SCAN_FILE" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
REPORT_CHECKSUM=$(shasum -a 256 "$SCANS_DIR/security-scan-report-$FILE_TIMESTAMP.txt" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
# Full checksums.md checksum for verification chain
CHECKSUMS_MD_CHECKSUM_FULL=$(shasum -a 256 "$SCANS_DIR/checksums.md" 2>/dev/null | awk '{print $1}' || echo "N/A")

# Extract PII allowlist count and checksum
PII_ALLOWLIST_FILE="$TARGET_DIR/.pii-allowlist"
PII_ALLOWLIST_COUNT=0
PII_ALLOWLIST_CHECKSUM="N/A"
if [ -f "$PII_ALLOWLIST_FILE" ]; then
    PII_ALLOWLIST_COUNT=$(grep -c "^[a-f0-9]" "$PII_ALLOWLIST_FILE" 2>/dev/null || echo "0")
    PII_ALLOWLIST_CHECKSUM=$(shasum -a 256 "$PII_ALLOWLIST_FILE" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
    # Mark PII scan as EXCEPT (pass with exceptions) if there are reviewed exceptions
    if [ "$PII_ALLOWLIST_COUNT" -gt 0 ]; then
        PII_RESULT="EXCEPT"
        PII_FINDINGS="$PII_ALLOWLIST_COUNT reviewed exceptions"
    fi
fi

# Extract secrets allowlist count and checksum
SECRETS_ALLOWLIST_FILE="$TARGET_DIR/.secrets-allowlist"
SECRETS_ALLOWLIST_COUNT=0
SECRETS_ALLOWLIST_CHECKSUM="N/A"
if [ -f "$SECRETS_ALLOWLIST_FILE" ]; then
    SECRETS_ALLOWLIST_COUNT=$(grep -c "^[a-f0-9]" "$SECRETS_ALLOWLIST_FILE" 2>/dev/null || echo "0")
    SECRETS_ALLOWLIST_CHECKSUM=$(shasum -a 256 "$SECRETS_ALLOWLIST_FILE" 2>/dev/null | awk '{print substr($1,1,16)}' || echo "N/A")
    # Mark secrets scan as EXCEPT if there are reviewed exceptions
    if [ "$SECRETS_ALLOWLIST_COUNT" -gt 0 ]; then
        SECRETS_RESULT="EXCEPT"
        SECRETS_FINDINGS="$SECRETS_ALLOWLIST_COUNT reviewed exceptions"
    fi
fi

# Set default vulnerability scan result if not provided
VULN_RESULT="${VULN_RESULT:-SKIP}"
VULN_FINDINGS="${VULN_FINDINGS:-Not run}"

# Recalculate pass/fail counts after applying EXCEPT status
# EXCEPT counts as PASS for the summary (reviewed and accepted)
# SKIP doesn't count towards pass/fail totals
PASS_COUNT=0
FAIL_COUNT=0
for result in "$PII_RESULT" "$MALWARE_RESULT" "$SECRETS_RESULT" "$MAC_RESULT" "$HOST_RESULT" "$VULN_RESULT"; do
    case "$result" in
        PASS|EXCEPT) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) ;; # Don't count SKIP towards totals
    esac
done

# Update overall status based on recalculated counts
if [ "$FAIL_COUNT" -eq 0 ]; then
    OVERALL_STATUS="PASS"
else
    OVERALL_STATUS="FAIL"
fi

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
    -e "s/2026-01-15T000000Z/$FILE_TIMESTAMP/g" \
    -e "s/2026-01-15/$DATE_STAMP/g" \
    -e "s/ProjectName/$REPO_NAME/g" \
    -e "s|/path/to/project|$ESCAPED_TARGET_PATH|g" \
    -e "s/v1.0.0/$TOOLKIT_VERSION/g" \
    -e "s/abc1234/$TOOLKIT_COMMIT/g" \
    -e "s/PLACEHOLDER_HOSTNAME/$INVENTORY_CHECKSUM/g" \
    -e "s/0000000000000000000000000000000000000000000000000000000000000000/$INVENTORY_CHECKSUM_SHORT/g" \
    -e "s/host-inventory-2026-01-15.txt/host-inventory-$FILE_TIMESTAMP.txt/g" \
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
    -e "s/\\\\newcommand{\\\\VulnScanResult}{SKIP}/\\\\newcommand{\\\\VulnScanResult}{$VULN_RESULT}/g" \
    -e "s/\\\\newcommand{\\\\VulnScanFindings}{Not run}/\\\\newcommand{\\\\VulnScanFindings}{$VULN_FINDINGS}/g" \
    -e "s/\\\\newcommand{\\\\OverallResult}{PASS}/\\\\newcommand{\\\\OverallResult}{$OVERALL_STATUS}/g" \
    -e "s/\\\\newcommand{\\\\PassCount}{5}/\\\\newcommand{\\\\PassCount}{$PASS_COUNT}/g" \
    -e "s/\\\\newcommand{\\\\FailCount}{0}/\\\\newcommand{\\\\FailCount}{$FAIL_COUNT}/g" \
    -e "s/\\\\newcommand{\\\\PIIAllowlistCount}{0}/\\\\newcommand{\\\\PIIAllowlistCount}{$PII_ALLOWLIST_COUNT}/g" \
    -e "s/\\\\newcommand{\\\\PIIAllowlistChecksum}{N\\/A}/\\\\newcommand{\\\\PIIAllowlistChecksum}{$PII_ALLOWLIST_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\SecretsAllowlistCount}{0}/\\\\newcommand{\\\\SecretsAllowlistCount}{$SECRETS_ALLOWLIST_COUNT}/g" \
    -e "s/\\\\newcommand{\\\\SecretsAllowlistChecksum}{N\\/A}/\\\\newcommand{\\\\SecretsAllowlistChecksum}{$SECRETS_ALLOWLIST_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\PIIScanChecksum}{N\\/A}/\\\\newcommand{\\\\PIIScanChecksum}{$PII_SCAN_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\MalwareScanChecksum}{N\\/A}/\\\\newcommand{\\\\MalwareScanChecksum}{$MALWARE_SCAN_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\SecretsScanChecksum}{N\\/A}/\\\\newcommand{\\\\SecretsScanChecksum}{$SECRETS_SCAN_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\MACScanChecksum}{N\\/A}/\\\\newcommand{\\\\MACScanChecksum}{$MAC_SCAN_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\HostSecurityScanChecksum}{N\\/A}/\\\\newcommand{\\\\HostSecurityScanChecksum}{$HOST_SECURITY_SCAN_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\VulnScanChecksum}{N\\/A}/\\\\newcommand{\\\\VulnScanChecksum}{$VULN_SCAN_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\ReportChecksum}{N\\/A}/\\\\newcommand{\\\\ReportChecksum}{$REPORT_CHECKSUM}/g" \
    -e "s/\\\\newcommand{\\\\ChecksumsMdChecksumFull}{CHECKSUMS_MD_FULL_PLACEHOLDER}/\\\\newcommand{\\\\ChecksumsMdChecksumFull}{$CHECKSUMS_MD_CHECKSUM_FULL}/g" \
    "$PDF_BUILD_DIR/scan_attestation.tex"

# Function to build allowlist entries for LaTeX (output to file for \input)
# Note: Last row must NOT have trailing \\ before \bottomrule
build_allowlist_entries() {
    local allowlist_file="$1"
    local entries_file="$2"

    : > "$entries_file"  # Clear/create file

    # Collect all entries first
    local entries=()
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            # Extract reason (format: HASH # REASON # CONTENT_SNIPPET)
            reason=$(echo "$line" | sed 's/^[a-f0-9]* # \([^#]*\) #.*/\1/')
            if [ -n "$reason" ]; then
                # Escape LaTeX special characters: $ _ { } & % #
                reason=$(echo "$reason" | sed -e 's/\$/\\$/g' \
                                              -e 's/_/\\_/g' \
                                              -e 's/{/\\{/g' \
                                              -e 's/}/\\}/g' \
                                              -e 's/&/\\&/g' \
                                              -e 's/%/\\%/g' \
                                              -e 's/#/\\#/g')
                entries+=("$reason")
            fi
        fi
    done < <(grep "^[a-f0-9]" "$allowlist_file" 2>/dev/null | head -20)

    # Write entries with proper row separators
    local total=${#entries[@]}
    if [ "$total" -eq 0 ]; then
        # No entries - use spanning cell
        printf '\\multicolumn{2}{c}{None}' > "$entries_file"
    else
        for i in "${!entries[@]}"; do
            local num=$((i + 1))
            if [ "$num" -lt "$total" ]; then
                printf '%d & %s \\\\\n' "$num" "${entries[$i]}" >> "$entries_file"
            else
                # Last entry - no trailing \\
                printf '%d & %s' "$num" "${entries[$i]}" >> "$entries_file"
            fi
        done
    fi
}

# Create PII allowlist entries file (always create, even if empty for \input)
if [ "$PII_ALLOWLIST_COUNT" -gt 0 ]; then
    build_allowlist_entries "$PII_ALLOWLIST_FILE" "$PDF_BUILD_DIR/pii_entries.tex"
else
    printf '\\multicolumn{2}{c}{None}' > "$PDF_BUILD_DIR/pii_entries.tex"
fi

# Create Secrets allowlist entries file
if [ "$SECRETS_ALLOWLIST_COUNT" -gt 0 ]; then
    build_allowlist_entries "$SECRETS_ALLOWLIST_FILE" "$PDF_BUILD_DIR/secrets_entries.tex"
else
    printf '\\multicolumn{2}{c}{None}' > "$PDF_BUILD_DIR/secrets_entries.tex"
fi

# Run pdflatex (twice for references)
cd "$PDF_BUILD_DIR"
PDFLATEX_LOG="$PDF_BUILD_DIR/pdflatex.log"

# Run pdflatex twice (for cross-references)
# Don't rely on exit code - pdflatex returns non-zero for warnings too
$PDFLATEX -interaction=nonstopmode scan_attestation.tex > "$PDFLATEX_LOG" 2>&1 || true
$PDFLATEX -interaction=nonstopmode scan_attestation.tex > /dev/null 2>&1 || true

# Check if PDF was generated (regardless of exit code)
EXIT_CODE=0
if [ -f "scan_attestation.pdf" ]; then
    cp "scan_attestation.pdf" "$SCANS_DIR/scan-attestation-$FILE_TIMESTAMP.pdf"
    echo "  scan-attestation-$FILE_TIMESTAMP.pdf"
else
    echo "  PDF generation failed"
    echo ""
    echo "  pdflatex output:"
    # Show last 20 lines of error log (where the actual error usually is)
    if [ -f "$PDFLATEX_LOG" ]; then
        tail -20 "$PDFLATEX_LOG" | while read -r line; do
            echo "    $line"
        done
    fi
    # Also check the .log file pdflatex generates
    if [ -f "scan_attestation.log" ]; then
        echo ""
        echo "  LaTeX errors from scan_attestation.log:"
        grep -E "^!" "scan_attestation.log" | head -5 | while read -r line; do
            echo "    $line"
        done
    fi
    EXIT_CODE=1
fi

# Cleanup
rm -rf "$PDF_BUILD_DIR"

exit $EXIT_CODE
