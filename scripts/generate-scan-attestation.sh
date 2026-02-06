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

set -eu

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

# Convert to absolute path (needed since we cd to build dir later)
SCANS_DIR="$(cd "$SCANS_DIR" && pwd)"

# Check for required environment variables
REQUIRED_VARS="TARGET_DIR FILE_TIMESTAMP TIMESTAMP DATE_STAMP INVENTORY_CHECKSUM TOOLKIT_VERSION TOOLKIT_COMMIT OVERALL_STATUS PASS_COUNT FAIL_COUNT"
for var in $REQUIRED_VARS; do
    if [ -z "${!var:-}" ]; then
        echo "Error: Required environment variable $var is not set" >&2
        exit 2
    fi
done

# Check for pdflatex
PDFLATEX=$(which pdflatex 2>/dev/null || echo "")
if [ -z "$PDFLATEX" ] || [ ! -x "$PDFLATEX" ]; then
    echo "Warning: pdflatex not found, PDF attestation generation skipped"
    echo "         Install with: brew install basictex (macOS) or apt install texlive-latex-base (Linux)"
    echo ""
    echo "Note: PDF generation is optional. Scan results are still valid without attestation."
    # Return exit code 2 for "skipped" (vs. 1 for "failed")
    # Allows caller to distinguish between failure and optional feature skipped
    exit 2
fi

# Check for template
TEMPLATE_FILE="$SECURITY_REPO_DIR/templates/scan_attestation.tex"
if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "Note: PDF attestation template not found at $TEMPLATE_FILE"
    exit 0
fi

# Function to escape LaTeX special characters
# Prevents LaTeX injection and ensures proper PDF generation
# Escapes: $ _ { } & % # \ ^ ~
escape_latex_chars() {
    local input="$1"
    # Order matters: backslash must be first to avoid double-escaping
    echo "$input" | \
        sed 's/\\/\\textbackslash{}/g' | \
        sed 's/\$/\\$/g' | \
        sed 's/_/\\_/g' | \
        sed 's/{/\\{/g' | \
        sed 's/}/\\}/g' | \
        sed 's/&/\\&/g' | \
        sed 's/%/\\%/g' | \
        sed 's/#/\\#/g' | \
        sed 's/\^/\\textasciicircum{}/g' | \
        sed 's/~/\\textasciitilde{}/g'
}

echo "Generating PDF attestation..."

# Delete previous attestation PDFs to avoid conflicts
rm -f "$SCANS_DIR"/scan-attestation-*.pdf 2>/dev/null

# Create temp directory for LaTeX build
PDF_BUILD_DIR=$(mktemp -d)

# Generate unique ID based on UTC timestamp (unique to the second)
UNIQUE_ID="SCAN-$(date -u +%Y%m%d-%H%M%S)"
FORMATTED_DATE=$(date "+%B %d, %Y")

# Get repo name from target dir
# For remote scans, TARGET_DIR is "hostname (remote)" with no path separator
# In that case, strip the "(remote)" or "(remote scan)" suffix to avoid duplication in the PDF
if [[ "$TARGET_DIR" != */* ]]; then
    # Remote scan: extract name without remote scan suffix
    REPO_NAME=$(echo "$TARGET_DIR" | sed -E 's/ *\(remote( scan)?\)$//')
else
    # Local scan: use basename of path
    REPO_NAME=$(basename "$TARGET_DIR")
fi

# Find the actual inventory file (could be host-inventory or remote-inventory)
INVENTORY_FILE=$(ls -t "$SCANS_DIR"/remote-inventory-*.txt "$SCANS_DIR"/host-inventory-*.txt 2>/dev/null | head -1)
if [ -n "$INVENTORY_FILE" ]; then
    INVENTORY_BASENAME=$(basename "$INVENTORY_FILE")
    INVENTORY_FILE_CHECKSUM=$(shasum -a 256 "$INVENTORY_FILE" 2>/dev/null | awk '{print $1}' || echo "N/A")
else
    INVENTORY_BASENAME="inventory-not-found.txt"
    INVENTORY_FILE_CHECKSUM="N/A"
fi

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
PII_ALLOWLIST_FILE="$TARGET_DIR/.allowlists/pii-allowlist"
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
SECRETS_ALLOWLIST_FILE="$TARGET_DIR/.allowlists/secrets-allowlist"
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
# All variables are escaped to prevent LaTeX injection
# Escape special characters in paths for sed
ESCAPED_TARGET_PATH=$(echo "$TARGET_DIR" | sed 's/[&/\]/\\&/g')

# Truncate inventory checksum for display (first 16 chars)
INVENTORY_CHECKSUM_SHORT="${INVENTORY_CHECKSUM:0:16}..."

# Escape all LaTeX variables to prevent injection
PII_RESULT_ESCAPED=$(escape_latex_chars "$PII_RESULT")
PII_FINDINGS_ESCAPED=$(escape_latex_chars "$PII_FINDINGS")
MALWARE_RESULT_ESCAPED=$(escape_latex_chars "$MALWARE_RESULT")
MALWARE_FINDINGS_ESCAPED=$(escape_latex_chars "$MALWARE_FINDINGS")
SECRETS_RESULT_ESCAPED=$(escape_latex_chars "$SECRETS_RESULT")
SECRETS_FINDINGS_ESCAPED=$(escape_latex_chars "$SECRETS_FINDINGS")
MAC_RESULT_ESCAPED=$(escape_latex_chars "$MAC_RESULT")
MAC_FINDINGS_ESCAPED=$(escape_latex_chars "$MAC_FINDINGS")
HOST_RESULT_ESCAPED=$(escape_latex_chars "$HOST_RESULT")
HOST_FINDINGS_ESCAPED=$(escape_latex_chars "$HOST_FINDINGS")
VULN_RESULT_ESCAPED=$(escape_latex_chars "$VULN_RESULT")
VULN_FINDINGS_ESCAPED=$(escape_latex_chars "$VULN_FINDINGS")
OVERALL_STATUS_ESCAPED=$(escape_latex_chars "$OVERALL_STATUS")
REPO_NAME_ESCAPED=$(escape_latex_chars "$REPO_NAME")
TOOLKIT_VERSION_ESCAPED=$(escape_latex_chars "$TOOLKIT_VERSION")
TOOLKIT_COMMIT_ESCAPED=$(escape_latex_chars "$TOOLKIT_COMMIT")
INVENTORY_CHECKSUM_SHORT_ESCAPED=$(escape_latex_chars "$INVENTORY_CHECKSUM_SHORT")
PII_ALLOWLIST_COUNT_ESCAPED=$(escape_latex_chars "$PII_ALLOWLIST_COUNT")
PII_ALLOWLIST_CHECKSUM_ESCAPED=$(escape_latex_chars "$PII_ALLOWLIST_CHECKSUM")
SECRETS_ALLOWLIST_COUNT_ESCAPED=$(escape_latex_chars "$SECRETS_ALLOWLIST_COUNT")
SECRETS_ALLOWLIST_CHECKSUM_ESCAPED=$(escape_latex_chars "$SECRETS_ALLOWLIST_CHECKSUM")
PII_SCAN_CHECKSUM_ESCAPED=$(escape_latex_chars "$PII_SCAN_CHECKSUM")
MALWARE_SCAN_CHECKSUM_ESCAPED=$(escape_latex_chars "$MALWARE_SCAN_CHECKSUM")
SECRETS_SCAN_CHECKSUM_ESCAPED=$(escape_latex_chars "$SECRETS_SCAN_CHECKSUM")
MAC_SCAN_CHECKSUM_ESCAPED=$(escape_latex_chars "$MAC_SCAN_CHECKSUM")
HOST_SECURITY_SCAN_CHECKSUM_ESCAPED=$(escape_latex_chars "$HOST_SECURITY_SCAN_CHECKSUM")
VULN_SCAN_CHECKSUM_ESCAPED=$(escape_latex_chars "$VULN_SCAN_CHECKSUM")
REPORT_CHECKSUM_ESCAPED=$(escape_latex_chars "$REPORT_CHECKSUM")
CHECKSUMS_MD_CHECKSUM_FULL_ESCAPED=$(escape_latex_chars "$CHECKSUMS_MD_CHECKSUM_FULL")
PASS_COUNT_ESCAPED=$(escape_latex_chars "$PASS_COUNT")
FAIL_COUNT_ESCAPED=$(escape_latex_chars "$FAIL_COUNT")
UNIQUE_ID_ESCAPED=$(escape_latex_chars "$UNIQUE_ID")
FORMATTED_DATE_ESCAPED=$(escape_latex_chars "$FORMATTED_DATE")
TIMESTAMP_ESCAPED=$(escape_latex_chars "$TIMESTAMP")
FILE_TIMESTAMP_ESCAPED=$(escape_latex_chars "$FILE_TIMESTAMP")
DATE_STAMP_ESCAPED=$(escape_latex_chars "$DATE_STAMP")
INVENTORY_BASENAME_ESCAPED=$(escape_latex_chars "$INVENTORY_BASENAME")
SCAN_SCOPE_ESCAPED=$(escape_latex_chars "${SCAN_SCOPE:-Local Scan}")

sed -i.bak \
    -e "s/SCAN-YYYY-NNN/$UNIQUE_ID_ESCAPED/g" \
    -e "s/January 15, 2026/$FORMATTED_DATE_ESCAPED/g" \
    -e "s/2026-01-15 08:00:00/$TIMESTAMP_ESCAPED/g" \
    -e "s/2026-01-15T000000Z/$FILE_TIMESTAMP_ESCAPED/g" \
    -e "s/2026-01-15/$DATE_STAMP_ESCAPED/g" \
    -e "s/ProjectName/$REPO_NAME_ESCAPED/g" \
    -e "s|/path/to/project|$ESCAPED_TARGET_PATH|g" \
    -e "s/Local Scan/$SCAN_SCOPE_ESCAPED/g" \
    -e "s/v1.0.0/$TOOLKIT_VERSION_ESCAPED/g" \
    -e "s/abc1234/$TOOLKIT_COMMIT_ESCAPED/g" \
    -e "s|PLACEHOLDER_HOSTNAME|$INVENTORY_CHECKSUM|g" \
    -e "s|0000000000000000000000000000000000000000000000000000000000000000|$INVENTORY_CHECKSUM_SHORT_ESCAPED|g" \
    -e "s/host-inventory-2026-01-15.txt/$INVENTORY_BASENAME_ESCAPED/g" \
    -e "s/\\\\newcommand{\\\\PIIScanResult}{PASS}/\\\\newcommand{\\\\PIIScanResult}{$PII_RESULT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\PIIScanFindings}{No PII detected}/\\\\newcommand{\\\\PIIScanFindings}{$PII_FINDINGS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\MalwareScanResult}{PASS}/\\\\newcommand{\\\\MalwareScanResult}{$MALWARE_RESULT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\MalwareScanFindings}{No malware detected}/\\\\newcommand{\\\\MalwareScanFindings}{$MALWARE_FINDINGS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\SecretsScanResult}{PASS}/\\\\newcommand{\\\\SecretsScanResult}{$SECRETS_RESULT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\SecretsScanFindings}{No secrets detected}/\\\\newcommand{\\\\SecretsScanFindings}{$SECRETS_FINDINGS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\MACScanResult}{PASS}/\\\\newcommand{\\\\MACScanResult}{$MAC_RESULT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\MACScanFindings}{No MAC addresses detected}/\\\\newcommand{\\\\MACScanFindings}{$MAC_FINDINGS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\HostSecurityResult}{PASS}/\\\\newcommand{\\\\HostSecurityResult}{$HOST_RESULT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\HostSecurityFindings}{All checks passed}/\\\\newcommand{\\\\HostSecurityFindings}{$HOST_FINDINGS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\VulnScanResult}{SKIP}/\\\\newcommand{\\\\VulnScanResult}{$VULN_RESULT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\VulnScanFindings}{Not run}/\\\\newcommand{\\\\VulnScanFindings}{$VULN_FINDINGS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\OverallResult}{PASS}/\\\\newcommand{\\\\OverallResult}{$OVERALL_STATUS_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\PassCount}{5}/\\\\newcommand{\\\\PassCount}{$PASS_COUNT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\FailCount}{0}/\\\\newcommand{\\\\FailCount}{$FAIL_COUNT_ESCAPED}/g" \
    -e "s/\\\\newcommand{\\\\PIIAllowlistCount}{0}/\\\\newcommand{\\\\PIIAllowlistCount}{$PII_ALLOWLIST_COUNT_ESCAPED}/g" \
    -e "s|\\\\newcommand{\\\\PIIAllowlistChecksum}{N/A}|\\\\newcommand{\\\\PIIAllowlistChecksum}{$PII_ALLOWLIST_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\SecretsAllowlistCount}{0}|\\\\newcommand{\\\\SecretsAllowlistCount}{$SECRETS_ALLOWLIST_COUNT_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\SecretsAllowlistChecksum}{N/A}|\\\\newcommand{\\\\SecretsAllowlistChecksum}{$SECRETS_ALLOWLIST_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\PIIScanChecksum}{N/A}|\\\\newcommand{\\\\PIIScanChecksum}{$PII_SCAN_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\MalwareScanChecksum}{N/A}|\\\\newcommand{\\\\MalwareScanChecksum}{$MALWARE_SCAN_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\SecretsScanChecksum}{N/A}|\\\\newcommand{\\\\SecretsScanChecksum}{$SECRETS_SCAN_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\MACScanChecksum}{N/A}|\\\\newcommand{\\\\MACScanChecksum}{$MAC_SCAN_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\HostSecurityScanChecksum}{N/A}|\\\\newcommand{\\\\HostSecurityScanChecksum}{$HOST_SECURITY_SCAN_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\VulnScanChecksum}{N/A}|\\\\newcommand{\\\\VulnScanChecksum}{$VULN_SCAN_CHECKSUM_ESCAPED}|g" \
    -e "s|\\\\newcommand{\\\\ReportChecksum}{N/A}|\\\\newcommand{\\\\ReportChecksum}{$REPORT_CHECKSUM_ESCAPED}|g" \
    -e "s/\\\\newcommand{\\\\ChecksumsMdChecksumFull}{CHECKSUMS_MD_FULL_PLACEHOLDER}/\\\\newcommand{\\\\ChecksumsMdChecksumFull}{$CHECKSUMS_MD_CHECKSUM_FULL_ESCAPED}/g" \
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

# ============================================================================
# APPENDIX GENERATION - Extract findings from scan files
# ============================================================================

# Function to escape text for LaTeX verbatim-like environments
escape_for_listing() {
    local input="$1"
    # Escape special characters for lstlisting
    echo "$input" | sed -e 's/\\/\\\\/g' -e 's/{/\\{/g' -e 's/}/\\}/g'
}

# Generate Appendix A: Open Ports (from nmap)
generate_ports_appendix() {
    local appendix_file="$PDF_BUILD_DIR/appendix_ports.tex"

    # Find nmap output file
    local nmap_file
    nmap_file=$(ls -t "$SCANS_DIR"/nmap-*.txt 2>/dev/null | head -1)

    if [ -z "$nmap_file" ] || [ ! -f "$nmap_file" ]; then
        printf '%s\n' '\textbf{No network scan data available}' > "$appendix_file"
        return
    fi

    local nmap_basename
    nmap_basename=$(basename "$nmap_file")

    {
        printf '\\subsection*{Source: \\texttt{%s}}\n' "$nmap_basename"
        printf '\n'
        printf '\\begin{lstlisting}[basicstyle=\\ttfamily\\small,breaklines=true]\n'

        # Extract open ports section with line numbers
        local line_num=0
        local in_ports=false
        while IFS= read -r line; do
            line_num=$((line_num + 1))
            # Look for port lines
            if [[ "$line" =~ ^[0-9]+/(tcp|udp) ]]; then
                printf "L%d: %s\n" "$line_num" "$line"
            elif [[ "$line" =~ "PORT" && "$line" =~ "STATE" ]]; then
                in_ports=true
                printf "L%d: %s\n" "$line_num" "$line"
            elif [[ "$line" =~ "Nmap scan report" ]]; then
                printf "L%d: %s\n" "$line_num" "$line"
            elif [[ "$line" =~ "Host is up" ]]; then
                printf "L%d: %s\n" "$line_num" "$line"
            fi
        done < "$nmap_file"

        printf '\\end{lstlisting}\n'
    } > "$appendix_file"
}

# Generate Appendix B: Security Configuration
generate_security_appendix() {
    local appendix_file="$PDF_BUILD_DIR/appendix_security.tex"

    # Find security check file
    local sec_file
    sec_file=$(ls -t "$SCANS_DIR"/remote-security-*.txt "$SCANS_DIR"/host-security-scan-*.txt 2>/dev/null | head -1)

    if [ -z "$sec_file" ] || [ ! -f "$sec_file" ]; then
        printf '%s\n' '\textbf{No security configuration data available}' > "$appendix_file"
        return
    fi

    local sec_basename
    sec_basename=$(basename "$sec_file")

    {
        printf '\\subsection*{Source: \\texttt{%s}}\n' "$sec_basename"
        printf '\n'
        printf '\\begin{lstlisting}[basicstyle=\\ttfamily\\small,breaklines=true]\n'

        # Extract key sections with line numbers
        local line_num=0
        while IFS= read -r line; do
            line_num=$((line_num + 1))
            # Include section headers and important findings
            if [[ "$line" =~ ^--- ]] || \
               [[ "$line" =~ LISTEN ]] || \
               [[ "$line" =~ "root:" ]] || \
               [[ "$line" =~ "/bin/bash" ]] || \
               [[ "$line" =~ "/bin/zsh" ]] || \
               [[ "$line" =~ "PermitRoot" ]] || \
               [[ "$line" =~ "Password" ]] || \
               [[ "$line" =~ "randomize" ]] || \
               [[ "$line" =~ "protect" ]]; then
                printf "L%d: %s\n" "$line_num" "$line"
            fi
        done < "$sec_file" | head -50

        printf '\\end{lstlisting}\n'
    } > "$appendix_file"
}

# Generate Appendix C: System Summary
generate_system_appendix() {
    local appendix_file="$PDF_BUILD_DIR/appendix_system.tex"

    # Find inventory file
    local inv_file
    inv_file=$(ls -t "$SCANS_DIR"/remote-inventory-*.txt "$SCANS_DIR"/host-inventory-*.txt 2>/dev/null | head -1)

    if [ -z "$inv_file" ] || [ ! -f "$inv_file" ]; then
        printf '%s\n' '\textbf{No system inventory data available}' > "$appendix_file"
        return
    fi

    local inv_basename
    inv_basename=$(basename "$inv_file")

    {
        printf '\\subsection*{Source: \\texttt{%s}}\n' "$inv_basename"
        printf '\n'
        printf '\\begin{lstlisting}[basicstyle=\\ttfamily\\small,breaklines=true]\n'

        # Extract key system info with line numbers
        local line_num=0
        local in_section=""
        while IFS= read -r line; do
            line_num=$((line_num + 1))
            # Include section headers and key info
            if [[ "$line" =~ ^--- ]]; then
                in_section="$line"
                printf "L%d: %s\n" "$line_num" "$line"
            elif [[ "$line" =~ "Linux " ]] || \
                 [[ "$line" =~ "Darwin " ]] || \
                 [[ "$line" =~ "PRETTY_NAME" ]] || \
                 [[ "$line" =~ "Model name" ]] || \
                 [[ "$line" =~ "CPU(s):" ]] || \
                 [[ "$line" =~ "Mem:" ]] || \
                 [[ "$line" =~ "/dev/" && "$line" =~ "%" ]] || \
                 [[ "$line" =~ "inet " ]]; then
                printf "L%d: %s\n" "$line_num" "$line"
            fi
        done < "$inv_file" | head -40

        printf '\\end{lstlisting}\n'
    } > "$appendix_file"
}

# Generate all appendices
generate_ports_appendix
generate_security_appendix
generate_system_appendix

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
