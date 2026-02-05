#!/bin/bash
#
# Vulnerability Scan Attestation PDF Generator
#
# Purpose: Generate PDF attestation from vulnerability scan results
# Supports: Lynis (extensible to other scanners)
#
# Usage: ./generate-vuln-attestation.sh <scans_dir> [scan_file]
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
if [ -z "${1:-}" ]; then
    echo "Usage: $0 <scans_dir> [scan_file]" >&2
    exit 2
fi

SCANS_DIR="$1"
SCAN_FILE="${2:-}"

# Verify scans directory
if [ ! -d "$SCANS_DIR" ]; then
    echo "Error: Scans directory not found: $SCANS_DIR" >&2
    exit 2
fi

SCANS_DIR="$(cd "$SCANS_DIR" && pwd)"

# Find vulnerability scan file (Lynis for now)
if [ -z "$SCAN_FILE" ]; then
    SCAN_FILE=$(ls -t "$SCANS_DIR"/lynis-*.txt "$SCANS_DIR"/remote-lynis-*.txt 2>/dev/null | head -1)
fi

if [ -z "$SCAN_FILE" ] || [ ! -f "$SCAN_FILE" ]; then
    echo "Error: No vulnerability scan file found in $SCANS_DIR" >&2
    exit 2
fi

# Find companion .dat file (machine-readable report)
DAT_FILE=$(ls -t "$SCANS_DIR"/lynis-*-report.dat 2>/dev/null | head -1)
if [ -z "$DAT_FILE" ] || [ ! -f "$DAT_FILE" ]; then
    DAT_FILE=""
elif [ ! -r "$DAT_FILE" ]; then
    echo "  Note: .dat file exists but not readable (owned by root)"
    DAT_FILE=""
fi

echo "Generating Lynis vulnerability attestation PDF..."
echo "  Source: $(basename "$SCAN_FILE")"

# Check for pdflatex
PDFLATEX=$(which pdflatex 2>/dev/null || echo "")
if [ -z "$PDFLATEX" ] || [ ! -x "$PDFLATEX" ]; then
    echo "Warning: pdflatex not found, PDF generation skipped"
    exit 2
fi

# Check for template
TEMPLATE_FILE="$SECURITY_REPO_DIR/templates/vuln_attestation.tex"
if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "Error: Template not found at $TEMPLATE_FILE" >&2
    exit 1
fi

# Function to escape LaTeX special characters
escape_latex_chars() {
    local input="$1"
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

# ============================================================================
# DETECT SCANNER TYPE
# ============================================================================
SCANNER_NAME="Unknown"
SOURCE_FILE_BASENAME=$(basename "$SCAN_FILE")

if [[ "$SOURCE_FILE_BASENAME" == *lynis* ]]; then
    SCANNER_NAME="Lynis"
fi

# ============================================================================
# PARSE SCAN OUTPUT (Lynis-specific)
# ============================================================================

SOURCE_FILE_CHECKSUM=$(shasum -a 256 "$SCAN_FILE" 2>/dev/null | awk '{print $1}')

# Create a clean version of the file without ANSI codes for parsing
CLEAN_SCAN=$(sed 's/\x1b\[[0-9;]*m//g' "$SCAN_FILE")

# Extract timestamp - use current time since Lynis doesn't embed timestamp
SCAN_TIMESTAMP=$(date -u "+%Y-%m-%d %H:%M:%S UTC")

# Extract Lynis version
SCANNER_VERSION=$(echo "$CLEAN_SCAN" | grep -E "Lynis [0-9]" | tail -1 | sed -E 's/.*Lynis ([0-9.]+).*/\1/' || echo "Unknown")

# Extract scan mode - Lynis uses "quick" or "normal"
if echo "$CLEAN_SCAN" | grep -q "\-\-quick\|quick mode" 2>/dev/null; then
    SCAN_MODE="quick"
else
    SCAN_MODE="normal"
fi

# Determine local vs remote - Lynis scans the whole system
if [[ "$SOURCE_FILE_BASENAME" == remote-* ]]; then
    IS_REMOTE=true
    SCAN_TARGET="(remote) system root"
else
    IS_REMOTE=false
    SCAN_TARGET="(local) system root"
fi

# ============================================================================
# EXTRACT DATA (prefer .dat file if available, fallback to .txt parsing)
# ============================================================================

if [ -n "$DAT_FILE" ] && [ -f "$DAT_FILE" ]; then
    echo "  Using machine-readable report: $(basename "$DAT_FILE")"

    # Extract from .dat file (more reliable)
    HARDENING_INDEX=$(grep "^hardening_index=" "$DAT_FILE" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]')
    # grep -c exits with 1 when count is 0, so use || true to prevent set -e from killing script
    WARNINGS_COUNT=$(grep -c "^warning\[\]=" "$DAT_FILE" 2>/dev/null || true)
    SUGGESTIONS_COUNT=$(grep -c "^suggestion\[\]=" "$DAT_FILE" 2>/dev/null || true)
    # tests_executed contains test IDs, not count - count the pipe-separated values
    TESTS_LINE=$(grep "^tests_executed=" "$DAT_FILE" 2>/dev/null | head -1 | cut -d= -f2)
    if [ -n "$TESTS_LINE" ]; then
        TESTS_PERFORMED=$(echo "$TESTS_LINE" | tr '|' '\n' | grep -c . 2>/dev/null)
    else
        TESTS_PERFORMED="0"
    fi
    PLUGINS_ENABLED=$(grep "^plugins_enabled=" "$DAT_FILE" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]')
    SCANNER_VERSION=$(grep "^lynis_version=" "$DAT_FILE" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]')

    # Extract scan timestamp from .dat
    DAT_TIMESTAMP=$(grep "^report_datetime_start=" "$DAT_FILE" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$DAT_TIMESTAMP" ] && SCAN_TIMESTAMP="$DAT_TIMESTAMP UTC"
else
    # Fallback to parsing .txt file
    echo "  Parsing from text output (no .dat file found)"

    # Extract hardening index (handle format: "Hardening index : 75 [###...")
    HARDENING_INDEX=$(echo "$CLEAN_SCAN" | grep -E "Hardening index" | head -1 | sed -E 's/.*: *([0-9]+).*/\1/' | tr -d '[:space:]' || echo "0")

    # Extract warnings count - count actual [ WARNING ] occurrences
    WARNINGS_COUNT=$(echo "$CLEAN_SCAN" | grep -c "\[ WARNING \]" 2>/dev/null || echo "0")

    # Extract suggestions count - Lynis format: "Suggestions (N):" or count [ SUGGESTION ]
    SUGGESTIONS_COUNT=$(echo "$CLEAN_SCAN" | grep -E "Suggestions \([0-9]+\)" | head -1 | sed -E 's/.*Suggestions \(([0-9]+)\).*/\1/' | tr -d '[:space:]')
    if [ -z "$SUGGESTIONS_COUNT" ]; then
        SUGGESTIONS_COUNT=$(echo "$CLEAN_SCAN" | grep -c "\[ SUGGESTION \]" 2>/dev/null || echo "0")
    fi

    # Extract tests performed
    TESTS_PERFORMED=$(echo "$CLEAN_SCAN" | grep -E "Tests performed" | head -1 | sed -E 's/.*: *([0-9]+).*/\1/' | tr -d '[:space:]' || echo "0")

    # Extract plugins
    PLUGINS_ENABLED=$(echo "$CLEAN_SCAN" | grep -E "Plugins enabled" | head -1 | sed -E 's/.*: *([0-9]+).*/\1/' | tr -d '[:space:]' || echo "0")
fi

# Ensure defaults
[ -z "$HARDENING_INDEX" ] && HARDENING_INDEX="0"
[ -z "$WARNINGS_COUNT" ] && WARNINGS_COUNT="0"
[ -z "$SUGGESTIONS_COUNT" ] && SUGGESTIONS_COUNT="0"
[ -z "$TESTS_PERFORMED" ] && TESTS_PERFORMED="0"
[ -z "$PLUGINS_ENABLED" ] && PLUGINS_ENABLED="0"

# Determine result based on hardening index (75+ = PASS)
if [ "$HARDENING_INDEX" -ge 75 ] 2>/dev/null; then
    SCAN_RESULT="PASS"
elif [ "$WARNINGS_COUNT" = "0" ]; then
    SCAN_RESULT="PASS"
else
    SCAN_RESULT="FAIL"
fi

# ============================================================================
# MACHINE IDENTIFICATION
# ============================================================================

# Sets global variables: MACHINE_FINGERPRINT, FINGERPRINT_INTERFACE, FINGERPRINT_METHOD
generate_machine_fingerprint() {
    local mac=""
    local interface=""
    local hostname=$(hostname 2>/dev/null || echo "unknown")

    case "$(uname -s)" in
        Darwin)
            # macOS: try en0 first, then any active interface
            if ifconfig en0 &>/dev/null; then
                mac=$(ifconfig en0 2>/dev/null | grep ether | awk '{print $2}')
                if [ -n "$mac" ]; then
                    interface="en0"
                fi
            fi
            if [ -z "$mac" ]; then
                for iface in $(ifconfig -l 2>/dev/null); do
                    if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
                        mac=$(ifconfig "$iface" 2>/dev/null | grep ether | awk '{print $2}')
                        if [ -n "$mac" ]; then
                            interface="$iface"
                            break
                        fi
                    fi
                done
            fi
            ;;
        Linux)
            interface=$(ip link show 2>/dev/null | grep "state UP" | head -1 | awk -F: '{print $2}' | tr -d ' ')
            if [ -n "$interface" ]; then
                mac=$(ip link show "$interface" 2>/dev/null | grep link/ether | awk '{print $2}')
            fi
            if [ -z "$mac" ]; then
                mac=$(ifconfig 2>/dev/null | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
                interface="unknown"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            if command -v getmac &>/dev/null; then
                local getmac_line=$(getmac /fo csv /nh 2>/dev/null | head -1)
                mac=$(echo "$getmac_line" | cut -d',' -f1 | tr -d '"')
                interface=$(echo "$getmac_line" | cut -d',' -f3 | tr -d '"' | sed 's/\\Device\\Tcpip_//')
            fi
            ;;
    esac

    if [ -n "$mac" ]; then
        MACHINE_FINGERPRINT=$(echo -n "${mac}:${hostname}" | shasum -a 256 | awk '{print substr($1,1,16)}')
        FINGERPRINT_INTERFACE="${interface:-unknown}"
        FINGERPRINT_METHOD="SHA256(MAC[$FINGERPRINT_INTERFACE]:hostname)[0:16]"
    else
        MACHINE_FINGERPRINT=$(echo -n "${hostname}:$(uname -s)" | shasum -a 256 | awk '{print substr($1,1,16)}')
        FINGERPRINT_INTERFACE="none"
        FINGERPRINT_METHOD="SHA256(hostname:os)[0:16]"
    fi
}

generate_machine_fingerprint
SCAN_MACHINE_ID="$MACHINE_FINGERPRINT"
SCAN_MACHINE_ID_TYPE="Fingerprint"
SCAN_MACHINE_ID_METHOD="$FINGERPRINT_METHOD"

if [ "$IS_REMOTE" = true ]; then
    REMOTE_INVENTORY=$(ls -t "$SCANS_DIR"/remote-inventory-*.txt 2>/dev/null | head -1)
    if [ -n "$REMOTE_INVENTORY" ] && [ -f "$REMOTE_INVENTORY" ]; then
        TARGET_INVENTORY_FILE=$(basename "$REMOTE_INVENTORY")
        TARGET_MACHINE_ID=$(shasum -a 256 "$REMOTE_INVENTORY" 2>/dev/null | awk '{print substr($1,1,16)}')
        TARGET_MACHINE_ID_TYPE="Inventory Hash"
        TARGET_MACHINE_ID_METHOD="SHA256(inventory)[0:16]"
    else
        TARGET_MACHINE_ID=$(echo -n "remote" | shasum -a 256 | awk '{print substr($1,1,16)}')
        TARGET_MACHINE_ID_TYPE="Host Hash"
        TARGET_MACHINE_ID_METHOD="SHA256(hostname)[0:16]"
        TARGET_INVENTORY_FILE="N/A"
    fi
else
    TARGET_MACHINE_ID="$SCAN_MACHINE_ID"
    TARGET_MACHINE_ID_TYPE="$SCAN_MACHINE_ID_TYPE (same as scan machine)"
    TARGET_MACHINE_ID_METHOD="$SCAN_MACHINE_ID_METHOD"
    LOCAL_INVENTORY=$(ls -t "$SCANS_DIR"/host-inventory-*.txt 2>/dev/null | head -1)
    if [ -n "$LOCAL_INVENTORY" ] && [ -f "$LOCAL_INVENTORY" ]; then
        TARGET_INVENTORY_FILE=$(basename "$LOCAL_INVENTORY")
    else
        TARGET_INVENTORY_FILE="N/A"
    fi
fi

# ============================================================================
# EXTRACT TOOLKIT INFO
# ============================================================================
# Get from environment or detect from git
if [ -z "${TOOLKIT_VERSION:-}" ] || [ "$TOOLKIT_VERSION" = "Unknown" ]; then
    TOOLKIT_VERSION=$(git -C "$SECURITY_REPO_DIR" describe --tags --always 2>/dev/null || echo "Unknown")
fi
if [ -z "${TOOLKIT_COMMIT:-}" ] || [ "$TOOLKIT_COMMIT" = "Unknown" ]; then
    TOOLKIT_COMMIT=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "Unknown")
fi

# ============================================================================
# GENERATE FINDINGS FILES
# ============================================================================
PDF_BUILD_DIR=$(mktemp -d)
KEY_FINDINGS_TEX="$PDF_BUILD_DIR/vuln_key_findings.tex"
FINDINGS_TEX="$PDF_BUILD_DIR/vuln_findings.tex"

# Use clean version without ANSI codes
CLEAN_FILE=$(mktemp)
sed 's/\x1b\[[0-9;]*m//g' "$SCAN_FILE" > "$CLEAN_FILE"

# Function to convert Lynis status to LaTeX colored command
colorize_lynis_line() {
    local line="$1"
    # Escape LaTeX special chars first (except backslash which we add)
    line=$(echo "$line" | sed 's/\$/\\$/g; s/_/\\_/g; s/{/\\{/g; s/}/\\}/g; s/&/\\&/g; s/%/\\%/g; s/#/\\#/g')
    # Replace status tags with colored LaTeX commands
    line=$(echo "$line" | sed \
        -e 's/\[ OK \]/\\lynisOK{}/g' \
        -e 's/\[ DONE \]/\\lynisDONE{}/g' \
        -e 's/\[ FOUND \]/\\lynisFOUND{}/g' \
        -e 's/\[ WARNING \]/\\lynisWARNING{}/g' \
        -e 's/\[ SUGGESTION \]/\\lynisSUGGESTION{}/g' \
        -e 's/\[ NOT FOUND \]/\\lynisNOTFOUND{}/g' \
        -e 's/\[ NONE \]/\\lynisNONE{}/g' \
        -e 's/\[ UNKNOWN \]/\\lynisUNKNOWN{}/g' \
        -e 's/\[ SKIPPED \]/\\lynisSKIPPED{}/g' \
        -e 's/\[ WEAK \]/\\textcolor{lynisyellow}{[ WEAK ]}/g' \
        -e 's/\[ DIFFERENT \]/\\textcolor{lynisyellow}{[ DIFFERENT ]}/g' \
        -e 's/\[ UNSAFE \]/\\textcolor{lynisred}{[ UNSAFE ]}/g' \
        -e 's/\[ DISABLED \]/\\textcolor{codegray}{[ DISABLED ]}/g' \
        -e 's/\[ ENABLED \]/\\textcolor{lynisgreen}{[ ENABLED ]}/g' \
        -e 's/\[ ACTIVE \]/\\textcolor{lynisgreen}{[ ACTIVE ]}/g' \
        -e 's/\[ NOT ACTIVE \]/\\textcolor{lynisred}{[ NOT ACTIVE ]}/g' \
        -e 's/\[ NOT RUNNING \]/\\textcolor{lynisred}{[ NOT RUNNING ]}/g' \
        -e 's/\[ RUNNING \]/\\textcolor{lynisgreen}{[ RUNNING ]}/g' \
    )
    # Clean up terminal escape artifacts
    line=$(echo "$line" | sed 's/\[2C//g; s/\[4C//g; s/\[8C//g; s/\[10C//g; s/\[[0-9]*C//g')
    echo "$line"
}

# =========================================================================
# FINDINGS (for main document - use ANSI color codes to identify)
# Red (ANSI 31) = actual findings (WARNING, ERROR, FAIL)
# Include section headings for context, numbered for easy reference
# =========================================================================

# Process findings into a temp file, tracking state with markers
FINDINGS_TEMP=$(mktemp)
CLEANED_SCAN=$(mktemp)
sed 's/\[2C//g; s/\[4C//g; s/\[8C//g; s/\[10C//g; s/\[[0-9]*C//g' "$SCAN_FILE" > "$CLEANED_SCAN"

{
    echo '\begin{itemize}[leftmargin=0.3in, itemsep=6pt]'

    current_section=""
    last_printed_section=""
    in_enumerate="no"
    finding_count=0

    while IFS= read -r raw_line; do
        # Check if this is a section heading [+]
        if echo "$raw_line" | grep -q '^\[+\]'; then
            current_section=$(echo "$raw_line" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^\[+\] *//')
            continue
        fi

        # Check if this line has a RED ANSI code (finding)
        if echo "$raw_line" | grep -qE '\x1b\[(1;)?31m'; then
            clean_text=$(echo "$raw_line" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^[[:space:]]*//')

            # Skip startup/banner text that happens to be red
            case "$clean_text" in
                Initializing*|Lynis*|Copyright*|Website*|Enterprise*|">"*|"="*|"----"*|Program*|" "*|"")
                    continue
                    ;;
            esac

            # Skip very short lines
            if [ ${#clean_text} -lt 5 ]; then
                continue
            fi

            # New section? Close previous enumerate and start new one
            if [ -n "$current_section" ] && [ "$current_section" != "$last_printed_section" ]; then
                if [ "$in_enumerate" = "yes" ]; then
                    echo '\end{enumerate}'
                fi
                echo "\\item \\textbf{$current_section}"
                echo '\\begin{enumerate}[leftmargin=0.2in, itemsep=1pt, label=\\arabic*.]'
                in_enumerate="yes"
                last_printed_section="$current_section"
            fi

            # Output the finding
            clean_line=$(echo "$clean_text" | cut -c1-90)
            colorized=$(colorize_lynis_line "$clean_line")
            echo "\\item \\small $colorized"
            finding_count=$((finding_count + 1))

            if [ $finding_count -ge 100 ]; then
                break
            fi
        fi
    done < "$CLEANED_SCAN"

    # Close final enumerate if open
    if [ "$in_enumerate" = "yes" ]; then
        echo '\end{enumerate}'
    fi

    echo '\end{itemize}'
    echo ''
    echo '{\small\textit{Total: \WarningsCount{} warnings, \SuggestionsCount{} suggestions}}'

} > "$KEY_FINDINGS_TEX"

rm -f "$FINDINGS_TEMP" "$CLEANED_SCAN"

# =========================================================================
# FULL OUTPUT (for appendix - complete colorized scan)
# =========================================================================
{
    echo '{\scriptsize'
    echo '\begin{flushleft}'

    # Process the ENTIRE scan file - no truncation
    while IFS= read -r line; do
        # Skip empty lines or just add spacing
        if [ -z "$line" ]; then
            echo '\\'
            continue
        fi
        # Clean terminal artifacts
        line=$(echo "$line" | sed 's/\[2C//g; s/\[4C//g; s/\[8C//g; s/\[10C//g; s/\[[0-9]*C//g')
        # Truncate very long lines for PDF width
        line=$(echo "$line" | cut -c1-95)
        # Colorize and output
        colorized=$(colorize_lynis_line "$line")
        echo "\\texttt{$colorized}\\\\"
    done < "$CLEAN_FILE"

    echo '\end{flushleft}'
    echo '}'

} > "$FINDINGS_TEX"

rm -f "$CLEAN_FILE"

# ============================================================================
# BUILD PDF
# ============================================================================

UNIQUE_ID="VULN-$(date -u +%Y%m%d-%H%M%S)"
FORMATTED_DATE=$(date "+%B %d, %Y")
# Use full timestamp for file naming
FILE_TIMESTAMP=$(date -u "+%Y-%m-%dT%H%M%SZ")

cp "$TEMPLATE_FILE" "$PDF_BUILD_DIR/vuln_attestation.tex"

if [ -f "$SECURITY_REPO_DIR/templates/logo.png" ]; then
    cp "$SECURITY_REPO_DIR/templates/logo.png" "$PDF_BUILD_DIR/"
fi

# Key findings and full findings are already in PDF_BUILD_DIR from earlier

# Escape variables
UNIQUE_ID_ESC=$(escape_latex_chars "$UNIQUE_ID")
FORMATTED_DATE_ESC=$(escape_latex_chars "$FORMATTED_DATE")
SCAN_TIMESTAMP_ESC=$(escape_latex_chars "$SCAN_TIMESTAMP")
SCANNER_NAME_ESC=$(escape_latex_chars "$SCANNER_NAME")
SCANNER_VERSION_ESC=$(escape_latex_chars "$SCANNER_VERSION")
SCAN_MODE_ESC=$(escape_latex_chars "$SCAN_MODE")
SCAN_TARGET_ESC=$(escape_latex_chars "$SCAN_TARGET")
TOOLKIT_VERSION_ESC=$(escape_latex_chars "$TOOLKIT_VERSION")
TOOLKIT_COMMIT_ESC=$(escape_latex_chars "$TOOLKIT_COMMIT")
SCAN_RESULT_ESC=$(escape_latex_chars "$SCAN_RESULT")
HARDENING_INDEX_ESC=$(escape_latex_chars "$HARDENING_INDEX")
WARNINGS_COUNT_ESC=$(escape_latex_chars "$WARNINGS_COUNT")
SUGGESTIONS_COUNT_ESC=$(escape_latex_chars "$SUGGESTIONS_COUNT")
TESTS_PERFORMED_ESC=$(escape_latex_chars "$TESTS_PERFORMED")
PLUGINS_ENABLED_ESC=$(escape_latex_chars "$PLUGINS_ENABLED")
SOURCE_FILE_BASENAME_ESC=$(escape_latex_chars "$SOURCE_FILE_BASENAME")
SOURCE_FILE_CHECKSUM_ESC=$(escape_latex_chars "$SOURCE_FILE_CHECKSUM")
SCAN_MACHINE_ID_ESC=$(escape_latex_chars "$SCAN_MACHINE_ID")
SCAN_MACHINE_ID_TYPE_ESC=$(escape_latex_chars "$SCAN_MACHINE_ID_TYPE")
SCAN_MACHINE_ID_METHOD_ESC=$(escape_latex_chars "$SCAN_MACHINE_ID_METHOD")
TARGET_MACHINE_ID_ESC=$(escape_latex_chars "$TARGET_MACHINE_ID")
TARGET_MACHINE_ID_TYPE_ESC=$(escape_latex_chars "$TARGET_MACHINE_ID_TYPE")
TARGET_MACHINE_ID_METHOD_ESC=$(escape_latex_chars "$TARGET_MACHINE_ID_METHOD")
TARGET_INVENTORY_FILE_ESC=$(escape_latex_chars "$TARGET_INVENTORY_FILE")

# Perform substitutions
sed -i.bak \
    -e "s/VULN-YYYY-NNN/$UNIQUE_ID_ESC/g" \
    -e "s/January 15, 2026/$FORMATTED_DATE_ESC/g" \
    -e "s/2026-01-15 08:00:00/$SCAN_TIMESTAMP_ESC/g" \
    -e "s/\\\\newcommand{\\\\ScannerName}{Lynis}/\\\\newcommand{\\\\ScannerName}{$SCANNER_NAME_ESC}/g" \
    -e "s/\\\\newcommand{\\\\ScannerVersion}{3.0.0}/\\\\newcommand{\\\\ScannerVersion}{$SCANNER_VERSION_ESC}/g" \
    -e "s/\\\\newcommand{\\\\ScanMode}{normal}/\\\\newcommand{\\\\ScanMode}{$SCAN_MODE_ESC}/g" \
    -e "s|\\\\newcommand{\\\\ScanTarget}{(local) /}|\\\\newcommand{\\\\ScanTarget}{$SCAN_TARGET_ESC}|g" \
    -e "s/v1.0.0/$TOOLKIT_VERSION_ESC/g" \
    -e "s/abc1234/$TOOLKIT_COMMIT_ESC/g" \
    -e "s/\\\\newcommand{\\\\ScanResult}{PASS}/\\\\newcommand{\\\\ScanResult}{$SCAN_RESULT_ESC}/g" \
    -e "s/\\\\newcommand{\\\\HardeningIndex}{0}/\\\\newcommand{\\\\HardeningIndex}{$HARDENING_INDEX_ESC}/g" \
    -e "s/\\\\newcommand{\\\\WarningsCount}{0}/\\\\newcommand{\\\\WarningsCount}{$WARNINGS_COUNT_ESC}/g" \
    -e "s/\\\\newcommand{\\\\SuggestionsCount}{0}/\\\\newcommand{\\\\SuggestionsCount}{$SUGGESTIONS_COUNT_ESC}/g" \
    -e "s/\\\\newcommand{\\\\TestsPerformed}{0}/\\\\newcommand{\\\\TestsPerformed}{$TESTS_PERFORMED_ESC}/g" \
    -e "s/\\\\newcommand{\\\\PluginsEnabled}{0}/\\\\newcommand{\\\\PluginsEnabled}{$PLUGINS_ENABLED_ESC}/g" \
    -e "s/lynis-scan-2026-01-15.txt/$SOURCE_FILE_BASENAME_ESC/g" \
    -e "s/\\\\newcommand{\\\\SourceFileChecksum}{0000000000000000000000000000000000000000000000000000000000000000}/\\\\newcommand{\\\\SourceFileChecksum}{$SOURCE_FILE_CHECKSUM_ESC}/g" \
    -e "s|\\\\newcommand{\\\\ScanMachineID}{N/A}|\\\\newcommand{\\\\ScanMachineID}{$SCAN_MACHINE_ID_ESC}|g" \
    -e "s|\\\\newcommand{\\\\ScanMachineIDType}{Fingerprint}|\\\\newcommand{\\\\ScanMachineIDType}{$SCAN_MACHINE_ID_TYPE_ESC}|g" \
    -e "s|\\\\newcommand{\\\\ScanMachineIDMethod}{SHA256(MAC:hostname)}|\\\\newcommand{\\\\ScanMachineIDMethod}{$SCAN_MACHINE_ID_METHOD_ESC}|g" \
    -e "s|\\\\newcommand{\\\\TargetMachineID}{N/A}|\\\\newcommand{\\\\TargetMachineID}{$TARGET_MACHINE_ID_ESC}|g" \
    -e "s|\\\\newcommand{\\\\TargetMachineIDType}{Fingerprint}|\\\\newcommand{\\\\TargetMachineIDType}{$TARGET_MACHINE_ID_TYPE_ESC}|g" \
    -e "s|\\\\newcommand{\\\\TargetMachineIDMethod}{SHA256(MAC:hostname)}|\\\\newcommand{\\\\TargetMachineIDMethod}{$TARGET_MACHINE_ID_METHOD_ESC}|g" \
    -e "s|\\\\newcommand{\\\\TargetInventoryFile}{N/A}|\\\\newcommand{\\\\TargetInventoryFile}{$TARGET_INVENTORY_FILE_ESC}|g" \
    "$PDF_BUILD_DIR/vuln_attestation.tex"

# Run pdflatex
cd "$PDF_BUILD_DIR"
PDFLATEX_LOG="$PDF_BUILD_DIR/pdflatex.log"

$PDFLATEX -interaction=nonstopmode vuln_attestation.tex > "$PDFLATEX_LOG" 2>&1 || true
$PDFLATEX -interaction=nonstopmode vuln_attestation.tex > /dev/null 2>&1 || true

# Check result
EXIT_CODE=0
if [ -f "vuln_attestation.pdf" ]; then
    OUTPUT_PDF="$SCANS_DIR/vulnerability-attestation-lynis-$FILE_TIMESTAMP.pdf"
    cp "vuln_attestation.pdf" "$OUTPUT_PDF"
    echo "  Output: $(basename "$OUTPUT_PDF")"
    echo ""
    echo "Lynis vulnerability attestation PDF generated successfully."
else
    echo "  PDF generation failed"
    if [ -f "$PDFLATEX_LOG" ]; then
        echo "  pdflatex errors:"
        tail -20 "$PDFLATEX_LOG"
    fi
    EXIT_CODE=1
fi

rm -rf "$PDF_BUILD_DIR"
exit $EXIT_CODE
