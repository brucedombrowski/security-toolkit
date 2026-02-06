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

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source shared libraries
AUDIT_AVAILABLE=0
TIMESTAMPS_AVAILABLE=0
PROGRESS_AVAILABLE=0

if [ -f "$SCRIPT_DIR/lib/audit-log.sh" ]; then
    source "$SCRIPT_DIR/lib/audit-log.sh"
    AUDIT_AVAILABLE=1
fi

if [ -f "$SCRIPT_DIR/lib/timestamps.sh" ]; then
    source "$SCRIPT_DIR/lib/timestamps.sh"
    TIMESTAMPS_AVAILABLE=1
fi

if [ -f "$SCRIPT_DIR/lib/progress.sh" ]; then
    source "$SCRIPT_DIR/lib/progress.sh"
    PROGRESS_AVAILABLE=1
fi

# Toolkit identification
if [ -f "$SCRIPT_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPT_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SECURITY_REPO_DIR"
fi

# Default to interactive mode
INTERACTIVE=1
INTERACTIVE_FLAG="-i"
TARGET_DIR=""

# Help function
show_help() {
    cat << 'EOF'
Usage: run-all-scans.sh [OPTIONS] [TARGET_DIRECTORY]

Run comprehensive security verification scans on a target directory.

OPTIONS:
  -h, --help              Show this help message and exit
  -n, --non-interactive   Skip interactive prompts (for CI/CD)

ARGUMENTS:
  TARGET_DIRECTORY        Directory to scan (default: parent of script location)

SCANS PERFORMED:
  - PII Detection         SSN, phone, IP, credit card patterns (NIST SI-12)
  - Malware Scanning      ClamAV virus/trojan detection (NIST SI-3)
  - Secrets Detection     API keys, passwords, tokens (NIST SA-11)
  - MAC Address Scan      IEEE 802.3 identifiers (NIST SC-8)
  - Host Security         OS configuration audit (NIST CM-6)
  - Vulnerability Scan    Nmap/Lynis assessment (NIST RA-5)

OUTPUT:
  Results saved to <TARGET>/.scans/ including:
  - Individual scan logs
  - Consolidated report
  - PDF attestation (if pdflatex available)
  - SHA256 checksums

EXAMPLES:
  ./run-all-scans.sh                      # Scan parent directory (interactive)
  ./run-all-scans.sh /path/to/project     # Scan specific directory
  ./run-all-scans.sh -n .                 # Non-interactive scan of current dir

EXIT CODES:
  0  All scans passed
  1  One or more scans failed
  2  Invalid target directory

NIST CONTROLS: CA-2, CA-7, CM-6, CM-8, RA-5, SA-11, SC-8, SI-2, SI-3, SI-12
EOF
    exit 0
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
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

# Check Docker daemon status (informational - some scans may benefit from Docker)
check_docker_status() {
    if command -v docker &>/dev/null; then
        # Docker CLI is installed, check if daemon is running
        if ! docker info &>/dev/null 2>&1; then
            echo "WARNING: Docker is installed but the Docker daemon is not running."
            echo "  Some advanced scanning features may require Docker."
            echo "  To start Docker:"
            echo "    - macOS: Open Docker Desktop application"
            echo "    - Linux: sudo systemctl start docker"
            echo ""

            # Give user a chance to start Docker if running interactively
            if [ "$INTERACTIVE" -eq 1 ] && [ -t 0 ]; then
                read -p "Press Enter to continue without Docker, or start Docker and press Enter... " -r </dev/tty
                echo ""
                # Check again after user had a chance to start it
                if docker info &>/dev/null 2>&1; then
                    echo "Docker daemon is now running."
                    echo ""
                fi
            fi
        fi
    fi
}

# Run Docker status check
check_docker_status

# Use standardized timestamps (UTC for consistency across time zones)
if [ "$TIMESTAMPS_AVAILABLE" -eq 1 ]; then
    TIMESTAMP=$(get_iso_timestamp)
    DATE_STAMP=$(get_date_stamp)
    FILE_TIMESTAMP=$(get_filename_timestamp)
else
    TIMESTAMP=$(date -u "+%Y-%m-%dT%H:%M:%SZ")
    DATE_STAMP=$(date -u "+%Y-%m-%d")
    # Filesystem-safe timestamp for unique filenames (no colons)
    # Format: YYYY-MM-DD-THHMMSSZ (e.g., 2026-01-15-T154452Z)
    FILE_TIMESTAMP=$(date -u "+%Y-%m-%d-T%H%M%SZ")
fi

# Get hostname for attestation
TARGET_HOST=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")

# Function to validate scan directory path (CRITICAL-002: rm -rf safety)
# Prevents deletion of dangerous directories through path traversal or validation bypass
# Returns: 0 (safe) or 1 (unsafe)
validate_scan_directory() {
    local target_path="$1"
    
    # Check if target path is empty
    if [ -z "$target_path" ]; then
        echo "Error: Target path is empty" >&2
        return 1
    fi
    
    # Check if path is absolute (prevents relative path traversal)
    if [[ "$target_path" != /* ]]; then
        echo "Error: Target path must be absolute" >&2
        return 1
    fi
    
    # Check if target directory exists
    if [ ! -d "$target_path" ]; then
        echo "Error: Target directory does not exist: $target_path" >&2
        return 1
    fi
    
    # Prevent deletion of critical system directories
    # Check if .scans path would be in a system location
    local scans_path="$target_path/.scans"
    case "$scans_path" in
        "/.scans"|"/etc/.scans"|"/var/.scans"|"/bin/.scans"|"/sbin/.scans"|"/boot/.scans"|"/usr/.scans"|"/root/.scans")
            echo "Error: Cannot delete .scans in critical system directory: $scans_path" >&2
            return 1
            ;;
    esac
    
    # Detect if .scans is a symlink (would delete linked content instead)
    if [ -L "$target_path/.scans" ]; then
        echo "Error: .scans is a symlink, refusing to delete" >&2
        return 1
    fi
    
    return 0
}

# Create .scans directory for output (delete previous results first)
# get_scans_dir handles fallback if target is not writable (e.g., scanning /)
SCANS_DIR=$(get_scans_dir "$TARGET_DIR")

# Validate directory before deletion
if ! validate_scan_directory "$TARGET_DIR"; then
    echo "Fatal: Invalid target directory - cannot proceed with scans" >&2
    exit 2
fi

# Delete previous scan results with safety checks
if [ -d "$SCANS_DIR" ]; then
    if [ "$INTERACTIVE" -eq 1 ]; then
        # Interactive mode: show preview and require confirmation
        echo "Previous scan results found at:"
        echo "  $SCANS_DIR"
        echo ""
        
        # Show file preview (first 20 files)
        file_count=$(find "$SCANS_DIR" -type f 2>/dev/null | wc -l)
        if [ "$file_count" -gt 0 ]; then
            echo "Files to be deleted (showing first 20):"
            find "$SCANS_DIR" -type f 2>/dev/null | head -20 | while read -r file; do
                echo "  - ${file#$SCANS_DIR/}"
            done
            if [ "$file_count" -gt 20 ]; then
                echo "  ... and $((file_count - 20)) more files"
            fi
        fi
        echo ""
        
        # Require explicit confirmation
        read -p "Delete previous scan results? Type 'yes' to confirm: " confirm </dev/tty
        if [ "$confirm" != "yes" ]; then
            echo "Preserving existing scan results. Exiting."
            exit 0
        fi
    fi
    
    # Safe deletion: use find + rm instead of rm -rf
    echo "Removing previous scan results: $SCANS_DIR"
    find "$SCANS_DIR" -type f -delete 2>/dev/null
    find "$SCANS_DIR" -type d -delete 2>/dev/null
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to remove previous scan results" >&2
        exit 1
    fi
fi

mkdir -p "$SCANS_DIR"

# Initialize audit logging for the master scan
if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
    init_audit_log "$TARGET_DIR" "master-scan" || true
fi

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
SKIP_COUNT=0

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
        elif [ $exit_code -eq 2 ]; then
            # Exit code 2 = dependency missing, skip gracefully
            log "  Status: SKIPPED (missing dependency)"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            # Update result variable if provided
            if [ -n "$result_var" ]; then
                eval "$result_var=SKIP"
            fi
            if [ -n "$findings_var" ]; then
                eval "$findings_var=\"Skipped - dependency not installed\""
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
# Total scans: 7 (5 standard + 1 NVD CVE + 1 vulnerability)
TOTAL_SCANS=7
CURRENT_SCAN=0

# Start overall progress tracking
if [ "$PROGRESS_AVAILABLE" -eq 1 ]; then
    progress_start
    echo ""
    echo "Running $TOTAL_SCANS security scans..."
    echo ""
fi

CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "PII Pattern Scan"
run_scan "PII Pattern Scan" \
    "$SCRIPT_DIR/check-pii.sh $INTERACTIVE_FLAG" \
    "NIST 800-53: SI-12 (Information Management)" \
    "pii-scan-$FILE_TIMESTAMP.txt" \
    "PII_RESULT" "PII_FINDINGS"

CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "Malware Scan (ClamAV)"
run_scan "Malware Scan (ClamAV)" \
    "$SCRIPT_DIR/check-malware.sh" \
    "NIST 800-53: SI-3 (Malicious Code Protection)" \
    "malware-scan-$FILE_TIMESTAMP.txt" \
    "MALWARE_RESULT" "MALWARE_FINDINGS"

CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "Secrets/Credentials Scan"
run_scan "Secrets/Credentials Scan" \
    "$SCRIPT_DIR/check-secrets.sh $INTERACTIVE_FLAG" \
    "NIST 800-53: SA-11 (Developer Testing)" \
    "secrets-scan-$FILE_TIMESTAMP.txt" \
    "SECRETS_RESULT" "SECRETS_FINDINGS"

CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "MAC Address Scan"
run_scan "IEEE 802.3 MAC Address Scan" \
    "$SCRIPT_DIR/check-mac-addresses.sh" \
    "NIST 800-53: SC-8 (Transmission Confidentiality)" \
    "mac-address-scan-$FILE_TIMESTAMP.txt" \
    "MAC_RESULT" "MAC_FINDINGS"

CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "NVD CVE Vulnerability Lookup"
run_scan "NVD CVE Vulnerability Lookup" \
    "$SCRIPT_DIR/check-nvd-cves.sh --offline -i $SCANS_DIR/host-inventory-$FILE_TIMESTAMP.txt" \
    "NIST 800-53: RA-5 (Vulnerability Monitoring), SI-2 (Flaw Remediation)" \
    "nvd-cve-scan-$FILE_TIMESTAMP.txt" \
    "NVD_RESULT" "NVD_FINDINGS"

CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "Host Security Configuration"
run_scan "Host Security Configuration" \
    "$SCRIPT_DIR/check-host-security.sh" \
    "NIST 800-53: CM-6 (Configuration Settings)" \
    "host-security-scan-$FILE_TIMESTAMP.txt" \
    "HOST_RESULT" "HOST_FINDINGS"

# Run vulnerability scan (quick mode, scans localhost)
# Note: This scans the HOST system, not the codebase - uses different invocation
# The script creates its own output files in .scans/ directory
CURRENT_SCAN=$((CURRENT_SCAN + 1))
[ "$PROGRESS_AVAILABLE" -eq 1 ] && progress_step $CURRENT_SCAN $TOTAL_SCANS "Vulnerability Scan (Nmap/Lynis)"
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

# Show elapsed time
if [ "$PROGRESS_AVAILABLE" -eq 1 ]; then
    echo ""
    progress_end "All scans complete"
fi

log "========================================================"
log ""
log "SCAN SUMMARY"
log "============"
log "Passed:  $PASS_COUNT"
log "Failed:  $FAIL_COUNT"
log "Skipped: $SKIP_COUNT"
if [ "$PROGRESS_AVAILABLE" -eq 1 ] && [ -n "$PROGRESS_START_TIME" ]; then
    elapsed=$(($(date +%s) - PROGRESS_START_TIME))
    log "Elapsed: $(format_elapsed $elapsed)"
fi
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
    echo "Toolkit: $TOOLKIT_NAME $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
    echo "Source: $TOOLKIT_SOURCE"
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
export TOOLKIT_NAME TOOLKIT_VERSION TOOLKIT_COMMIT TOOLKIT_SOURCE
export PII_RESULT PII_FINDINGS MALWARE_RESULT MALWARE_FINDINGS
export SECRETS_RESULT SECRETS_FINDINGS MAC_RESULT MAC_FINDINGS
export HOST_RESULT HOST_FINDINGS VULN_RESULT VULN_FINDINGS
export OVERALL_STATUS PASS_COUNT FAIL_COUNT SKIP_COUNT

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

# Finalize audit logging
if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
    if [ "$OVERALL_STATUS" = "PASS" ]; then
        finalize_audit_log "PASS" "passed=$PASS_COUNT failed=$FAIL_COUNT skipped=$SKIP_COUNT"
    else
        finalize_audit_log "FAIL" "passed=$PASS_COUNT failed=$FAIL_COUNT skipped=$SKIP_COUNT"
    fi
fi

if [ "$OVERALL_STATUS" = "PASS" ]; then
    exit 0
else
    exit 1
fi
