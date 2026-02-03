#!/bin/bash
#
# IEEE 802.3 MAC Address Verification Script
#
# Purpose: Automated scanning for MAC addresses per IEEE 802.3
# Method: Pattern matching for MAC address formats
#
# IEEE 802.3 defines MAC addresses as 48-bit identifiers
# Format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
# First 3 octets = OUI (Organizationally Unique Identifier) assigned by IEEE
#
# Exit codes:
#   0 = All checks passed (no MAC addresses found)
#   1 = MAC addresses detected (requires review)
#
# Usage: ./check-mac-addresses.sh [target_directory]
#        If no target specified, uses parent directory of script location
#
# Note: Test fixture directories (tests/, test/) are excluded from scanning
#       as they intentionally contain MAC address patterns for validation.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# Allow target directory to be specified as argument
if [ -n "${1:-}" ]; then
    TARGET_DIR="$1"
else
    TARGET_DIR="$SECURITY_REPO_DIR"
fi

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit
REPO_NAME=$(basename "$TARGET_DIR")

# MAC address patterns (IEEE 802.3)
MAC_PATTERN_COLON="([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
MAC_PATTERN_DASH="([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
MAC_PATTERN_CISCO="([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"

FOUND_ISSUES=0
TOTAL_FOUND=0

echo "IEEE 802.3 MAC Address Verification Scan"
echo "========================================="
echo "Timestamp: $TIMESTAMP"
echo "Toolkit: Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
echo "Target: $TARGET_DIR"
echo "Repository: $REPO_NAME"
echo ""
echo "Note: Test fixture directories (tests/, test/, fixtures/) are excluded"
echo ""

# Initialize audit logging
if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
    init_audit_log "$TARGET_DIR" "mac-scan" || true
fi

# Function to run a MAC address check
run_mac_check() {
    local format_name="$1"
    local pattern="$2"

    echo "Checking: $format_name"

    # Run grep, capture output
    local results=""
    results=$(grep -r -n -o -E "$pattern" "$TARGET_DIR" \
        --include="*.sh" \
        --include="*.py" \
        --include="*.js" \
        --include="*.ts" \
        --include="*.yaml" \
        --include="*.yml" \
        --include="*.json" \
        --include="*.md" \
        --include="*.tex" \
        --include="*.conf" \
        --include="*.config" \
        --include="*.log" \
        --exclude-dir=".git" \
        --exclude-dir="node_modules" \
        --exclude-dir="venv" \
        --exclude-dir=".venv" \
        --exclude-dir="__pycache__" \
        --exclude-dir=".scans" \
        --exclude-dir="obj" \
        --exclude-dir="bin" \
        --exclude-dir="publish" \
        --exclude-dir="tests" \
        --exclude-dir="test" \
        --exclude-dir="fixtures" \
        --exclude-dir="examples" \
        --exclude="*Scan-Results.md" \
        --exclude="check-*.sh" \
        --exclude="*-EXAMPLE.*" \
        2>/dev/null || true)

    local count=0
    if [ -n "$results" ]; then
        count=$(echo "$results" | wc -l | tr -d ' ')
        TOTAL_FOUND=$((TOTAL_FOUND + count))
    fi

    if [ "$count" -eq 0 ]; then
        echo "  Result: PASS (0 matches)"
    else
        echo "  Result: REVIEW - $count MAC address(es) found"
        echo "$results" | head -10
        if [ "$count" -gt 10 ]; then
            echo "  ... and $((count - 10)) more"
        fi
        FOUND_ISSUES=1
    fi
}

# Run MAC address checks for each format
run_mac_check "Colon-Separated (XX:XX:XX:XX:XX:XX)" "$MAC_PATTERN_COLON"
run_mac_check "Dash-Separated (XX-XX-XX-XX-XX-XX)" "$MAC_PATTERN_DASH"
run_mac_check "Cisco Format (XXXX.XXXX.XXXX)" "$MAC_PATTERN_CISCO"

# Summary
echo ""
echo "========================================="

if [ $FOUND_ISSUES -eq 0 ]; then
    echo "OVERALL RESULT: PASS"
    echo "No MAC addresses detected in production code."
    # Finalize audit log with PASS status
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        finalize_audit_log "PASS" "mac_addresses=0"
    fi
else
    echo "OVERALL RESULT: REVIEW REQUIRED"
    echo "$TOTAL_FOUND MAC address(es) found in production code."
    echo "Manual review required to determine if they represent actual hardware identifiers."
    # Finalize audit log with FAIL status
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        finalize_audit_log "FAIL" "mac_addresses=$TOTAL_FOUND"
    fi
fi

exit $FOUND_ISSUES
