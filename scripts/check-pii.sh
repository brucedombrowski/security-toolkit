#!/bin/bash
#
# PII Verification Script
#
# Purpose: Automated scanning of repository files for potential PII patterns
# Method: Pattern matching using grep with regex
#
# Patterns checked:
#   - IP addresses (IPv4)
#   - Phone numbers (US formats)
#   - Social Security Numbers
#   - Credit Card Numbers
#
# Exit codes:
#   0 = All checks passed (no PII found)
#   1 = Potential PII detected (requires review)
#
# Usage: ./check-pii.sh [target_directory]
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

# Files to scan (common text file types)
INCLUDE_PATTERNS=(
    "*.md" "*.txt" "*.tex" "*.rst"
    "*.sh" "*.bash" "*.zsh"
    "*.py" "*.js" "*.ts" "*.rb" "*.php" "*.go" "*.rs" "*.java" "*.cs" "*.c" "*.cpp" "*.h"
    "*.yaml" "*.yml" "*.json" "*.xml" "*.toml" "*.ini" "*.conf" "*.config"
    "*.html" "*.css" "*.scss"
    "*.sql"
    "*.env" "*.env.example"
)

FOUND_ISSUES=0

echo "PII Verification Scan"
echo "====================="
echo "Timestamp: $TIMESTAMP"
echo "Target: $TARGET_DIR"
echo "Repository: $REPO_NAME"
echo ""

# Build include arguments for grep
INCLUDE_ARGS=""
for pattern in "${INCLUDE_PATTERNS[@]}"; do
    INCLUDE_ARGS="$INCLUDE_ARGS --include=$pattern"
done

# Function to run a check and log results
run_check() {
    local check_name="$1"
    local pattern="$2"
    local description="$3"

    echo "Checking: $check_name"

    # Run grep, capture output
    local results=""
    results=$(grep -r -n -E "$pattern" "$TARGET_DIR" \
        $INCLUDE_ARGS \
        --exclude-dir=".git" \
        --exclude-dir="node_modules" \
        --exclude-dir="venv" \
        --exclude-dir=".venv" \
        --exclude-dir="__pycache__" \
        --exclude-dir=".scans" \
        --exclude="*Scan-Results.md" \
        --exclude="check-*.sh" \
        2>/dev/null || true)

    local count=0
    if [ -n "$results" ]; then
        count=$(echo "$results" | wc -l | tr -d ' ')
    fi

    if [ "$count" -eq 0 ]; then
        echo "  Result: PASS (0 matches)"
    else
        echo "  Result: REVIEW - $count match(es) found"
        echo "$results" | head -10
        if [ "$count" -gt 10 ]; then
            echo "  ... and $((count - 10)) more"
        fi
        FOUND_ISSUES=1
    fi
}

# Run all checks
run_check "IPv4 Addresses" \
    "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    "Searches for IP address patterns that could identify network infrastructure"

run_check "US Phone Numbers (dashed)" \
    "[0-9]{3}[-][0-9]{3}[-][0-9]{4}" \
    "Searches for phone numbers in XXX-XXX-XXXX format"

run_check "US Phone Numbers (dotted)" \
    "[0-9]{3}[.][0-9]{3}[.][0-9]{4}" \
    "Searches for phone numbers in XXX.XXX.XXXX format"

run_check "US Phone Numbers (parenthetical)" \
    "\([0-9]{3}\)[ ]*[0-9]{3}[-. ][0-9]{4}" \
    "Searches for phone numbers in (XXX) XXX-XXXX format"

run_check "Social Security Numbers" \
    "[0-9]{3}-[0-9]{2}-[0-9]{4}" \
    "Searches for SSN patterns in XXX-XX-XXXX format"

run_check "Credit Card Numbers (16 digit)" \
    "[0-9]{4}[-. ]?[0-9]{4}[-. ]?[0-9]{4}[-. ]?[0-9]{4}" \
    "Searches for 16-digit sequences that could be credit card numbers"

# Summary
echo ""
echo "====================="

if [ $FOUND_ISSUES -eq 0 ]; then
    echo "OVERALL RESULT: PASS"
    echo "No PII patterns detected."
else
    echo "OVERALL RESULT: REVIEW REQUIRED"
    echo "Potential PII patterns detected. Manual review required."
fi

exit $FOUND_ISSUES
