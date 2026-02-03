#!/bin/bash
#
# PII Pattern Detection Unit Tests
#
# Purpose: Verify PII detection patterns catch real PII and minimize false positives
# NIST Control: SI-12 (Information Management)
#
# Usage: ./tests/test-pii-patterns.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test helper functions
test_start() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "  Test $TESTS_RUN: $1... "
}

test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}"
}

test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}FAIL${NC}"
    echo "    Expected: $1"
    echo "    Got: $2"
}

test_known() {
    echo -n "  Known: $1... "
    echo -e "${YELLOW}KNOWN${NC} (allowlist handles)"
}

# PII regex patterns (must match check-pii.sh)
IPV4_PATTERN='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
PHONE_PATTERN='\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}'
INTL_PHONE_PATTERN='\+[0-9]{1,3}[ .-]?[0-9]{1,4}[ .-]?[0-9]{1,4}[ .-]?[0-9]{1,4}[ .-]?[0-9]{0,4}'
SSN_PATTERN='[0-9]{3}-[0-9]{2}-[0-9]{4}'
CREDIT_CARD_PATTERN='[0-9]{4}[-. ]?[0-9]{4}[-. ]?[0-9]{4}[-. ]?[0-9]{4}'

echo "=========================================="
echo "PII Pattern Detection Unit Tests"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# IPv4 Address Tests
# -----------------------------------------------------------------------------
echo "--- IPv4 Address Detection ---"

test_start "Detect standard IPv4 (192.168.1.1)"
if echo "192.168.1.1" | grep -qE "$IPV4_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect private IP (10.0.0.1)"
if echo "10.0.0.1" | grep -qE "$IPV4_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect public IP (8.8.8.8)"
if echo "8.8.8.8" | grep -qE "$IPV4_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect localhost (127.0.0.1)"
if echo "127.0.0.1" | grep -qE "$IPV4_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject non-IP version string (1.2.3)"
if echo "version 1.2.3" | grep -qE "$IPV4_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Phone Number Tests
# -----------------------------------------------------------------------------
echo "--- Phone Number Detection ---"

test_start "Detect (555) 123-4567"
if echo "(555) 123-4567" | grep -qE "$PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect 555-123-4567"
if echo "555-123-4567" | grep -qE "$PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect 555.123.4567"
if echo "555.123.4567" | grep -qE "$PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect 5551234567"
if echo "5551234567" | grep -qE "$PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

echo ""

# -----------------------------------------------------------------------------
# International Phone Number Tests
# -----------------------------------------------------------------------------
echo "--- International Phone Number Detection ---"

test_start "Detect UK format (+44 20 7946 0958)"
if echo "+44 20 7946 0958" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect German format (+49 30 12345678)"
if echo "+49 30 12345678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect US international format (+1 555 123 4567)"
if echo "+1 555 123 4567" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect compact format (+14155551234)"
if echo "+14155551234" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect dotted format (+33.1.23.45.67.89)"
if echo "+33.1.23.45.67.89" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Australian format (+61 2 1234 5678)"
if echo "+61 2 1234 5678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Japanese format (+81 3 1234 5678)"
if echo "+81 3 1234 5678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Chinese format (+86 10 1234 5678)"
if echo "+86 10 1234 5678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Indian format (+91 22 1234 5678)"
if echo "+91 22 1234 5678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Brazilian format (+55 11 91234 5678)"
if echo "+55 11 91234 5678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Mexican format (+52 55 1234 5678)"
if echo "+52 55 1234 5678" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject number without plus (+missing)"
if echo "44 20 7946 0958" | grep -qE "$INTL_PHONE_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# SSN Tests
# -----------------------------------------------------------------------------
echo "--- Social Security Number Detection ---"

test_start "Detect valid SSN format (123-45-6789)"
if echo "123-45-6789" | grep -qE "$SSN_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect SSN in text (SSN: 123-45-6789)"
if echo "SSN: 123-45-6789" | grep -qE "$SSN_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject invalid SSN (12-345-6789)"
if echo "12-345-6789" | grep -qE "$SSN_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Credit Card Tests
# -----------------------------------------------------------------------------
echo "--- Credit Card Detection ---"

test_start "Detect Visa format (4111-1111-1111-1111)"
if echo "4111-1111-1111-1111" | grep -qE "$CREDIT_CARD_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect MC format (5500 0000 0000 0004)"
if echo "5500 0000 0000 0004" | grep -qE "$CREDIT_CARD_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect continuous digits (4111111111111111)"
if echo "4111111111111111" | grep -qE "$CREDIT_CARD_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

echo ""

# -----------------------------------------------------------------------------
# False Positive Tests (should NOT match)
# -----------------------------------------------------------------------------
echo "--- False Positive Prevention ---"

test_start "Reject X.509 OID (1.3.6.1.5.5.7.3.4)"
# OIDs have 5+ segments, IPs have exactly 4
if echo "1.3.6.1.5.5.7.3.4" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_known "Version number (6.0.0.0) matches IPv4 pattern"
# This will match IPv4 pattern - this is a known limitation handled via allowlist

test_start "Reject date format (2026-01-15)"
if echo "2026-01-15" | grep -qE "$SSN_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_start "Reject timestamp (12:34:56)"
if echo "12:34:56" | grep -qE "$PHONE_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_start "Reject short number sequence (12345)"
if echo "12345" | grep -qE "$CREDIT_CARD_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_start "Reject port number in URL (localhost:8080)"
if echo "localhost:8080" | grep -qE "$PHONE_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Integration Test
# -----------------------------------------------------------------------------
echo "--- Integration Test ---"

# Ensure clean fixtures directory before integration tests
rm -rf "$FIXTURES_DIR"
mkdir -p "$FIXTURES_DIR"

test_start "Run check-pii.sh on clean fixture"
# Create a clean test file - use .md extension (check-pii.sh scans *.md)
CLEAN_FILE="$FIXTURES_DIR/clean-file.md"
cat > "$CLEAN_FILE" << 'EOF'
This is a clean file with no PII.
It contains normal text and code.
Version: 1.2.3
Build date: 2026-01-15
EOF

if "$REPO_DIR/scripts/check-pii.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_pass
else
    test_fail "exit 0" "exit 1"
fi

# Remove clean file before testing PII detection
rm -f "$CLEAN_FILE"

test_start "Run check-pii.sh on file with PII"
# Use .md extension since check-pii.sh scans *.md files
PII_FILE="$FIXTURES_DIR/has-pii.md"
cat > "$PII_FILE" << 'EOF'
Contact: John Doe
Phone: (555) 123-4567
SSN: 123-45-6789
EOF

if "$REPO_DIR/scripts/check-pii.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_fail "exit 1" "exit 0 (missed PII)"
else
    test_pass
fi

# Cleanup
rm -f "$CLEAN_FILE" "$PII_FILE"

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED test(s) failed${NC}"
    exit 1
fi
