#!/bin/bash
#
# MAC Address Pattern Detection Unit Tests
#
# Purpose: Verify MAC address detection patterns catch real MACs and minimize false positives
# NIST Control: SC-8 (Transmission Confidentiality and Integrity)
#
# Usage: ./tests/test-mac-patterns.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -e

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

# MAC address regex patterns (must match check-mac-addresses.sh)
MAC_PATTERN_COLON="([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
MAC_PATTERN_DASH="([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
MAC_PATTERN_CISCO="([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"

echo "=========================================="
echo "MAC Address Pattern Detection Unit Tests"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# Colon-Separated MAC Address Tests (Standard Linux/Unix format)
# -----------------------------------------------------------------------------
echo "--- Colon-Separated MAC Detection ---"

test_start "Detect standard MAC (00:11:22:33:44:55)"
if echo "00:11:22:33:44:55" | grep -qE "$MAC_PATTERN_COLON"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect lowercase MAC (aa:bb:cc:dd:ee:ff)"
if echo "aa:bb:cc:dd:ee:ff" | grep -qE "$MAC_PATTERN_COLON"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect mixed case MAC (Aa:Bb:Cc:Dd:Ee:Ff)"
if echo "Aa:Bb:Cc:Dd:Ee:Ff" | grep -qE "$MAC_PATTERN_COLON"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect MAC in text (eth0: 00:11:22:33:44:55)"
if echo "eth0: 00:11:22:33:44:55" | grep -qE "$MAC_PATTERN_COLON"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject invalid MAC (00:11:22:33:44)"
if echo "00:11:22:33:44" | grep -qE "$MAC_PATTERN_COLON"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_start "Reject MAC with invalid hex (00:11:22:33:44:GG)"
if echo "00:11:22:33:44:GG" | grep -qE "$MAC_PATTERN_COLON"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Dash-Separated MAC Address Tests (Windows format)
# -----------------------------------------------------------------------------
echo "--- Dash-Separated MAC Detection ---"

test_start "Detect Windows format MAC (00-11-22-33-44-55)"
if echo "00-11-22-33-44-55" | grep -qE "$MAC_PATTERN_DASH"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect lowercase Windows MAC (aa-bb-cc-dd-ee-ff)"
if echo "aa-bb-cc-dd-ee-ff" | grep -qE "$MAC_PATTERN_DASH"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect MAC in ipconfig output (Physical Address: AA-BB-CC-DD-EE-FF)"
if echo "Physical Address: AA-BB-CC-DD-EE-FF" | grep -qE "$MAC_PATTERN_DASH"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject incomplete dash MAC (00-11-22-33-44)"
if echo "00-11-22-33-44" | grep -qE "$MAC_PATTERN_DASH"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Cisco Format MAC Address Tests (XXXX.XXXX.XXXX)
# -----------------------------------------------------------------------------
echo "--- Cisco Format MAC Detection ---"

test_start "Detect Cisco MAC (0011.2233.4455)"
if echo "0011.2233.4455" | grep -qE "$MAC_PATTERN_CISCO"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Cisco MAC lowercase (aabb.ccdd.eeff)"
if echo "aabb.ccdd.eeff" | grep -qE "$MAC_PATTERN_CISCO"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Cisco MAC in config (mac-address 0011.2233.4455)"
if echo "mac-address 0011.2233.4455" | grep -qE "$MAC_PATTERN_CISCO"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject incomplete Cisco MAC (0011.2233)"
if echo "0011.2233" | grep -qE "$MAC_PATTERN_CISCO"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# False Positive Tests
# -----------------------------------------------------------------------------
echo "--- False Positive Prevention ---"

test_start "Reject IPv6 address segment (2001:0db8:85a3)"
# IPv6 has more segments than MAC pattern
if echo "2001:0db8:85a3" | grep -qE "$MAC_PATTERN_COLON"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_start "Reject timestamp (12:34:56)"
if echo "12:34:56" | grep -qE "$MAC_PATTERN_COLON"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

test_start "Reject version number (1.2.3.4.5.6)"
if echo "1.2.3.4.5.6" | grep -qE "$MAC_PATTERN_CISCO"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Integration Test
# -----------------------------------------------------------------------------
echo "--- Integration Test ---"

test_start "Run check-mac-addresses.sh on clean fixture"
# Use .md extension since check-mac-addresses.sh includes *.md files
CLEAN_FILE="$FIXTURES_DIR/clean-mac.md"
mkdir -p "$FIXTURES_DIR"
cat > "$CLEAN_FILE" << 'EOF'
This file contains no MAC addresses.
Just regular text and timestamps like 12:30:45.
And version numbers like 1.2.3.4
EOF

if "$REPO_DIR/scripts/check-mac-addresses.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_pass
else
    test_fail "exit 0" "exit 1"
fi

test_start "Run check-mac-addresses.sh on file with MAC"
# Use .md extension since check-mac-addresses.sh includes *.md files
MAC_FILE="$FIXTURES_DIR/has-mac.md"
cat > "$MAC_FILE" << 'EOF'
Network Interface: eth0
MAC Address: 00:11:22:33:44:55
EOF

if "$REPO_DIR/scripts/check-mac-addresses.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_fail "exit 1" "exit 0 (missed MAC)"
else
    test_pass
fi

# Cleanup
rm -f "$CLEAN_FILE" "$MAC_FILE"
rmdir "$FIXTURES_DIR" 2>/dev/null || true

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
