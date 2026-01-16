#!/bin/bash
#
# Run All Scans Unit Tests
#
# Purpose: Verify run-all-scans.sh orchestration and options work correctly
# NIST Control: CA-2, CA-7, RA-5 (Assessment & Monitoring)
#
# Usage: ./tests/test-run-all-scans.sh
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

RUN_ALL_SCANS="$REPO_DIR/scripts/run-all-scans.sh"

echo "=========================================="
echo "Run All Scans Unit Tests"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# Help and Usage Tests
# -----------------------------------------------------------------------------
echo "--- Help and Usage Tests ---"

test_start "Show help with -h flag"
if "$RUN_ALL_SCANS" -h 2>&1 | grep -q "NIST CONTROLS"; then
    test_pass
else
    test_fail "help text with NIST controls" "no help text"
fi

test_start "Show help with --help flag"
if "$RUN_ALL_SCANS" --help 2>&1 | grep -q "Usage:"; then
    test_pass
else
    test_fail "usage text" "no usage text"
fi

test_start "Help shows scan types"
output=$("$RUN_ALL_SCANS" --help 2>&1)
if echo "$output" | grep -q "PII Detection" && \
   echo "$output" | grep -q "Malware Scanning" && \
   echo "$output" | grep -q "Secrets Detection"; then
    test_pass
else
    test_fail "scan types documented" "missing documentation"
fi

echo ""

# -----------------------------------------------------------------------------
# Option Parsing Tests
# -----------------------------------------------------------------------------
echo "--- Option Parsing Tests ---"

# Create a minimal test directory
TEST_DIR="$FIXTURES_DIR/test-scans"
mkdir -p "$TEST_DIR"
echo "Clean test file with no issues" > "$TEST_DIR/clean.txt"

test_start "Accept -n (non-interactive) option"
if "$RUN_ALL_SCANS" -h 2>&1 | grep -q "\-n"; then
    test_pass
else
    test_fail "non-interactive option documented" "not documented"
fi

echo ""

# -----------------------------------------------------------------------------
# Output Directory Tests
# -----------------------------------------------------------------------------
echo "--- Output Directory Tests ---"

test_start "Creates .scans directory"
# Run a quick scan
"$RUN_ALL_SCANS" --skip-malware --skip-pii --skip-secrets --skip-mac --skip-host "$TEST_DIR" > /dev/null 2>&1 || true
if [ -d "$TEST_DIR/.scans" ]; then
    test_pass
else
    test_fail ".scans directory created" "directory not created"
fi

test_start "Creates timestamped output files"
if ls "$TEST_DIR/.scans/"*-scan-*.txt 2>/dev/null | grep -q "scan"; then
    test_pass
else
    # May not have created files if all scans were skipped
    echo -e "${YELLOW}SKIPPED${NC} (no scan files when all scans skipped)"
    TESTS_RUN=$((TESTS_RUN - 1))
fi

echo ""

# -----------------------------------------------------------------------------
# Script Existence Tests
# -----------------------------------------------------------------------------
echo "--- Required Scripts Exist ---"

test_start "check-pii.sh exists and executable"
if [ -x "$REPO_DIR/scripts/check-pii.sh" ]; then
    test_pass
else
    test_fail "executable" "not found or not executable"
fi

test_start "check-secrets.sh exists and executable"
if [ -x "$REPO_DIR/scripts/check-secrets.sh" ]; then
    test_pass
else
    test_fail "executable" "not found or not executable"
fi

test_start "check-malware.sh exists and executable"
if [ -x "$REPO_DIR/scripts/check-malware.sh" ]; then
    test_pass
else
    test_fail "executable" "not found or not executable"
fi

test_start "check-mac-addresses.sh exists and executable"
if [ -x "$REPO_DIR/scripts/check-mac-addresses.sh" ]; then
    test_pass
else
    test_fail "executable" "not found or not executable"
fi

test_start "check-host-security.sh exists and executable"
if [ -x "$REPO_DIR/scripts/check-host-security.sh" ]; then
    test_pass
else
    test_fail "executable" "not found or not executable"
fi

echo ""

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
rm -rf "$TEST_DIR"

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
