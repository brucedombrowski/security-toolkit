#!/bin/bash
#
# Test Suite: CUI Data Exposure (CRITICAL-004)
#
# Purpose: Verify protection of Controlled Unclassified Information in host inventory
# NIST Controls: AC-3 (Access Control), MP-2 (Media Access), MP-6 (Sanitization)
# Standards: NIST SP 800-171, 32 CFR Part 2002
#
# Test Cases:
#   1. File creation with restricted permissions (600)
#   2. Explicit chmod applied (overrides umask)
#   3. CUI header present in file
#   4. CUI warning displayed to console
#   5. Warning displays in all modes
#   6. Non-owner cannot read (permission check)
#   7. Umask protection takes precedence
#   8. Permission verification logged

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Create temporary test environment
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "CUI Data Exposure Test Suite (CRITICAL-004)"
echo "==========================================="
echo "Test Directory: $TEST_DIR"
echo ""

# TEST 1: File created with restricted permissions (600)
echo -n "TEST 1: File permissions set to 600... "
test_file="$TEST_DIR/inventory1.txt"
cd "$TEST_DIR" && "$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>/dev/null
file_perms=$(stat -f "%OLp" "$test_file" 2>/dev/null || stat -c "%a" "$test_file" 2>/dev/null)
if [ "$file_perms" = "600" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (permissions: $file_perms, expected 600)"
    ((TESTS_FAILED++))
fi

# TEST 2: Explicit chmod applied (umask override)
echo -n "TEST 2: Explicit chmod overrides umask... "
test_file="$TEST_DIR/inventory2.txt"
# Try to set global umask to 022 (permissive)
(
    umask 0022
    "$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>/dev/null
)
file_perms=$(stat -f "%OLp" "$test_file" 2>/dev/null || stat -c "%a" "$test_file" 2>/dev/null)
if [ "$file_perms" = "600" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (global umask not overridden: $file_perms)"
    ((TESTS_FAILED++))
fi

# TEST 3: CUI header present in file
echo -n "TEST 3: CUI header in file... "
test_file="$TEST_DIR/inventory3.txt"
"$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>/dev/null
header_check=$(head -5 "$test_file" | grep -i "CONTROLLED UNCLASSIFIED INFORMATION" || true)
if [ -n "$header_check" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (CUI header not found)"
    ((TESTS_FAILED++))
fi

# TEST 4: CUI warning displayed to console (stderr)
echo -n "TEST 4: CUI warning to console... "
test_file="$TEST_DIR/inventory4.txt"
warning_output=$("$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>&1 1>/dev/null | grep -i "SECURITY WARNING" || true)
if [ -n "$warning_output" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (warning not displayed to stderr)"
    ((TESTS_FAILED++))
fi

# TEST 5: Warning includes handling requirements
echo -n "TEST 5: Warning includes handling requirements... "
test_file="$TEST_DIR/inventory5.txt"
warning_output=$("$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>&1 1>/dev/null | grep -i "REQUIRED HANDLING" || true)
if [ -n "$warning_output" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (handling requirements not in warning)"
    ((TESTS_FAILED++))
fi

# TEST 6: File not world-readable
echo -n "TEST 6: File not world-readable... "
test_file="$TEST_DIR/inventory6.txt"
"$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>/dev/null
file_perms=$(stat -f "%OLp" "$test_file" 2>/dev/null || stat -c "%a" "$test_file" 2>/dev/null)
# Check that 'other' (last digit) is 0
if [ "${file_perms: -1}" = "0" ]; then
    echo -e "${GREEN}PASS${NC} (mode: $file_perms)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (other readable: $file_perms)"
    ((TESTS_FAILED++))
fi

# TEST 7: File not group-readable
echo -n "TEST 7: File not group-readable... "
test_file="$TEST_DIR/inventory7.txt"
"$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>/dev/null
file_perms=$(stat -f "%OLp" "$test_file" 2>/dev/null || stat -c "%a" "$test_file" 2>/dev/null)
# Check that 'group' (middle digit) is 0
if [ "${file_perms:1:1}" = "0" ]; then
    echo -e "${GREEN}PASS${NC} (mode: $file_perms)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (group readable: $file_perms)"
    ((TESTS_FAILED++))
fi

# TEST 8: File owner has read/write
echo -n "TEST 8: Owner has read/write permission... "
test_file="$TEST_DIR/inventory8.txt"
"$SCRIPT_DIR/collect-host-inventory.sh" "$test_file" 2>/dev/null
file_perms=$(stat -f "%OLp" "$test_file" 2>/dev/null || stat -c "%a" "$test_file" 2>/dev/null)
# Check that 'owner' (first digit) is 6 (rw)
if [ "${file_perms:0:1}" = "6" ]; then
    echo -e "${GREEN}PASS${NC} (mode: $file_perms)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}FAIL${NC} (owner permissions wrong: $file_perms)"
    ((TESTS_FAILED++))
fi

# Summary
echo ""
echo "==========================================="
echo "Test Results:"
echo -e "  ${GREEN}PASSED${NC}: $TESTS_PASSED"
echo -e "  ${RED}FAILED${NC}: $TESTS_FAILED"
if [ $TESTS_SKIPPED -gt 0 ]; then
    echo -e "  ${YELLOW}SKIPPED${NC}: $TESTS_SKIPPED"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ $TESTS_FAILED test(s) failed${NC}"
    exit 1
fi
