#!/bin/bash
#
# Progress Library Unit Tests
#
# Tests the progress indicator functions in scripts/lib/progress.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../scripts/lib"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Test helper
test_case() {
    local name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "TEST $TESTS_RUN: $name... "
}

pass() {
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    local reason="${1:-}"
    echo -e "${RED}FAIL${NC}"
    [ -n "$reason" ] && echo "  Reason: $reason"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

echo "Progress Library Unit Tests"
echo "==========================="
echo ""

# Source the library
source "$LIB_DIR/progress.sh"

# ============================================================================
# Test: Library loads
# ============================================================================
test_case "Library loads without error"
if [ -f "$LIB_DIR/progress.sh" ]; then
    pass
else
    fail "progress.sh not found"
fi

# ============================================================================
# Test: TTY detection variable exists
# ============================================================================
test_case "PROGRESS_IS_TTY variable defined"
if [ -n "${PROGRESS_IS_TTY+x}" ]; then
    pass
else
    fail "PROGRESS_IS_TTY not defined"
fi

# ============================================================================
# Test: format_elapsed function exists
# ============================================================================
test_case "format_elapsed function exists"
if type format_elapsed >/dev/null 2>&1; then
    pass
else
    fail "format_elapsed not defined"
fi

# ============================================================================
# Test: format_elapsed seconds
# ============================================================================
test_case "format_elapsed handles seconds"
result=$(format_elapsed 45)
if [ "$result" = "45s" ]; then
    pass
else
    fail "Expected '45s', got '$result'"
fi

# ============================================================================
# Test: format_elapsed minutes
# ============================================================================
test_case "format_elapsed handles minutes"
result=$(format_elapsed 125)
if [ "$result" = "2m 5s" ]; then
    pass
else
    fail "Expected '2m 5s', got '$result'"
fi

# ============================================================================
# Test: format_elapsed hours
# ============================================================================
test_case "format_elapsed handles hours"
result=$(format_elapsed 3725)
if [ "$result" = "1h 2m" ]; then
    pass
else
    fail "Expected '1h 2m', got '$result'"
fi

# ============================================================================
# Test: progress_start sets start time
# ============================================================================
test_case "progress_start sets PROGRESS_START_TIME"
PROGRESS_START_TIME=""
progress_start
if [ -n "$PROGRESS_START_TIME" ]; then
    pass
else
    fail "PROGRESS_START_TIME not set"
fi

# ============================================================================
# Test: progress_bar function exists
# ============================================================================
test_case "progress_bar function exists"
if type progress_bar >/dev/null 2>&1; then
    pass
else
    fail "progress_bar not defined"
fi

# ============================================================================
# Test: progress_step function exists
# ============================================================================
test_case "progress_step function exists"
if type progress_step >/dev/null 2>&1; then
    pass
else
    fail "progress_step not defined"
fi

# ============================================================================
# Test: spinner_start function exists
# ============================================================================
test_case "spinner_start function exists"
if type spinner_start >/dev/null 2>&1; then
    pass
else
    fail "spinner_start not defined"
fi

# ============================================================================
# Test: spinner_stop function exists
# ============================================================================
test_case "spinner_stop function exists"
if type spinner_stop >/dev/null 2>&1; then
    pass
else
    fail "spinner_stop not defined"
fi

# ============================================================================
# Test: status_line function exists
# ============================================================================
test_case "status_line function exists"
if type status_line >/dev/null 2>&1; then
    pass
else
    fail "status_line not defined"
fi

# ============================================================================
# Test: progress_bar handles zero total
# ============================================================================
test_case "progress_bar handles zero total gracefully"
# Should not crash or output errors
result=$(progress_bar 0 0 "Test" 2>&1)
if [ $? -eq 0 ]; then
    pass
else
    fail "Crashed on zero total"
fi

# ============================================================================
# Test: progress_step output format
# ============================================================================
test_case "progress_step outputs correct format"
# Force non-TTY mode for predictable output
PROGRESS_IS_TTY=0
result=$(progress_step 2 6 "Test Step")
if echo "$result" | grep -q "\[2/6\] Test Step"; then
    pass
else
    fail "Expected '[2/6] Test Step', got '$result'"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "==========================================="
echo "Test Results:"
echo "  ${GREEN}PASSED${NC}: $TESTS_PASSED"
echo "  ${RED}FAILED${NC}: $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
