#!/bin/bash
#
# Application Security Integration Tests
#
# Purpose: Verify check-applications.sh functionality
# NIST Control: CM-7 (Least Functionality), CM-11 (User-Installed Software), SI-2 (Flaw Remediation)
#
# Usage: ./tests/test-applications.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APPLICATIONS_SCRIPT="$REPO_DIR/scripts/check-applications.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

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

test_skip() {
    echo -n "  Skip: $1... "
    echo -e "${YELLOW}SKIP${NC} ($2)"
}

echo "=========================================="
echo "Application Security Integration Tests"
echo "=========================================="
echo ""

# --- Script Validation ---
echo "--- Script Validation ---"

test_start "check-applications.sh exists"
[ -f "$APPLICATIONS_SCRIPT" ] && test_pass || test_fail "exists" "not found"

test_start "check-applications.sh is executable"
[ -x "$APPLICATIONS_SCRIPT" ] && test_pass || test_fail "executable" "not executable"

test_start "Script has correct shebang"
if head -1 "$APPLICATIONS_SCRIPT" | grep -q "^#!/bin/bash"; then
    test_pass
else
    test_fail "#!/bin/bash" "$(head -1 "$APPLICATIONS_SCRIPT")"
fi

test_start "Script uses set -eu"
if head -30 "$APPLICATIONS_SCRIPT" | grep -q "set -eu"; then
    test_pass
else
    test_fail "set -eu" "not found"
fi

echo ""

# --- NIST Control Mapping ---
echo "--- NIST Control Mapping ---"

test_start "Script documents CM-7 control"
if grep -q "CM-7" "$APPLICATIONS_SCRIPT"; then
    test_pass
else
    test_fail "CM-7 in comments" "not found"
fi

test_start "Script documents CM-11 control"
if grep -q "CM-11" "$APPLICATIONS_SCRIPT"; then
    test_pass
else
    test_fail "CM-11 in comments" "not found"
fi

test_start "Script documents SI-2 control"
if grep -q "SI-2" "$APPLICATIONS_SCRIPT"; then
    test_pass
else
    test_fail "SI-2 in comments" "not found"
fi

echo ""

# --- Output Format ---
echo "--- Output Format ---"

# Capture output (may exit 0 or 1 depending on application security state)
OUTPUT=$("$APPLICATIONS_SCRIPT" 2>&1) || true

test_start "Output includes hostname"
if echo "$OUTPUT" | grep -q "Host:"; then
    test_pass
else
    test_fail "Host: in output" "no hostname"
fi

test_start "Output includes timestamp"
if echo "$OUTPUT" | grep -q "Timestamp:"; then
    test_pass
else
    test_fail "Timestamp: in output" "no timestamp"
fi

test_start "Output includes toolkit version"
if echo "$OUTPUT" | grep -q "Toolkit:"; then
    test_pass
else
    test_fail "Toolkit: in output" "no toolkit info"
fi

test_start "Output shows OVERALL RESULT"
if echo "$OUTPUT" | grep -q "OVERALL RESULT:"; then
    test_pass
else
    test_fail "OVERALL RESULT: in output" "no result"
fi

echo ""

# --- Security Check Execution ---
echo "--- Security Check Execution ---"

test_start "Script checks for EOL software"
if echo "$OUTPUT" | grep -q "Checking for EOL/Deprecated Software"; then
    test_pass
else
    test_fail "EOL software check" "not found"
fi

test_start "Script checks for duplicate applications"
if echo "$OUTPUT" | grep -q "Checking for Duplicate Applications"; then
    test_pass
else
    test_fail "duplicate app check" "not found"
fi

test_start "Script provides inventory summary"
if echo "$OUTPUT" | grep -q "Application Inventory Summary"; then
    test_pass
else
    test_fail "inventory summary" "not found"
fi

# Platform-specific checks
PLATFORM=$(uname)
if [ "$PLATFORM" = "Darwin" ]; then
    test_start "Script checks unsigned apps (macOS)"
    if echo "$OUTPUT" | grep -q "Checking for Unsigned/Unnotarized Applications"; then
        test_pass
    else
        test_fail "unsigned app check" "not found"
    fi
else
    test_skip "Unsigned app check" "macOS-specific"
fi

echo ""

# --- Exit Code Behavior ---
echo "--- Exit Code Behavior ---"

test_start "Exit code is 0 or 1"
EXIT_CODE=0
"$APPLICATIONS_SCRIPT" >/dev/null 2>&1 || EXIT_CODE=$?
if [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 1 ]; then
    test_pass
else
    test_fail "exit 0 or 1" "exit $EXIT_CODE"
fi

echo ""

# --- EOL Software Detection ---
echo "--- EOL Software Pattern Detection ---"

test_start "Script defines EOL software patterns"
if grep -q "EOL_SOFTWARE" "$APPLICATIONS_SCRIPT"; then
    test_pass
else
    test_fail "EOL_SOFTWARE array" "not found"
fi

test_start "Script checks for Flash Player"
if grep -qi "Flash Player" "$APPLICATIONS_SCRIPT"; then
    test_pass
else
    test_fail "Flash Player pattern" "not found"
fi

test_start "Script checks for Silverlight"
if grep -qi "Silverlight" "$APPLICATIONS_SCRIPT"; then
    test_pass
else
    test_fail "Silverlight pattern" "not found"
fi

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
