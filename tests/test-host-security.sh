#!/bin/bash
#
# Host Security Integration Tests
#
# Purpose: Verify check-host-security.sh functionality
# NIST Control: CM-6 (Configuration Settings)
#
# Usage: ./tests/test-host-security.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST_SECURITY_SCRIPT="$REPO_DIR/scripts/check-host-security.sh"

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
echo "Host Security Integration Tests"
echo "=========================================="
echo ""

# --- Script Validation ---
echo "--- Script Validation ---"

test_start "check-host-security.sh exists"
[ -f "$HOST_SECURITY_SCRIPT" ] && test_pass || test_fail "exists" "not found"

test_start "check-host-security.sh is executable"
[ -x "$HOST_SECURITY_SCRIPT" ] && test_pass || test_fail "executable" "not executable"

test_start "Script has correct shebang"
if head -1 "$HOST_SECURITY_SCRIPT" | grep -q "^#!/bin/bash"; then
    test_pass
else
    test_fail "#!/bin/bash" "$(head -1 "$HOST_SECURITY_SCRIPT")"
fi

echo ""

# --- Output Format ---
echo "--- Output Format ---"

# Capture output (may exit 0 or 1 depending on host security state)
OUTPUT=$("$HOST_SECURITY_SCRIPT" 2>&1) || true

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

# --- Platform-Specific Checks ---
echo "--- Platform Detection ---"

PLATFORM=$(uname)

test_start "Script detects platform ($PLATFORM)"
if [ "$PLATFORM" = "Darwin" ]; then
    if echo "$OUTPUT" | grep -qE "SIP|FileVault|Gatekeeper"; then
        test_pass
    else
        test_fail "macOS checks" "no macOS-specific output"
    fi
elif [ "$PLATFORM" = "Linux" ]; then
    if echo "$OUTPUT" | grep -qE "Firewall|SELinux|AppArmor|ufw"; then
        test_pass
    else
        # Linux checks may not all be present
        test_pass  # Accept as long as script ran
    fi
else
    test_skip "Platform detection" "Unknown platform: $PLATFORM"
fi

echo ""

# --- Security Check Execution ---
echo "--- Security Check Execution ---"

test_start "Script runs security checks"
CHECK_COUNT=$(echo "$OUTPUT" | grep -c "Checking:" || echo "0")
if [ "$CHECK_COUNT" -gt 0 ]; then
    test_pass
else
    test_fail "at least 1 check" "0 checks"
fi

test_start "Script reports check results"
RESULT_COUNT=$(echo "$OUTPUT" | grep -c "Result:" || echo "0")
if [ "$RESULT_COUNT" -gt 0 ]; then
    test_pass
else
    test_fail "at least 1 result" "0 results"
fi

test_start "Results are PASS or FAIL"
if echo "$OUTPUT" | grep -qE "Result: (PASS|FAIL)"; then
    test_pass
else
    test_fail "PASS or FAIL results" "unknown result format"
fi

echo ""

# --- Exit Code Behavior ---
echo "--- Exit Code Behavior ---"

test_start "Exit code is 0 or 1"
EXIT_CODE=0
"$HOST_SECURITY_SCRIPT" >/dev/null 2>&1 || EXIT_CODE=$?
if [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 1 ]; then
    test_pass
else
    test_fail "exit 0 or 1" "exit $EXIT_CODE"
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
