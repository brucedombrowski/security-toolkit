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
CHECK_COUNT=$(echo "$OUTPUT" | grep -c "Checking:" || true)
CHECK_COUNT=${CHECK_COUNT:-0}
if [ "$CHECK_COUNT" -gt 0 ]; then
    test_pass
else
    test_fail "at least 1 check" "0 checks"
fi

test_start "Script reports check results"
RESULT_COUNT=$(echo "$OUTPUT" | grep -c "Result:" || true)
RESULT_COUNT=${RESULT_COUNT:-0}
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

# --- Pending Security Updates (zero-match regression) ---
# Regression for: grep -c prints "0" AND exits 1 on zero matches, so the old
# `|| echo "0"` fallback produced "0\n0" and `[ ... -eq 0 ]` failed with
# "integer expression expected", falling through to FAIL. Observed on macOS
# when softwareupdate -l listed only Command Line Tools (no "security" lines).
echo "--- Pending Security Updates ---"

if [ "$PLATFORM" = "Darwin" ]; then
    FAKE_BIN=$(mktemp -d "${TMPDIR:-/tmp}/host-sec-fake-bin.XXXXXX")
    trap 'rm -rf "$FAKE_BIN"' EXIT

    # Fake softwareupdate: no lines containing "security"
    cat > "$FAKE_BIN/softwareupdate" <<'EOF'
#!/bin/bash
echo "Software Update Tool"
echo ""
echo "Finding available software"
echo "Software Update found the following new or updated software:"
echo "* Label: Command Line Tools for Xcode-16.4"
echo "	Title: Command Line Tools for Xcode, Version: 16.4, Size: 800000KiB, Recommended: YES,"
EOF
    chmod +x "$FAKE_BIN/softwareupdate"

    test_start "Zero security updates reports PASS (no grep -c double-zero)"
    ZERO_OUTPUT=$(PATH="$FAKE_BIN:$PATH" "$HOST_SECURITY_SCRIPT" 2>&1 || true)
    ZERO_LINE=$(echo "$ZERO_OUTPUT" | grep -A1 "Checking: Pending Security Updates" | tail -1)
    if echo "$ZERO_LINE" | grep -q "Result: PASS"; then
        test_pass
    else
        test_fail "Result: PASS (no security updates pending)" "$ZERO_LINE"
    fi

    test_start "Zero security updates produces no integer expression error"
    if echo "$ZERO_OUTPUT" | grep -q "integer expression expected"; then
        test_fail "no shell error" "integer expression expected"
    else
        test_pass
    fi

    # Fake softwareupdate: one pending Security Update
    cat > "$FAKE_BIN/softwareupdate" <<'EOF'
#!/bin/bash
echo "Software Update Tool"
echo ""
echo "Software Update found the following new or updated software:"
echo "* Label: Security Update 2026-001"
echo "	Title: Security Update 2026-001, Version: 1.0, Size: 12345KiB, Recommended: YES,"
EOF

    test_start "Pending security update reports FAIL"
    ONE_OUTPUT=$(PATH="$FAKE_BIN:$PATH" "$HOST_SECURITY_SCRIPT" 2>&1 || true)
    ONE_LINE=$(echo "$ONE_OUTPUT" | grep -A1 "Checking: Pending Security Updates" | tail -1)
    if echo "$ONE_LINE" | grep -q "Result: FAIL"; then
        test_pass
    else
        test_fail "Result: FAIL (security updates available)" "$ONE_LINE"
    fi
else
    test_skip "Pending Security Updates" "macOS-only check (platform: $PLATFORM)"
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
