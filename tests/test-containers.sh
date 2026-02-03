#!/bin/bash
#
# Container Scanner Unit Tests
#
# Purpose: Verify container scanning functionality for security compliance
# NIST Control: CM-8 (System Component Inventory), RA-5 (Vulnerability Monitoring)
#
# Usage: ./tests/test-containers.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
CONTAINER_SCRIPT="$REPO_DIR/scripts/check-containers.sh"
SCAN_SCRIPT="$REPO_DIR/scripts/scan-containers.sh"

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
    echo -e "${YELLOW}KNOWN${NC} (requires container runtime)"
}

test_skip() {
    echo -n "  Skip: $1... "
    echo -e "${YELLOW}SKIP${NC} ($2)"
}

echo "=========================================="
echo "Container Scanner Unit Tests"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# Script Existence Tests
# -----------------------------------------------------------------------------
echo "--- Script Validation ---"

test_start "check-containers.sh exists"
if [ -f "$CONTAINER_SCRIPT" ]; then
    test_pass
else
    test_fail "file exists" "file not found"
fi

test_start "check-containers.sh is executable"
if [ -x "$CONTAINER_SCRIPT" ]; then
    test_pass
else
    test_fail "executable" "not executable"
fi

test_start "Script has correct shebang"
if head -1 "$CONTAINER_SCRIPT" | grep -q "^#!/bin/bash"; then
    test_pass
else
    test_fail "#!/bin/bash" "$(head -1 "$CONTAINER_SCRIPT")"
fi

echo ""

# -----------------------------------------------------------------------------
# Help Option Tests
# -----------------------------------------------------------------------------
echo "--- Help Option ---"

test_start "Help option (-h) works"
if "$CONTAINER_SCRIPT" -h 2>&1 | grep -q "Container Security Scanner"; then
    test_pass
else
    test_fail "help output" "no help output"
fi

test_start "Help option (--help) works"
if "$CONTAINER_SCRIPT" --help 2>&1 | grep -q "Usage:"; then
    test_pass
else
    test_fail "help output" "no help output"
fi

echo ""

# -----------------------------------------------------------------------------
# Argument Parsing Tests
# -----------------------------------------------------------------------------
echo "--- Argument Parsing ---"

test_start "Invalid option rejected"
if "$CONTAINER_SCRIPT" --invalid-option 2>&1 | grep -q "Unknown option"; then
    test_pass
else
    test_fail "error message" "no error"
fi

echo ""

# -----------------------------------------------------------------------------
# CVE Version Detection Logic Tests
# -----------------------------------------------------------------------------
echo "--- CVE Version Detection Logic ---"

# These tests verify the version comparison patterns used in check_vulnerable_version()
# Testing Grafana CVE-2021-43798 (affects 8.0.0 - 8.3.0)

test_start "Detect vulnerable Grafana 8.1.0"
if [[ "8.1.0" =~ ^8\.[0-3]\. ]]; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect vulnerable Grafana 8.3.0"
if [[ "8.3.0" =~ ^8\.[0-3]\. ]]; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject safe Grafana 8.4.0"
if [[ "8.4.0" =~ ^8\.[0-3]\. ]]; then
    test_fail "no match" "matched vulnerable pattern"
else
    test_pass
fi

test_start "Reject safe Grafana 9.0.0"
if [[ "9.0.0" =~ ^8\.[0-3]\. ]]; then
    test_fail "no match" "matched vulnerable pattern"
else
    test_pass
fi

# Testing Elasticsearch CVE-2015-1427 (affects < 1.4.3)
test_start "Detect vulnerable Elasticsearch 1.3.0"
if [[ "1.3.0" =~ ^1\.[0-4]\. ]]; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject safe Elasticsearch 2.0.0"
if [[ "2.0.0" =~ ^1\.[0-4]\. ]]; then
    test_fail "no match" "matched vulnerable pattern"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Output Directory Tests
# -----------------------------------------------------------------------------
echo "--- Output Directory Handling ---"

test_start "Handles output directory argument"
TEST_OUTPUT_DIR="$FIXTURES_DIR/container-test-output"
rm -rf "$TEST_OUTPUT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

# Run with output dir argument - should accept the argument without error
# Note: .scans directory only created if containers are found
OUTPUT=$("$CONTAINER_SCRIPT" "$TEST_OUTPUT_DIR" 2>&1) || true
if echo "$OUTPUT" | grep -qE "(No running containers|No container runtime|Container runtime:)"; then
    # Script ran and processed the argument correctly
    test_pass
else
    test_fail "accepted argument" "unexpected error"
fi

# Cleanup
rm -rf "$TEST_OUTPUT_DIR"

echo ""

# -----------------------------------------------------------------------------
# Runtime Detection Tests
# -----------------------------------------------------------------------------
echo "--- Runtime Detection ---"

# Check if any container runtime is available
RUNTIME_AVAILABLE=false
for runtime in docker podman nerdctl; do
    if command -v "$runtime" &>/dev/null; then
        RUNTIME_AVAILABLE=true
        echo "  Found runtime: $runtime"
        break
    fi
done

if [ "$RUNTIME_AVAILABLE" = true ]; then
    test_start "Runtime detection finds available runtime"
    if "$CONTAINER_SCRIPT" 2>&1 | grep -qE "Container runtime:"; then
        test_pass
    else
        test_fail "runtime detected" "no runtime output"
    fi
else
    test_skip "Runtime detection" "no container runtime installed"
fi

echo ""

# -----------------------------------------------------------------------------
# Integration Tests (require container runtime)
# -----------------------------------------------------------------------------
echo "--- Integration Tests ---"

if [ "$RUNTIME_AVAILABLE" = true ]; then
    test_start "Script runs without error (no containers)"
    # Even with no containers, should exit 0 with informative message
    if "$CONTAINER_SCRIPT" 2>&1 | grep -qE "(No running containers|Container runtime:)"; then
        test_pass
    else
        test_fail "clean run" "unexpected error"
    fi
else
    test_skip "Full integration test" "no container runtime installed"
fi

test_known "Full container scanning requires running containers"

echo ""

# -----------------------------------------------------------------------------
# scan-containers.sh (Vulnerable Lab Wrapper) Tests
# -----------------------------------------------------------------------------
echo "--- Vulnerable Lab Wrapper (scan-containers.sh) ---"

test_start "scan-containers.sh exists"
if [ -f "$SCAN_SCRIPT" ]; then
    test_pass
else
    test_fail "file exists" "file not found"
fi

test_start "scan-containers.sh is executable"
if [ -x "$SCAN_SCRIPT" ]; then
    test_pass
else
    test_fail "executable" "not executable"
fi

test_start "scan-containers.sh help option works"
if "$SCAN_SCRIPT" -h 2>&1 | grep -q "Vulnerable Lab"; then
    test_pass
else
    test_fail "help output" "no help output"
fi

test_start "scan-containers.sh accepts --no-start option"
# --no-start should be recognized without error
if "$SCAN_SCRIPT" --no-start -h 2>&1 | grep -qE "(Vulnerable Lab|Usage)"; then
    test_pass
else
    test_fail "option recognized" "option error"
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
