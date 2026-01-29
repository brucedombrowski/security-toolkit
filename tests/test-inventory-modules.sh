#!/bin/bash
#
# Inventory Modules Unit Tests
#
# Purpose: Verify inventory detection helpers and collectors work correctly
# NIST Control: CM-8 (System Component Inventory)
#
# Usage: ./tests/test-inventory-modules.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

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
    if [ -n "${1:-}" ]; then
        echo "    Expected: $1"
        echo "    Got: ${2:-}"
    fi
}

echo "=========================================="
echo "Inventory Modules Unit Tests"
echo "=========================================="
echo ""

# =============================================================================
# Setup: Source the libraries
# =============================================================================

# Create a temporary output file for testing
TEST_OUTPUT_FILE=$(mktemp)
trap "rm -f '$TEST_OUTPUT_FILE'" EXIT

# Source the output library first (defines output function)
OUTPUT_FILE=""
source "$REPO_DIR/scripts/lib/inventory/output.sh"

# Source the detection library
source "$REPO_DIR/scripts/lib/inventory/detect.sh"

# =============================================================================
# Output Library Tests
# =============================================================================
echo "--- Output Library (output.sh) ---"

test_start "output() writes to stdout when OUTPUT_FILE empty"
OUTPUT_FILE=""
result=$(output "test message")
if [ "$result" = "test message" ]; then
    test_pass
else
    test_fail "test message" "$result"
fi

test_start "output() writes to file when OUTPUT_FILE set"
OUTPUT_FILE="$TEST_OUTPUT_FILE"
> "$TEST_OUTPUT_FILE"
output "file message"
result=$(cat "$TEST_OUTPUT_FILE")
if [ "$result" = "file message" ]; then
    test_pass
else
    test_fail "file message" "$result"
fi

test_start "init_output() creates file with mode 600"
init_output "$TEST_OUTPUT_FILE"
if [[ "$(uname)" == "Darwin" ]]; then
    mode=$(stat -f "%OLp" "$TEST_OUTPUT_FILE" 2>/dev/null)
else
    mode=$(stat -c "%a" "$TEST_OUTPUT_FILE" 2>/dev/null)
fi
if [ "$mode" = "600" ]; then
    test_pass
else
    test_fail "600" "$mode"
fi

test_start "show_cui_warning() outputs to stderr"
OUTPUT_FILE=""
result=$(show_cui_warning 2>&1)
if echo "$result" | grep -q "CONTROLLED UNCLASSIFIED INFORMATION"; then
    test_pass
else
    test_fail "CUI warning text" "no CUI warning found"
fi

test_start "output_cui_header() includes timestamp"
OUTPUT_FILE=""
result=$(output_cui_header "2026-01-29T00:00:00Z" "Test Toolkit" "1.0.0" "abc123" "https://example.com")
if echo "$result" | grep -q "2026-01-29T00:00:00Z"; then
    test_pass
else
    test_fail "timestamp in header" "no timestamp found"
fi

test_start "output_cui_header() includes toolkit info"
OUTPUT_FILE=""
result=$(output_cui_header "2026-01-29T00:00:00Z" "Test Toolkit" "1.0.0" "abc123" "https://example.com")
if echo "$result" | grep -q "Test Toolkit 1.0.0"; then
    test_pass
else
    test_fail "toolkit info in header" "no toolkit info found"
fi

test_start "output_cui_footer() includes CUI notice"
OUTPUT_FILE=""
result=$(output_cui_footer)
if echo "$result" | grep -q "CONTROLLED UNCLASSIFIED INFORMATION"; then
    test_pass
else
    test_fail "CUI notice in footer" "no CUI notice found"
fi

echo ""

# =============================================================================
# Detection Library Tests
# =============================================================================
echo "--- Detection Library (detect.sh) ---"

test_start "section_header() formats correctly"
OUTPUT_FILE=""
result=$(section_header "Test Section")
if echo "$result" | grep -q "Test Section:" && echo "$result" | grep -q "^-------------"; then
    test_pass
else
    test_fail "formatted header" "$result"
fi

test_start "detect_tool() finds existing tool (bash)"
OUTPUT_FILE=""
result=$(detect_tool "Bash Test" "bash" "--version" "head -1")
if echo "$result" | grep -q "Bash Test:"; then
    test_pass
else
    test_fail "Bash Test: <version>" "$result"
fi

test_start "detect_tool() reports missing tool"
OUTPUT_FILE=""
result=$(detect_tool "Nonexistent" "this_command_does_not_exist_xyz" "--version" "cat")
if echo "$result" | grep -q "not installed"; then
    test_pass
else
    test_fail "not installed" "$result"
fi

test_start "detect_tool_stderr() captures stderr output"
OUTPUT_FILE=""
# ssh -V outputs to stderr
if command -v ssh >/dev/null 2>&1; then
    result=$(detect_tool_stderr "SSH Test" "ssh" "-V")
    if echo "$result" | grep -q "SSH Test:"; then
        test_pass
    else
        test_fail "SSH Test: <version>" "$result"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (ssh not installed)"
fi

# macOS-specific tests
if [[ "$(uname)" == "Darwin" ]]; then
    test_start "detect_macos_app() finds Safari"
    OUTPUT_FILE=""
    result=$(detect_macos_app "Safari Test" "/Applications/Safari.app")
    if echo "$result" | grep -qE "Safari Test: [0-9]"; then
        test_pass
    else
        test_fail "Safari Test: <version>" "$result"
    fi

    test_start "detect_macos_app() reports missing app"
    OUTPUT_FILE=""
    result=$(detect_macos_app "Missing App" "/Applications/NonexistentApp12345.app")
    if echo "$result" | grep -q "not installed"; then
        test_pass
    else
        test_fail "not installed" "$result"
    fi

    test_start "detect_macos_app_paths() finds first available"
    OUTPUT_FILE=""
    result=$(detect_macos_app_paths "Safari Multi" "/Applications/NonexistentApp.app" "/Applications/Safari.app")
    if echo "$result" | grep -qE "Safari Multi: [0-9]"; then
        test_pass
    else
        test_fail "Safari Multi: <version>" "$result"
    fi

    test_start "find_macos_ide_version() returns version string"
    result=$(find_macos_ide_version "/Applications/Safari.app" || echo "")
    if [ -n "$result" ] && [[ "$result" =~ ^[0-9] ]]; then
        test_pass
    else
        test_fail "version number" "$result"
    fi
fi

echo ""

# =============================================================================
# Collector Module Tests
# =============================================================================
echo "--- Collector Modules ---"

# Source all collectors
for collector in "$REPO_DIR/scripts/lib/inventory/collectors/"*.sh; do
    source "$collector"
done

# Test each collector produces output without errors
collectors=(
    "collect_os_info:Operating System"
    "collect_network:Network Interfaces"
    "collect_packages:Installed Software"
    "collect_security_tools:Security Tools"
    "collect_languages:Programming Languages"
    "collect_ides:Development Tools"
    "collect_browsers:Web Browsers"
    "collect_backup:Backup"
    "collect_remote_desktop:Remote Desktop"
    "collect_productivity:Productivity"
    "collect_containers:Containers"
    "collect_web_servers:Web Servers"
    "collect_databases:Database"
)

for entry in "${collectors[@]}"; do
    func="${entry%%:*}"
    expected_text="${entry##*:}"

    test_start "$func() runs without error"
    OUTPUT_FILE=""
    if result=$($func 2>&1); then
        if echo "$result" | grep -qi "$expected_text"; then
            test_pass
        else
            test_fail "output containing '$expected_text'" "function ran but output missing expected text"
        fi
    else
        test_fail "success" "function failed with exit code $?"
    fi
done

echo ""

# =============================================================================
# Integration Test: Full Inventory Collection
# =============================================================================
echo "--- Integration Test ---"

test_start "Full inventory collection runs successfully"
if "$REPO_DIR/scripts/collect-host-inventory.sh" >/dev/null 2>&1; then
    test_pass
else
    test_fail "exit code 0" "non-zero exit"
fi

test_start "Full inventory includes all sections"
OUTPUT_FILE=""
result=$("$REPO_DIR/scripts/collect-host-inventory.sh" 2>/dev/null)
missing_sections=""
for section in "Operating System" "Network Interfaces" "Security Tools" "Programming Languages" "Web Browsers" "Database"; do
    if ! echo "$result" | grep -qi "$section"; then
        missing_sections="$missing_sections $section"
    fi
done
if [ -z "$missing_sections" ]; then
    test_pass
else
    test_fail "all sections present" "missing:$missing_sections"
fi

test_start "File output mode works correctly"
test_file=$(mktemp)
if "$REPO_DIR/scripts/collect-host-inventory.sh" "$test_file" 2>/dev/null; then
    if [ -s "$test_file" ] && grep -q "Operating System" "$test_file"; then
        test_pass
    else
        test_fail "non-empty file with content" "file empty or missing content"
    fi
else
    test_fail "exit code 0" "non-zero exit"
fi
rm -f "$test_file"

echo ""

# =============================================================================
# Summary
# =============================================================================
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
