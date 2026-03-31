#!/bin/bash
#
# AI Software Detection Tests
#
# Purpose: Test the AI software detection collector
# Tests: Catalog parsing, detection methods, output formatting
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Test helpers
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

echo "AI Software Detection Tests"
echo "============================"
echo ""

# ============================================================================
# Catalog Tests
# ============================================================================

echo "Catalog Structure Tests:"

test_start "Catalog file exists"
if [ -f "$REPO_DIR/data/ai-software-catalog.json" ]; then
    test_pass
else
    test_fail "file exists" "file not found"
fi

test_start "Catalog is valid JSON"
if jq empty "$REPO_DIR/data/ai-software-catalog.json" 2>/dev/null; then
    test_pass
else
    test_fail "valid JSON" "parse error"
fi

test_start "Catalog has required fields"
if jq -e '.title and .catalogVersion and .categories' "$REPO_DIR/data/ai-software-catalog.json" >/dev/null 2>&1; then
    test_pass
else
    test_fail "title, catalogVersion, categories" "missing fields"
fi

test_start "Catalog has frameworks category"
if jq -e '.categories.frameworks | length > 0' "$REPO_DIR/data/ai-software-catalog.json" >/dev/null 2>&1; then
    test_pass
else
    test_fail "frameworks array" "missing or empty"
fi

test_start "Catalog has apiServices category"
if jq -e '.categories.apiServices | length > 0' "$REPO_DIR/data/ai-software-catalog.json" >/dev/null 2>&1; then
    test_pass
else
    test_fail "apiServices array" "missing or empty"
fi

test_start "Catalog has localRuntimes category"
if jq -e '.categories.localRuntimes | length > 0' "$REPO_DIR/data/ai-software-catalog.json" >/dev/null 2>&1; then
    test_pass
else
    test_fail "localRuntimes array" "missing or empty"
fi

test_start "Catalog has devTools category"
if jq -e '.categories.devTools | length > 0' "$REPO_DIR/data/ai-software-catalog.json" >/dev/null 2>&1; then
    test_pass
else
    test_fail "devTools array" "missing or empty"
fi

test_start "Each framework has name and detectMethods"
INVALID=$(jq -r '.categories.frameworks[] | select(.name == null or .detectMethods == null) | .name // "unnamed"' "$REPO_DIR/data/ai-software-catalog.json" 2>/dev/null)
if [ -z "$INVALID" ]; then
    test_pass
else
    test_fail "all have name and detectMethods" "missing in: $INVALID"
fi

echo ""

# ============================================================================
# Collector Module Tests
# ============================================================================

echo "Collector Module Tests:"

test_start "Collector script exists"
if [ -f "$REPO_DIR/scripts/lib/inventory/collectors/ai-software.sh" ]; then
    test_pass
else
    test_fail "file exists" "file not found"
fi

test_start "Collector script is syntactically valid"
if bash -n "$REPO_DIR/scripts/lib/inventory/collectors/ai-software.sh" 2>/dev/null; then
    test_pass
else
    test_fail "no syntax errors" "syntax error"
fi

test_start "Collector script has collect_ai_software function"
if grep -q "^collect_ai_software()" "$REPO_DIR/scripts/lib/inventory/collectors/ai-software.sh"; then
    test_pass
else
    test_fail "function defined" "function not found"
fi

test_start "Collector is sourced in host inventory"
if grep -q "ai-software.sh" "$REPO_DIR/scripts/collect-host-inventory.sh"; then
    test_pass
else
    test_fail "sourced" "not sourced"
fi

test_start "Collector is called in host inventory"
if grep -q "collect_ai_software" "$REPO_DIR/scripts/collect-host-inventory.sh"; then
    test_pass
else
    test_fail "called" "not called"
fi

echo ""

# ============================================================================
# Integration Tests
# ============================================================================

echo "Integration Tests:"

test_start "Host inventory runs without error"
if "$REPO_DIR/scripts/collect-host-inventory.sh" >/dev/null 2>&1; then
    test_pass
else
    test_fail "exit 0" "non-zero exit"
fi

test_start "AI/ML Software section appears in output"
OUTPUT=$("$REPO_DIR/scripts/collect-host-inventory.sh" 2>/dev/null)
if echo "$OUTPUT" | grep -q "AI/ML Software:"; then
    test_pass
else
    test_fail "AI/ML Software: header" "not found"
fi

test_start "Category headers appear in output"
if echo "$OUTPUT" | grep -q "\[Frameworks\]"; then
    test_pass
else
    test_fail "[Frameworks] header" "not found"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================

echo "============================"
echo "Tests run: $TESTS_RUN"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    exit 1
else
    echo -e "Failed: $TESTS_FAILED"
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
