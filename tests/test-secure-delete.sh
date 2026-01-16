#!/bin/bash
#
# Secure Delete Unit Tests
#
# Purpose: Verify secure-delete.sh correctly handles file deletion and safety checks
# NIST Control: MP-6 (Media Sanitization)
#
# Usage: ./tests/test-secure-delete.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed
#
# NOTE: These tests use --dry-run mode to avoid actual file deletion during testing

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

SECURE_DELETE="$REPO_DIR/scripts/secure-delete.sh"

echo "=========================================="
echo "Secure Delete Unit Tests"
echo "=========================================="
echo ""

# Setup fixtures
mkdir -p "$FIXTURES_DIR"

# -----------------------------------------------------------------------------
# Help and Usage Tests
# -----------------------------------------------------------------------------
echo "--- Help and Usage Tests ---"

test_start "Show help with -h flag"
if "$SECURE_DELETE" -h 2>&1 | grep -q "NIST SP 800-88"; then
    test_pass
else
    test_fail "help text with NIST reference" "no help text"
fi

test_start "Show help with --help flag"
if "$SECURE_DELETE" --help 2>&1 | grep -q "Usage:"; then
    test_pass
else
    test_fail "usage text" "no usage text"
fi

echo ""

# -----------------------------------------------------------------------------
# Argument Validation Tests
# -----------------------------------------------------------------------------
echo "--- Argument Validation Tests ---"

test_start "Error on missing target"
if "$SECURE_DELETE" 2>&1 | grep -q "No target specified"; then
    test_pass
else
    test_fail "error message" "no error"
fi

test_start "Error on non-existent file"
if "$SECURE_DELETE" "/nonexistent/file/path" 2>&1 | grep -q "does not exist"; then
    test_pass
else
    test_fail "error message" "no error"
fi

test_start "Error on directory without -r flag"
if "$SECURE_DELETE" "$FIXTURES_DIR" 2>&1 | grep -q "is a directory"; then
    test_pass
else
    test_fail "error message" "no error"
fi

test_start "Error on unknown option"
if "$SECURE_DELETE" --invalid-option 2>&1 | grep -q "Unknown option"; then
    test_pass
else
    test_fail "error message" "no error"
fi

echo ""

# -----------------------------------------------------------------------------
# Dry Run Tests (Core functionality without actual deletion)
# -----------------------------------------------------------------------------
echo "--- Dry Run Tests ---"

# Create a test file
TEST_FILE="$FIXTURES_DIR/test-delete-me.txt"
echo "This is test content for secure deletion" > "$TEST_FILE"

test_start "Dry run on single file"
output=$("$SECURE_DELETE" -n -f "$TEST_FILE" 2>&1)
if echo "$output" | grep -q "Would securely delete"; then
    test_pass
else
    test_fail "Would securely delete message" "unexpected output"
fi

test_start "File still exists after dry run"
if [ -f "$TEST_FILE" ]; then
    test_pass
else
    test_fail "file exists" "file deleted"
fi

# Create a test directory structure
TEST_DIR="$FIXTURES_DIR/test-dir-delete"
mkdir -p "$TEST_DIR/subdir"
echo "file1" > "$TEST_DIR/file1.txt"
echo "file2" > "$TEST_DIR/file2.txt"
echo "file3" > "$TEST_DIR/subdir/file3.txt"

test_start "Dry run on directory with -r flag"
output=$("$SECURE_DELETE" -n -r -f "$TEST_DIR" 2>&1)
if echo "$output" | grep -q "Would securely delete 3 files"; then
    test_pass
else
    test_fail "Would delete 3 files" "unexpected output: $output"
fi

test_start "Directory still exists after dry run"
if [ -d "$TEST_DIR" ]; then
    test_pass
else
    test_fail "directory exists" "directory deleted"
fi

echo ""

# -----------------------------------------------------------------------------
# Combined Flag Tests
# -----------------------------------------------------------------------------
echo "--- Combined Flag Tests ---"

test_start "Combined -rf flags work"
output=$("$SECURE_DELETE" -rf -n "$TEST_DIR" 2>&1)
if echo "$output" | grep -q "Would securely delete"; then
    test_pass
else
    test_fail "dry run output" "no output"
fi

test_start "Combined -nf flags work"
output=$("$SECURE_DELETE" -nf "$TEST_FILE" 2>&1)
if echo "$output" | grep -q "Would securely delete"; then
    test_pass
else
    test_fail "dry run output" "no output"
fi

test_start "Combined -nrf flags work"
output=$("$SECURE_DELETE" -nrf "$TEST_DIR" 2>&1)
if echo "$output" | grep -q "Would securely delete"; then
    test_pass
else
    test_fail "dry run output" "no output"
fi

echo ""

# -----------------------------------------------------------------------------
# Actual Deletion Test (controlled)
# -----------------------------------------------------------------------------
echo "--- Actual Deletion Test ---"

# Create a file specifically for deletion testing
DELETE_TEST_FILE="$FIXTURES_DIR/actually-delete-me.txt"
echo "delete this content" > "$DELETE_TEST_FILE"

test_start "Force delete single file"
"$SECURE_DELETE" -f "$DELETE_TEST_FILE" > /dev/null 2>&1
if [ ! -f "$DELETE_TEST_FILE" ]; then
    test_pass
else
    test_fail "file deleted" "file still exists"
fi

# Create directory for deletion testing
DELETE_TEST_DIR="$FIXTURES_DIR/actually-delete-dir"
mkdir -p "$DELETE_TEST_DIR"
echo "content1" > "$DELETE_TEST_DIR/file1.txt"
echo "content2" > "$DELETE_TEST_DIR/file2.txt"

test_start "Force recursive delete directory"
"$SECURE_DELETE" -rf "$DELETE_TEST_DIR" > /dev/null 2>&1
if [ ! -d "$DELETE_TEST_DIR" ]; then
    test_pass
else
    test_fail "directory deleted" "directory still exists"
fi

echo ""

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
rm -f "$TEST_FILE"
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
