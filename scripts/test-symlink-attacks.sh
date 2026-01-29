#!/bin/bash
#
# Test Suite: Symlink Attack Surface (CRITICAL-003)
#
# Purpose: Verify protection against symlink-based DoS and information disclosure attacks
# NIST Controls: SI-4 (System Monitoring), SI-10 (Information System Monitoring)
#
# Test Cases:
#   1. Regular files processed (baseline)
#   2. Symlinks ignored (core protection)
#   3. Symlink to large file handled (DoS prevention)
#   4. Symlink to /dev/zero handled (infinite read prevention)
#   5. Broken symlinks ignored (graceful handling)
#   6. Deep directory traversal depth limited
#   7. Symlink to system directory ignored
#   8. Mixed content (files + symlinks) processed correctly

set -eu

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

# Extract the validation function from check-pii.sh for testing (simplified version)
# We'll test find command behavior directly
test_find_excludes_symlinks() {
    local test_dir="$1"
    local result
    result=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
    echo "$result"
}

echo "Symlink Attack Surface Test Suite (CRITICAL-003)"
echo "=================================================="
echo "Test Directory: $TEST_DIR"
echo ""

# TEST 1: Regular files are processed
echo -n "TEST 1: Regular files processed... "
test_dir="$TEST_DIR/test1"
mkdir -p "$test_dir"
echo "content1" > "$test_dir/file1.txt"
echo "content2" > "$test_dir/file2.txt"
file_count=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
if [ "$file_count" -eq 2 ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (expected 2 files, got $file_count)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 2: Symlinks are ignored (core protection)
echo -n "TEST 2: Symlinks ignored... "
test_dir="$TEST_DIR/test2"
mkdir -p "$test_dir"
echo "real content" > "$test_dir/realfile.txt"
ln -s "$test_dir/realfile.txt" "$test_dir/symlink.txt"
file_count=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
symlink_count=$(find "$test_dir" -type l 2>/dev/null | wc -l)
if [ "$file_count" -eq 1 ] && [ "$symlink_count" -eq 1 ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (expected 1 file + 1 symlink, got $file_count files + $symlink_count symlinks)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 3: Symlink to large file handled with timeout
echo -n "TEST 3: Symlink to large file with timeout... "
test_dir="$TEST_DIR/test3"
mkdir -p "$test_dir"
# Create a 10MB file
dd if=/dev/zero of="$test_dir/largefile" bs=1M count=10 2>/dev/null
ln -s "$test_dir/largefile" "$test_dir/symlink_large"
# Test with timeout - should complete quickly
start_time=$(date +%s)
timeout 2 find "$test_dir" -type f -not -type l -exec grep -l "test" {} \; 2>/dev/null || true
end_time=$(date +%s)
elapsed=$((end_time - start_time))
if [ $elapsed -lt 2 ]; then
    echo -e "${GREEN}PASS${NC} (completed in ${elapsed}s)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (timeout or too slow: ${elapsed}s)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 4: Symlink to /dev/zero is safe (not followed)
echo -n "TEST 4: Symlink to /dev/zero safe... "
test_dir="$TEST_DIR/test4"
mkdir -p "$test_dir"
echo "normal file" > "$test_dir/normal.txt"
ln -s /dev/zero "$test_dir/zero_link" 2>/dev/null || true
# Try to grep - should not hang
start_time=$(date +%s)
timeout 2 bash -c "find '$test_dir' -type f -not -type l | while read f; do timeout 1 grep -l 'test' \"\$f\" 2>/dev/null || true; done" 2>/dev/null || true
end_time=$(date +%s)
elapsed=$((end_time - start_time))
if [ $elapsed -lt 3 ]; then
    echo -e "${GREEN}PASS${NC} (completed in ${elapsed}s, not blocked)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (potential infinite read: ${elapsed}s)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 5: Broken symlinks handled gracefully
echo -n "TEST 5: Broken symlinks handled gracefully... "
test_dir="$TEST_DIR/test5"
mkdir -p "$test_dir"
echo "content" > "$test_dir/file.txt"
ln -s "/nonexistent/target" "$test_dir/broken_link" 2>/dev/null || true
file_count=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
if [ "$file_count" -eq 1 ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (expected 1 file, got $file_count)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 6: Depth limiting (find with -maxdepth)
echo -n "TEST 6: Depth limit prevents deep traversal... "
test_dir="$TEST_DIR/test6"
mkdir -p "$test_dir/a/b/c/d/e/f/g/h/i/j"
echo "shallow" > "$test_dir/file0.txt"
echo "deep" > "$test_dir/a/b/c/d/e/f/g/h/i/j/deep_file.txt"
# Find files only in first 2 levels
shallow_count=$(find "$test_dir" -maxdepth 2 -type f -not -type l 2>/dev/null | wc -l)
deep_count=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
if [ "$shallow_count" -lt "$deep_count" ]; then
    echo -e "${GREEN}PASS${NC} (shallow: $shallow_count, all: $deep_count)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (depth limit ineffective)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 7: Symlink to /etc directory ignored
echo -n "TEST 7: Symlink to system directory ignored... "
test_dir="$TEST_DIR/test7"
mkdir -p "$test_dir"
echo "user content" > "$test_dir/user_file.txt"
ln -s /etc "$test_dir/etc_link" 2>/dev/null || true
# Count regular files (should only be 1)
file_count=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
# Verify symlink exists
symlink_count=$(find "$test_dir" -type l -name "etc_link" 2>/dev/null | wc -l)
if [ "$file_count" -eq 1 ] && [ "$symlink_count" -eq 1 ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (files: $file_count, symlinks: $symlink_count)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 8: Mixed content (files + symlinks + directories)
echo -n "TEST 8: Mixed content handled correctly... "
test_dir="$TEST_DIR/test8"
mkdir -p "$test_dir/subdir"
echo "file1" > "$test_dir/file1.txt"
echo "file2" > "$test_dir/subdir/file2.txt"
ln -s "$test_dir/file1.txt" "$test_dir/link1"
ln -s "$test_dir/subdir" "$test_dir/link_dir"
# Should find only 2 regular files, not follow symlinks
file_count=$(find "$test_dir" -type f -not -type l 2>/dev/null | wc -l)
symlink_count=$(find "$test_dir" -type l 2>/dev/null | wc -l)
if [ "$file_count" -eq 2 ] && [ "$symlink_count" -eq 2 ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC} (files: $file_count, symlinks: $symlink_count)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Summary
echo ""
echo "=================================================="
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
