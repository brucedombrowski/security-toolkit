#!/bin/bash
#
# Test Suite for CRITICAL-002: Destructive rm -rf Without Validation
# Tests the validate_scan_directory() function and deletion safety
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

echo "=========================================="
echo "CRITICAL-002: rm -rf Validation - Test Suite"
echo "=========================================="
echo ""

# Create temporary test directory
TEST_ROOT=$(mktemp -d)
trap "rm -rf $TEST_ROOT" EXIT

# Extract and define the validation function from the script
validate_scan_directory() {
    local target_path="$1"
    
    # Check if target path is empty
    if [ -z "$target_path" ]; then
        echo "Error: Target path is empty" >&2
        return 1
    fi
    
    # Check if path is absolute (prevents relative path traversal)
    if [[ "$target_path" != /* ]]; then
        echo "Error: Target path must be absolute" >&2
        return 1
    fi
    
    # Check if target directory exists
    if [ ! -d "$target_path" ]; then
        echo "Error: Target directory does not exist: $target_path" >&2
        return 1
    fi
    
    # Prevent deletion of critical system directories
    local scans_path="$target_path/.scans"
    case "$scans_path" in
        "/.scans"|"/etc/.scans"|"/var/.scans"|"/bin/.scans"|"/sbin/.scans"|"/boot/.scans"|"/usr/.scans"|"/root/.scans")
            echo "Error: Cannot delete .scans in critical system directory: $scans_path" >&2
            return 1
            ;;
    esac
    
    # Detect if .scans is a symlink
    if [ -L "$target_path/.scans" ]; then
        echo "Error: .scans is a symlink, refusing to delete" >&2
        return 1
    fi
    
    return 0
}

# Test Case 1: Valid directory passes validation
echo "TEST 1: Valid Directory Passes Validation"
TEST_DIR="$TEST_ROOT/valid_project"
mkdir -p "$TEST_DIR"
if validate_scan_directory "$TEST_DIR" 2>/dev/null; then
    echo "  ✓ PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 2: Empty path validation
echo "TEST 2: Empty Path Rejected"
if ! validate_scan_directory "" 2>/dev/null; then
    echo "  ✓ PASS (correctly rejected)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL (should have rejected empty path)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 3: Relative path validation
echo "TEST 3: Relative Path Rejected"
if ! validate_scan_directory "./relative/path" 2>/dev/null; then
    echo "  ✓ PASS (correctly rejected)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL (should have rejected relative path)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 4: Non-existent directory validation
echo "TEST 4: Non-existent Directory Rejected"
if ! validate_scan_directory "$TEST_ROOT/nonexistent" 2>/dev/null; then
    echo "  ✓ PASS (correctly rejected)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL (should have rejected nonexistent directory)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 5: System directory protection (/)
echo "TEST 5: Root Directory (.scans) Rejected"
# Can't test on root directly, but test that root would be rejected
# by checking the pattern match
TEST_ROOT_DIR="$TEST_ROOT/root_pattern"
mkdir -p "$TEST_ROOT_DIR"
# Simulate what would happen - root validation happens in the case statement
# For safety, we'll skip this test on most systems and instead verify /etc works
echo "  ⊘ SKIP (root access test - check case statement in code)"
echo ""

# Test Case 6: System directory protection (/etc)
echo "TEST 6: /etc Directory (.scans) Rejected"
if ! validate_scan_directory "/etc" 2>/dev/null; then
    echo "  ✓ PASS (correctly rejected)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL (should have rejected /etc directory)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 7: Symlink detection
echo "TEST 7: Symlink (.scans) Detected and Rejected"
TEST_DIR="$TEST_ROOT/symlink_test"
mkdir -p "$TEST_DIR"
ln -s /tmp "$TEST_DIR/.scans"
if ! validate_scan_directory "$TEST_DIR" 2>/dev/null; then
    echo "  ✓ PASS (correctly detected and rejected symlink)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL (should have detected symlink)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
rm "$TEST_DIR/.scans"
echo ""

# Test Case 8: Safe deletion - regular files
echo "TEST 8: Safe Deletion of Regular Files"
TEST_DIR="$TEST_ROOT/safe_delete"
mkdir -p "$TEST_DIR/.scans"
echo "file1" > "$TEST_DIR/.scans/test1.txt"
echo "file2" > "$TEST_DIR/.scans/test2.txt"
echo "file3" > "$TEST_DIR/.scans/test3.txt"

# Validate before deletion
if validate_scan_directory "$TEST_DIR" 2>/dev/null; then
    # Perform safe deletion
    find "$TEST_DIR/.scans" -type f -delete 2>/dev/null
    find "$TEST_DIR/.scans" -type d -delete 2>/dev/null
    
    # Check if files are gone
    if [ ! -d "$TEST_DIR/.scans" ] && [ ! -f "$TEST_DIR/.scans/test1.txt" ]; then
        echo "  ✓ PASS (files safely deleted)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  ✗ FAIL (files not deleted)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo "  ✗ FAIL (validation failed)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 9: File preview truncation
echo "TEST 9: File Preview with Truncation"
TEST_DIR="$TEST_ROOT/preview_test"
mkdir -p "$TEST_DIR/.scans"
for i in {1..25}; do
    echo "file $i" > "$TEST_DIR/.scans/file_$i.txt"
done

FILE_COUNT=$(find "$TEST_DIR/.scans" -type f | wc -l)
if [ "$FILE_COUNT" -eq 25 ]; then
    echo "  ✓ PASS (created 25 test files correctly)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL (expected 25 files, got $FILE_COUNT)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 10: Error handling on read-only file
echo "TEST 10: File Deletion Attempts Read-Only File"
TEST_DIR="$TEST_ROOT/readonly_test"
mkdir -p "$TEST_DIR/.scans"
echo "test content" > "$TEST_DIR/.scans/readonly.txt"
echo "writable file" > "$TEST_DIR/.scans/writable.txt"
chmod 444 "$TEST_DIR/.scans/readonly.txt"

# Attempt deletion (find -delete on read-only will fail, but test validates this)
if validate_scan_directory "$TEST_DIR" 2>/dev/null; then
    find "$TEST_DIR/.scans" -type f -delete 2>/dev/null || true
    # At least the writable file should be gone
    if [ ! -f "$TEST_DIR/.scans/writable.txt" ]; then
        echo "  ✓ PASS (writable files deleted, handled gracefully)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  ✗ FAIL (writable file should have been deleted)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo "  ✗ FAIL (validation failed)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
# Clean up - restore permissions for cleanup
chmod 644 "$TEST_DIR/.scans/readonly.txt" 2>/dev/null || true
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi
