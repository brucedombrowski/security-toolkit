#!/bin/bash
#
# Timestamp Library Test Suite
#
# Purpose: Verify timestamp library functionality
# NIST Controls: AU-8
#
# Tests:
#   1. ISO 8601 format generation
#   2. Date stamp generation
#   3. Filename-safe timestamp generation
#   4. Compact timestamp generation
#   5. Human-readable date generation
#   6. Unix timestamp generation
#   7. Elapsed time calculation
#   8. Format validation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$SECURITY_REPO_DIR/scripts/lib"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test helper functions
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}FAIL${NC}: $1"
    if [ -n "$2" ]; then
        echo "       Details: $2"
    fi
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Test $TESTS_RUN: "
}

# Source the timestamp library
source "$LIB_DIR/timestamps.sh"

echo "========================================"
echo "Timestamp Library Test Suite"
echo "========================================"
echo "Library: $LIB_DIR/timestamps.sh"
echo ""

# ============================================================================
# Test 1: ISO 8601 timestamp format
# ============================================================================
run_test
TEST_NAME="ISO 8601 timestamp format"
ISO_TS=$(get_iso_timestamp)
# Pattern: YYYY-MM-DDTHH:MM:SSZ
if [[ "$ISO_TS" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    pass "$TEST_NAME ($ISO_TS)"
else
    fail "$TEST_NAME" "Got: $ISO_TS"
fi

# ============================================================================
# Test 2: Date stamp format
# ============================================================================
run_test
TEST_NAME="Date stamp format"
DATE_STAMP=$(get_date_stamp)
# Pattern: YYYY-MM-DD
if [[ "$DATE_STAMP" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    pass "$TEST_NAME ($DATE_STAMP)"
else
    fail "$TEST_NAME" "Got: $DATE_STAMP"
fi

# ============================================================================
# Test 3: Filename-safe timestamp format
# ============================================================================
run_test
TEST_NAME="Filename-safe timestamp format"
FILENAME_TS=$(get_filename_timestamp)
# Pattern: YYYY-MM-DD-THHMMSSZ (no colons)
if [[ "$FILENAME_TS" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}-T[0-9]{6}Z$ ]]; then
    pass "$TEST_NAME ($FILENAME_TS)"
else
    fail "$TEST_NAME" "Got: $FILENAME_TS"
fi

# ============================================================================
# Test 4: No colons in filename timestamp
# ============================================================================
run_test
TEST_NAME="Filename timestamp has no colons"
FILENAME_TS=$(get_filename_timestamp)
if [[ "$FILENAME_TS" != *":"* ]]; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "Found colon in: $FILENAME_TS"
fi

# ============================================================================
# Test 5: Compact timestamp format
# ============================================================================
run_test
TEST_NAME="Compact timestamp format"
COMPACT_TS=$(get_compact_timestamp)
# Pattern: YYYYMMDD-HHMMSS
if [[ "$COMPACT_TS" =~ ^[0-9]{8}-[0-9]{6}$ ]]; then
    pass "$TEST_NAME ($COMPACT_TS)"
else
    fail "$TEST_NAME" "Got: $COMPACT_TS"
fi

# ============================================================================
# Test 6: Human-readable date format
# ============================================================================
run_test
TEST_NAME="Human-readable date format"
HUMAN_DATE=$(get_human_date)
# Pattern: Month DD, YYYY
if [[ "$HUMAN_DATE" =~ ^[A-Z][a-z]+\ [0-9]{1,2},\ [0-9]{4}$ ]]; then
    pass "$TEST_NAME ($HUMAN_DATE)"
else
    fail "$TEST_NAME" "Got: $HUMAN_DATE"
fi

# ============================================================================
# Test 7: Unix timestamp is numeric
# ============================================================================
run_test
TEST_NAME="Unix timestamp is numeric"
UNIX_TS=$(get_unix_timestamp)
if [[ "$UNIX_TS" =~ ^[0-9]+$ ]]; then
    pass "$TEST_NAME ($UNIX_TS)"
else
    fail "$TEST_NAME" "Got: $UNIX_TS"
fi

# ============================================================================
# Test 8: Unix timestamp is reasonable (after year 2000)
# ============================================================================
run_test
TEST_NAME="Unix timestamp is reasonable (after year 2000)"
UNIX_TS=$(get_unix_timestamp)
# Timestamp for 2000-01-01 is 946684800
if [ "$UNIX_TS" -gt 946684800 ]; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "Timestamp $UNIX_TS seems too old"
fi

# ============================================================================
# Test 9: Elapsed time calculation
# ============================================================================
run_test
TEST_NAME="Elapsed time calculation"
START=1000
END=1065
ELAPSED=$(calculate_elapsed_seconds "$START" "$END")
if [ "$ELAPSED" -eq 65 ]; then
    pass "$TEST_NAME (65 seconds)"
else
    fail "$TEST_NAME" "Expected 65, got $ELAPSED"
fi

# ============================================================================
# Test 10: Format elapsed time (seconds only)
# ============================================================================
run_test
TEST_NAME="Format elapsed time (seconds only)"
FORMATTED=$(format_elapsed_time 45)
if [ "$FORMATTED" = "45s" ]; then
    pass "$TEST_NAME ($FORMATTED)"
else
    fail "$TEST_NAME" "Expected '45s', got '$FORMATTED'"
fi

# ============================================================================
# Test 11: Format elapsed time (minutes and seconds)
# ============================================================================
run_test
TEST_NAME="Format elapsed time (minutes and seconds)"
FORMATTED=$(format_elapsed_time 125)  # 2m 5s
if [ "$FORMATTED" = "2m 5s" ]; then
    pass "$TEST_NAME ($FORMATTED)"
else
    fail "$TEST_NAME" "Expected '2m 5s', got '$FORMATTED'"
fi

# ============================================================================
# Test 12: Format elapsed time (hours, minutes, seconds)
# ============================================================================
run_test
TEST_NAME="Format elapsed time (hours, minutes, seconds)"
FORMATTED=$(format_elapsed_time 3665)  # 1h 1m 5s
if [ "$FORMATTED" = "1h 1m 5s" ]; then
    pass "$TEST_NAME ($FORMATTED)"
else
    fail "$TEST_NAME" "Expected '1h 1m 5s', got '$FORMATTED'"
fi

# ============================================================================
# Test 13: Validate ISO timestamp (valid)
# ============================================================================
run_test
TEST_NAME="Validate ISO timestamp (valid)"
if validate_iso_timestamp "2026-01-15T08:30:00Z"; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "Valid timestamp rejected"
fi

# ============================================================================
# Test 14: Validate ISO timestamp (invalid - no Z)
# ============================================================================
run_test
TEST_NAME="Validate ISO timestamp (invalid - no Z)"
if validate_iso_timestamp "2026-01-15T08:30:00"; then
    fail "$TEST_NAME" "Invalid timestamp accepted"
else
    pass "$TEST_NAME"
fi

# ============================================================================
# Test 15: Validate ISO timestamp (invalid - wrong format)
# ============================================================================
run_test
TEST_NAME="Validate ISO timestamp (invalid - wrong format)"
if validate_iso_timestamp "01-15-2026T08:30:00Z"; then
    fail "$TEST_NAME" "Invalid timestamp accepted"
else
    pass "$TEST_NAME"
fi

# ============================================================================
# Test 16: Validate date stamp (valid)
# ============================================================================
run_test
TEST_NAME="Validate date stamp (valid)"
if validate_date_stamp "2026-01-15"; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "Valid date stamp rejected"
fi

# ============================================================================
# Test 17: Validate date stamp (invalid)
# ============================================================================
run_test
TEST_NAME="Validate date stamp (invalid)"
if validate_date_stamp "01-15-2026"; then
    fail "$TEST_NAME" "Invalid date stamp accepted"
else
    pass "$TEST_NAME"
fi

# ============================================================================
# Test 18: Format constants defined
# ============================================================================
run_test
TEST_NAME="Format constants defined"
if [ -n "$TS_FORMAT_ISO" ] && [ -n "$TS_FORMAT_DATE" ] && [ -n "$TS_FORMAT_FILENAME" ]; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "Some format constants are empty"
fi

# ============================================================================
# Test 19: Format constants work with date command
# ============================================================================
run_test
TEST_NAME="Format constants work with date command"
RESULT=$(date -u "$TS_FORMAT_ISO")
if [[ "$RESULT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "date with TS_FORMAT_ISO gave: $RESULT"
fi

# ============================================================================
# Test 20: All timestamps use UTC
# ============================================================================
run_test
TEST_NAME="Timestamps are UTC (end with Z)"
ISO_TS=$(get_iso_timestamp)
FILENAME_TS=$(get_filename_timestamp)
if [[ "$ISO_TS" == *"Z" ]] && [[ "$FILENAME_TS" == *"Z" ]]; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "Missing Z suffix in ISO or filename timestamp"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED test(s) failed${NC}"
    exit 1
fi
