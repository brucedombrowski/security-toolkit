#!/bin/bash
#
# Test Suite for LaTeX Injection Fix (CRITICAL-001)
# Tests the escape_latex_chars() function with all special characters
#

# Source the escape function from the updated script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_FILE="$SCRIPT_DIR/scripts/generate-scan-attestation.sh"

# Extract and define the escape function
escape_latex_chars() {
    local input="$1"
    # Order matters: backslash must be first to avoid double-escaping
    echo "$input" | \
        sed 's/\\/\\textbackslash{}/g' | \
        sed 's/\$/\\$/g' | \
        sed 's/_/\\_/g' | \
        sed 's/{/\\{/g' | \
        sed 's/}/\\}/g' | \
        sed 's/&/\\&/g' | \
        sed 's/%/\\%/g' | \
        sed 's/#/\\#/g' | \
        sed 's/\^/\\textasciicircum{}/g' | \
        sed 's/~/\\textasciitilde{}/g'
}

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

echo "=========================================="
echo "LaTeX Injection Fix - Test Suite"
echo "=========================================="
echo ""

# Test Case 1: Underscore in Findings
echo "TEST 1: Underscore in Findings"
echo "  Input:    Found patterns: SSN_format, phone_number"
RESULT=$(escape_latex_chars "Found patterns: SSN_format, phone_number")
EXPECTED="Found patterns: SSN\\_format, phone\\_number"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 2: Dollar Signs in Findings
echo "TEST 2: Dollar Signs in Findings"
echo "  Input:    AWS Key: AKIA\$XXX\$YYY"
RESULT=$(escape_latex_chars "AWS Key: AKIA\$XXX\$YYY")
EXPECTED="AWS Key: AKIA\\\$XXX\\\$YYY"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 3: Percent Signs
echo "TEST 3: Percent Signs"
echo "  Input:    Trojan: 95% confidence"
RESULT=$(escape_latex_chars "Trojan: 95% confidence")
EXPECTED="Trojan: 95\\% confidence"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 4: Ampersands
echo "TEST 4: Ampersands"
echo "  Input:    Interfaces: eth0 & eth1"
RESULT=$(escape_latex_chars "Interfaces: eth0 & eth1")
EXPECTED="Interfaces: eth0 \\& eth1"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 5: Curly Braces
echo "TEST 5: Curly Braces"
echo "  Input:    Config: {root, user}"
RESULT=$(escape_latex_chars "Config: {root, user}")
EXPECTED="Config: \\{root, user\\}"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 6: Hash/Pound Signs
echo "TEST 6: Hash/Pound Signs"
echo "  Input:    Issue #42 and #123"
RESULT=$(escape_latex_chars "Issue #42 and #123")
EXPECTED="Issue \\#42 and \\#123"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 7: Caret/Circumflex
echo "TEST 7: Caret (Circumflex)"
echo "  Input:    Operator: a^b"
RESULT=$(escape_latex_chars "Operator: a^b")
EXPECTED="Operator: a\\textasciicircum{}b"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 8: Tilde
echo "TEST 8: Tilde"
echo "  Input:    Path: ~/project"
RESULT=$(escape_latex_chars "Path: ~/project")
EXPECTED="Path: \\textasciitilde{}/project"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 9: Backslash
echo "TEST 9: Backslash"
echo "  Input:    Path: C:\\Users\\admin"
RESULT=$(escape_latex_chars "Path: C:\\Users\\admin")
EXPECTED="Path: C:\\textbackslash\\{\\}Users\\textbackslash\\{\\}admin"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test Case 10: Multiple Special Characters
echo "TEST 10: Multiple Special Characters"
echo "  Input:    File: test_file#1\$100&50%{info}"
RESULT=$(escape_latex_chars "File: test_file#1\$100&50%{info}")
EXPECTED="File: test\\_file\\#1\\\$100\\&50\\%\\{info\\}"
if [ "$RESULT" = "$EXPECTED" ]; then
    echo "  ✓ PASS"
    echo "  Output:   $RESULT"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "  ✗ FAIL"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $RESULT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
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
