#!/bin/bash
#
# NVD CVE Lookup Unit Tests
#
# Tests for:
#   - lib/nvd/api.sh - NVD API integration
#   - lib/nvd/matcher.sh - Package-to-CPE matching
#   - check-nvd-cves.sh - Main scan script

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$REPO_DIR/scripts/lib/nvd"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

test_skip() {
    TESTS_RUN=$((TESTS_RUN - 1))
    echo -e "${YELLOW}SKIP${NC} ($1)"
}

section_header() {
    echo ""
    echo -e "${CYAN}--- $1 ---${NC}"
}

echo "=========================================="
echo "NVD CVE Lookup Unit Tests"
echo "=========================================="

# Create temporary test directory
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
echo "Test directory: $TEST_DIR"

# =============================================================================
# Matcher Library Tests
# =============================================================================
section_header "Matcher Library (matcher.sh)"

test_start "matcher.sh can be sourced"
if SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'" 2>/dev/null; then
    test_pass
else
    test_fail "sourceable" "failed to source"
fi

test_start "package_to_cpe function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; type -t package_to_cpe")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "package_to_cpe converts openssl correctly"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; package_to_cpe openssl 3.0.10")
if echo "$result" | grep -q "cpe:2.3:a:openssl:openssl:3.0.10"; then
    test_pass
else
    test_fail "cpe:2.3:a:openssl:openssl:3.0.10:*" "$result"
fi

test_start "package_to_cpe converts python correctly"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; package_to_cpe python 3.11.5")
if echo "$result" | grep -q "cpe:2.3:a:python:python:3.11.5"; then
    test_pass
else
    test_fail "cpe:2.3:a:python:python:3.11.5:*" "$result"
fi

test_start "package_to_cpe converts nginx correctly"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; package_to_cpe nginx 1.25.0")
if echo "$result" | grep -q "cpe:2.3:a:nginx:nginx:1.25.0"; then
    test_pass
else
    test_fail "cpe:2.3:a:nginx:nginx:1.25.0:*" "$result"
fi

test_start "package_to_cpe handles unknown packages"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; package_to_cpe unknown-pkg 1.0.0")
if echo "$result" | grep -q "cpe:2.3:a:\*:unknown-pkg:1.0.0"; then
    test_pass
else
    test_fail "cpe:2.3:a:*:unknown-pkg:1.0.0:*" "$result"
fi

test_start "parse_version extracts version correctly"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; parse_version '3.0.10-1ubuntu1'")
if [ "$result" = "3.0.10" ]; then
    test_pass
else
    test_fail "3.0.10" "$result"
fi

test_start "parse_version handles simple versions"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; parse_version '1.2.3'")
if [ "$result" = "1.2.3" ]; then
    test_pass
else
    test_fail "1.2.3" "$result"
fi

test_start "get_priority_packages returns list"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; get_priority_packages | wc -l")
if [ "$result" -ge 10 ]; then
    test_pass
else
    test_fail ">=10 packages" "$result packages"
fi

test_start "is_priority_package detects openssl"
if SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; is_priority_package openssl"; then
    test_pass
else
    test_fail "true" "false"
fi

test_start "is_priority_package rejects unknown"
if ! SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; is_priority_package unknown-random-pkg"; then
    test_pass
else
    test_fail "false" "true"
fi

test_start "get_cpe_vendor returns correct vendor"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; get_cpe_vendor postgresql")
if [ "$result" = "postgresql" ]; then
    test_pass
else
    test_fail "postgresql" "$result"
fi

test_start "get_cpe_product returns correct product"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; get_cpe_product nodejs")
if [ "$result" = "node.js" ]; then
    test_pass
else
    test_fail "node.js" "$result"
fi

# =============================================================================
# API Library Tests
# =============================================================================
section_header "API Library (api.sh)"

test_start "api.sh can be sourced"
if SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'" 2>/dev/null; then
    test_pass
else
    test_fail "sourceable" "failed to source"
fi

test_start "init_nvd_cache function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t init_nvd_cache")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "query_nvd_by_cpe function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t query_nvd_by_cpe")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "query_nvd_by_cve function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t query_nvd_by_cve")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "query_nvd_by_keyword function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t query_nvd_by_keyword")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "extract_cvss_score function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t extract_cvss_score")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "extract_severity function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t extract_severity")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "check_nvd_api function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t check_nvd_api")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "clear_nvd_cache function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t clear_nvd_cache")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "nvd_cache_stats function exists"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; type -t nvd_cache_stats")
if [ "$result" = "function" ]; then
    test_pass
else
    test_fail "function" "$result"
fi

test_start "init_nvd_cache creates directory"
NVD_CACHE_DIR="$TEST_DIR/cache"
SECURITY_REPO_DIR="$REPO_DIR" bash -c "
    export NVD_CACHE_DIR='$NVD_CACHE_DIR'
    source '$LIB_DIR/api.sh'
    init_nvd_cache
"
if [ -d "$NVD_CACHE_DIR" ]; then
    test_pass
else
    test_fail "directory exists" "directory not created"
fi

test_start "NVD_API_BASE is set correctly"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/api.sh'; echo \$NVD_API_BASE")
if echo "$result" | grep -q "services.nvd.nist.gov"; then
    test_pass
else
    test_fail "services.nvd.nist.gov URL" "$result"
fi

# =============================================================================
# CVSS Parsing Tests (with mock data)
# =============================================================================
section_header "CVSS Parsing Tests"

# Create mock NVD response
MOCK_NVD_RESPONSE='{"vulnerabilities":[{"cve":{"id":"CVE-2024-1234","descriptions":[{"lang":"en","value":"Test vulnerability description"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}]}'

if command -v jq &>/dev/null; then
    test_start "extract_cvss_score parses CVSS 3.1 score"
    result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "
        source '$LIB_DIR/api.sh'
        extract_cvss_score '$MOCK_NVD_RESPONSE'
    ")
    if [ "$result" = "9.8" ]; then
        test_pass
    else
        test_fail "9.8" "$result"
    fi

    test_start "extract_severity parses CVSS 3.1 severity"
    result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "
        source '$LIB_DIR/api.sh'
        extract_severity '$MOCK_NVD_RESPONSE'
    ")
    if [ "$result" = "CRITICAL" ]; then
        test_pass
    else
        test_fail "CRITICAL" "$result"
    fi

    test_start "extract_cve_description parses description"
    result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "
        source '$LIB_DIR/api.sh'
        extract_cve_description '$MOCK_NVD_RESPONSE'
    ")
    if echo "$result" | grep -q "Test vulnerability description"; then
        test_pass
    else
        test_fail "Test vulnerability description" "$result"
    fi
else
    test_start "extract_cvss_score parses CVSS 3.1 score"
    test_skip "jq not installed"
    test_start "extract_severity parses CVSS 3.1 severity"
    test_skip "jq not installed"
    test_start "extract_cve_description parses description"
    test_skip "jq not installed"
fi

# =============================================================================
# Main Script Tests
# =============================================================================
section_header "Main Script (check-nvd-cves.sh)"

test_start "check-nvd-cves.sh exists and is executable"
if [ -x "$REPO_DIR/scripts/check-nvd-cves.sh" ]; then
    test_pass
else
    test_fail "executable" "not executable"
fi

test_start "check-nvd-cves.sh shows help with -h"
if "$REPO_DIR/scripts/check-nvd-cves.sh" -h 2>&1 | grep -q "NVD CVE Lookup"; then
    test_pass
else
    test_fail "help output" "no help"
fi

test_start "check-nvd-cves.sh shows help with --help"
if "$REPO_DIR/scripts/check-nvd-cves.sh" --help 2>&1 | grep -q "NIST CONTROLS"; then
    test_pass
else
    test_fail "NIST CONTROLS in help" "not found"
fi

test_start "check-nvd-cves.sh help includes RA-5 control"
if "$REPO_DIR/scripts/check-nvd-cves.sh" -h 2>&1 | grep -q "RA-5"; then
    test_pass
else
    test_fail "RA-5 reference" "not found"
fi

test_start "check-nvd-cves.sh help includes SI-2 control"
if "$REPO_DIR/scripts/check-nvd-cves.sh" -h 2>&1 | grep -q "SI-2"; then
    test_pass
else
    test_fail "SI-2 reference" "not found"
fi

# Create mock inventory file for testing
MOCK_INVENTORY="$TEST_DIR/host-inventory.txt"
cat > "$MOCK_INVENTORY" << 'EOF'
Host System Inventory
=====================

Security Tools:
---------------
  OpenSSL: 3.0.10
  SSH: 9.0
  GPG: 2.4.0

Programming Languages:
----------------------
  Python: 3.11.5
  Node.js: 20.10.0
  Ruby: 3.2.0

Homebrew Packages:
------------------
    curl 8.4.0
    git 2.43.0
    nginx 1.25.0

EOF

test_start "check-nvd-cves.sh accepts -i flag for inventory"
# Test with offline mode to avoid actual API calls
if "$REPO_DIR/scripts/check-nvd-cves.sh" -i "$MOCK_INVENTORY" --offline 2>&1 | grep -q "Parsing installed packages"; then
    test_pass
else
    test_fail "parses inventory" "failed"
fi

test_start "check-nvd-cves.sh accepts --priority-only flag"
if "$REPO_DIR/scripts/check-nvd-cves.sh" -i "$MOCK_INVENTORY" --priority-only --offline 2>&1 | grep -q "priority packages"; then
    test_pass
else
    test_fail "priority mode" "not working"
fi

test_start "check-nvd-cves.sh accepts --offline flag"
if "$REPO_DIR/scripts/check-nvd-cves.sh" -i "$MOCK_INVENTORY" --offline 2>&1 | grep -q "RESULT"; then
    test_pass
else
    test_fail "offline mode" "not working"
fi

test_start "check-nvd-cves.sh outputs NIST control references"
if "$REPO_DIR/scripts/check-nvd-cves.sh" -i "$MOCK_INVENTORY" --offline 2>&1 | grep -q "RA-5"; then
    test_pass
else
    test_fail "RA-5 in output" "not found"
fi

# =============================================================================
# Integration Tests
# =============================================================================
section_header "Integration Tests"

test_start "All NVD modules can be sourced together"
if SECURITY_REPO_DIR="$REPO_DIR" bash -c "
    source '$LIB_DIR/api.sh'
    source '$LIB_DIR/matcher.sh'
" 2>/dev/null; then
    test_pass
else
    test_fail "all modules source" "conflict or error"
fi

test_start "Package-to-CPE and API functions integrate"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "
    source '$LIB_DIR/api.sh'
    source '$LIB_DIR/matcher.sh'
    cpe=\$(package_to_cpe openssl 3.0.10)
    echo \$cpe
")
if echo "$result" | grep -q "cpe:2.3:a:openssl:openssl"; then
    test_pass
else
    test_fail "integrated CPE generation" "$result"
fi

test_start "Mock inventory parsing works"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "
    source '$LIB_DIR/matcher.sh'
    parse_inventory_packages '$MOCK_INVENTORY' | grep -c ':'
")
if [ "$result" -ge 5 ]; then
    test_pass
else
    test_fail ">=5 packages parsed" "$result packages"
fi

test_start "Inventory parsing extracts curl version"
result=$(SECURITY_REPO_DIR="$REPO_DIR" bash -c "
    source '$LIB_DIR/matcher.sh'
    parse_inventory_packages '$MOCK_INVENTORY' | grep curl
")
if echo "$result" | grep -q "curl:8.4.0"; then
    test_pass
else
    test_fail "curl:8.4.0" "$result"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=========================================="
echo "NVD CVE Lookup Test Summary"
echo "=========================================="
echo "  Total:   $TESTS_RUN"
echo "  Passed:  $TESTS_PASSED"
echo "  Failed:  $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All NVD CVE tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED NVD CVE test(s) failed${NC}"
    exit 1
fi
