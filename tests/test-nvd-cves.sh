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
# Version Range Matching (matcher.sh)
# =============================================================================
# Regression: CVE-2025-68973 ("In GnuPG before 2.4.9") was reported against an
# installed gnupg 2.4.9 because NVD configuration version ranges were ignored.
section_header "Version Range Matching (matcher.sh)"

# Helper: run a matcher.sh function and return its exit code
matcher_rc() {
    local rc=0
    SECURITY_REPO_DIR="$REPO_DIR" bash -c "source '$LIB_DIR/matcher.sh'; $1" >/dev/null 2>&1 || rc=$?
    echo "$rc"
}

test_start "version_lt: 2.4.8 < 2.4.9"
if [ "$(matcher_rc 'version_lt 2.4.8 2.4.9')" = "0" ]; then test_pass; else test_fail "0" "non-zero"; fi

test_start "version_lt: 2.4.9 is not < 2.4.9"
if [ "$(matcher_rc 'version_lt 2.4.9 2.4.9')" = "1" ]; then test_pass; else test_fail "1" "0"; fi

test_start "version_lt: 2.4.10 is not < 2.4.9 (numeric, not lexical)"
if [ "$(matcher_rc 'version_lt 2.4.10 2.4.9')" = "1" ]; then test_pass; else test_fail "1" "0"; fi

test_start "version_gt: 2.4.10 > 2.4.9"
if [ "$(matcher_rc 'version_gt 2.4.10 2.4.9')" = "0" ]; then test_pass; else test_fail "0" "non-zero"; fi

test_start "version_lte: 2.4.9 <= 2.4.9"
if [ "$(matcher_rc 'version_lte 2.4.9 2.4.9')" = "0" ]; then test_pass; else test_fail "0" "non-zero"; fi

# cpe_range_matches "installed" "cpe_version" "start_incl" "start_excl" "end_incl" "end_excl"
test_start "cpe_range_matches: versionEndExcluding=2.4.9 excludes installed 2.4.9"
if [ "$(matcher_rc "cpe_range_matches 2.4.9 '*' '' '' '' 2.4.9")" = "1" ]; then test_pass; else test_fail "1 (not affected)" "0"; fi

test_start "cpe_range_matches: versionEndExcluding=2.4.9 includes installed 2.4.8"
if [ "$(matcher_rc "cpe_range_matches 2.4.8 '*' '' '' '' 2.4.9")" = "0" ]; then test_pass; else test_fail "0 (affected)" "1"; fi

test_start "cpe_range_matches: versionEndIncluding=2.4.9 includes installed 2.4.9"
if [ "$(matcher_rc "cpe_range_matches 2.4.9 '*' '' '' 2.4.9 ''")" = "0" ]; then test_pass; else test_fail "0 (affected)" "1"; fi

test_start "cpe_range_matches: versionStartIncluding=2.4.0 excludes installed 2.3.9"
if [ "$(matcher_rc "cpe_range_matches 2.3.9 '*' 2.4.0 '' '' 2.5.0")" = "1" ]; then test_pass; else test_fail "1 (not affected)" "0"; fi

test_start "cpe_range_matches: versionStartExcluding=2.4.0 excludes installed 2.4.0"
if [ "$(matcher_rc "cpe_range_matches 2.4.0 '*' '' 2.4.0 '' 2.5.0")" = "1" ]; then test_pass; else test_fail "1 (not affected)" "0"; fi

test_start "cpe_range_matches: installed 2.4.5 inside [2.4.0, 2.5.0)"
if [ "$(matcher_rc "cpe_range_matches 2.4.5 '*' 2.4.0 '' '' 2.5.0")" = "0" ]; then test_pass; else test_fail "0 (affected)" "1"; fi

test_start "cpe_range_matches: exact CPE version 2.4.8 does not match installed 2.4.9"
if [ "$(matcher_rc "cpe_range_matches 2.4.9 2.4.8 '' '' '' ''")" = "1" ]; then test_pass; else test_fail "1 (not affected)" "0"; fi

test_start "cpe_range_matches: exact CPE version 2.4.9 matches installed 2.4.9"
if [ "$(matcher_rc "cpe_range_matches 2.4.9 2.4.9 '' '' '' ''")" = "0" ]; then test_pass; else test_fail "0 (affected)" "1"; fi

# Build a single NVD vulnerability record (one element of .vulnerabilities[])
# Usage: mock_vuln_record CVE_ID SCORE SEVERITY DESCRIPTION [CPE_MATCH_JSON]
#   CPE_MATCH_JSON: contents of the cpeMatch array; omit for no configurations
mock_vuln_record() {
    local cve_id="$1" score="$2" severity="$3" desc="$4" cpe_match="${5:-}"
    local configurations=""
    if [ -n "$cpe_match" ]; then
        configurations=',"configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":['"$cpe_match"']}]}]'
    fi
    printf '{"cve":{"id":"%s","descriptions":[{"lang":"en","value":"%s"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":%s,"baseSeverity":"%s"}}]}%s}}' \
        "$cve_id" "$desc" "$score" "$severity" "$configurations"
}

GNUPG_BEFORE_249='{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionEndExcluding":"2.4.9"}'

# cve_affects_version "$vuln_json" vendor product installed -> 0 affected, 1 not affected, 2 undetermined
affects_rc() {
    local vuln_json="$1" vendor="$2" product="$3" installed="$4"
    local rc=0
    SECURITY_REPO_DIR="$REPO_DIR" bash -c "
        source '$LIB_DIR/matcher.sh'
        cve_affects_version \"\$1\" '$vendor' '$product' '$installed'
    " _ "$vuln_json" >/dev/null 2>&1 || rc=$?
    echo "$rc"
}

if command -v jq &>/dev/null; then
    V=$(mock_vuln_record CVE-2025-68973 7.8 HIGH "In GnuPG before 2.4.9, a flaw." "$GNUPG_BEFORE_249")

    test_start "cve_affects_version: 'before 2.4.9' does not affect installed 2.4.9"
    rc=$(affects_rc "$V" gnupg gnupg 2.4.9)
    if [ "$rc" = "1" ]; then test_pass; else test_fail "1 (not affected)" "$rc"; fi

    test_start "cve_affects_version: 'before 2.4.9' affects installed 2.4.8"
    rc=$(affects_rc "$V" gnupg gnupg 2.4.8)
    if [ "$rc" = "0" ]; then test_pass; else test_fail "0 (affected)" "$rc"; fi

    test_start "cve_affects_version: handles Homebrew revision suffix (2.4.9_1)"
    rc=$(affects_rc "$V" gnupg gnupg 2.4.9_1)
    if [ "$rc" = "1" ]; then test_pass; else test_fail "1 (not affected)" "$rc"; fi

    test_start "cve_affects_version: vendor wildcard '*' matches any vendor"
    rc=$(affects_rc "$V" '*' gnupg 2.4.8)
    if [ "$rc" = "0" ]; then test_pass; else test_fail "0 (affected)" "$rc"; fi

    test_start "cve_affects_version: undetermined (2) when record has no configurations"
    V_NOCONF=$(mock_vuln_record CVE-2025-0001 7.8 HIGH "No configuration data.")
    rc=$(affects_rc "$V_NOCONF" gnupg gnupg 2.4.9)
    if [ "$rc" = "2" ]; then test_pass; else test_fail "2 (undetermined)" "$rc"; fi

    test_start "cve_affects_version: undetermined (2) when cpeMatch is for a different product"
    rc=$(affects_rc "$V" openssl openssl 3.0.10)
    if [ "$rc" = "2" ]; then test_pass; else test_fail "2 (undetermined)" "$rc"; fi

    test_start "cve_affects_version: ignores cpeMatch entries with vulnerable=false"
    V_NOTVULN=$(mock_vuln_record CVE-2025-0002 7.8 HIGH "Fixed version listed as not vulnerable." \
        '{"vulnerable":false,"criteria":"cpe:2.3:a:gnupg:gnupg:2.4.9:*:*:*:*:*:*:*"}')
    rc=$(affects_rc "$V_NOTVULN" gnupg gnupg 2.4.9)
    if [ "$rc" = "2" ]; then test_pass; else test_fail "2 (undetermined)" "$rc"; fi

    test_start "cve_affects_version: any matching range among several is affected"
    V_MULTI=$(mock_vuln_record CVE-2025-0003 7.8 HIGH "Two branches affected." \
        '{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionStartIncluding":"2.2.0","versionEndExcluding":"2.2.50"},{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionStartIncluding":"2.4.0","versionEndExcluding":"2.4.9"}')
    rc=$(affects_rc "$V_MULTI" gnupg gnupg 2.2.10)
    if [ "$rc" = "0" ]; then test_pass; else test_fail "0 (affected)" "$rc"; fi
else
    for name in "'before 2.4.9' does not affect 2.4.9" "'before 2.4.9' affects 2.4.8" \
                "Homebrew revision suffix" "vendor wildcard" "no configurations" \
                "different product" "vulnerable=false" "multiple ranges"; do
        test_start "cve_affects_version: $name"
        test_skip "jq not installed"
    done
fi

# =============================================================================
# Regression: Counters and Version Ranges (check-nvd-cves.sh)
# =============================================================================
# Regression: the per-CVE loop ran in a `jq | while` pipeline subshell, so
# VULNERABILITIES_FOUND stayed 0 and the summary said PASS after printing a
# [VULNERABILITY] block. See docs/BASH-SET-E-PITFALLS.md.
section_header "Regression: Counters and Version Ranges (check-nvd-cves.sh)"

# Mirror the cache-key hashing used by check-nvd-cves.sh / api.sh
nvd_cache_hash() {
    echo "$1" | md5 -q 2>/dev/null || echo "$1" | md5sum | cut -d' ' -f1
}

# Seed the offline cache with a keyword response for package/version
# Usage: seed_nvd_cache CACHE_DIR PACKAGE VERSION RECORD_JSON...
seed_nvd_cache() {
    local cache_dir="$1" package="$2" version="$3"
    shift 3
    mkdir -p "$cache_dir"
    local records
    records=$(printf '%s,' "$@")
    records="${records%,}"
    local n=$#
    printf '{"totalResults":%d,"vulnerabilities":[%s]}' "$n" "$records" \
        > "$cache_dir/keyword-$(nvd_cache_hash "${package}-${version}").json"
}

# Run the scan offline against a seeded cache.
# Sets SCAN_OUTPUT (combined stdout/stderr) and SCAN_RC (exit code) in the
# caller's shell - do not wrap in $(...) or SCAN_RC is lost to a subshell.
# Usage: run_offline_scan CACHE_DIR INVENTORY TARGET [extra args...]
run_offline_scan() {
    local cache_dir="$1" inventory="$2" target="$3"
    shift 3
    SCAN_RC=0
    SCAN_OUTPUT=$(NVD_CACHE_DIR="$cache_dir" "$REPO_DIR/scripts/check-nvd-cves.sh" \
        -i "$inventory" --offline "$@" "$target" 2>&1) || SCAN_RC=$?
}

GNUPG_INVENTORY="$TEST_DIR/gnupg-inventory.txt"
cat > "$GNUPG_INVENTORY" << 'EOF'
Host System Inventory
=====================

Homebrew Packages:
------------------
    gnupg 2.4.9

EOF

if command -v jq &>/dev/null; then
    # --- Counter regression: an affected HIGH CVE must be counted and fail ---
    CASE_DIR="$TEST_DIR/case-counter"
    mkdir -p "$CASE_DIR/target"
    seed_nvd_cache "$CASE_DIR/cache" gnupg 2.4.9 \
        "$(mock_vuln_record CVE-2025-99001 7.8 HIGH "In GnuPG before 2.5.0, a flaw." \
            '{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionEndExcluding":"2.5.0"}')"
    run_offline_scan "$CASE_DIR/cache" "$GNUPG_INVENTORY" "$CASE_DIR/target" --min-cvss 7; output="$SCAN_OUTPUT"

    test_start "counter: [VULNERABILITY] block is printed for affected CVE"
    if echo "$output" | grep -q "\[VULNERABILITY\].*CVE-2025-99001"; then test_pass; else test_fail "CVE-2025-99001 reported" "not reported"; fi

    test_start "counter: summary reports Vulnerabilities: 1 (not 0)"
    if echo "$output" | grep -q "Vulnerabilities:[[:space:]]*1"; then test_pass; else test_fail "Vulnerabilities: 1" "$(echo "$output" | grep 'Vulnerabilities:')"; fi

    test_start "counter: summary reports HIGH: 1"
    if echo "$output" | grep -q "HIGH:.*1"; then test_pass; else test_fail "HIGH: 1" "$(echo "$output" | grep -i 'high:')"; fi

    test_start "counter: RESULT is FAIL when HIGH CVE reported"
    if echo "$output" | grep -q "RESULT: FAIL"; then test_pass; else test_fail "RESULT: FAIL" "$(echo "$output" | grep 'RESULT')"; fi

    test_start "counter: exit code is 1 when HIGH CVE reported"
    if [ "$SCAN_RC" = "1" ]; then test_pass; else test_fail "1" "$SCAN_RC"; fi

    test_start "counter: audit log records FINDING_DETECTED"
    if grep -rq "FINDING_DETECTED" "$CASE_DIR/target/.scans" 2>/dev/null; then test_pass; else test_fail "FINDING_DETECTED in audit log" "not found"; fi

    # --- Counter across multiple CVEs in one response ---
    CASE_DIR="$TEST_DIR/case-multi"
    mkdir -p "$CASE_DIR/target"
    seed_nvd_cache "$CASE_DIR/cache" gnupg 2.4.9 \
        "$(mock_vuln_record CVE-2025-99002 9.8 CRITICAL "Critical one." \
            '{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionEndExcluding":"2.5.0"}')" \
        "$(mock_vuln_record CVE-2025-99003 5.3 MEDIUM "Medium one." \
            '{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionEndExcluding":"2.5.0"}')" \
        "$(mock_vuln_record CVE-2025-99004 3.1 LOW "Low one." \
            '{"vulnerable":true,"criteria":"cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*","versionEndExcluding":"2.5.0"}')"
    run_offline_scan "$CASE_DIR/cache" "$GNUPG_INVENTORY" "$CASE_DIR/target"; output="$SCAN_OUTPUT"

    test_start "counter: three CVEs in one response sum to Vulnerabilities: 3"
    if echo "$output" | grep -q "Vulnerabilities:[[:space:]]*3"; then test_pass; else test_fail "Vulnerabilities: 3" "$(echo "$output" | grep 'Vulnerabilities:')"; fi

    test_start "counter: --min-cvss 7 keeps only the CRITICAL one"
    run_offline_scan "$CASE_DIR/cache" "$GNUPG_INVENTORY" "$CASE_DIR/target" --min-cvss 7; output="$SCAN_OUTPUT"
    if echo "$output" | grep -q "Vulnerabilities:[[:space:]]*1" && ! echo "$output" | grep -q "CVE-2025-99003"; then
        test_pass
    else
        test_fail "Vulnerabilities: 1 without CVE-2025-99003" "$(echo "$output" | grep -E 'Vulnerabilities:|CVE-')"
    fi

    # --- Version range regression: 'before 2.4.9' must not flag installed 2.4.9 ---
    CASE_DIR="$TEST_DIR/case-range"
    mkdir -p "$CASE_DIR/target"
    seed_nvd_cache "$CASE_DIR/cache" gnupg 2.4.9 \
        "$(mock_vuln_record CVE-2025-68973 7.8 HIGH "In GnuPG before 2.4.9, a flaw." "$GNUPG_BEFORE_249")"
    run_offline_scan "$CASE_DIR/cache" "$GNUPG_INVENTORY" "$CASE_DIR/target" --min-cvss 7; output="$SCAN_OUTPUT"

    test_start "range: CVE fixed in installed version is not reported as [VULNERABILITY]"
    if ! echo "$output" | grep -q "\[VULNERABILITY\]"; then test_pass; else test_fail "no [VULNERABILITY] block" "$(echo "$output" | grep 'VULNERABILITY')"; fi

    test_start "range: summary reports Vulnerabilities: 0"
    if echo "$output" | grep -q "Vulnerabilities:[[:space:]]*0"; then test_pass; else test_fail "Vulnerabilities: 0" "$(echo "$output" | grep 'Vulnerabilities:')"; fi

    test_start "range: summary reports Not Affected: 1 (transparency)"
    if echo "$output" | grep -q "Not Affected:[[:space:]]*1"; then test_pass; else test_fail "Not Affected: 1" "$(echo "$output" | grep 'Not Affected')"; fi

    test_start "range: RESULT is PASS and exit code 0"
    if echo "$output" | grep -q "RESULT: PASS" && [ "$SCAN_RC" = "0" ]; then test_pass; else test_fail "PASS / 0" "$(echo "$output" | grep 'RESULT') / $SCAN_RC"; fi

    test_start "range: -v lists the excluded CVE as [NOT AFFECTED]"
    run_offline_scan "$CASE_DIR/cache" "$GNUPG_INVENTORY" "$CASE_DIR/target" -v; output="$SCAN_OUTPUT"
    if echo "$output" | grep -q "\[NOT AFFECTED\] CVE-2025-68973"; then test_pass; else test_fail "[NOT AFFECTED] CVE-2025-68973" "not listed"; fi

    test_start "range: audit log records FINDING_EXCLUDED with reason"
    if grep -rq "FINDING_EXCLUDED.*version_not_in_range" "$CASE_DIR/target/.scans" 2>/dev/null; then test_pass; else test_fail "FINDING_EXCLUDED in audit log" "not found"; fi

    # --- Conservative fallback: no CPE data -> still reported, marked unverified ---
    CASE_DIR="$TEST_DIR/case-unverified"
    mkdir -p "$CASE_DIR/target"
    seed_nvd_cache "$CASE_DIR/cache" gnupg 2.4.9 \
        "$(mock_vuln_record CVE-2025-99005 7.8 HIGH "Record without configurations.")"
    run_offline_scan "$CASE_DIR/cache" "$GNUPG_INVENTORY" "$CASE_DIR/target"; output="$SCAN_OUTPUT"

    test_start "unverified: CVE without CPE data is still reported (fail-safe)"
    if echo "$output" | grep -q "\[VULNERABILITY\].*CVE-2025-99005" && [ "$SCAN_RC" = "1" ]; then test_pass; else test_fail "reported, exit 1" "$SCAN_RC"; fi

    test_start "unverified: finding is annotated 'Version: unverified'"
    if echo "$output" | grep -q "Version:[[:space:]]*unverified"; then test_pass; else test_fail "Version: unverified" "not annotated"; fi

    test_start "unverified: summary reports Unverified: 1"
    if echo "$output" | grep -q "Unverified:[[:space:]]*1"; then test_pass; else test_fail "Unverified: 1" "$(echo "$output" | grep 'Unverified')"; fi
else
    for name in "[VULNERABILITY] printed" "Vulnerabilities: 1" "HIGH: 1" "RESULT: FAIL" "exit code 1" \
                "audit FINDING_DETECTED" "three CVEs sum to 3" "--min-cvss 7 filter" \
                "range not reported" "range Vulnerabilities: 0" "range Not Affected: 1" \
                "range PASS / 0" "range -v NOT AFFECTED" "range audit FINDING_EXCLUDED" \
                "unverified reported" "unverified annotated" "unverified summary"; do
        test_start "regression: $name"
        test_skip "jq not installed"
    done
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
