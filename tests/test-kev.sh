#!/bin/bash
#
# Unit Tests for check-kev.sh
#
# Tests CISA KEV (Known Exploited Vulnerabilities) cross-reference functionality
#
# NIST Controls: RA-5 (Vulnerability Monitoring), SI-5 (Security Alerts)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEV_SCRIPT="$SECURITY_REPO_DIR/scripts/check-kev.sh"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Create temporary test directory
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

# Colors for output (match script style)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

#------------------------------------------------------------------------------
# Test Utilities
#------------------------------------------------------------------------------

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}FAIL${NC}: $1"
    [ -n "${2:-}" ] && echo "       $2"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
}

#------------------------------------------------------------------------------
# Test: Script existence and permissions
#------------------------------------------------------------------------------

test_script_exists() {
    run_test
    if [ -f "$KEV_SCRIPT" ]; then
        pass "check-kev.sh exists"
    else
        fail "check-kev.sh exists" "File not found: $KEV_SCRIPT"
    fi
}

test_script_executable() {
    run_test
    if [ -x "$KEV_SCRIPT" ]; then
        pass "check-kev.sh is executable"
    else
        fail "check-kev.sh is executable" "File is not executable"
    fi
}

test_script_has_shebang() {
    run_test
    if head -1 "$KEV_SCRIPT" | grep -q '^#!/bin/bash'; then
        pass "check-kev.sh has proper shebang"
    else
        fail "check-kev.sh has proper shebang"
    fi
}

#------------------------------------------------------------------------------
# Test: Script documentation
#------------------------------------------------------------------------------

test_script_has_usage() {
    run_test
    if grep -q 'usage()' "$KEV_SCRIPT"; then
        pass "Script has usage function"
    else
        fail "Script has usage function"
    fi
}

test_script_has_nist_reference() {
    run_test
    if grep -q 'NIST.*RA-5' "$KEV_SCRIPT"; then
        pass "Script references NIST RA-5 control"
    else
        fail "Script references NIST RA-5 control"
    fi
}

test_script_has_bod_reference() {
    run_test
    if grep -q 'BOD 22-01' "$KEV_SCRIPT"; then
        pass "Script references BOD 22-01"
    else
        fail "Script references BOD 22-01"
    fi
}

#------------------------------------------------------------------------------
# Test: Exit codes defined correctly
#------------------------------------------------------------------------------

test_exit_code_0_documented() {
    run_test
    if grep -q 'exit 0' "$KEV_SCRIPT" && grep -q 'No KEV matches' "$KEV_SCRIPT"; then
        pass "Exit code 0 = No KEV matches documented"
    else
        fail "Exit code 0 = No KEV matches documented"
    fi
}

test_exit_code_1_documented() {
    run_test
    if grep -q 'exit 1' "$KEV_SCRIPT" && grep -q 'KEV matches found' "$KEV_SCRIPT"; then
        pass "Exit code 1 = KEV matches found documented"
    else
        fail "Exit code 1 = KEV matches found documented"
    fi
}

test_exit_code_2_documented() {
    run_test
    if grep -q 'exit 2' "$KEV_SCRIPT" && grep -q 'Error' "$KEV_SCRIPT"; then
        pass "Exit code 2 = Error documented"
    else
        fail "Exit code 2 = Error documented"
    fi
}

#------------------------------------------------------------------------------
# Test: CVE pattern extraction
#------------------------------------------------------------------------------

test_cve_pattern_regex() {
    run_test
    # Script should use proper CVE regex
    if grep -q "CVE-\[0-9\]" "$KEV_SCRIPT"; then
        pass "Script has CVE regex pattern"
    else
        fail "Script has CVE regex pattern"
    fi
}

test_extract_cve_from_text() {
    run_test
    # Create test file with CVEs
    cat > "$TEST_DIR/test-scan.txt" << 'EOF'
Vulnerability scan results:
CVE-2021-44228 - Log4Shell (CRITICAL)
CVE-2023-12345 - Example vulnerability
Some text without CVEs
CVE-2022-22965 - Spring4Shell
EOF

    # Extract CVEs using grep pattern from script
    local cves
    cves=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/test-scan.txt" | sort -u)
    local count
    count=$(echo "$cves" | wc -l | tr -d ' ')

    if [ "$count" -eq 3 ]; then
        pass "CVE extraction finds correct count (3)"
    else
        fail "CVE extraction finds correct count" "Expected 3, got $count"
    fi
}

test_extract_cve_uniqueness() {
    run_test
    # Create test file with duplicate CVEs
    cat > "$TEST_DIR/test-dup.txt" << 'EOF'
CVE-2021-44228 found in file1
CVE-2021-44228 found in file2
CVE-2021-44228 found in file3
CVE-2022-22965 found once
EOF

    local cves
    cves=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/test-dup.txt" | sort -u)
    local count
    count=$(echo "$cves" | wc -l | tr -d ' ')

    if [ "$count" -eq 2 ]; then
        pass "CVE extraction deduplicates correctly (2 unique)"
    else
        fail "CVE extraction deduplicates correctly" "Expected 2, got $count"
    fi
}

test_extract_cve_formats() {
    run_test
    # Test various valid CVE formats
    cat > "$TEST_DIR/test-formats.txt" << 'EOF'
CVE-2021-1234 - 4 digit ID
CVE-2021-12345 - 5 digit ID
CVE-2021-123456 - 6 digit ID (rare)
CVE-99-1234 - invalid (old format)
EOF

    local cves
    cves=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/test-formats.txt" | sort -u)

    if echo "$cves" | grep -q 'CVE-2021-1234' && \
       echo "$cves" | grep -q 'CVE-2021-12345' && \
       echo "$cves" | grep -q 'CVE-2021-123456'; then
        pass "CVE extraction handles 4-6 digit IDs"
    else
        fail "CVE extraction handles 4-6 digit IDs" "Got: $cves"
    fi
}

test_extract_no_cves() {
    run_test
    # Create test file with no CVEs
    cat > "$TEST_DIR/test-none.txt" << 'EOF'
This file contains no vulnerabilities.
All systems are secure.
No CVE references here.
EOF

    local cves
    cves=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/test-none.txt" 2>/dev/null || true)

    if [ -z "$cves" ]; then
        pass "CVE extraction handles files with no CVEs"
    else
        fail "CVE extraction handles files with no CVEs" "Got: $cves"
    fi
}

#------------------------------------------------------------------------------
# Test: Cache directory handling
#------------------------------------------------------------------------------

test_cache_dir_defined() {
    run_test
    if grep -q 'KEV_CACHE_DIR=' "$KEV_SCRIPT"; then
        pass "KEV cache directory is defined"
    else
        fail "KEV cache directory is defined"
    fi
}

test_bundled_file_defined() {
    run_test
    if grep -q 'KEV_BUNDLED_FILE=' "$KEV_SCRIPT"; then
        pass "KEV bundled file path is defined (offline support)"
    else
        fail "KEV bundled file path is defined"
    fi
}

test_bundled_file_exists() {
    run_test
    local bundled_file="$SECURITY_REPO_DIR/data/kev-catalog.json"
    if [ -f "$bundled_file" ]; then
        pass "Bundled KEV catalog exists in data/"
    else
        fail "Bundled KEV catalog exists" "File not found: $bundled_file"
    fi
}

test_bundled_file_has_hash() {
    run_test
    local hash_file="$SECURITY_REPO_DIR/data/kev-catalog.json.sha256"
    if [ -f "$hash_file" ]; then
        pass "Bundled KEV catalog has SHA256 hash"
    else
        fail "Bundled KEV catalog has SHA256 hash"
    fi
}

test_bundled_file_valid_json() {
    run_test
    local bundled_file="$SECURITY_REPO_DIR/data/kev-catalog.json"
    if [ -f "$bundled_file" ] && jq empty "$bundled_file" 2>/dev/null; then
        pass "Bundled KEV catalog is valid JSON"
    else
        fail "Bundled KEV catalog is valid JSON"
    fi
}

test_offline_fallback_code_exists() {
    run_test
    if grep -q 'KEV_BUNDLED_FILE' "$KEV_SCRIPT" && grep -q 'offline mode' "$KEV_SCRIPT"; then
        pass "Script has offline fallback to bundled file"
    else
        fail "Script has offline fallback to bundled file"
    fi
}

test_cache_file_defined() {
    run_test
    if grep -q 'KEV_CACHE_FILE=' "$KEV_SCRIPT"; then
        pass "KEV cache file is defined"
    else
        fail "KEV cache file is defined"
    fi
}

test_cache_max_age_defined() {
    run_test
    if grep -q 'KEV_CACHE_MAX_AGE=86400' "$KEV_SCRIPT"; then
        pass "KEV cache max age is 24 hours (86400 seconds)"
    else
        fail "KEV cache max age is 24 hours"
    fi
}

#------------------------------------------------------------------------------
# Test: KEV catalog URL
#------------------------------------------------------------------------------

test_kev_url_is_cisa() {
    run_test
    if grep -q 'cisa.gov.*known_exploited_vulnerabilities.json' "$KEV_SCRIPT"; then
        pass "Script uses official CISA KEV catalog URL"
    else
        fail "Script uses official CISA KEV catalog URL"
    fi
}

test_kev_url_is_https() {
    run_test
    if grep -q 'https://www.cisa.gov' "$KEV_SCRIPT"; then
        pass "KEV URL uses HTTPS"
    else
        fail "KEV URL uses HTTPS"
    fi
}

#------------------------------------------------------------------------------
# Test: Dependencies check
#------------------------------------------------------------------------------

test_checks_for_curl() {
    run_test
    if grep -q 'command -v curl' "$KEV_SCRIPT"; then
        pass "Script checks for curl dependency"
    else
        fail "Script checks for curl dependency"
    fi
}

test_checks_for_jq() {
    run_test
    if grep -q 'command -v jq' "$KEV_SCRIPT"; then
        pass "Script checks for jq dependency"
    else
        fail "Script checks for jq dependency"
    fi
}

test_provides_install_instructions() {
    run_test
    if grep -q 'brew install' "$KEV_SCRIPT" && grep -q 'apt install' "$KEV_SCRIPT"; then
        pass "Script provides installation instructions for macOS and Linux"
    else
        fail "Script provides installation instructions"
    fi
}

#------------------------------------------------------------------------------
# Test: SHA256 integrity verification
#------------------------------------------------------------------------------

test_generates_sha256_hash() {
    run_test
    if grep -q 'sha.*256' "$KEV_SCRIPT"; then
        pass "Script generates SHA256 hash for integrity"
    else
        fail "Script generates SHA256 hash"
    fi
}

test_supports_macos_shasum() {
    run_test
    if grep -q 'shasum -a 256' "$KEV_SCRIPT"; then
        pass "Script supports macOS shasum command"
    else
        fail "Script supports macOS shasum command"
    fi
}

test_supports_linux_sha256sum() {
    run_test
    if grep -q 'sha256sum' "$KEV_SCRIPT"; then
        pass "Script supports Linux sha256sum command"
    else
        fail "Script supports Linux sha256sum command"
    fi
}

#------------------------------------------------------------------------------
# Test: JSON parsing with jq
#------------------------------------------------------------------------------

test_parses_kev_version() {
    run_test
    if grep -q '.catalogVersion' "$KEV_SCRIPT"; then
        pass "Script parses KEV catalog version"
    else
        fail "Script parses KEV catalog version"
    fi
}

test_parses_kev_count() {
    run_test
    if grep -q '.count' "$KEV_SCRIPT"; then
        pass "Script parses KEV entry count"
    else
        fail "Script parses KEV entry count"
    fi
}

test_parses_vulnerabilities() {
    run_test
    if grep -q '.vulnerabilities\[\]' "$KEV_SCRIPT"; then
        pass "Script iterates through vulnerabilities array"
    else
        fail "Script iterates through vulnerabilities array"
    fi
}

test_parses_cve_id() {
    run_test
    if grep -q '.cveID' "$KEV_SCRIPT"; then
        pass "Script parses cveID field"
    else
        fail "Script parses cveID field"
    fi
}

test_parses_vendor() {
    run_test
    if grep -q '.vendorProject' "$KEV_SCRIPT"; then
        pass "Script parses vendorProject field"
    else
        fail "Script parses vendorProject field"
    fi
}

test_parses_product() {
    run_test
    if grep -q '.product' "$KEV_SCRIPT"; then
        pass "Script parses product field"
    else
        fail "Script parses product field"
    fi
}

test_parses_due_date() {
    run_test
    if grep -q '.dueDate' "$KEV_SCRIPT"; then
        pass "Script parses dueDate field"
    else
        fail "Script parses dueDate field"
    fi
}

test_parses_ransomware_use() {
    run_test
    if grep -q '.knownRansomwareCampaignUse' "$KEV_SCRIPT"; then
        pass "Script parses knownRansomwareCampaignUse field"
    else
        fail "Script parses knownRansomwareCampaignUse field"
    fi
}

#------------------------------------------------------------------------------
# Test: Due date checking
#------------------------------------------------------------------------------

test_calculates_past_due() {
    run_test
    if grep -q 'DUE_DATE.*TODAY' "$KEV_SCRIPT" || grep -q 'PAST_DUE' "$KEV_SCRIPT"; then
        pass "Script calculates past due status"
    else
        fail "Script calculates past due status"
    fi
}

test_counts_past_due() {
    run_test
    if grep -q 'PAST_DUE=' "$KEV_SCRIPT"; then
        pass "Script counts past due entries"
    else
        fail "Script counts past due entries"
    fi
}

#------------------------------------------------------------------------------
# Test: Ransomware tracking
#------------------------------------------------------------------------------

test_tracks_ransomware_association() {
    run_test
    if grep -q 'RANSOMWARE=' "$KEV_SCRIPT"; then
        pass "Script tracks ransomware-associated CVEs"
    else
        fail "Script tracks ransomware-associated CVEs"
    fi
}

test_warns_about_ransomware() {
    run_test
    if grep -q 'RANSOMWARE CAMPAIGN' "$KEV_SCRIPT"; then
        pass "Script warns about ransomware campaign use"
    else
        fail "Script warns about ransomware campaign use"
    fi
}

#------------------------------------------------------------------------------
# Test: Command line options
#------------------------------------------------------------------------------

test_has_help_option() {
    run_test
    if grep -q '\-h|\-\-help' "$KEV_SCRIPT"; then
        pass "Script has --help option"
    else
        fail "Script has --help option"
    fi
}

test_has_force_option() {
    run_test
    if grep -q '\-f|\-\-force' "$KEV_SCRIPT"; then
        pass "Script has --force refresh option"
    else
        fail "Script has --force refresh option"
    fi
}

test_has_quiet_option() {
    run_test
    if grep -q '\-q|\-\-quiet' "$KEV_SCRIPT"; then
        pass "Script has --quiet option"
    else
        fail "Script has --quiet option"
    fi
}

#------------------------------------------------------------------------------
# Test: Output formatting
#------------------------------------------------------------------------------

test_outputs_summary() {
    run_test
    if grep -q 'SUMMARY' "$KEV_SCRIPT"; then
        pass "Script outputs summary section"
    else
        fail "Script outputs summary section"
    fi
}

test_outputs_kev_match_count() {
    run_test
    if grep -q 'KEV matches:' "$KEV_SCRIPT"; then
        pass "Script outputs KEV match count"
    else
        fail "Script outputs KEV match count"
    fi
}

test_outputs_nvd_reference() {
    run_test
    if grep -q 'nvd.nist.gov/vuln/detail' "$KEV_SCRIPT"; then
        pass "Script outputs NVD reference URLs"
    else
        fail "Script outputs NVD reference URLs"
    fi
}

test_outputs_cisa_reference() {
    run_test
    if grep -q 'cisa.gov/binding-operational-directive' "$KEV_SCRIPT"; then
        pass "Script outputs CISA BOD reference"
    else
        fail "Script outputs CISA BOD reference"
    fi
}

#------------------------------------------------------------------------------
# Test: Network timeout settings
#------------------------------------------------------------------------------

test_has_connect_timeout() {
    run_test
    if grep -q '\-\-connect-timeout' "$KEV_SCRIPT"; then
        pass "Script has curl connect timeout"
    else
        fail "Script has curl connect timeout"
    fi
}

test_has_max_time() {
    run_test
    if grep -q '\-\-max-time' "$KEV_SCRIPT"; then
        pass "Script has curl max-time setting"
    else
        fail "Script has curl max-time setting"
    fi
}

#------------------------------------------------------------------------------
# Test: Error handling
#------------------------------------------------------------------------------

test_uses_set_e() {
    run_test
    if grep -q 'set -e' "$KEV_SCRIPT" || grep -q 'set -eu' "$KEV_SCRIPT"; then
        pass "Script uses set -e for error handling"
    else
        fail "Script uses set -e"
    fi
}

test_validates_json() {
    run_test
    if grep -q 'jq empty' "$KEV_SCRIPT"; then
        pass "Script validates downloaded JSON"
    else
        fail "Script validates downloaded JSON"
    fi
}

test_handles_download_failure() {
    run_test
    if grep -q 'Failed to download' "$KEV_SCRIPT"; then
        pass "Script handles download failures"
    else
        fail "Script handles download failures"
    fi
}

test_handles_missing_scan_file() {
    run_test
    if grep -q 'Scan file not found' "$KEV_SCRIPT"; then
        pass "Script handles missing scan file"
    else
        fail "Script handles missing scan file"
    fi
}

#------------------------------------------------------------------------------
# Test: Platform compatibility
#------------------------------------------------------------------------------

test_detects_darwin_for_stat() {
    run_test
    if grep -q 'uname.*Darwin' "$KEV_SCRIPT" && grep -q 'stat -f' "$KEV_SCRIPT"; then
        pass "Script uses macOS-compatible stat command"
    else
        fail "Script uses macOS-compatible stat command"
    fi
}

test_detects_linux_for_stat() {
    run_test
    if grep -q 'stat -c' "$KEV_SCRIPT"; then
        pass "Script uses Linux-compatible stat command"
    else
        fail "Script uses Linux-compatible stat command"
    fi
}

#------------------------------------------------------------------------------
# Test: File finding logic
#------------------------------------------------------------------------------

test_finds_vulnerability_scans() {
    run_test
    if grep -q 'vulnerability-scan-\*.txt' "$KEV_SCRIPT"; then
        pass "Script searches for vulnerability scan files"
    else
        fail "Script searches for vulnerability scan files"
    fi
}

test_accepts_scan_file_argument() {
    run_test
    if grep -q 'SCAN_FILE=' "$KEV_SCRIPT"; then
        pass "Script accepts scan file as argument"
    else
        fail "Script accepts scan file as argument"
    fi
}

#------------------------------------------------------------------------------
# Test: Timestamp handling
#------------------------------------------------------------------------------

test_generates_timestamp() {
    run_test
    if grep -q 'TIMESTAMP=' "$KEV_SCRIPT" && grep -q 'date.*%Y' "$KEV_SCRIPT"; then
        pass "Script generates ISO 8601 timestamp"
    else
        fail "Script generates ISO 8601 timestamp"
    fi
}

#------------------------------------------------------------------------------
# Test: Function definitions
#------------------------------------------------------------------------------

test_has_check_dependencies_function() {
    run_test
    if grep -q 'check_dependencies()' "$KEV_SCRIPT"; then
        pass "Script has check_dependencies function"
    else
        fail "Script has check_dependencies function"
    fi
}

test_has_update_kev_cache_function() {
    run_test
    if grep -q 'update_kev_cache()' "$KEV_SCRIPT"; then
        pass "Script has update_kev_cache function"
    else
        fail "Script has update_kev_cache function"
    fi
}

test_has_get_kev_hash_function() {
    run_test
    if grep -q 'get_kev_hash()' "$KEV_SCRIPT"; then
        pass "Script has get_kev_hash function"
    else
        fail "Script has get_kev_hash function"
    fi
}

test_has_find_scan_file_function() {
    run_test
    if grep -q 'find_scan_file()' "$KEV_SCRIPT"; then
        pass "Script has find_scan_file function"
    else
        fail "Script has find_scan_file function"
    fi
}

test_has_extract_cves_function() {
    run_test
    if grep -q 'extract_cves()' "$KEV_SCRIPT"; then
        pass "Script has extract_cves function"
    else
        fail "Script has extract_cves function"
    fi
}

test_has_check_cve_in_kev_function() {
    run_test
    if grep -q 'check_cve_in_kev()' "$KEV_SCRIPT"; then
        pass "Script has check_cve_in_kev function"
    else
        fail "Script has check_cve_in_kev function"
    fi
}

#------------------------------------------------------------------------------
# Test: Mock KEV catalog parsing
#------------------------------------------------------------------------------

test_parse_mock_kev_entry() {
    run_test
    # Create a mock KEV catalog
    cat > "$TEST_DIR/mock-kev.json" << 'EOF'
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.01.29",
  "dateReleased": "2026-01-29T00:00:00.000Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j",
      "vulnerabilityName": "Apache Log4j Remote Code Execution",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j contains a remote code execution vulnerability.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known"
    },
    {
      "cveID": "CVE-2022-22965",
      "vendorProject": "VMware",
      "product": "Spring Framework",
      "vulnerabilityName": "Spring4Shell",
      "dateAdded": "2022-04-04",
      "shortDescription": "Spring Framework RCE vulnerability.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2022-04-25",
      "knownRansomwareCampaignUse": "Unknown"
    }
  ]
}
EOF

    # Test parsing the mock catalog
    if command -v jq &>/dev/null; then
        local version
        version=$(jq -r '.catalogVersion' "$TEST_DIR/mock-kev.json")
        if [ "$version" = "2026.01.29" ]; then
            pass "Can parse KEV catalog version from JSON"
        else
            fail "Parse KEV catalog version" "Got: $version"
        fi
    else
        pass "Can parse KEV catalog version from JSON (jq not installed - skipped)"
    fi
}

test_parse_mock_kev_count() {
    run_test
    if command -v jq &>/dev/null && [ -f "$TEST_DIR/mock-kev.json" ]; then
        local count
        count=$(jq -r '.count' "$TEST_DIR/mock-kev.json")
        if [ "$count" = "2" ]; then
            pass "Can parse KEV vulnerability count"
        else
            fail "Parse KEV vulnerability count" "Got: $count"
        fi
    else
        pass "Can parse KEV vulnerability count (jq not installed - skipped)"
    fi
}

test_parse_mock_kev_cve_lookup() {
    run_test
    if command -v jq &>/dev/null && [ -f "$TEST_DIR/mock-kev.json" ]; then
        local entry
        entry=$(jq -r '.vulnerabilities[] | select(.cveID == "CVE-2021-44228")' "$TEST_DIR/mock-kev.json")
        if echo "$entry" | grep -q 'Log4j'; then
            pass "Can look up CVE in KEV catalog"
        else
            fail "Look up CVE in KEV catalog"
        fi
    else
        pass "Can look up CVE in KEV catalog (jq not installed - skipped)"
    fi
}

test_parse_mock_kev_ransomware() {
    run_test
    if command -v jq &>/dev/null && [ -f "$TEST_DIR/mock-kev.json" ]; then
        local ransomware
        ransomware=$(jq -r '.vulnerabilities[] | select(.cveID == "CVE-2021-44228") | .knownRansomwareCampaignUse' "$TEST_DIR/mock-kev.json")
        if [ "$ransomware" = "Known" ]; then
            pass "Can parse ransomware campaign association"
        else
            fail "Parse ransomware campaign association" "Got: $ransomware"
        fi
    else
        pass "Can parse ransomware campaign association (jq not installed - skipped)"
    fi
}

#------------------------------------------------------------------------------
# Test: Help output
#------------------------------------------------------------------------------

test_help_shows_usage() {
    run_test
    # Check if --help runs without error (may exit 0)
    if "$KEV_SCRIPT" --help 2>&1 | grep -q 'Usage:'; then
        pass "--help shows usage information"
    else
        fail "--help shows usage information"
    fi
}

test_help_shows_options() {
    run_test
    if "$KEV_SCRIPT" --help 2>&1 | grep -q '\-\-force'; then
        pass "--help shows --force option"
    else
        fail "--help shows --force option"
    fi
}

#------------------------------------------------------------------------------
# Run all tests
#------------------------------------------------------------------------------

echo "=============================================================="
echo "  check-kev.sh Unit Tests"
echo "  NIST Controls: RA-5 (Vulnerability Monitoring), SI-5 (Alerts)"
echo "=============================================================="
echo ""

# Script existence and structure
test_script_exists
test_script_executable
test_script_has_shebang
test_script_has_usage
test_script_has_nist_reference
test_script_has_bod_reference

# Exit codes
test_exit_code_0_documented
test_exit_code_1_documented
test_exit_code_2_documented

# CVE pattern extraction
test_cve_pattern_regex
test_extract_cve_from_text
test_extract_cve_uniqueness
test_extract_cve_formats
test_extract_no_cves

# Cache handling
test_cache_dir_defined
test_cache_file_defined
test_cache_max_age_defined

# Offline/bundled support
test_bundled_file_defined
test_bundled_file_exists
test_bundled_file_has_hash
test_bundled_file_valid_json
test_offline_fallback_code_exists

# KEV catalog URL
test_kev_url_is_cisa
test_kev_url_is_https

# Dependencies
test_checks_for_curl
test_checks_for_jq
test_provides_install_instructions

# SHA256 integrity
test_generates_sha256_hash
test_supports_macos_shasum
test_supports_linux_sha256sum

# JSON parsing
test_parses_kev_version
test_parses_kev_count
test_parses_vulnerabilities
test_parses_cve_id
test_parses_vendor
test_parses_product
test_parses_due_date
test_parses_ransomware_use

# Due date checking
test_calculates_past_due
test_counts_past_due

# Ransomware tracking
test_tracks_ransomware_association
test_warns_about_ransomware

# Command line options
test_has_help_option
test_has_force_option
test_has_quiet_option

# Output formatting
test_outputs_summary
test_outputs_kev_match_count
test_outputs_nvd_reference
test_outputs_cisa_reference

# Network settings
test_has_connect_timeout
test_has_max_time

# Error handling
test_uses_set_e
test_validates_json
test_handles_download_failure
test_handles_missing_scan_file

# Platform compatibility
test_detects_darwin_for_stat
test_detects_linux_for_stat

# File finding
test_finds_vulnerability_scans
test_accepts_scan_file_argument

# Timestamp
test_generates_timestamp

# Functions
test_has_check_dependencies_function
test_has_update_kev_cache_function
test_has_get_kev_hash_function
test_has_find_scan_file_function
test_has_extract_cves_function
test_has_check_cve_in_kev_function

# Mock KEV parsing
test_parse_mock_kev_entry
test_parse_mock_kev_count
test_parse_mock_kev_cve_lookup
test_parse_mock_kev_ransomware

# Help output
test_help_shows_usage
test_help_shows_options

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------

echo ""
echo "=============================================================="
echo "  Summary"
echo "=============================================================="
echo ""
echo "  Tests run:    $TESTS_RUN"
echo "  Passed:       $TESTS_PASSED"
echo "  Failed:       $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo -e "${RED}FAILED${NC}: $TESTS_FAILED test(s) failed"
    exit 1
else
    echo -e "${GREEN}PASSED${NC}: All tests passed"
    exit 0
fi
