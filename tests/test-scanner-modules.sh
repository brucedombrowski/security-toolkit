#!/bin/bash
#
# Scanner Module Unit Tests
#
# Purpose: Unit tests for lib/scanners/ module libraries
# NIST Control: CA-2 (Security Assessments), SA-11 (Developer Testing)
#
# Usage: ./tests/test-scanner-modules.sh
#
# Tests:
#   - common.sh: Logging helpers, dependency checking, output initialization
#   - nist-controls.sh: NIST 800-53/171 control definitions and lookups
#   - report.sh: Report generation functions
#   - nmap.sh: Nmap module sourcing and result summarization
#   - lynis.sh: Lynis module sourcing and result summarization
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$REPO_DIR/scripts/lib/scanners"
TEST_DIR=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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

section_header() {
    echo ""
    echo -e "${CYAN}--- $1 ---${NC}"
}

# Cleanup function
cleanup() {
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
}
trap cleanup EXIT

echo "=========================================="
echo "Scanner Module Unit Tests"
echo "=========================================="

# Create test directory
TEST_DIR=$(mktemp -d)
echo "Test directory: $TEST_DIR"

# =============================================================================
# SECTION 1: Common Library Tests
# =============================================================================
section_header "Common Library (common.sh)"

test_start "common.sh can be sourced"
if source "$LIB_DIR/common.sh" 2>/dev/null; then
    test_pass
else
    test_fail "successful source" "source failed"
fi

test_start "log_info function exists"
if type log_info &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "log_success function exists"
if type log_success &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "log_warning function exists"
if type log_warning &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "log_error function exists"
if type log_error &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "log_info produces output"
output=$(log_info "test message" 2>&1)
if echo "$output" | grep -q "test message"; then
    test_pass
else
    test_fail "output with message" "no output"
fi

test_start "log_info includes INFO tag"
output=$(log_info "test" 2>&1)
if echo "$output" | grep -q "INFO"; then
    test_pass
else
    test_fail "INFO tag" "not found"
fi

test_start "log_success includes PASS tag"
output=$(log_success "test" 2>&1)
if echo "$output" | grep -q "PASS"; then
    test_pass
else
    test_fail "PASS tag" "not found"
fi

test_start "log_warning includes WARN tag"
output=$(log_warning "test" 2>&1)
if echo "$output" | grep -q "WARN"; then
    test_pass
else
    test_fail "WARN tag" "not found"
fi

test_start "log_error includes FAIL tag"
output=$(log_error "test" 2>&1)
if echo "$output" | grep -q "FAIL"; then
    test_pass
else
    test_fail "FAIL tag" "not found"
fi

test_start "check_root function exists"
if type check_root &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "check_scanner_deps function exists"
if type check_scanner_deps &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "init_scanner_output function exists"
if type init_scanner_output &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "init_scanner_output creates directory"
# Pass empty base_dir so the function creates .scans under security_repo_dir
init_scanner_output "" "2026-01-30" "$TEST_DIR" > /dev/null 2>&1
if [ -d "$TEST_DIR/.scans" ]; then
    test_pass
else
    test_fail ".scans directory" "not created"
fi

test_start "init_scanner_output sets SCANNER_OUTPUT_DIR"
if [ -n "$SCANNER_OUTPUT_DIR" ]; then
    test_pass
else
    test_fail "SCANNER_OUTPUT_DIR set" "not set"
fi

test_start "print_scanner_section function exists"
if type print_scanner_section &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "print_scanner_section produces formatted output"
output=$(print_scanner_section "TEST SECTION" 2>&1)
if echo "$output" | grep -q "TEST SECTION" && echo "$output" | grep -q "===="; then
    test_pass
else
    test_fail "formatted section" "missing title or border"
fi

# =============================================================================
# SECTION 2: NIST Controls Library Tests
# =============================================================================
section_header "NIST Controls Library (nist-controls.sh)"

test_start "nist-controls.sh can be sourced"
if source "$LIB_DIR/nist-controls.sh" 2>/dev/null; then
    test_pass
else
    test_fail "successful source" "source failed"
fi

test_start "get_nist_800_53_control function exists"
if type get_nist_800_53_control &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "get_nist_800_53_control returns correct value for RA-5"
result=$(get_nist_800_53_control "RA-5")
if echo "$result" | grep -qi "vulnerability"; then
    test_pass
else
    test_fail "Vulnerability description" "$result"
fi

test_start "get_nist_800_53_control returns correct value for CA-2"
result=$(get_nist_800_53_control "CA-2")
if echo "$result" | grep -qi "assessment"; then
    test_pass
else
    test_fail "Assessment description" "$result"
fi

test_start "get_nist_800_53_control handles unknown control"
result=$(get_nist_800_53_control "XX-99")
if echo "$result" | grep -qi "unknown"; then
    test_pass
else
    test_fail "Unknown control message" "$result"
fi

test_start "get_nist_800_53_family function exists"
if type get_nist_800_53_family &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "get_nist_800_53_family returns correct family for RA-*"
result=$(get_nist_800_53_family "RA-5")
if echo "$result" | grep -qi "risk"; then
    test_pass
else
    test_fail "Risk Assessment family" "$result"
fi

test_start "get_nist_800_53_family returns correct family for SI-*"
result=$(get_nist_800_53_family "SI-2")
if echo "$result" | grep -qi "integrity"; then
    test_pass
else
    test_fail "System Integrity family" "$result"
fi

test_start "get_nist_800_171_control function exists"
if type get_nist_800_171_control &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "get_nist_800_171_control returns correct value for 3.11.2"
result=$(get_nist_800_171_control "3.11.2")
if echo "$result" | grep -qi "vulnerabilit"; then
    test_pass
else
    test_fail "Vulnerability description" "$result"
fi

test_start "get_nist_800_171_family function exists"
if type get_nist_800_171_family &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "get_nist_800_171_family returns correct family for 3.11.*"
result=$(get_nist_800_171_family "3.11.1")
if echo "$result" | grep -qi "risk"; then
    test_pass
else
    test_fail "Risk Assessment family" "$result"
fi

test_start "get_scanner_controls_800_53 function exists"
if type get_scanner_controls_800_53 &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "get_scanner_controls_800_53 returns controls for nmap"
result=$(get_scanner_controls_800_53 "nmap")
if echo "$result" | grep -q "RA-5"; then
    test_pass
else
    test_fail "RA-5 control for nmap" "$result"
fi

test_start "get_scanner_controls_800_53 returns controls for lynis"
result=$(get_scanner_controls_800_53 "lynis")
if echo "$result" | grep -q "CM-6\|SI-7\|CA-2"; then
    test_pass
else
    test_fail "CM-6/SI-7/CA-2 for lynis" "$result"
fi

test_start "get_scanner_controls_800_171 function exists"
if type get_scanner_controls_800_171 &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "print_nist_controls_header function exists"
if type print_nist_controls_header &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "print_nist_controls_header produces output"
output=$(print_nist_controls_header "nmap" 2>&1)
if echo "$output" | grep -q "NIST"; then
    test_pass
else
    test_fail "NIST in output" "not found"
fi

test_start "NIST_800_53_CONTROLS variable is set"
if [ -n "$NIST_800_53_CONTROLS" ]; then
    test_pass
else
    test_fail "variable set" "not set"
fi

test_start "NIST_800_171_CONTROLS variable is set"
if [ -n "$NIST_800_171_CONTROLS" ]; then
    test_pass
else
    test_fail "variable set" "not set"
fi

# =============================================================================
# SECTION 3: Report Library Tests
# =============================================================================
section_header "Report Library (report.sh)"

test_start "report.sh can be sourced"
if source "$LIB_DIR/report.sh" 2>/dev/null; then
    test_pass
else
    test_fail "successful source" "source failed"
fi

test_start "print_scan_header function exists"
if type print_scan_header &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "print_scan_header produces formatted output"
output=$(print_scan_header "2026-01-30" "localhost" "full" "testhost" "Security" "1.0.0" "abc123" "https://example.com" 2>&1)
if echo "$output" | grep -q "VULNERABILITY SCANNING REPORT"; then
    test_pass
else
    test_fail "report header" "not found"
fi

test_start "print_scan_header includes timestamp"
output=$(print_scan_header "2026-01-30T12:00:00Z" "localhost" "full" "testhost" "Security" "1.0.0" "abc123" "https://example.com" 2>&1)
if echo "$output" | grep -q "2026-01-30"; then
    test_pass
else
    test_fail "timestamp in output" "not found"
fi

test_start "init_report_file function exists"
if type init_report_file &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "init_report_file creates file"
report_file="$TEST_DIR/test-report.txt"
init_report_file "$report_file" "2026-01-30" "localhost" "Security" "1.0.0" "abc123" "https://example.com"
if [ -f "$report_file" ]; then
    test_pass
else
    test_fail "report file created" "not created"
fi

test_start "init_report_file writes header content"
if grep -q "VULNERABILITY SCANNING REPORT" "$report_file"; then
    test_pass
else
    test_fail "header in file" "not found"
fi

test_start "generate_compliance_report function exists"
if type generate_compliance_report &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "generate_compliance_report appends to file"
generate_compliance_report "$report_file" "2026-01-30" "localhost" "testhost" "full" "1.0.0" "abc123" "true" "false" "true"
if grep -q "NIST COMPLIANCE MAPPING" "$report_file"; then
    test_pass
else
    test_fail "compliance mapping in file" "not found"
fi

test_start "generate_compliance_report includes 800-53 controls"
if grep -q "NIST SP 800-53" "$report_file"; then
    test_pass
else
    test_fail "800-53 reference" "not found"
fi

test_start "generate_compliance_report includes 800-171 controls"
if grep -q "NIST SP 800-171" "$report_file"; then
    test_pass
else
    test_fail "800-171 reference" "not found"
fi

test_start "generate_compliance_report shows tool status"
if grep -q "\[X\] Nmap" "$report_file"; then
    test_pass
else
    test_fail "tool status markers" "not found"
fi

test_start "print_scan_summary function exists"
if type print_scan_summary &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "print_scan_summary produces output"
output=$(print_scan_summary "3" "2" "$report_file" "0" 2>&1)
if echo "$output" | grep -q "SCAN COMPLETION SUMMARY"; then
    test_pass
else
    test_fail "summary header" "not found"
fi

test_start "print_scanner_usage function exists"
if type print_scanner_usage &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "print_scanner_usage produces help text"
output=$(print_scanner_usage "test-script" 2>&1)
if echo "$output" | grep -q "Usage:" && echo "$output" | grep -q "Options:"; then
    test_pass
else
    test_fail "usage text" "incomplete"
fi

# =============================================================================
# SECTION 4: Nmap Module Tests
# =============================================================================
section_header "Nmap Module (nmap.sh)"

test_start "nmap.sh can be sourced"
if source "$LIB_DIR/nmap.sh" 2>/dev/null; then
    test_pass
else
    test_fail "successful source" "source failed"
fi

test_start "run_nmap_scan function exists"
if type run_nmap_scan &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "summarize_nmap_results function exists"
if type summarize_nmap_results &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

# Create mock nmap output for testing summarization
mock_nmap_output="$TEST_DIR/mock-nmap.txt"
cat > "$mock_nmap_output" << 'EOF'
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00012s latency).

PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 8.4
80/tcp   open     http     Apache httpd
443/tcp  open     https    Apache httpd
3306/tcp filtered mysql

EOF

test_start "summarize_nmap_results parses open ports"
output=$(summarize_nmap_results "$mock_nmap_output" 2>&1)
if echo "$output" | grep -q "Open ports found: 3"; then
    test_pass
else
    test_fail "3 open ports" "incorrect count"
fi

test_start "summarize_nmap_results parses filtered ports"
if echo "$output" | grep -q "Filtered ports: 1"; then
    test_pass
else
    test_fail "1 filtered port" "incorrect count"
fi

test_start "summarize_nmap_results shows security assessment"
if echo "$output" | grep -q "Security assessment"; then
    test_pass
else
    test_fail "security assessment section" "not found"
fi

# Create mock output with vulnerable services
mock_nmap_vuln="$TEST_DIR/mock-nmap-vuln.txt"
cat > "$mock_nmap_vuln" << 'EOF'
Nmap scan report for target (10.0.0.1)
Host is up.

PORT     STATE SERVICE
21/tcp   open  ftp
23/tcp   open  telnet
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

EOF

test_start "summarize_nmap_results detects telnet"
output=$(summarize_nmap_results "$mock_nmap_vuln" 2>&1)
if echo "$output" | grep -qi "telnet.*detected\|insecure"; then
    test_pass
else
    test_fail "telnet warning" "not detected"
fi

test_start "summarize_nmap_results detects FTP"
if echo "$output" | grep -qi "ftp.*detected\|SFTP"; then
    test_pass
else
    test_fail "FTP warning" "not detected"
fi

# =============================================================================
# SECTION 5: Lynis Module Tests
# =============================================================================
section_header "Lynis Module (lynis.sh)"

test_start "lynis.sh can be sourced"
if source "$LIB_DIR/lynis.sh" 2>/dev/null; then
    test_pass
else
    test_fail "successful source" "source failed"
fi

test_start "run_lynis_audit function exists"
if type run_lynis_audit &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

test_start "summarize_lynis_results function exists"
if type summarize_lynis_results &>/dev/null; then
    test_pass
else
    test_fail "function defined" "not found"
fi

# Create mock lynis output for testing summarization
mock_lynis_output="$TEST_DIR/mock-lynis.txt"
cat > "$mock_lynis_output" << 'EOF'
Lynis 3.0.8 - Security auditing tool

[+] Initializing program
------------------------------------

  ---------------------------------------------------
  Program version:           3.0.8
  Operating system:          macOS
  Operating system name:     macOS Sequoia
  Operating system version:  15.0
  ---------------------------------------------------

[ warning ] SSH Daemon is running
[ warning ] Found some issue with firewall
[ suggestion ] Consider enabling full disk encryption
[ suggestion ] Disable unused services
[ suggestion ] Update system packages

  Hardening index : 72 [##############      ]
  Tests performed : 250
  Plugins enabled : 0

EOF

mock_lynis_report="$TEST_DIR/mock-lynis-report.dat"
cat > "$mock_lynis_report" << 'EOF'
hardening_index=72
tests_performed=250
warnings=2
suggestions=3
EOF

test_start "summarize_lynis_results parses hardening index"
output=$(summarize_lynis_results "$mock_lynis_output" "$mock_lynis_report" 2>&1)
if echo "$output" | grep -q "Hardening Index: 72"; then
    test_pass
else
    test_fail "hardening index 72" "not parsed correctly"
fi

test_start "summarize_lynis_results counts warnings"
if echo "$output" | grep -q "Warnings:.*2"; then
    test_pass
else
    test_fail "2 warnings" "incorrect count"
fi

test_start "summarize_lynis_results counts suggestions"
if echo "$output" | grep -q "Suggestions:.*3"; then
    test_pass
else
    test_fail "3 suggestions" "incorrect count"
fi

test_start "summarize_lynis_results assesses hardening level"
# 72 is >= 60 and < 80, so should be MODERATE
if echo "$output" | grep -qi "MODERATE\|improvements"; then
    test_pass
else
    test_fail "MODERATE assessment" "not found"
fi

# =============================================================================
# SECTION 6: Integration Tests
# =============================================================================
section_header "Integration Tests"

test_start "All modules can be sourced together"
if bash -c "
    source '$LIB_DIR/common.sh'
    source '$LIB_DIR/nist-controls.sh'
    source '$LIB_DIR/report.sh'
    source '$LIB_DIR/nmap.sh'
    source '$LIB_DIR/lynis.sh'
" 2>/dev/null; then
    test_pass
else
    test_fail "all modules source" "conflict or error"
fi

test_start "NIST control lookup integration"
result=$(bash -c "
    source '$LIB_DIR/nist-controls.sh'
    for control in RA-5 CA-2 SI-2; do
        desc=\$(get_nist_800_53_control \"\$control\")
        echo \"\$control: \$desc\"
    done
")
if echo "$result" | grep -q "RA-5:" && echo "$result" | grep -q "CA-2:" && echo "$result" | grep -q "SI-2:"; then
    test_pass
else
    test_fail "multiple control lookups" "some failed"
fi

test_start "Report generation uses NIST controls"
# Ensure compliance report references controls from nist-controls.sh
if grep -q "RA-5\|CA-2\|SI-2" "$report_file"; then
    test_pass
else
    test_fail "NIST controls in report" "not found"
fi

test_start "scan-vulnerabilities.sh sources all modules"
if head -200 "$REPO_DIR/scripts/scan-vulnerabilities.sh" | grep -q "source.*scanners/common.sh"; then
    test_pass
else
    test_fail "sources common.sh" "not found"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=========================================="
echo "Scanner Module Test Summary"
echo "=========================================="
echo "  Total:   $TESTS_RUN"
echo "  Passed:  $TESTS_PASSED"
echo "  Failed:  $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All scanner module tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED scanner module test(s) failed${NC}"
    exit 1
fi
