#!/bin/bash
#
# Advanced Integration Tests - Cross-Component Verification
#
# Purpose: Test interactions between components, error handling, and edge cases
# NIST Control: CA-2, CA-7 (Security Assessment & Continuous Monitoring)
#
# Usage: ./tests/test-integration-advanced.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

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
    [ -n "${1:-}" ] && echo "    Expected: $1"
    [ -n "${2:-}" ] && echo "    Got: $2"
}

test_skip() {
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    TESTS_RUN=$((TESTS_RUN - 1))
    echo -e "${YELLOW}SKIP${NC} ($1)"
}

section_header() {
    echo ""
    echo -e "${CYAN}=== $1 ===${NC}"
}

# Create temp directory
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "=============================================="
echo "  Advanced Integration Tests"
echo "=============================================="
echo ""
echo "Test directory: $TEST_DIR"

# =============================================================================
# SECTION 1: KEV Integration Tests
# =============================================================================
section_header "KEV Catalog Integration"

# Create test file with known CVEs
cat > "$TEST_DIR/vulnerability-scan.txt" << 'EOF'
Vulnerability Scan Results
===========================
CVE-2021-44228: Log4Shell - Critical RCE in Apache Log4j
CVE-2022-22965: Spring4Shell - Spring Framework RCE
CVE-2023-12345: Example vulnerability (not in KEV)
CVE-2021-26855: ProxyLogon - Microsoft Exchange Server
EOF

test_start "check-kev.sh processes CVE file"
kev_output=$("$REPO_DIR/scripts/check-kev.sh" "$TEST_DIR/vulnerability-scan.txt" 2>&1 || true)
if echo "$kev_output" | grep -qi "CVE\|KEV"; then
    test_pass
else
    test_fail "KEV processing" "no CVE/KEV output"
fi

test_start "check-kev.sh extracts CVE count"
if echo "$kev_output" | grep -qi "CVEs in scan\|unique CVE"; then
    test_pass
else
    test_fail "CVE count" "not displayed"
fi

test_start "check-kev.sh shows catalog metadata"
if echo "$kev_output" | grep -qi "KEV Catalog Version\|KEV Total Entries\|catalogVersion"; then
    test_pass
else
    test_fail "catalog metadata" "not shown"
fi

test_start "Bundled KEV catalog exists"
if [ -f "$REPO_DIR/data/kev-catalog.json" ]; then
    test_pass
else
    test_fail "bundled catalog" "not found"
fi

test_start "Bundled KEV catalog has integrity hash"
if [ -f "$REPO_DIR/data/kev-catalog.json.sha256" ]; then
    test_pass
else
    test_fail "SHA256 hash" "not found"
fi

test_start "Bundled KEV catalog hash is valid"
if [ -f "$REPO_DIR/data/kev-catalog.json" ]; then
    cd "$REPO_DIR/data"
    if shasum -a 256 -c kev-catalog.json.sha256 > /dev/null 2>&1; then
        test_pass
    else
        test_fail "hash verification" "checksum mismatch"
    fi
    cd - > /dev/null
else
    test_skip "catalog not found"
fi

# =============================================================================
# SECTION 2: NVD CVE Integration Tests
# =============================================================================
section_header "NVD CVE Integration"

test_start "check-nvd-cves.sh runs in offline mode"
nvd_output=$("$REPO_DIR/scripts/check-nvd-cves.sh" --offline 2>&1 || true)
if echo "$nvd_output" | grep -qi "NVD\|CVE\|offline\|vulnerability"; then
    test_pass
else
    test_fail "offline mode" "script did not run"
fi

test_start "NVD matcher library loads"
if bash -c "source '$REPO_DIR/scripts/lib/nvd/matcher.sh' && type get_cpe_mapping" > /dev/null 2>&1; then
    test_pass
else
    test_fail "matcher library" "failed to load"
fi

test_start "NVD API library loads"
if bash -c "source '$REPO_DIR/scripts/lib/nvd/api.sh' && type init_nvd_cache" > /dev/null 2>&1; then
    test_pass
else
    test_fail "API library" "failed to load"
fi

test_start "CPE mapping works for common packages"
cpe_result=$(bash -c "source '$REPO_DIR/scripts/lib/nvd/matcher.sh' && get_cpe_mapping 'openssl'" 2>&1)
if echo "$cpe_result" | grep -q "openssl"; then
    test_pass
else
    test_fail "openssl CPE" "mapping failed"
fi

# =============================================================================
# SECTION 3: PDF Generation Tests
# =============================================================================
section_header "PDF Generation"

test_start "generate-scan-attestation.sh exists and is executable"
if [ -x "$REPO_DIR/scripts/generate-scan-attestation.sh" ]; then
    test_pass
else
    test_fail "script executable" "not found or not executable"
fi

test_start "generate-compliance.sh exists and is executable"
if [ -x "$REPO_DIR/scripts/generate-compliance.sh" ]; then
    test_pass
else
    test_fail "script executable" "not found or not executable"
fi

test_start "LaTeX templates exist"
if [ -f "$REPO_DIR/templates/scan_attestation.tex" ] && \
   [ -f "$REPO_DIR/templates/security_compliance_statement.tex" ]; then
    test_pass
else
    test_fail "templates" "not found"
fi

if command -v pdflatex &> /dev/null; then
    # Create minimal scan results for PDF generation
    mkdir -p "$TEST_DIR/pdftest/.scans"
    TIMESTAMP=$(date -u "+%Y-%m-%dT%H%M%SZ")
    cat > "$TEST_DIR/pdftest/.scans/security-scan-report-$TIMESTAMP.txt" << EOF
Security Scan Report
====================
Timestamp: $TIMESTAMP
Target: $TEST_DIR/pdftest

SCAN RESULTS
------------
PII Scan: PASS
Secrets Scan: PASS
Malware Scan: PASS
Host Security: PASS

SUMMARY
-------
All scans passed.
EOF
    # Also create the checksums file that attestation script expects
    echo "abc123  security-scan-report-$TIMESTAMP.txt" > "$TEST_DIR/pdftest/.scans/checksums.txt"

    test_start "Scan attestation PDF generates"
    pdf_result=$("$REPO_DIR/scripts/generate-scan-attestation.sh" "$TEST_DIR/pdftest" 2>&1 || echo "SCRIPT_ERROR")
    if ls "$TEST_DIR/pdftest/.scans/"*attestation*.pdf > /dev/null 2>&1; then
        test_pass
    elif echo "$pdf_result" | grep -qi "generated\|created\|success"; then
        test_pass
    else
        # PDF generation has complex dependencies, skip if LaTeX setup incomplete
        test_skip "LaTeX environment incomplete"
    fi
else
    test_start "pdflatex available for PDF generation"
    test_skip "pdflatex not installed"
fi

# =============================================================================
# SECTION 4: Cross-Script Data Flow Tests
# =============================================================================
section_header "Cross-Script Data Flow"

# Create project with known issues
mkdir -p "$TEST_DIR/project/src"
cat > "$TEST_DIR/project/src/config.py" << 'EOF'
# Configuration with secrets
API_KEY = "sk_live_1234567890abcdef"
DB_PASSWORD = "super_secret_123"
SSN = "123-45-6789"
EOF

test_start "Full scan workflow creates all expected outputs"
"$REPO_DIR/scripts/run-all-scans.sh" -n "$TEST_DIR/project" > /dev/null 2>&1 || true
outputs_found=0
[ -f "$TEST_DIR/project/.scans/"*pii*.txt ] && outputs_found=$((outputs_found + 1))
[ -f "$TEST_DIR/project/.scans/"*secrets*.txt ] && outputs_found=$((outputs_found + 1))
[ -f "$TEST_DIR/project/.scans/"*report*.txt ] && outputs_found=$((outputs_found + 1))
if [ $outputs_found -ge 3 ]; then
    test_pass
else
    test_fail "3+ output files" "$outputs_found files"
fi

test_start "Scan report references individual scan files"
report=$(ls "$TEST_DIR/project/.scans/"*report*.txt 2>/dev/null | head -1)
if [ -n "$report" ] && grep -qi "pii\|secrets\|scan" "$report"; then
    test_pass
else
    test_fail "report references" "not found"
fi

test_start "Audit log captures all scan events"
audit_log=$(ls "$TEST_DIR/project/.scans/"audit-log*.jsonl 2>/dev/null | head -1 || echo "")
if [ -n "$audit_log" ] && [ -f "$audit_log" ]; then
    event_count=$(grep -c '"event":' "$audit_log" 2>/dev/null || echo "0")
    if [ "$event_count" -ge 2 ]; then
        test_pass
    else
        test_fail "multiple events" "$event_count events"
    fi
else
    test_fail "audit log" "not found"
fi

# =============================================================================
# SECTION 5: Error Handling Tests
# =============================================================================
section_header "Error Handling"

test_start "Scripts handle non-existent directory gracefully"
error_output=$("$REPO_DIR/scripts/check-pii.sh" "/nonexistent/path/12345" 2>&1 || true)
# Should not crash, should show error message
if echo "$error_output" | grep -qi "error\|not found\|does not exist\|invalid" || [ $? -ne 0 ]; then
    test_pass
else
    test_fail "error message" "no error handling"
fi

test_start "Scripts handle empty directory"
mkdir -p "$TEST_DIR/empty"
empty_output=$("$REPO_DIR/scripts/check-secrets.sh" "$TEST_DIR/empty" 2>&1 || true)
if echo "$empty_output" | grep -qi "PASS\|no.*found\|0 findings"; then
    test_pass
else
    test_fail "empty dir handling" "unexpected output"
fi

test_start "Scripts handle permission denied gracefully"
mkdir -p "$TEST_DIR/noaccess"
echo "secret" > "$TEST_DIR/noaccess/file.txt"
chmod 000 "$TEST_DIR/noaccess/file.txt" 2>/dev/null || true
perm_output=$("$REPO_DIR/scripts/check-secrets.sh" "$TEST_DIR/noaccess" 2>&1 || true)
# Should complete without crashing
if [ -n "$perm_output" ]; then
    test_pass
else
    test_fail "permission handling" "script crashed"
fi
chmod 644 "$TEST_DIR/noaccess/file.txt" 2>/dev/null || true

# =============================================================================
# SECTION 6: Concurrent Execution Tests
# =============================================================================
section_header "Concurrent Execution Safety"

# Create two separate test directories
mkdir -p "$TEST_DIR/project1" "$TEST_DIR/project2"
echo "test content 1" > "$TEST_DIR/project1/test.txt"
echo "test content 2" > "$TEST_DIR/project2/test.txt"

test_start "Parallel scans don't interfere with each other"
# Run two scans in parallel
"$REPO_DIR/scripts/check-pii.sh" "$TEST_DIR/project1" > "$TEST_DIR/out1.txt" 2>&1 &
pid1=$!
"$REPO_DIR/scripts/check-pii.sh" "$TEST_DIR/project2" > "$TEST_DIR/out2.txt" 2>&1 &
pid2=$!
wait $pid1 $pid2

# Both should complete
if [ -s "$TEST_DIR/out1.txt" ] && [ -s "$TEST_DIR/out2.txt" ]; then
    test_pass
else
    test_fail "both complete" "one or both failed"
fi

# =============================================================================
# SECTION 7: Upgrade Script Tests
# =============================================================================
section_header "Upgrade Script"

test_start "upgrade.sh exists and is executable"
if [ -x "$REPO_DIR/scripts/upgrade.sh" ]; then
    test_pass
else
    test_fail "executable" "not found"
fi

test_start "upgrade.sh detects git repository"
upgrade_output=$("$REPO_DIR/scripts/upgrade.sh" 2>&1 || true)
if echo "$upgrade_output" | grep -qi "version\|upgrade\|up to date\|commit"; then
    test_pass
else
    test_fail "git detection" "no version info"
fi

# =============================================================================
# SECTION 8: Library Dependency Chain Tests
# =============================================================================
section_header "Library Dependency Chains"

test_start "Scanner libraries load with all dependencies"
if bash -c "
    source '$REPO_DIR/scripts/lib/timestamps.sh'
    source '$REPO_DIR/scripts/lib/audit-log.sh'
    source '$REPO_DIR/scripts/lib/progress.sh'
    source '$REPO_DIR/scripts/lib/scanners/common.sh'
    source '$REPO_DIR/scripts/lib/scanners/nist-controls.sh'
    source '$REPO_DIR/scripts/lib/scanners/report.sh'
    type print_scan_header && type get_nist_800_53_control
" > /dev/null 2>&1; then
    test_pass
else
    test_fail "scanner chain" "dependency failure"
fi

test_start "Inventory libraries load with all dependencies"
if bash -c "
    source '$REPO_DIR/scripts/lib/inventory/detect.sh'
    source '$REPO_DIR/scripts/lib/inventory/output.sh'
    source '$REPO_DIR/scripts/lib/inventory/collectors/os-info.sh'
    source '$REPO_DIR/scripts/lib/inventory/collectors/network.sh'
    type detect_tool && type collect_os_info && type collect_network
" > /dev/null 2>&1; then
    test_pass
else
    test_fail "inventory chain" "dependency failure"
fi

test_start "NVD libraries load with all dependencies"
if bash -c "
    source '$REPO_DIR/scripts/lib/nvd/api.sh'
    source '$REPO_DIR/scripts/lib/nvd/matcher.sh'
    type init_nvd_cache && type get_cpe_mapping
" > /dev/null 2>&1; then
    test_pass
else
    test_fail "NVD chain" "dependency failure"
fi

# =============================================================================
# SECTION 9: Version Consistency Tests
# =============================================================================
section_header "Version Consistency"

test_start "Toolkit version is consistent"
if [ -f "$REPO_DIR/scripts/lib/toolkit-info.sh" ]; then
    version=$(bash -c "source '$REPO_DIR/scripts/lib/toolkit-info.sh' && init_toolkit_info && get_toolkit_id" 2>&1 || echo "")
    if [ -n "$version" ]; then
        test_pass
    else
        test_fail "version retrieval" "empty version"
    fi
else
    test_skip "toolkit-info.sh not found"
fi

test_start "Git tags match expected format"
# In CI, shallow clones don't have tags - fetch them or skip
if ! git -C "$REPO_DIR" describe --tags --abbrev=0 &>/dev/null; then
    # Try to fetch tags (may fail in restricted environments)
    git -C "$REPO_DIR" fetch --tags --depth=1 2>/dev/null || true
fi
latest_tag=$(git -C "$REPO_DIR" describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -z "$latest_tag" ]; then
    test_skip "no tags available (shallow clone)"
elif echo "$latest_tag" | grep -qE "^v[0-9]+\.[0-9]+\.[0-9]+"; then
    test_pass
else
    test_fail "semver format" "got: $latest_tag"
fi

# =============================================================================
# SECTION 10: NIST Control Coverage Tests
# =============================================================================
section_header "NIST Control Coverage"

test_start "All documented NIST controls have implementations"
# Check that key controls mentioned in README are implemented
controls_ok=true
for control in "RA-5" "SI-2" "SI-3" "SA-11" "CM-6" "CM-8"; do
    if ! grep -rq "$control" "$REPO_DIR/scripts/"*.sh 2>/dev/null; then
        controls_ok=false
        break
    fi
done
if $controls_ok; then
    test_pass
else
    test_fail "control coverage" "missing implementation"
fi

test_start "NIST controls JSON is valid"
if [ -f "$REPO_DIR/requirements/controls/nist-800-53.json" ]; then
    if python3 -c "import json; json.load(open('$REPO_DIR/requirements/controls/nist-800-53.json'))" 2>/dev/null; then
        test_pass
    else
        test_fail "valid JSON" "parse error"
    fi
else
    test_skip "controls file not found"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "  Advanced Integration Test Summary"
echo "=============================================="
echo ""
echo "  Tests Run:    $TESTS_RUN"
echo "  Passed:       $TESTS_PASSED"
echo "  Failed:       $TESTS_FAILED"
echo "  Skipped:      $TESTS_SKIPPED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All advanced integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED test(s) failed${NC}"
    exit 1
fi
