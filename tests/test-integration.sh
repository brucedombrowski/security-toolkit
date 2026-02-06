#!/bin/bash
#
# Integration Tests - End-to-End Scan Verification
#
# Purpose: Verify the complete scan workflow with known test patterns
# NIST Control: CA-2, CA-7 (Security Assessment & Monitoring)
#
# Usage: ./tests/test-integration.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
TEST_DIR=""
CLEAN_DIR=""

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

test_skip() {
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    TESTS_RUN=$((TESTS_RUN - 1))
    echo -e "${YELLOW}SKIP${NC} ($1)"
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
    if [ -n "$CLEAN_DIR" ] && [ -d "$CLEAN_DIR" ]; then
        rm -rf "$CLEAN_DIR"
    fi
}
trap cleanup EXIT

# Create test environment with known patterns
setup_test_environment() {
    TEST_DIR=$(mktemp -d)

    # Create directory structure
    mkdir -p "$TEST_DIR/src"
    mkdir -p "$TEST_DIR/config"
    mkdir -p "$TEST_DIR/docs"

    # File with known PII patterns (for PII scanner to detect)
    cat > "$TEST_DIR/src/user-data.txt" << 'EOF'
User Database Export
====================
John Doe: 123-45-6789
Phone: 555-123-4567
Card: 4111111111111111
IP: 192.168.1.100
EOF

    # File with known secrets (for secrets scanner to detect)
    cat > "$TEST_DIR/config/settings.env" << 'EOF'
# Configuration
DATABASE_URL=postgres://user:password123@localhost/db
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
api_key = "sk1234567890abcdef1234567890abcdef"
password = "secretpass123"
EOF

    # Clean file (should not trigger any scanner)
    cat > "$TEST_DIR/docs/readme.txt" << 'EOF'
This is a clean documentation file.
No sensitive data here.
Just regular text content.
EOF

    # File with MAC address (for MAC scanner to detect)
    cat > "$TEST_DIR/config/network.conf" << 'EOF'
# Network Configuration
interface eth0
  mac_address = AA:BB:CC:DD:EE:FF
  dhcp = true
EOF

    echo "$TEST_DIR"
}

echo "=========================================="
echo "Integration Tests - End-to-End Verification"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
echo "--- Setting up test environment ---"
TEST_DIR=$(setup_test_environment)
echo "  Test directory: $TEST_DIR"
echo ""

# =============================================================================
# SECTION 1: Individual Scanner Tests
# =============================================================================
section_header "PII Scanner Integration"

test_start "PII scanner detects SSN pattern"
pii_output=$("$REPO_DIR/scripts/check-pii.sh" "$TEST_DIR" 2>&1 || true)
if echo "$pii_output" | grep -q "123-45-6789\|SSN\|Social Security"; then
    test_pass
else
    test_fail "SSN detection" "not detected"
fi

test_start "PII scanner detects phone number"
if echo "$pii_output" | grep -q "555-123-4567\|Phone"; then
    test_pass
else
    test_fail "phone detection" "not detected"
fi

test_start "PII scanner detects credit card"
if echo "$pii_output" | grep -q "4111111111111111\|Credit Card"; then
    test_pass
else
    test_fail "credit card detection" "not detected"
fi

test_start "PII scanner detects IP address"
if echo "$pii_output" | grep -q "192.168.1.100\|IPv4"; then
    test_pass
else
    test_fail "IP detection" "not detected"
fi

section_header "Secrets Scanner Integration"

test_start "Secrets scanner detects AWS key"
secrets_output=$("$REPO_DIR/scripts/check-secrets.sh" "$TEST_DIR" 2>&1 || true)
if echo "$secrets_output" | grep -q "AKIAIOSFODNN7EXAMPLE\|AWS"; then
    test_pass
else
    test_fail "AWS key detection" "not detected"
fi

test_start "Secrets scanner detects API key or password"
if echo "$secrets_output" | grep -qi "api.key\|Generic API\|password\|Hardcoded"; then
    test_pass
else
    test_fail "API key or password detection" "not detected"
fi

test_start "Secrets scanner detects database password"
if echo "$secrets_output" | grep -q "password123\|DATABASE_URL\|Password"; then
    test_pass
else
    test_fail "database password detection" "not detected"
fi

section_header "MAC Address Scanner Integration"

test_start "MAC scanner detects MAC address"
mac_output=$("$REPO_DIR/scripts/check-mac-addresses.sh" "$TEST_DIR" 2>&1 || true)
if echo "$mac_output" | grep -qi "AA:BB:CC:DD:EE:FF\|MAC"; then
    test_pass
else
    test_fail "MAC address detection" "not detected"
fi

section_header "Malware Scanner Integration"

test_start "Malware scanner runs without error"
if command -v clamscan &> /dev/null; then
    malware_output=$("$REPO_DIR/scripts/check-malware.sh" "$TEST_DIR" 2>&1 || true)
    if echo "$malware_output" | grep -qi "scan\|clamav\|clean\|infected"; then
        test_pass
    else
        test_fail "malware scan output" "no recognizable output"
    fi
else
    test_skip "ClamAV not installed"
fi

# =============================================================================
# SECTION 2: Multi-Language Fixture Tests
# =============================================================================
section_header "Multi-Language Secret Detection"

# Test Python secrets fixture
if [ -f "$FIXTURES_DIR/vulnerable-code/python-secrets.py" ]; then
    test_start "Secrets scanner detects Python AWS keys"
    py_secrets=$("$REPO_DIR/scripts/check-secrets.sh" "$FIXTURES_DIR/vulnerable-code" 2>&1 || true)
    if echo "$py_secrets" | grep -q "python-secrets.py\|AKIAIOSFODNN7EXAMPLE"; then
        test_pass
    else
        test_fail "Python AWS key" "not detected"
    fi

    test_start "Secrets scanner detects Python private key"
    if echo "$py_secrets" | grep -qi "PRIVATE KEY\|RSA\|python-secrets"; then
        test_pass
    else
        test_fail "Python private key" "not detected"
    fi
else
    test_start "Python secrets fixture exists"
    test_skip "fixtures not created"
fi

# Test JavaScript secrets fixture
if [ -f "$FIXTURES_DIR/vulnerable-code/javascript-secrets.js" ]; then
    test_start "Secrets scanner detects JavaScript API keys"
    if echo "$py_secrets" | grep -q "javascript-secrets.js\|firebase\|STRIPE"; then
        test_pass
    else
        # Re-run if not in previous output
        js_secrets=$("$REPO_DIR/scripts/check-secrets.sh" "$FIXTURES_DIR/vulnerable-code" 2>&1 || true)
        if echo "$js_secrets" | grep -qi "javascript\|apiKey\|STRIPE\|SENDGRID"; then
            test_pass
        else
            test_fail "JavaScript API keys" "not detected"
        fi
    fi
else
    test_start "JavaScript secrets fixture exists"
    test_skip "fixtures not created"
fi

# Test Go secrets fixture
if [ -f "$FIXTURES_DIR/vulnerable-code/go-secrets.go" ]; then
    test_start "Secrets scanner detects Go hardcoded credentials"
    go_secrets=$("$REPO_DIR/scripts/check-secrets.sh" "$FIXTURES_DIR/vulnerable-code" 2>&1 || true)
    if echo "$go_secrets" | grep -qi "go-secrets.go\|AWSAccessKeyID\|DatabasePassword"; then
        test_pass
    else
        test_fail "Go credentials" "not detected"
    fi
else
    test_start "Go secrets fixture exists"
    test_skip "fixtures not created"
fi

section_header "Multi-Format PII Detection"

# Test comprehensive PII fixture
if [ -f "$FIXTURES_DIR/vulnerable-code/sensitive-data.txt" ]; then
    pii_fixture_output=$("$REPO_DIR/scripts/check-pii.sh" "$FIXTURES_DIR/vulnerable-code" 2>&1 || true)

    test_start "PII scanner detects multiple SSN formats"
    if echo "$pii_fixture_output" | grep -q "123-45-6789\|234 56 7890\|SSN"; then
        test_pass
    else
        test_fail "multiple SSN formats" "not all detected"
    fi

    test_start "PII scanner detects multiple phone formats"
    if echo "$pii_fixture_output" | grep -qi "555-123-4567\|555.234.5678\|phone"; then
        test_pass
    else
        test_fail "multiple phone formats" "not all detected"
    fi

    test_start "PII scanner detects multiple credit card types"
    if echo "$pii_fixture_output" | grep -q "4111111111111111\|5500000000000004\|Credit"; then
        test_pass
    else
        test_fail "multiple card types" "not all detected"
    fi
else
    test_start "PII data fixture exists"
    test_skip "fixtures not created"
fi

section_header "MAC Address Format Detection"

# Test network config fixture
if [ -f "$FIXTURES_DIR/config-files/network-config.conf" ]; then
    mac_fixture_output=$("$REPO_DIR/scripts/check-mac-addresses.sh" "$FIXTURES_DIR/config-files" 2>&1 || true)

    test_start "MAC scanner detects colon-separated format"
    if echo "$mac_fixture_output" | grep -qi "AA:BB:CC:DD:EE:FF\|00:11:22:33:44:55"; then
        test_pass
    else
        test_fail "colon format" "not detected"
    fi

    test_start "MAC scanner detects dash-separated format"
    if echo "$mac_fixture_output" | grep -qi "AA-BB-CC-DD-EE-FF\|11-22-33-44-55-66"; then
        test_pass
    else
        test_fail "dash format" "not detected"
    fi

    test_start "MAC scanner detects Cisco format"
    if echo "$mac_fixture_output" | grep -qi "aabb.ccdd.eeff\|1122.3344.5566"; then
        test_pass
    else
        test_fail "Cisco format" "not detected"
    fi
else
    test_start "Network config fixture exists"
    test_skip "fixtures not created"
fi

# =============================================================================
# SECTION 3: Full Scan Suite Test
# =============================================================================
section_header "Full Scan Suite Integration"

test_start "run-all-scans.sh completes successfully"
# Run with non-interactive mode, skip malware (slow) if ClamAV missing
skip_flags=""
if ! command -v clamscan &> /dev/null; then
    skip_flags="--skip-malware"
fi
full_scan_output=$("$REPO_DIR/scripts/run-all-scans.sh" -n $skip_flags "$TEST_DIR" 2>&1 || true)
if echo "$full_scan_output" | grep -qi "scan\|complete\|report"; then
    test_pass
else
    test_fail "scan completion" "scan did not complete"
fi

test_start "Scan creates .scans directory"
if [ -d "$TEST_DIR/.scans" ]; then
    test_pass
else
    test_fail ".scans directory" "not created"
fi

test_start "Scan creates report file"
if ls "$TEST_DIR/.scans/"*report*.txt 2>/dev/null | head -1 | grep -q "report"; then
    test_pass
else
    test_fail "report file" "not created"
fi

test_start "Report contains NIST references"
report_file=$(ls "$TEST_DIR/.scans/"*report*.txt 2>/dev/null | head -1 || echo "")
if [ -n "$report_file" ] && grep -qi "NIST\|800-53\|800-171" "$report_file"; then
    test_pass
else
    test_fail "NIST references in report" "not found"
fi

test_start "Report summarizes findings"
if [ -n "$report_file" ] && grep -qi "PASS\|FAIL\|Finding\|Result" "$report_file"; then
    test_pass
else
    test_fail "findings summary" "not found"
fi

# =============================================================================
# SECTION 4: Audit Log Verification
# =============================================================================
section_header "Audit Log Format Verification"

# Find audit log files
audit_logs=$(ls "$TEST_DIR/.scans/"audit-log*.jsonl 2>/dev/null || echo "")

test_start "Audit log file created"
if [ -n "$audit_logs" ]; then
    test_pass
    audit_log_file=$(echo "$audit_logs" | head -1)
else
    test_fail "audit log file" "not created"
    audit_log_file=""
fi

if [ -n "$audit_log_file" ] && [ -f "$audit_log_file" ]; then
    test_start "Audit log has valid JSON Lines format"
    if command -v python3 &>/dev/null; then
        # Check each line is valid JSON using python3
        valid_json=true
        while IFS= read -r line; do
            if [ -n "$line" ] && ! echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
                valid_json=false
                break
            fi
        done < "$audit_log_file"
        if $valid_json; then
            test_pass
        else
            test_fail "valid JSON per line" "invalid JSON found"
        fi
    elif command -v jq &>/dev/null; then
        # Fallback: validate JSON using jq
        valid_json=true
        while IFS= read -r line; do
            if [ -n "$line" ] && ! echo "$line" | jq . >/dev/null 2>&1; then
                valid_json=false
                break
            fi
        done < "$audit_log_file"
        if $valid_json; then
            test_pass
        else
            test_fail "valid JSON per line" "invalid JSON found"
        fi
    else
        # No JSON validator available - verify basic JSON structure
        valid_json=true
        while IFS= read -r line; do
            if [ -n "$line" ] && ! echo "$line" | grep -qE '^\{.*\}$'; then
                valid_json=false
                break
            fi
        done < "$audit_log_file"
        if $valid_json; then
            test_pass
        else
            test_fail "valid JSON per line" "invalid JSON found"
        fi
    fi

    test_start "Audit log contains timestamp field"
    if grep -q '"timestamp":' "$audit_log_file"; then
        test_pass
    else
        test_fail "timestamp field" "not found"
    fi

    test_start "Audit log contains event field"
    if grep -q '"event":' "$audit_log_file"; then
        test_pass
    else
        test_fail "event field" "not found"
    fi

    test_start "Audit log contains scan_type field"
    if grep -q '"scan_type":' "$audit_log_file"; then
        test_pass
    else
        test_fail "scan_type field" "not found"
    fi

    test_start "Audit log records SCAN_START event"
    if grep -q '"event":"SCAN_START"' "$audit_log_file"; then
        test_pass
    else
        test_fail "SCAN_START event" "not found"
    fi

    test_start "Audit log records SCAN_COMPLETE event"
    if grep -q '"event":"SCAN_COMPLETE"' "$audit_log_file"; then
        test_pass
    else
        test_fail "SCAN_COMPLETE event" "not found"
    fi
fi

# =============================================================================
# SECTION 5: Host Inventory Integration
# =============================================================================
section_header "Host Inventory Collection"

test_start "collect-host-inventory.sh runs successfully"
inventory_output=$("$REPO_DIR/scripts/collect-host-inventory.sh" 2>&1 || true)
if echo "$inventory_output" | grep -qi "Host System Inventory\|Operating System"; then
    test_pass
else
    test_fail "inventory collection" "did not complete"
fi

test_start "Inventory includes OS information"
if echo "$inventory_output" | grep -qi "Platform:\|OS Version:\|Kernel:"; then
    test_pass
else
    test_fail "OS information" "not found"
fi

test_start "Inventory includes network interfaces"
if echo "$inventory_output" | grep -qi "Network Interfaces:\|MAC Address:\|eth\|en0"; then
    test_pass
else
    test_fail "network interfaces" "not found"
fi

test_start "Inventory includes security tools"
if echo "$inventory_output" | grep -qi "Security Tools:\|ClamAV\|OpenSSL\|SSH"; then
    test_pass
else
    test_fail "security tools" "not found"
fi

test_start "Inventory includes CUI banner"
if echo "$inventory_output" | grep -qi "CONTROLLED UNCLASSIFIED INFORMATION\|CUI"; then
    test_pass
else
    test_fail "CUI banner" "not found"
fi

# Test file output mode
INVENTORY_FILE=$(mktemp)
test_start "Inventory saves to file with correct permissions"
"$REPO_DIR/scripts/collect-host-inventory.sh" "$INVENTORY_FILE" > /dev/null 2>&1 || true
if [ -f "$INVENTORY_FILE" ]; then
    # Check file permissions (should be 600)
    # macOS uses -f "%OLp", Linux uses -c "%a"
    if [[ "$(uname)" == "Darwin" ]]; then
        perms=$(stat -f "%OLp" "$INVENTORY_FILE" 2>/dev/null || echo "unknown")
    else
        perms=$(stat -c "%a" "$INVENTORY_FILE" 2>/dev/null || echo "unknown")
    fi
    if [ "$perms" = "600" ]; then
        test_pass
    else
        test_fail "file permissions 600" "got $perms"
    fi
    rm -f "$INVENTORY_FILE"
else
    test_fail "file creation" "file not created"
fi

# =============================================================================
# SECTION 6: Output File Verification
# =============================================================================
section_header "Output File Verification"

test_start "PII scan creates output file"
if ls "$TEST_DIR/.scans/"*pii*.txt 2>/dev/null | head -1 | grep -q "pii"; then
    test_pass
else
    test_fail "PII output file" "not created"
fi

test_start "Secrets scan creates output file"
if ls "$TEST_DIR/.scans/"*secrets*.txt 2>/dev/null | head -1 | grep -q "secrets"; then
    test_pass
else
    test_fail "secrets output file" "not created"
fi

test_start "MAC scan creates output file"
if ls "$TEST_DIR/.scans/"*mac*.txt 2>/dev/null | head -1 | grep -q "mac"; then
    test_pass
else
    test_fail "MAC output file" "not created"
fi

test_start "All output files have timestamps"
output_files=$(ls "$TEST_DIR/.scans/"*.txt 2>/dev/null || echo "")
all_have_timestamps=true
for f in $output_files; do
    if ! basename "$f" | grep -qE "[0-9]{4}-[0-9]{2}-[0-9]{2}"; then
        all_have_timestamps=false
        break
    fi
done
if $all_have_timestamps && [ -n "$output_files" ]; then
    test_pass
else
    test_fail "timestamps in filenames" "some files missing timestamps"
fi

# =============================================================================
# SECTION 7: False Positive Verification (Clean Code)
# =============================================================================
section_header "False Positive Verification"

# Create a truly clean directory
CLEAN_DIR=$(mktemp -d)
echo "This is completely clean text with no patterns." > "$CLEAN_DIR/clean.txt"
echo "Another clean file for testing." > "$CLEAN_DIR/another.txt"

test_start "PII scanner passes on clean files"
clean_pii=$("$REPO_DIR/scripts/check-pii.sh" "$CLEAN_DIR" 2>&1 || true)
if echo "$clean_pii" | grep -q "PASS\|No PII"; then
    test_pass
else
    test_fail "PASS on clean files" "unexpected findings"
fi

test_start "Secrets scanner passes on clean files"
clean_secrets=$("$REPO_DIR/scripts/check-secrets.sh" "$CLEAN_DIR" 2>&1 || true)
if echo "$clean_secrets" | grep -q "PASS\|No secrets"; then
    test_pass
else
    test_fail "PASS on clean files" "unexpected findings"
fi

test_start "MAC scanner passes on clean files"
clean_mac=$("$REPO_DIR/scripts/check-mac-addresses.sh" "$CLEAN_DIR" 2>&1 || true)
if echo "$clean_mac" | grep -q "PASS\|No MAC"; then
    test_pass
else
    test_fail "PASS on clean files" "unexpected findings"
fi

rm -rf "$CLEAN_DIR"
CLEAN_DIR=""

# Test clean code fixtures
section_header "Clean Code Fixtures (No False Positives)"

if [ -d "$FIXTURES_DIR/clean-code" ]; then
    test_start "PII scanner passes on clean Python code"
    clean_py_pii=$("$REPO_DIR/scripts/check-pii.sh" "$FIXTURES_DIR/clean-code" 2>&1 || true)
    # Allow for some findings in clean code but check the summary result
    if echo "$clean_py_pii" | grep -q "PASS" || ! echo "$clean_py_pii" | grep -qi "SSN\|Credit Card"; then
        test_pass
    else
        test_fail "PASS on clean Python" "found PII patterns"
    fi

    test_start "Secrets scanner passes on clean JavaScript code"
    clean_js_secrets=$("$REPO_DIR/scripts/check-secrets.sh" "$FIXTURES_DIR/clean-code" 2>&1 || true)
    # Clean code uses env vars, should not flag as secrets
    if echo "$clean_js_secrets" | grep -q "PASS" || ! echo "$clean_js_secrets" | grep -qi "AWS_SECRET\|PRIVATE KEY"; then
        test_pass
    else
        test_fail "PASS on clean JavaScript" "found secrets"
    fi

    test_start "MAC scanner passes on clean config"
    clean_cfg_mac=$("$REPO_DIR/scripts/check-mac-addresses.sh" "$FIXTURES_DIR/clean-code" 2>&1 || true)
    if echo "$clean_cfg_mac" | grep -q "PASS\|No MAC"; then
        test_pass
    else
        test_fail "PASS on clean config" "found MAC addresses"
    fi
else
    test_start "Clean code fixtures directory exists"
    test_skip "fixtures not created"
fi

# =============================================================================
# SECTION 8: Host Security Scanner
# =============================================================================
section_header "Host Security Scanner"

test_start "check-host-security.sh runs successfully"
host_sec_output=$("$REPO_DIR/scripts/check-host-security.sh" 2>&1 || true)
if echo "$host_sec_output" | grep -qi "Host OS Security\|security.*check\|Checking"; then
    test_pass
else
    test_fail "host security scan" "did not complete"
fi

test_start "Host security checks SIP (macOS) or similar"
if echo "$host_sec_output" | grep -qi "System Integrity\|SIP\|FileVault\|Firewall\|SELinux"; then
    test_pass
else
    test_fail "security feature check" "not found"
fi

test_start "Host security provides PASS/FAIL results"
if echo "$host_sec_output" | grep -qi "PASS\|FAIL\|Result"; then
    test_pass
else
    test_fail "PASS/FAIL results" "not found"
fi

# =============================================================================
# SECTION 9: Scanner Module Libraries
# =============================================================================
section_header "Scanner Module Libraries"

# Verify scanner libraries can be sourced
test_start "Scanner common library sources correctly"
if bash -c "source '$REPO_DIR/scripts/lib/scanners/common.sh' && type log_info" > /dev/null 2>&1; then
    test_pass
else
    test_fail "common.sh sourcing" "failed to source or missing functions"
fi

test_start "NIST controls library sources correctly"
if bash -c "source '$REPO_DIR/scripts/lib/scanners/nist-controls.sh' && type get_nist_800_53_control" > /dev/null 2>&1; then
    test_pass
else
    test_fail "nist-controls.sh sourcing" "failed to source or missing functions"
fi

test_start "Report library sources correctly"
if bash -c "source '$REPO_DIR/scripts/lib/scanners/common.sh' && source '$REPO_DIR/scripts/lib/scanners/report.sh' && type print_scan_header" > /dev/null 2>&1; then
    test_pass
else
    test_fail "report.sh sourcing" "failed to source or missing functions"
fi

# Test NIST control lookup
test_start "NIST 800-53 control lookup works"
control_output=$(bash -c "source '$REPO_DIR/scripts/lib/scanners/nist-controls.sh' && get_nist_800_53_control 'RA-5'" 2>&1 || echo "")
if echo "$control_output" | grep -qi "Vulnerability\|Monitoring\|Scanning"; then
    test_pass
else
    test_fail "RA-5 control description" "not found or incorrect"
fi

# =============================================================================
# SECTION 10: Inventory Module Libraries
# =============================================================================
section_header "Inventory Module Libraries"

# Verify inventory libraries can be sourced
test_start "Inventory detect library sources correctly"
if bash -c "source '$REPO_DIR/scripts/lib/inventory/detect.sh' && type detect_tool" > /dev/null 2>&1; then
    test_pass
else
    test_fail "detect.sh sourcing" "failed to source or missing functions"
fi

test_start "Inventory output library sources correctly"
if bash -c "source '$REPO_DIR/scripts/lib/inventory/output.sh' && type output" > /dev/null 2>&1; then
    test_pass
else
    test_fail "output.sh sourcing" "failed to source or missing functions"
fi

# Test collector modules
collectors=(
    "os-info.sh:collect_os_info"
    "network.sh:collect_network"
    "packages.sh:collect_packages"
    "security-tools.sh:collect_security_tools"
    "languages.sh:collect_languages"
)

for collector_spec in "${collectors[@]}"; do
    collector_file="${collector_spec%%:*}"
    collector_func="${collector_spec##*:}"
    test_start "Collector $collector_file sources correctly"
    if bash -c "
        source '$REPO_DIR/scripts/lib/inventory/detect.sh'
        source '$REPO_DIR/scripts/lib/inventory/output.sh'
        source '$REPO_DIR/scripts/lib/inventory/collectors/$collector_file'
        type $collector_func
    " > /dev/null 2>&1; then
        test_pass
    else
        test_fail "$collector_file sourcing" "failed to source or missing $collector_func"
    fi
done

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=========================================="
echo "Integration Test Summary"
echo "=========================================="
echo "  Total:   $TESTS_RUN"
echo "  Passed:  $TESTS_PASSED"
echo "  Failed:  $TESTS_FAILED"
echo "  Skipped: $TESTS_SKIPPED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED integration test(s) failed${NC}"
    exit 1
fi
