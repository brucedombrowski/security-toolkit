#!/bin/bash
#
# CISA KEV Check Unit Tests
#
# Purpose: Verify KEV catalog cross-reference functionality
# NIST Controls: RA-5 (Vulnerability Scanning), SI-5 (Security Alerts)
#
# Usage: ./tests/test-check-kev.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEV_SCRIPT="$REPO_DIR/scripts/check-kev.sh"
TEST_DIR=$(mktemp -d)

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
    if [ -n "$1" ]; then
        echo "    Expected: $1"
    fi
    if [ -n "$2" ]; then
        echo "    Got: $2"
    fi
}

# Cleanup on exit
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=========================================="
echo "CISA KEV Check Unit Tests"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# Dependency Tests
# -----------------------------------------------------------------------------
echo "Dependency Tests:"
echo "-----------------"

test_start "check-kev.sh exists"
if [ -f "$KEV_SCRIPT" ]; then
    test_pass
else
    test_fail "Script exists" "Script not found"
fi

test_start "check-kev.sh is executable"
if [ -x "$KEV_SCRIPT" ]; then
    test_pass
else
    test_fail "Script executable" "Script not executable"
fi

test_start "jq is installed"
if command -v jq &>/dev/null; then
    test_pass
else
    test_fail "jq installed" "jq not found"
fi

test_start "curl is installed"
if command -v curl &>/dev/null; then
    test_pass
else
    test_fail "curl installed" "curl not found"
fi

echo ""

# -----------------------------------------------------------------------------
# CVE Extraction Tests
# -----------------------------------------------------------------------------
echo "CVE Extraction Tests:"
echo "---------------------"

test_start "Extract single CVE"
echo "CVE-2021-44228" > "$TEST_DIR/single-cve.txt"
EXTRACTED=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/single-cve.txt" | head -1)
if [ "$EXTRACTED" = "CVE-2021-44228" ]; then
    test_pass
else
    test_fail "CVE-2021-44228" "$EXTRACTED"
fi

test_start "Extract multiple CVEs"
cat > "$TEST_DIR/multi-cve.txt" << 'EOF'
Found vulnerability CVE-2021-44228 in log4j
Also found CVE-2022-22965 (Spring4Shell)
And CVE-2021-34527 (PrintNightmare)
EOF
CVE_COUNT=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/multi-cve.txt" | sort -u | wc -l | tr -d ' ')
if [ "$CVE_COUNT" -eq 3 ]; then
    test_pass
else
    test_fail "3 CVEs" "$CVE_COUNT CVEs"
fi

test_start "Extract CVE with 5-digit ID"
echo "CVE-2023-12345" > "$TEST_DIR/long-cve.txt"
EXTRACTED=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/long-cve.txt" | head -1)
if [ "$EXTRACTED" = "CVE-2023-12345" ]; then
    test_pass
else
    test_fail "CVE-2023-12345" "$EXTRACTED"
fi

test_start "No false positive on version strings"
echo "Version 2021-4422 released" > "$TEST_DIR/version.txt"
CVE_COUNT=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/version.txt" 2>/dev/null | wc -l | tr -d ' ')
if [ "$CVE_COUNT" -eq 0 ]; then
    test_pass
else
    test_fail "0 CVEs" "$CVE_COUNT CVEs"
fi

test_start "Extract CVE from Nmap-style output"
cat > "$TEST_DIR/nmap-cve.txt" << 'EOF'
| VULNERABLE:
|   Apache Log4j RCE
|     CVE:      CVE-2021-44228
|     Risk:     Critical
EOF
EXTRACTED=$(grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$TEST_DIR/nmap-cve.txt" | head -1)
if [ "$EXTRACTED" = "CVE-2021-44228" ]; then
    test_pass
else
    test_fail "CVE-2021-44228" "$EXTRACTED"
fi

echo ""

# -----------------------------------------------------------------------------
# KEV Catalog Tests (requires network)
# -----------------------------------------------------------------------------
echo "KEV Catalog Tests:"
echo "------------------"

# Check if we can access the KEV catalog
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE="$REPO_DIR/.cache/kev-catalog.json"

test_start "KEV catalog URL accessible"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$KEV_URL" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    test_pass
else
    test_fail "HTTP 200" "HTTP $HTTP_CODE"
    echo -e "    ${YELLOW}(Network tests may fail without internet)${NC}"
fi

test_start "KEV catalog is valid JSON"
if [ -f "$KEV_CACHE" ]; then
    if jq empty "$KEV_CACHE" 2>/dev/null; then
        test_pass
    else
        test_fail "Valid JSON" "Invalid JSON"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "KEV catalog has catalogVersion"
if [ -f "$KEV_CACHE" ]; then
    VERSION=$(jq -r '.catalogVersion' "$KEV_CACHE" 2>/dev/null)
    if [ -n "$VERSION" ] && [ "$VERSION" != "null" ]; then
        test_pass
    else
        test_fail "Version present" "Version: $VERSION"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "KEV catalog has count field"
if [ -f "$KEV_CACHE" ]; then
    COUNT=$(jq -r '.count' "$KEV_CACHE" 2>/dev/null)
    if [ -n "$COUNT" ] && [ "$COUNT" -gt 0 ] 2>/dev/null; then
        test_pass
    else
        test_fail "Count > 0" "Count: $COUNT"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "KEV catalog has vulnerabilities array"
if [ -f "$KEV_CACHE" ]; then
    VULN_COUNT=$(jq '.vulnerabilities | length' "$KEV_CACHE" 2>/dev/null)
    if [ -n "$VULN_COUNT" ] && [ "$VULN_COUNT" -gt 0 ] 2>/dev/null; then
        test_pass
    else
        test_fail "Vulnerabilities present" "Count: $VULN_COUNT"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

echo ""

# -----------------------------------------------------------------------------
# KEV Lookup Tests
# -----------------------------------------------------------------------------
echo "KEV Lookup Tests:"
echo "-----------------"

test_start "Log4Shell (CVE-2021-44228) is in KEV"
if [ -f "$KEV_CACHE" ]; then
    FOUND=$(jq -r '.vulnerabilities[] | select(.cveID == "CVE-2021-44228") | .cveID' "$KEV_CACHE" 2>/dev/null)
    if [ "$FOUND" = "CVE-2021-44228" ]; then
        test_pass
    else
        test_fail "CVE found in KEV" "Not found"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "Log4Shell has ransomware flag"
if [ -f "$KEV_CACHE" ]; then
    RANSOMWARE=$(jq -r '.vulnerabilities[] | select(.cveID == "CVE-2021-44228") | .knownRansomwareCampaignUse' "$KEV_CACHE" 2>/dev/null)
    if [ "$RANSOMWARE" = "Known" ]; then
        test_pass
    else
        test_fail "Known" "$RANSOMWARE"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "KEV entry has required fields"
if [ -f "$KEV_CACHE" ]; then
    ENTRY=$(jq '.vulnerabilities[0]' "$KEV_CACHE" 2>/dev/null)
    HAS_CVE=$(echo "$ENTRY" | jq -r '.cveID' 2>/dev/null)
    HAS_VENDOR=$(echo "$ENTRY" | jq -r '.vendorProject' 2>/dev/null)
    HAS_PRODUCT=$(echo "$ENTRY" | jq -r '.product' 2>/dev/null)
    HAS_DATE=$(echo "$ENTRY" | jq -r '.dateAdded' 2>/dev/null)
    HAS_DUE=$(echo "$ENTRY" | jq -r '.dueDate' 2>/dev/null)

    if [ -n "$HAS_CVE" ] && [ "$HAS_CVE" != "null" ] && \
       [ -n "$HAS_VENDOR" ] && [ "$HAS_VENDOR" != "null" ] && \
       [ -n "$HAS_PRODUCT" ] && [ "$HAS_PRODUCT" != "null" ] && \
       [ -n "$HAS_DATE" ] && [ "$HAS_DATE" != "null" ] && \
       [ -n "$HAS_DUE" ] && [ "$HAS_DUE" != "null" ]; then
        test_pass
    else
        test_fail "All required fields" "Missing fields"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "Non-existent CVE not in KEV"
if [ -f "$KEV_CACHE" ]; then
    FOUND=$(jq -r '.vulnerabilities[] | select(.cveID == "CVE-9999-99999") | .cveID' "$KEV_CACHE" 2>/dev/null)
    if [ -z "$FOUND" ]; then
        test_pass
    else
        test_fail "Not found" "Found: $FOUND"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

echo ""

# -----------------------------------------------------------------------------
# Hash Verification Tests
# -----------------------------------------------------------------------------
echo "Hash Verification Tests:"
echo "------------------------"

test_start "SHA256 hash file exists"
if [ -f "${KEV_CACHE}.sha256" ]; then
    test_pass
elif [ -f "$KEV_CACHE" ]; then
    echo -e "${YELLOW}SKIP${NC} (hash file not generated yet)"
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "SHA256 hash matches catalog"
if [ -f "${KEV_CACHE}.sha256" ] && [ -f "$KEV_CACHE" ]; then
    STORED_HASH=$(cat "${KEV_CACHE}.sha256" | awk '{print $1}')
    if [[ "$(uname)" == "Darwin" ]]; then
        ACTUAL_HASH=$(shasum -a 256 "$KEV_CACHE" | awk '{print $1}')
    else
        ACTUAL_HASH=$(sha256sum "$KEV_CACHE" | awk '{print $1}')
    fi

    if [ "$STORED_HASH" = "$ACTUAL_HASH" ]; then
        test_pass
    else
        test_fail "$STORED_HASH" "$ACTUAL_HASH"
    fi
elif [ -f "$KEV_CACHE" ]; then
    echo -e "${YELLOW}SKIP${NC} (hash file not generated yet)"
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "Hash is 64 characters (SHA256)"
if [ -f "${KEV_CACHE}.sha256" ]; then
    HASH=$(cat "${KEV_CACHE}.sha256" | awk '{print $1}')
    HASH_LEN=${#HASH}
    if [ "$HASH_LEN" -eq 64 ]; then
        test_pass
    else
        test_fail "64 chars" "$HASH_LEN chars"
    fi
elif [ -f "$KEV_CACHE" ]; then
    echo -e "${YELLOW}SKIP${NC} (hash file not generated yet)"
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

echo ""

# -----------------------------------------------------------------------------
# Script Execution Tests
# -----------------------------------------------------------------------------
echo "Script Execution Tests:"
echo "-----------------------"

test_start "Script shows help with -h"
OUTPUT=$("$KEV_SCRIPT" -h 2>&1 || true)
if echo "$OUTPUT" | grep -q "Usage:"; then
    test_pass
else
    test_fail "Usage message" "No usage message"
fi

test_start "Script handles missing file gracefully"
OUTPUT=$("$KEV_SCRIPT" "/nonexistent/file.txt" 2>&1 || true)
EXIT_CODE=$?
if echo "$OUTPUT" | grep -qi "error\|not found"; then
    test_pass
else
    test_fail "Error message" "Exit code: $EXIT_CODE"
fi

test_start "Script exits 0 with no KEV matches"
echo "No CVEs here" > "$TEST_DIR/no-cves.txt"
EXIT_CODE=0
"$KEV_SCRIPT" -q "$TEST_DIR/no-cves.txt" >/dev/null 2>&1 || EXIT_CODE=$?
if [ "$EXIT_CODE" -eq 0 ]; then
    test_pass
else
    test_fail "Exit 0" "Exit $EXIT_CODE"
fi

test_start "Script exits 1 with KEV match (Log4Shell)"
if [ -f "$KEV_CACHE" ]; then
    echo "CVE-2021-44228" > "$TEST_DIR/log4j.txt"
    EXIT_CODE=0
    "$KEV_SCRIPT" -q "$TEST_DIR/log4j.txt" >/dev/null 2>&1 || EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 1 ]; then
        test_pass
    else
        test_fail "Exit 1" "Exit $EXIT_CODE"
    fi
else
    echo -e "${YELLOW}SKIP${NC} (cache not present)"
fi

test_start "Quiet mode suppresses intro header"
echo "CVE-2021-44228" > "$TEST_DIR/quiet-test.txt"
OUTPUT=$("$KEV_SCRIPT" -q "$TEST_DIR/quiet-test.txt" 2>&1 || true)
if ! echo "$OUTPUT" | grep -q "CISA Known Exploited Vulnerabilities"; then
    test_pass
else
    test_fail "No intro header" "Intro header present"
fi

echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo ""
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
