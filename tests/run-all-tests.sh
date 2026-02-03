#!/bin/bash
#
# Master Test Runner
#
# Purpose: Execute all unit tests and report results
# Usage: ./tests/run-all-tests.sh
#
# Exit codes:
#   0 = All test suites passed
#   1 = One or more test suites failed
#
# This script orchestrates all test suites in the tests/ directory.
# Each test suite is a self-contained script that:
#   - Runs its own tests
#   - Outputs results to stdout
#   - Exits 0 on success, 1 on failure
#
# To add a new test suite:
#   1. Create tests/test-<name>.sh
#   2. Add run_test_suite call below (see "Test Suite Execution" section)
#
# See docs/TESTING.md for full documentation.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0
FAILED_SUITES=""

echo "=============================================="
echo "Security Verification Toolkit - Test Runner"
echo "=============================================="
echo ""
echo "Repository: $REPO_DIR"
echo "Timestamp:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# -----------------------------------------------------------------------------
# run_test_suite - Execute a single test suite and track results
# -----------------------------------------------------------------------------
# Arguments:
#   $1 - Human-readable name for the test suite (displayed in output)
#   $2 - Path to the test script to execute
#
# Behavior:
#   - Increments SUITES_RUN counter
#   - Executes the script and captures exit code
#   - Updates SUITES_PASSED or SUITES_FAILED based on result
#   - If script is not executable, attempts chmod +x before running
#
# Example:
#   run_test_suite "PII Pattern Detection" "$SCRIPT_DIR/test-pii-patterns.sh"
# -----------------------------------------------------------------------------
run_test_suite() {
    local name="$1"
    local script="$2"

    SUITES_RUN=$((SUITES_RUN + 1))
    echo -e "${BLUE}[$SUITES_RUN] Running: $name${NC}"
    echo "    Script: $script"
    echo ""

    if [ -x "$script" ]; then
        if "$script"; then
            SUITES_PASSED=$((SUITES_PASSED + 1))
            echo ""
            echo -e "    ${GREEN}Suite PASSED${NC}"
        else
            SUITES_FAILED=$((SUITES_FAILED + 1))
            FAILED_SUITES="$FAILED_SUITES\n    - $name"
            echo ""
            echo -e "    ${RED}Suite FAILED${NC}"
        fi
    else
        # Script not executable - try to fix and run anyway
        echo -e "    ${YELLOW}SKIPPED (not executable)${NC}"
        chmod +x "$script" 2>/dev/null || true
        if "$script"; then
            SUITES_PASSED=$((SUITES_PASSED + 1))
            echo -e "    ${GREEN}Suite PASSED (after chmod)${NC}"
        else
            SUITES_FAILED=$((SUITES_FAILED + 1))
            FAILED_SUITES="$FAILED_SUITES\n    - $name"
            echo -e "    ${RED}Suite FAILED${NC}"
        fi
    fi
    echo ""
    echo "----------------------------------------------"
    echo ""
}

# =============================================================================
# TEST SUITE EXECUTION
# =============================================================================
# Add new test suites here. Order matters - run faster/simpler tests first
# so failures are detected quickly.
#
# Categories:
#   1. Pattern Detection - Regex validation for PII, secrets, MAC addresses
#   2. Script Functionality - Individual script behavior tests
#   3. Integration - Cross-script workflow tests
#   4. Critical Security - Security vulnerability regression tests
# =============================================================================

# -----------------------------------------------------------------------------
# 1. Pattern Detection Tests
# -----------------------------------------------------------------------------
# These validate regex patterns used by detection scripts.
# Fast to run, catches most regressions early.
run_test_suite "PII Pattern Detection" "$SCRIPT_DIR/test-pii-patterns.sh"
run_test_suite "Secrets Pattern Detection" "$SCRIPT_DIR/test-secrets-patterns.sh"
run_test_suite "MAC Address Pattern Detection" "$SCRIPT_DIR/test-mac-patterns.sh"

# -----------------------------------------------------------------------------
# 2. Script Functionality Tests
# -----------------------------------------------------------------------------
# These test individual scripts in isolation.
run_test_suite "Secure Delete" "$SCRIPT_DIR/test-secure-delete.sh"
run_test_suite "Run All Scans Orchestration" "$SCRIPT_DIR/test-run-all-scans.sh"
run_test_suite "Inventory Modules" "$SCRIPT_DIR/test-inventory-modules.sh"
run_test_suite "Scanner Modules" "$SCRIPT_DIR/test-scanner-modules.sh"
run_test_suite "Container Scanner" "$SCRIPT_DIR/test-containers.sh"
run_test_suite "Malware Scanner" "$SCRIPT_DIR/test-malware.sh"
run_test_suite "Edge Cases" "$SCRIPT_DIR/test-edge-cases.sh"
run_test_suite "Integration Tests" "$SCRIPT_DIR/test-integration.sh"
run_test_suite "NVD CVE Lookup" "$SCRIPT_DIR/test-nvd-cves.sh"

# -----------------------------------------------------------------------------
# 3. Critical Security Tests (Optional)
# -----------------------------------------------------------------------------
# These are security regression tests created during security audits.
# They live in scripts/ rather than tests/ for historical reasons.
# Only run if the test scripts exist (not all deployments have them).
if [ -x "$REPO_DIR/scripts/test-latex-injection.sh" ]; then
    run_test_suite "LaTeX Injection (CRITICAL-001)" "$REPO_DIR/scripts/test-latex-injection.sh"
fi

if [ -x "$REPO_DIR/scripts/test-rm-rf-validation.sh" ]; then
    run_test_suite "rm -rf Validation (CRITICAL-002)" "$REPO_DIR/scripts/test-rm-rf-validation.sh"
fi

if [ -x "$REPO_DIR/scripts/test-symlink-attacks.sh" ]; then
    run_test_suite "Symlink Attacks (CRITICAL-003)" "$REPO_DIR/scripts/test-symlink-attacks.sh"
fi

if [ -x "$REPO_DIR/scripts/test-cui-data-exposure.sh" ]; then
    run_test_suite "CUI Data Exposure (CRITICAL-004)" "$REPO_DIR/scripts/test-cui-data-exposure.sh"
fi

if [ -x "$REPO_DIR/scripts/test-git-purge-dry-run.sh" ]; then
    run_test_suite "Git Purge Dry-Run (CRITICAL-005)" "$REPO_DIR/scripts/test-git-purge-dry-run.sh"
fi

echo "=============================================="
echo "Test Results Summary"
echo "=============================================="
echo ""
echo "  Test Suites Run:    $SUITES_RUN"
echo "  Test Suites Passed: $SUITES_PASSED"
echo "  Test Suites Failed: $SUITES_FAILED"
echo ""

if [ "$SUITES_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All test suites passed!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}Failed test suites:${NC}"
    echo -e "$FAILED_SUITES"
    echo ""
    exit 1
fi
