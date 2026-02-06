# Testing Guide

This document describes the test architecture for the Security Verification Toolkit and provides guidance for running and writing tests.

## Overview

The toolkit uses a custom bash-based testing framework. Tests are organized by functionality and run through a master test runner that aggregates results.

**Key files:**
- `tests/run-all-tests.sh` - Master test runner (orchestrates all suites)
- `tests/test-*.sh` - Individual test suites
- `tests/fixtures/` - Temporary files created during test runs
- `tests/expected/` - Expected output for comparison tests (if needed)

## Running Tests

### Run All Tests

```bash
./tests/run-all-tests.sh
```

This executes all test suites and reports a summary. Exit code is `0` if all suites pass, `1` if any fail.

### Run a Specific Test Suite

```bash
./tests/test-pii-patterns.sh
./tests/test-secrets-patterns.sh
./tests/test-mac-patterns.sh
```

Each test script is self-contained and can run independently.

### Quick Syntax Check

Before running tests, verify all scripts have valid bash syntax:

```bash
for script in scripts/*.sh tests/*.sh; do
  bash -n "$script" && echo "OK: $script"
done
```

## Test File Naming

Tests follow a strict naming convention:

| Pattern | Purpose | Example |
|---------|---------|---------|
| `test-<feature>-patterns.sh` | Regex pattern validation | `test-pii-patterns.sh` |
| `test-<script>.sh` | Script functionality tests | `test-secure-delete.sh` |
| `test-<module>-modules.sh` | Library module tests | `test-scanner-modules.sh` |
| `test-integration.sh` | Cross-script integration | `test-integration.sh` |
| `test-integration-advanced.sh` | Extended integration tests | `test-integration-advanced.sh` |

## Test Structure

Every test script follows this structure:

```bash
#!/bin/bash
#
# <Test Suite Name> Unit Tests
#
# Purpose: <What this test suite validates>
# NIST Control: <Related control, if applicable>
#
# Usage: ./tests/test-<name>.sh
#
# Exit codes:
#   0 = All tests passed
#   1 = One or more tests failed

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test helper functions (see below)

# --- Test sections ---
echo "--- Section Name ---"
# tests...

# --- Summary ---
echo "Test Summary"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"

if [ "$TESTS_FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi
```

## Test Helper Functions

Copy these helpers into new test scripts:

### `test_start()`

Announces the start of a test case:

```bash
test_start() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "  Test $TESTS_RUN: $1... "
}
```

### `test_pass()`

Records a passing test:

```bash
test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}"
}
```

### `test_fail()`

Records a failing test with expected vs actual:

```bash
test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}FAIL${NC}"
    echo "    Expected: $1"
    echo "    Got: $2"
}
```

### `test_known()`

Documents a known limitation handled by allowlists:

```bash
test_known() {
    echo -n "  Known: $1... "
    echo -e "${YELLOW}KNOWN${NC} (allowlist handles)"
}
```

**When to use `test_known()`:**
- Pattern matches something that's technically a false positive
- The issue is acknowledged and handled via `.allowlists/`
- Documenting why we don't "fix" the pattern (would cause false negatives)

Example:
```bash
test_known "Version number (6.0.0.0) matches IPv4 pattern"
# This will match IPv4 pattern - known limitation handled via allowlist
```

## Writing Tests

### Pattern Detection Tests

For testing regex patterns (PII, secrets, MAC addresses):

```bash
# Test that pattern MATCHES expected input
test_start "Detect valid SSN format"
if echo "123-45-6789" | grep -qE "$SSN_PATTERN"; then
    test_pass
else
    test_fail "match" "no match"
fi

# Test that pattern REJECTS invalid input (false positive prevention)
test_start "Reject date that looks like SSN"
if echo "2024-01-15" | grep -qE "$SSN_PATTERN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi
```

### Script Functionality Tests

For testing script behavior:

```bash
test_start "check-pii.sh exits 0 on clean directory"
if "$REPO_DIR/scripts/check-pii.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_pass
else
    test_fail "exit 0" "exit 1"
fi
```

### Integration Tests

For testing multiple scripts together:

```bash
test_start "Full scan workflow completes"
if "$REPO_DIR/scripts/run-all-scans.sh" -n "$TEST_PROJECT" > /dev/null 2>&1; then
    test_pass
else
    test_fail "exit 0" "non-zero exit"
fi
```

## Using Fixtures

The `tests/fixtures/` directory holds temporary files for testing:

```bash
# Create fixture at start of test
mkdir -p "$FIXTURES_DIR"
cat > "$FIXTURES_DIR/test-file.md" << 'EOF'
Test content here
EOF

# Run test against fixture
"$REPO_DIR/scripts/check-pii.sh" "$FIXTURES_DIR"

# Clean up after test
rm -f "$FIXTURES_DIR/test-file.md"
```

**Important:** Always clean up fixtures at the end of your test section. The `fixtures/` directory may contain `.scans/` output from previous test runs.

## CI/CD Integration

Tests run automatically in GitHub Actions on:
- Push to `main`
- Pull requests targeting `main`

### CI Jobs

| Job | Runner | Purpose |
|-----|--------|---------|
| `shellcheck` | Ubuntu | Static analysis of scripts and tests |
| `syntax-check` | Ubuntu | Bash syntax validation |
| `test-ubuntu` | Ubuntu | Full test suite on Linux |
| `test-macos` | macOS | Full test suite on macOS |
| `security-self-scan` | Ubuntu | Run toolkit on itself |
| `docs-check` | Ubuntu | Verify required docs exist |
| `kev-catalog-check` | Ubuntu | Validate bundled KEV data |

### CI Dependencies

CI installs these before running tests:
- `jq` - JSON processing
- `clamav` - Malware scanning (for `check-malware.sh` tests)

### Local CI Simulation

To simulate CI locally:

```bash
# Run ShellCheck
shellcheck scripts/*.sh tests/*.sh

# Run syntax check
for script in scripts/*.sh tests/*.sh; do
  bash -n "$script"
done

# Run tests
./tests/run-all-tests.sh
```

## Adding a New Test Suite

1. **Create the test file:**
   ```bash
   touch tests/test-<feature>.sh
   chmod +x tests/test-<feature>.sh
   ```

2. **Use the standard template** (see Test Structure above)

3. **Add to the test runner** (`run-all-tests.sh`):
   ```bash
   run_test_suite "<Feature> Tests" "$SCRIPT_DIR/test-<feature>.sh"
   ```

4. **Run locally to verify:**
   ```bash
   ./tests/test-<feature>.sh
   ./tests/run-all-tests.sh
   ```

## Test Categories

### Pattern Detection

| Suite | Tests | Script Under Test |
|-------|-------|-------------------|
| `test-pii-patterns.sh` | IPv4, phone, SSN, credit card regex | `check-pii.sh` |
| `test-secrets-patterns.sh` | API keys, AWS creds, tokens, passwords | `check-secrets.sh` |
| `test-mac-patterns.sh` | MAC address formats | `check-mac-addresses.sh` |

### Script Functionality

| Suite | Tests |
|-------|-------|
| `test-secure-delete.sh` | Secure file deletion (NIST SP 800-88) |
| `test-run-all-scans.sh` | Scan orchestration, exit codes |
| `test-inventory-modules.sh` | Host inventory collectors |
| `test-scanner-modules.sh` | Vulnerability scanner modules |
| `test-audit-logging.sh` | JSON Lines audit log format |
| `test-timestamps.sh` | ISO 8601 timestamp utilities |
| `test-progress.sh` | Progress bars, spinners |
| `test-check-kev.sh` | CISA KEV catalog checks |
| `test-kev.sh` | KEV API and caching |
| `test-nvd-cves.sh` | NVD CVE lookups |
| `test-containers.sh` | Container scanning (Docker/Podman) |
| `test-edge-cases.sh` | Boundary conditions, unusual inputs |
| `test-host-security.sh` | Host security posture checks |
| `test-malware.sh` | Malware scanning (ClamAV integration) |

### Integration

| Suite | Tests |
|-------|-------|
| `test-integration.sh` | End-to-end workflows |
| `test-integration-advanced.sh` | Extended scenarios (CI only) |

## Troubleshooting

### Test fails with "command not found"

Ensure script is executable:
```bash
chmod +x tests/test-<name>.sh
```

### Tests pass locally but fail in CI

- Check for macOS vs Linux differences (e.g., `sed -i` syntax)
- Verify CI has required dependencies installed
- Check for hardcoded paths

### Fixture cleanup issues

If `tests/fixtures/` has stale files:
```bash
rm -rf tests/fixtures/*
git checkout tests/fixtures/.gitkeep 2>/dev/null || true
```

## Best Practices

1. **Test both positive and negative cases** - Verify patterns match what they should AND reject what they shouldn't
2. **Use `test_known()` for documented limitations** - Don't hide false positives; document them
3. **Clean up fixtures** - Remove temporary files after each test section
4. **Keep tests fast** - Avoid unnecessary sleeps or large file operations
5. **Test exit codes** - Scripts should exit `0` on success, `1` on failure
6. **Mirror production patterns** - Use the same regex patterns as the production scripts
