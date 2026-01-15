#!/bin/bash
#
# Secrets/Vulnerability Verification Script
#
# Purpose: Automated scanning for common security vulnerabilities
# Method: Pattern matching for secrets, credentials, and security anti-patterns
#
# Checks performed:
#   - Hardcoded API keys and tokens
#   - AWS/cloud credentials
#   - Private keys
#   - Database connection strings with passwords
#   - Hardcoded passwords in code
#   - GitHub/Slack tokens
#
# Exit codes:
#   0 = All checks passed (no vulnerabilities found)
#   1 = Potential vulnerabilities detected (requires review)
#
# Usage: ./check-secrets.sh [target_directory]
#        If no target specified, uses parent directory of script location

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Allow target directory to be specified as argument
if [ -n "$1" ]; then
    TARGET_DIR="$1"
else
    TARGET_DIR="$SECURITY_REPO_DIR"
fi

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
REPO_NAME=$(basename "$TARGET_DIR")
TOOLKIT_VERSION=$(git -C "$SECURITY_REPO_DIR" describe --tags --always 2>/dev/null || echo "unknown")
TOOLKIT_COMMIT=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

FOUND_ISSUES=0

echo "Secrets/Vulnerability Verification Scan"
echo "========================================"
echo "Timestamp: $TIMESTAMP"
echo "Toolkit: Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
echo "Target: $TARGET_DIR"
echo "Repository: $REPO_NAME"
echo ""

# Function to run a check and log results
run_check() {
    local check_name="$1"
    local pattern="$2"
    local severity="$3"

    echo "Checking: $check_name [$severity]"

    # Run grep, capture output (exclude .git, binary files, scan results, and verification scripts)
    local results=""
    results=$(grep -r -n -E "$pattern" "$TARGET_DIR" \
        --include="*.sh" \
        --include="*.py" \
        --include="*.js" \
        --include="*.ts" \
        --include="*.rb" \
        --include="*.php" \
        --include="*.go" \
        --include="*.rs" \
        --include="*.java" \
        --include="*.cs" \
        --include="*.yaml" \
        --include="*.yml" \
        --include="*.json" \
        --include="*.env" \
        --include="*.conf" \
        --include="*.config" \
        --include="*.md" \
        --include="*.tex" \
        --exclude-dir=".git" \
        --exclude-dir="node_modules" \
        --exclude-dir="venv" \
        --exclude-dir=".venv" \
        --exclude-dir="__pycache__" \
        --exclude-dir=".scans" \
        --exclude-dir="obj" \
        --exclude-dir="bin" \
        --exclude-dir="publish" \
        --exclude="*Scan-Results.md" \
        --exclude="check-*.sh" \
        2>/dev/null || true)

    local count=0
    if [ -n "$results" ]; then
        count=$(echo "$results" | wc -l | tr -d ' ')
    fi

    if [ "$count" -eq 0 ]; then
        echo "  Result: PASS (0 matches)"
    else
        echo "  Result: REVIEW - $count match(es) found"
        echo "$results" | head -5
        if [ "$count" -gt 5 ]; then
            echo "  ... and $((count - 5)) more"
        fi
        FOUND_ISSUES=1
    fi
}

# Run all vulnerability checks
run_check "AWS Access Keys" \
    "AKIA[0-9A-Z]{16}" \
    "CRITICAL"

run_check "AWS Secret Keys" \
    "['\"][A-Za-z0-9/+=]{40}['\"]" \
    "CRITICAL"

run_check "Generic API Keys" \
    "(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{16,}" \
    "HIGH"

run_check "Private Keys" \
    "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----" \
    "CRITICAL"

run_check "Database Connection Strings" \
    "(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@" \
    "CRITICAL"

run_check "Hardcoded Passwords" \
    "(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}" \
    "HIGH"

run_check "Bearer Tokens" \
    "Bearer\s+[A-Za-z0-9_-]{20,}" \
    "HIGH"

run_check "GitHub Tokens" \
    "gh[pousr]_[A-Za-z0-9_]{36,}" \
    "CRITICAL"

run_check "Slack Tokens" \
    "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}" \
    "HIGH"

run_check "Shell Command Injection" \
    "eval\s+\"\\\$" \
    "MEDIUM"

# Summary
echo ""
echo "========================================"

if [ $FOUND_ISSUES -eq 0 ]; then
    echo "OVERALL RESULT: PASS"
    echo "No secrets or vulnerabilities detected."
else
    echo "OVERALL RESULT: REVIEW REQUIRED"
    echo "Potential secrets/vulnerabilities detected. Manual review required."
fi

exit $FOUND_ISSUES
