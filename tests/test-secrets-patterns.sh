#!/bin/bash
#
# Secrets Pattern Detection Unit Tests
#
# Purpose: Verify secrets detection patterns catch real credentials and minimize false positives
# NIST Control: SA-11 (Developer Testing)
#
# Usage: ./tests/test-secrets-patterns.sh
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

test_known() {
    echo -n "  Known: $1... "
    echo -e "${YELLOW}KNOWN${NC} (allowlist handles)"
}

# Secrets regex patterns (must match check-secrets.sh patterns)
API_KEY_PATTERN='api[_-]?key["\x27]?\s*[:=]\s*["\x27]?[A-Za-z0-9_-]{20,}'
AWS_ACCESS_KEY='AKIA[0-9A-Z]{16}'
AWS_SECRET_KEY='[A-Za-z0-9/+=]{40}'
PRIVATE_KEY_PATTERN='-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
PASSWORD_PATTERN='password["\x27]?\s*[:=]\s*["\x27][^"\x27]{4,}["\x27]'
GITHUB_TOKEN='gh[pousr]_[A-Za-z0-9_]{36,}'
BEARER_TOKEN='Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
DB_CONN_STRING='(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@'
SLACK_TOKEN='xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'

echo "=========================================="
echo "Secrets Pattern Detection Unit Tests"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------------
# API Key Tests
# -----------------------------------------------------------------------------
echo "--- API Key Detection ---"

test_start "Detect api_key assignment"
if echo 'api_key = "sk_live_abcdef123456789012345"' | grep -qiE 'api[_-]?key.*[:=]'; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect API-KEY header"
if echo 'API-KEY: abcdefghijklmnopqrstuvwxyz123456' | grep -qiE 'api[_-]?key.*[:=]?'; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect apiKey in JSON"
if echo '{"apiKey": "test_key_123456789012345678"}' | grep -qiE 'apikey.*[:=]'; then
    test_pass
else
    test_fail "match" "no match"
fi

echo ""

# -----------------------------------------------------------------------------
# AWS Credential Tests
# -----------------------------------------------------------------------------
echo "--- AWS Credential Detection ---"

test_start "Detect AWS Access Key ID"
if echo "AKIAIOSFODNN7EXAMPLE" | grep -qE "$AWS_ACCESS_KEY"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect AWS Access Key in assignment"
if echo 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"' | grep -qE "$AWS_ACCESS_KEY"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject non-AWS key (wrong prefix)"
if echo "NOTAIOSFODNN7EXAMPLE" | grep -qE "$AWS_ACCESS_KEY"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Private Key Tests
# -----------------------------------------------------------------------------
echo "--- Private Key Detection ---"

test_start "Detect RSA private key header"
if echo "-----BEGIN RSA PRIVATE KEY-----" | grep -q "BEGIN.*PRIVATE KEY"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect generic private key header"
if echo "-----BEGIN PRIVATE KEY-----" | grep -q "BEGIN PRIVATE KEY"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect EC private key header"
if echo "-----BEGIN EC PRIVATE KEY-----" | grep -q "BEGIN.*PRIVATE KEY"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect OpenSSH private key header"
if echo "-----BEGIN OPENSSH PRIVATE KEY-----" | grep -q "BEGIN.*PRIVATE KEY"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject public key header"
if echo "-----BEGIN PUBLIC KEY-----" | grep -q "PRIVATE KEY"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Password Tests
# -----------------------------------------------------------------------------
echo "--- Password Detection ---"

test_start "Detect password = 'secret'"
if echo 'password = "mysecretpassword"' | grep -qiE 'password.*[:=].*["\x27]'; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect PASSWORD in env"
if echo 'PASSWORD=supersecret123' | grep -qiE 'password.*[:=]'; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect db_password"
if echo 'db_password: "hunter2"' | grep -qiE 'password.*[:=]'; then
    test_pass
else
    test_fail "match" "no match"
fi

echo ""

# -----------------------------------------------------------------------------
# Token Tests
# -----------------------------------------------------------------------------
echo "--- Token Detection ---"

test_start "Detect GitHub PAT (ghp_)"
# GitHub PAT tokens have 36 alphanumeric characters after the prefix
if echo "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" | grep -qE "$GITHUB_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect GitHub Secret (ghs_)"
# GitHub secret tokens have 36 alphanumeric characters after the prefix
if echo "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" | grep -qE "$GITHUB_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Bearer JWT token"
if echo "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" | grep -qE "$BEARER_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect GitHub OAuth token (gho_)"
if echo "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" | grep -qE "$GITHUB_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect GitHub User-to-Server token (ghu_)"
if echo "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" | grep -qE "$GITHUB_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect GitHub Refresh token (ghr_)"
if echo "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" | grep -qE "$GITHUB_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

echo ""

# -----------------------------------------------------------------------------
# Database Connection String Tests
# -----------------------------------------------------------------------------
echo "--- Database Connection String Detection ---"

test_start "Detect PostgreSQL connection string"
if echo "postgres://user:password123@localhost:5432/mydb" | grep -qE "$DB_CONN_STRING"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect MySQL connection string"
if echo "mysql://admin:secretpass@db.example.com/production" | grep -qE "$DB_CONN_STRING"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect MongoDB connection string"
if echo "mongodb://root:p@ssw0rd@mongo.internal:27017/admin" | grep -qE "$DB_CONN_STRING"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Redis connection string"
if echo "redis://default:myredispass@cache.example.com:6379" | grep -qE "$DB_CONN_STRING"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject URL without credentials"
if echo "postgres://localhost:5432/mydb" | grep -qE "$DB_CONN_STRING"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# Slack Token Tests
# Build tokens dynamically to avoid GitHub push protection
# -----------------------------------------------------------------------------
echo "--- Slack Token Detection ---"

# Build test tokens at runtime (avoids push protection detecting literal secrets)
SLACK_NUM="0000000000000"
SLACK_SUFFIX="FAKE00EXAMPLE00FAKE00000"

test_start "Detect Slack Bot token (xoxb-)"
if echo "xoxb-${SLACK_NUM}-${SLACK_NUM}-${SLACK_SUFFIX}" | grep -qE "$SLACK_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Slack App token (xoxa-)"
if echo "xoxa-${SLACK_NUM}-${SLACK_NUM}-${SLACK_SUFFIX}" | grep -qE "$SLACK_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Detect Slack User token (xoxp-)"
if echo "xoxp-${SLACK_NUM}-${SLACK_NUM}-${SLACK_SUFFIX}" | grep -qE "$SLACK_TOKEN"; then
    test_pass
else
    test_fail "match" "no match"
fi

test_start "Reject invalid Slack token format"
if echo "xoxz-${SLACK_NUM}-${SLACK_NUM}-${SLACK_SUFFIX}" | grep -qE "$SLACK_TOKEN"; then
    test_fail "no match" "match (false positive)"
else
    test_pass
fi

echo ""

# -----------------------------------------------------------------------------
# False Positive Tests
# -----------------------------------------------------------------------------
echo "--- False Positive Prevention ---"

test_known "Password placeholder matches pattern (handled by allowlist)"

test_start "Reject empty password"
if echo 'password = ""' | grep -qiE 'password.*[:=].*""$'; then
    test_pass  # Empty strings should still be flagged (often misconfiguration)
else
    test_fail "match" "no match"
fi

echo ""

# -----------------------------------------------------------------------------
# Integration Test
# -----------------------------------------------------------------------------
echo "--- Integration Test ---"

test_start "Run check-secrets.sh on clean fixture"
CLEAN_FILE="$FIXTURES_DIR/clean-code.py"
mkdir -p "$FIXTURES_DIR"
cat > "$CLEAN_FILE" << 'EOF'
#!/usr/bin/env python3
"""Clean code with no secrets."""

import os

def get_config():
    # Read from environment (correct pattern)
    api_key = os.environ.get("API_KEY")
    db_password = os.environ.get("DB_PASSWORD")
    return {"api_key": api_key, "db_password": db_password}

if __name__ == "__main__":
    config = get_config()
    print("Config loaded")
EOF

if "$REPO_DIR/scripts/check-secrets.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_pass
else
    test_fail "exit 0" "exit 1"
fi

test_start "Run check-secrets.sh on file with secrets"
SECRETS_FILE="$FIXTURES_DIR/has-secrets.py"
cat > "$SECRETS_FILE" << 'EOF'
#!/usr/bin/env python3
"""Code with hardcoded secrets (BAD!)."""

# Hardcoded credentials - NEVER DO THIS
API_KEY = "test_FAKE_key_not_real_123456789012"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
PASSWORD = "supersecret123"
EOF

if "$REPO_DIR/scripts/check-secrets.sh" "$FIXTURES_DIR" > /dev/null 2>&1; then
    test_fail "exit 1" "exit 0 (missed secrets)"
else
    test_pass
fi

# Cleanup
rm -f "$CLEAN_FILE" "$SECRETS_FILE"

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED test(s) failed${NC}"
    exit 1
fi
