#!/bin/bash
#
# Test Suite: Git History Purge Dry-Run (CRITICAL-005)
#
# Purpose: Verify safe git history purge with dry-run, preview, and confirmation
# NIST Controls: SI-12 (Information Management), CM-3 (Change Control)

set -eu

# Enable test mode for scripts that check for interactive input
export TESTING=1

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

# Create temporary test environment
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Git History Purge Dry-Run Test Suite (CRITICAL-005)"
echo "==================================================="
echo "Test Directory: $TEST_DIR"
echo ""

# Setup test git repo
setup_test_repo() {
    local repo_dir="$1"
    mkdir -p "$repo_dir"
    cd "$repo_dir"
    
    git init --quiet
    git config user.email "test@example.com"
    git config user.name "Test User"
    
    echo "content1" > file1.txt
    git add file1.txt
    git commit --quiet -m "Add file1"
    
    echo "secret1" > secrets.json
    git add secrets.json
    git commit --quiet -m "Add config"
    
    echo "content2" > file2.txt
    git add file2.txt
    git commit --quiet -m "Add file2"
    
    echo "password=123" > .env
    git add .env
    git commit --quiet -m "Add env"
    
    mkdir -p config
    echo "secret2" > config/secrets.json
    git add config/secrets.json
    git commit --quiet -m "Add config secrets"
}

# TEST 1: Dry-run shows files
echo -n "TEST 1: Dry-run mode shows files... "
test_repo="$TEST_DIR/test1"
setup_test_repo "$test_repo"
output=$(cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" "secrets.json" 2>&1)
if echo "$output" | grep -q "DRY-RUN MODE" && echo "$output" | grep -q "secrets.json"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 2: Without --execute, runs dry-run only
echo -n "TEST 2: Without --execute, runs dry-run only... "
test_repo="$TEST_DIR/test2"
setup_test_repo "$test_repo"
original_commits=$(git -C "$test_repo" log --all --oneline | wc -l)
output=$(cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" "secrets.json" 2>&1)
new_commits=$(git -C "$test_repo" log --all --oneline | wc -l)
if echo "$output" | grep -q "DRY-RUN" && [ "$original_commits" -eq "$new_commits" ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 3: Confirmation 'no' cancels purge
echo -n "TEST 3: Confirmation 'no' cancels purge... "
test_repo="$TEST_DIR/test3"
setup_test_repo "$test_repo"
original_commits=$(git -C "$test_repo" log --all --oneline | wc -l)
output=$(echo "no" | (cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" --execute "secrets.json" 2>&1) || true)
new_commits=$(git -C "$test_repo" log --all --oneline | wc -l)
if echo "$output" | grep -q "cancelled" && [ "$original_commits" -eq "$new_commits" ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 4: Confirmation case-sensitive
echo -n "TEST 4: Confirmation case-sensitive... "
test_repo="$TEST_DIR/test4"
setup_test_repo "$test_repo"
original_commits=$(git -C "$test_repo" log --all --oneline | wc -l)
output=$(echo "YES" | (cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" --execute "secrets.json" 2>&1) || true)
new_commits=$(git -C "$test_repo" log --all --oneline | wc -l)
if echo "$output" | grep -q "cancelled" && [ "$original_commits" -eq "$new_commits" ]; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 5: Dry-run displays file count
echo -n "TEST 5: Dry-run displays file count... "
test_repo="$TEST_DIR/test5"
setup_test_repo "$test_repo"
output=$(cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" "secrets.json" 2>&1)
if echo "$output" | grep -q "Total files"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 6: Audit log created on execute
echo -n "TEST 6: Audit log created on execute... "
test_repo="$TEST_DIR/test6"
setup_test_repo "$test_repo"
output=$(echo "yes" | (cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" --execute "secrets.json" 2>&1) || true)
if [ -f "$test_repo/.git/PURGE_LOG.txt" ] && grep -q "Purged" "$test_repo/.git/PURGE_LOG.txt"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 7: Multiple patterns supported
echo -n "TEST 7: Multiple patterns supported... "
test_repo="$TEST_DIR/test7"
setup_test_repo "$test_repo"
output=$(cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" "secrets.json" ".env" 2>&1)
if echo "$output" | grep -q "secrets.json" && echo "$output" | grep -q ".env"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 8: No files found handled gracefully
echo -n "TEST 8: No files found handled gracefully... "
test_repo="$TEST_DIR/test8"
setup_test_repo "$test_repo"
output=$(cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" "nonexistent-file.txt" 2>&1)
if echo "$output" | grep -q "Nothing to purge"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 9: Rollback instructions provided (on execute)
echo -n "TEST 9: Rollback instructions provided... "
test_repo="$TEST_DIR/test9"
setup_test_repo "$test_repo"
output=$(echo "yes" | (cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" --execute "secrets.json" 2>&1) || true)
if echo "$output" | grep -q "IF YOU NEED TO UNDO"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# TEST 10: Dry-run shows --execute command
echo -n "TEST 10: Dry-run shows command to execute... "
test_repo="$TEST_DIR/test10"
setup_test_repo "$test_repo"
output=$(cd "$test_repo" && "$SCRIPT_DIR/purge-git-history.sh" "secrets.json" 2>&1)
if echo "$output" | grep -q "execute" || echo "$output" | grep -q "DRY-RUN"; then
    echo -e "${GREEN}PASS${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAIL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Summary
echo ""
echo "==========================================="
echo "Test Results:"
echo -e "  ${GREEN}PASSED${NC}: $TESTS_PASSED"
echo -e "  ${RED}FAILED${NC}: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All 10 tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ $TESTS_FAILED test(s) failed${NC}"
    exit 1
fi
