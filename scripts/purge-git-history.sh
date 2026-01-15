#!/bin/bash
#
# Git History Purge Script
#
# Purpose: Remove sensitive files from entire git history per NIST SP 800-88
# Usage: ./scripts/purge-git-history.sh <file_pattern> [--force]
#
# This script removes files from all git commits, not just the current state.
# Use when sensitive data was accidentally committed and needs complete removal.
#
# WARNING: This rewrites git history. All collaborators must re-clone after push.
#
# NIST SP 800-88 Relevance:
#   While git filter-branch doesn't perform cryptographic erasure, it removes
#   the file from the repository's logical history. Combined with force push
#   and garbage collection, this satisfies the "Clear" sanitization level for
#   version control systems.
#
# Options:
#   --force     Skip confirmation prompt
#   --dry-run   Show what would be removed without making changes
#
# Exit codes:
#   0 = Success
#   1 = Error
#   2 = Invalid arguments

set -e

SCRIPT_NAME=$(basename "$0")
FORCE=false
DRY_RUN=false
FILE_PATTERN=""

print_usage() {
    echo "Usage: $SCRIPT_NAME [options] <file_pattern>"
    echo ""
    echo "Remove sensitive files from entire git history."
    echo ""
    echo "Options:"
    echo "  --force     Skip confirmation prompt"
    echo "  --dry-run   Show affected commits without making changes"
    echo "  -h, --help  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME 'examples/host-inventory-*.txt'"
    echo "  $SCRIPT_NAME --dry-run 'secrets.json'"
    echo "  $SCRIPT_NAME --force '.env'"
    echo ""
    echo "After running this script:"
    echo "  1. Force push to remote: git push origin --force --all"
    echo "  2. Notify collaborators to re-clone the repository"
    echo "  3. Run: git reflog expire --expire=now --all && git gc --prune=now"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            print_usage >&2
            exit 2
            ;;
        *)
            if [ -z "$FILE_PATTERN" ]; then
                FILE_PATTERN="$1"
            else
                echo "Error: Multiple file patterns not supported" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

# Validate arguments
if [ -z "$FILE_PATTERN" ]; then
    echo "Error: No file pattern specified" >&2
    print_usage >&2
    exit 2
fi

# Check we're in a git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not in a git repository" >&2
    exit 1
fi

# Find commits containing the file
echo "Searching git history for: $FILE_PATTERN"
echo ""

AFFECTED_COMMITS=$(git log --all --pretty=format:"%h %s" -- "$FILE_PATTERN" 2>/dev/null || true)

if [ -z "$AFFECTED_COMMITS" ]; then
    echo "No commits found containing: $FILE_PATTERN"
    echo "Nothing to purge."
    exit 0
fi

COMMIT_COUNT=$(echo "$AFFECTED_COMMITS" | wc -l | tr -d ' ')

echo "Found $COMMIT_COUNT commit(s) containing the file:"
echo ""
echo "$AFFECTED_COMMITS" | head -20
if [ "$COMMIT_COUNT" -gt 20 ]; then
    echo "... and $((COMMIT_COUNT - 20)) more"
fi
echo ""

# Dry run - just show what would happen
if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would remove '$FILE_PATTERN' from $COMMIT_COUNT commits"
    echo "[DRY RUN] No changes made"
    exit 0
fi

# Confirmation prompt
if [ "$FORCE" = false ]; then
    echo "WARNING: This will rewrite git history!"
    echo ""
    echo "This operation will:"
    echo "  1. Remove '$FILE_PATTERN' from ALL commits"
    echo "  2. Change commit hashes (breaking history for collaborators)"
    echo "  3. Require force push to update remote"
    echo ""
    read -p "Type 'PURGE' to confirm: " confirmation
    if [ "$confirmation" != "PURGE" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# Create backup branch
BACKUP_BRANCH="backup-before-purge-$(date +%Y%m%d-%H%M%S)"
echo ""
echo "Creating backup branch: $BACKUP_BRANCH"
git branch "$BACKUP_BRANCH"

# Perform the purge using git filter-branch
echo ""
echo "Purging '$FILE_PATTERN' from git history..."
echo ""

# Use filter-branch to remove the file from all commits
# --force: overwrite any existing backup refs
# --index-filter: faster than --tree-filter for file removal
# --prune-empty: remove commits that become empty after filtering
# -- --all: process all branches

git filter-branch --force --index-filter \
    "git rm --cached --ignore-unmatch '$FILE_PATTERN'" \
    --prune-empty -- --all 2>&1 || {
    echo ""
    echo "Error during filter-branch. Backup branch preserved: $BACKUP_BRANCH"
    exit 1
}

echo ""
echo "Purge complete."
echo ""
echo "Next steps:"
echo "  1. Review the changes: git log --oneline -10"
echo "  2. Force push to remote: git push origin --force --all"
echo "  3. Clean up local refs:"
echo "     rm -rf .git/refs/original/"
echo "     git reflog expire --expire=now --all"
echo "     git gc --prune=now --aggressive"
echo "  4. Notify all collaborators to re-clone the repository"
echo ""
echo "Backup branch available: $BACKUP_BRANCH"
echo "Delete after verification: git branch -D $BACKUP_BRANCH"
echo ""
echo "NIST SP 800-88: Git history sanitization complete (Clear level)"
