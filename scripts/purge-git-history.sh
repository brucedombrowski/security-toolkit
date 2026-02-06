#!/bin/bash
#
# Git History Purge Script
#
# Purpose: Remove sensitive files from entire git history per NIST SP 800-88
# Usage: ./scripts/purge-git-history.sh [options] <file_pattern> [<pattern2> ...]
#
# This script removes files from all git commits, not just the current state.
# Use when sensitive data was accidentally committed and needs complete removal.
#
# CRITICAL-005 SAFETY IMPROVEMENTS:
# - Dry-run is DEFAULT (preview-only mode unless --execute is specified)
# - Requires explicit "--execute" flag for destructive operation
# - Shows exact files that will be deleted (not just commit count)
# - Requires typed "yes" confirmation (case-sensitive, not just y/n)
# - Creates audit log in .git/PURGE_LOG.txt
# - Provides rollback instructions
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
#   --execute   Perform actual deletion (required for destructive operations)
#   --dry-run   Preview-only mode (DEFAULT if --execute not specified)
#   -h, --help  Show this help message
#
# Exit codes:
#   0 = Success or dry-run
#   1 = Error
#   2 = Invalid arguments

set -eu

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXECUTE=0
FILE_PATTERNS=()

print_usage() {
    echo "Usage: $SCRIPT_NAME [options] <file_pattern> [<pattern2> ...]"
    echo ""
    echo "Remove sensitive files from entire git history."
    echo ""
    echo "Options:"
    echo "  --execute   Actually perform purge (default is dry-run preview)"
    echo "  --dry-run   Preview-only mode (DEFAULT)"
    echo "  -h, --help  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME 'examples/host-inventory-*.txt'              # Dry-run preview"
    echo "  $SCRIPT_NAME --execute 'examples/host-inventory-*.txt'    # Actually purge"
    echo "  $SCRIPT_NAME --dry-run 'secrets.json' '.env'              # Multiple patterns"
    echo ""
    echo "After running this script:"
    echo "  1. Force push to remote: git push origin --force --all"
    echo "  2. Notify collaborators to re-clone the repository"
    echo "  3. Run: git reflog expire --expire=now --all && git gc --prune=now"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --execute)
            EXECUTE=1
            shift
            ;;
        --dry-run)
            EXECUTE=0
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
            FILE_PATTERNS+=("$1")
            shift
            ;;
    esac
done

# Validate arguments
if [ ${#FILE_PATTERNS[@]} -eq 0 ]; then
    echo "Error: No file pattern specified" >&2
    print_usage >&2
    exit 2
fi

# Check we're in a git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not in a git repository" >&2
    exit 1
fi

# Display mode at start
if [ "$EXECUTE" -eq 0 ]; then
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "DRY-RUN MODE (No changes will be made)"
    echo "────────────────────────────────────────────────────────────────────────────"
    echo "To actually remove files, run with: --execute"
    echo "════════════════════════════════════════════════════════════════════════════"
else
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "EXECUTE MODE - Changes will be made"
    echo "════════════════════════════════════════════════════════════════════════════"
fi
echo ""

# Function to find and list actual files that will be deleted

# Show files that would be purged for each pattern
total_files=0
for pattern in "${FILE_PATTERNS[@]}"; do
    echo "Files matching pattern: $pattern"
    echo "─────────────────────────────────────────"
    
    # Get file list and count
    file_list=$(git log --all --full-history --pretty=format: --name-only -- "$pattern" 2>/dev/null | sort -u || true)
    
    if [ -z "$file_list" ]; then
        echo "  (no files found)"
        file_count=0
    else
        echo "$file_list" | while read file; do
            if [ -n "$file" ]; then
                echo "  • $file"
            fi
        done
        file_count=$(echo "$file_list" | wc -l)
        total_files=$((total_files + file_count))
    fi
    echo ""
done

# Check if any files found
if [ "$total_files" -eq 0 ]; then
    echo "No files found matching patterns:"
    for pattern in "${FILE_PATTERNS[@]}"; do
        echo "  • $pattern"
    done
    echo ""
    echo "Nothing to purge."
    exit 0
fi

echo "Total files to be purged: $total_files"
echo ""

# Dry run - just show what would happen
if [ "$EXECUTE" -eq 0 ]; then
    echo "────────────────────────────────────────"
    echo "DRY-RUN PREVIEW COMPLETE"
    echo "────────────────────────────────────────"
    echo ""
    echo "To execute this purge, run:"
    for pattern in "${FILE_PATTERNS[@]}"; do
        echo "  $SCRIPT_NAME --execute \"$pattern\""
    done
    exit 0
fi

# EXECUTE MODE: Require explicit "yes" confirmation
echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║ ⚠️  WARNING: This will permanently remove files from git history!          ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "This operation will:"
echo "  1. Remove matching files from ALL commits"
echo "  2. Change all commit hashes (breaking history for collaborators)"
echo "  3. Require force push to update remote"
echo "  4. BE IRREVERSIBLE (unless you have backups)"
echo ""
echo "Please review the file list above carefully."
echo ""
# Use /dev/tty for interactive input unless in test mode
if [ -n "${TESTING:-}" ]; then
    read -p "Type exactly 'yes' to confirm purge (or anything else to cancel): " confirmation
else
    read -p "Type exactly 'yes' to confirm purge (or anything else to cancel): " confirmation </dev/tty
fi

if [ "$confirmation" != "yes" ]; then
    echo ""
    echo "Purge cancelled. No changes made."
    exit 0
fi

# Create audit log
AUDIT_LOG=".git/PURGE_LOG.txt"
TIMESTAMP=$(date -u "+%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname || echo "unknown")
USER_NAME="${USER:-unknown}"

if [ ! -f "$AUDIT_LOG" ]; then
    echo "# Git History Purge Audit Log" > "$AUDIT_LOG"
    echo "# Format: ISO8601_TIMESTAMP | HOSTNAME | USER | PATTERNS" >> "$AUDIT_LOG"
    echo "#" >> "$AUDIT_LOG"
fi

PATTERNS_STR=$(IFS=,; echo "${FILE_PATTERNS[*]}")
echo "$TIMESTAMP | $HOSTNAME | $USER_NAME | Purged: $PATTERNS_STR | Files: $total_files" >> "$AUDIT_LOG"

# Create backup branch
BACKUP_BRANCH="backup-before-purge-$(date +%Y%m%d-%H%M%S)"
echo ""
echo "Creating backup branch: $BACKUP_BRANCH"
git branch "$BACKUP_BRANCH"

# Perform the purge using git filter-branch
echo ""
echo "Purging files from git history..."
echo ""

# Use filter-branch to remove all matching patterns
# --force: overwrite any existing backup refs
# --index-filter: faster than --tree-filter for file removal
# --prune-empty: remove commits that become empty after filtering
# -- --all: process all branches

for pattern in "${FILE_PATTERNS[@]}"; do
    echo "  Removing: $pattern"
    git filter-branch --force --index-filter \
        "git rm --cached --ignore-unmatch '$pattern'" \
        --prune-empty -- --all 2>&1 || {
        echo ""
        echo "ERROR: Purge failed during processing of: $pattern"
        echo "Backup branch preserved: $BACKUP_BRANCH"
        exit 1
    }
done

echo ""
echo "✓ Purge completed successfully."
echo ""
echo "Audit log created: $AUDIT_LOG"
echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║ NEXT STEPS (REQUIRED)                                                      ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "1. Review the changes:"
echo "   git log --oneline -10"
echo ""
echo "2. Force push to remote (WARNING: This affects all collaborators):"
echo "   git push origin --force --all"
echo "   git push origin --force --tags"
echo ""
echo "3. Clean up local refs:"
echo "   rm -rf .git/refs/original/"
echo "   git reflog expire --expire=now --all"
echo "   git gc --prune=now --aggressive"
echo ""
echo "4. Notify all collaborators:"
echo "   They must re-clone the repository or use 'git reset --hard origin/main'"
echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║ IF YOU NEED TO UNDO THIS PURGE                                             ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Recovery options (use only if you have NOT yet force-pushed):"
echo ""
echo "1. Restore from backup branch:"
echo "   git reset --hard $BACKUP_BRANCH"
echo ""
echo "2. Or restore from remote (if not yet force-pushed):"
echo "   git fetch origin"
echo "   git reset --hard origin/main"
echo ""
echo "3. Or use git reflog to find previous state:"
echo "   git reflog"
echo "   git reset --hard <commit-hash>"
echo ""
echo "Backup branch will remain available: $BACKUP_BRANCH"
echo "Delete after verification: git branch -D $BACKUP_BRANCH"
echo ""
echo "NIST SP 800-88: Git history sanitization complete (Clear level)"
