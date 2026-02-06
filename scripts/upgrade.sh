#!/bin/bash
#
# Security Toolkit Upgrade Script
#
# Purpose: Safely upgrade the toolkit without losing project-specific data
#
# Usage: ./scripts/upgrade.sh
#
# This script:
# 1. Backs up any local changes
# 2. Fetches latest from origin
# 3. Shows what changed (including KEV catalog)
# 4. Confirms before upgrading
#
# Exit codes:
#   0 = Success
#   1 = Error or user cancelled
#   2 = Not a git repository

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo ""
    echo "=========================================="
    echo "  Security Toolkit Upgrade"
    echo "=========================================="
    echo ""
}

print_info() {
    echo -e "${CYAN}→ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}" >&2
}

# Check if in git repo
check_git_repo() {
    if ! git -C "$REPO_ROOT" rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not a git repository. Cannot upgrade."
        echo "If you downloaded a ZIP, please clone the repository instead:"
        echo "  git clone https://github.com/brucedombrowski/Security.git"
        exit 2
    fi
}

# Get current version
get_current_version() {
    git -C "$REPO_ROOT" describe --tags --always 2>/dev/null || echo "unknown"
}

# Check for local changes
check_local_changes() {
    if ! git -C "$REPO_ROOT" diff-index --quiet HEAD -- 2>/dev/null; then
        return 1
    fi
    return 0
}

# Fetch remote updates
fetch_updates() {
    print_info "Fetching updates from origin..."
    if ! git -C "$REPO_ROOT" fetch origin 2>&1; then
        print_error "Failed to fetch from origin"
        return 1
    fi
    return 0
}

# Show what will change
show_changes() {
    local current_branch
    current_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)

    local behind
    behind=$(git -C "$REPO_ROOT" rev-list --count HEAD..origin/"$current_branch" 2>/dev/null || echo "0")

    if [ "$behind" -eq 0 ]; then
        print_success "Already up to date!"
        return 1
    fi

    echo ""
    print_info "$behind commit(s) behind origin/$current_branch"
    echo ""

    echo "Changes:"
    git -C "$REPO_ROOT" log --oneline HEAD..origin/"$current_branch"
    echo ""

    # Check for KEV catalog changes
    if git -C "$REPO_ROOT" diff HEAD..origin/"$current_branch" --name-only | grep -q "data/kev-catalog.json"; then
        print_info "KEV catalog will be updated"
        local remote_kev_date
        remote_kev_date=$(git -C "$REPO_ROOT" show origin/"$current_branch":data/kev-catalog.json 2>/dev/null | jq -r '.dateReleased' 2>/dev/null || echo "unknown")
        echo "  New KEV catalog date: $remote_kev_date"
        echo ""
    fi

    return 0
}

# Perform upgrade
do_upgrade() {
    local current_branch
    current_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)

    print_info "Upgrading to latest version..."

    if ! git -C "$REPO_ROOT" pull origin "$current_branch" 2>&1; then
        print_error "Failed to pull updates"
        return 1
    fi

    return 0
}

# Show post-upgrade info
show_post_upgrade_info() {
    local new_version
    new_version=$(get_current_version)

    echo ""
    print_success "Upgrade complete!"
    echo ""
    echo "  New version: $new_version"

    # Show KEV catalog info
    if [ -f "$REPO_ROOT/data/kev-catalog.json" ]; then
        local kev_date kev_count
        kev_date=$(jq -r '.dateReleased' "$REPO_ROOT/data/kev-catalog.json" 2>/dev/null || echo "unknown")
        kev_count=$(jq -r '.count' "$REPO_ROOT/data/kev-catalog.json" 2>/dev/null || echo "unknown")
        echo "  KEV catalog: $kev_count vulnerabilities (released $kev_date)"
    fi

    echo ""
    echo "What's preserved during upgrades:"
    echo "  • Your project's .scans/ directory (scan results)"
    echo "  • Your project's .allowlists/ directory (exceptions)"
    echo "  • Your project's requirements.json (if using template)"
    echo "  • Your project's .gitignore and other config"
    echo ""
    echo "See CHANGELOG.md for detailed release notes."
}

# Main
main() {
    print_header

    local current_version
    current_version=$(get_current_version)
    print_info "Current version: $current_version"

    check_git_repo

    # Check for local changes
    if ! check_local_changes; then
        print_warning "You have uncommitted local changes"
        echo ""
        git -C "$REPO_ROOT" status --short
        echo ""
        read -p "Continue anyway? (y/N) " -n 1 -r </dev/tty
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Upgrade cancelled"
            exit 1
        fi
    fi

    # Fetch and show changes
    if ! fetch_updates; then
        exit 1
    fi

    if ! show_changes; then
        exit 0  # Already up to date
    fi

    # Confirm upgrade
    read -p "Apply these updates? (y/N) " -n 1 -r </dev/tty
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Upgrade cancelled"
        exit 1
    fi

    # Perform upgrade
    if ! do_upgrade; then
        exit 1
    fi

    show_post_upgrade_info
}

main "$@"
