#!/bin/bash
#
# System Hardening Script
#
# Purpose: Apply common hardening fixes to improve Lynis security score
# Usage: ./scripts/harden-system.sh [--check|--apply]
#
# NIST SP 800-53 Controls:
#   CM-6  Configuration Settings
#   AC-6  Least Privilege
#   SC-28 Protection of Information at Rest
#
# This script addresses common Lynis findings on macOS systems.
# Run with --check to see what would be changed (no modifications).
# Run with --apply to apply the hardening changes.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

MODE="check"
CHANGES_NEEDED=0
CHANGES_APPLIED=0

usage() {
    echo "Usage: $0 [--check|--apply]"
    echo ""
    echo "Options:"
    echo "  --check   Show what would be changed (default, no modifications)"
    echo "  --apply   Apply hardening changes (requires sudo for some)"
    echo ""
    echo "Hardening checks performed:"
    echo "  - NAME-4404: Hostname in /etc/hosts"
    echo "  - HOME-9304: Home directory permissions"
    echo "  - FILE-7524: sshd_config permissions"
    echo ""
    exit 0
}

log_check() {
    echo -e "${YELLOW}[CHECK]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[NEEDS FIX]${NC} $1"
    CHANGES_NEEDED=$((CHANGES_NEEDED + 1))
}

log_fixed() {
    echo -e "${GREEN}[FIXED]${NC} $1"
    CHANGES_APPLIED=$((CHANGES_APPLIED + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            MODE="check"
            shift
            ;;
        --apply)
            MODE="apply"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

echo "========================================"
echo "System Hardening Script"
echo "Mode: $MODE"
echo "========================================"
echo ""

# Get current hostname
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname 2>/dev/null)
HOSTNAME_FULL=$(hostname 2>/dev/null)

# -----------------------------------------------------------------------------
# CHECK 1: NAME-4404 - Hostname in /etc/hosts
# -----------------------------------------------------------------------------
echo "--- NAME-4404: Hostname Resolution ---"
log_check "Checking if hostname is in /etc/hosts..."

if grep -q "$HOSTNAME_SHORT" /etc/hosts 2>/dev/null; then
    log_pass "Hostname '$HOSTNAME_SHORT' found in /etc/hosts"
else
    log_fail "Hostname '$HOSTNAME_SHORT' not in /etc/hosts"

    if [ "$MODE" = "apply" ]; then
        echo "  Adding hostname to /etc/hosts (requires sudo)..."
        if sudo sh -c "echo '127.0.0.1	$HOSTNAME_SHORT $HOSTNAME_FULL' >> /etc/hosts"; then
            log_fixed "Added hostname to /etc/hosts"
        else
            echo "  Error: Failed to modify /etc/hosts"
        fi
    else
        echo "  To fix: sudo sh -c 'echo \"127.0.0.1	$HOSTNAME_SHORT $HOSTNAME_FULL\" >> /etc/hosts'"
    fi
fi
echo ""

# -----------------------------------------------------------------------------
# CHECK 2: HOME-9304 - Home Directory Permissions
# -----------------------------------------------------------------------------
echo "--- HOME-9304: Home Directory Permissions ---"
log_check "Checking home directory permissions..."

HOME_PERMS=$(stat -f "%OLp" "$HOME" 2>/dev/null || stat -c "%a" "$HOME" 2>/dev/null)

# Check if 'other' has any permissions (last digit should be 0)
OTHER_PERMS="${HOME_PERMS: -1}"

if [ "$OTHER_PERMS" = "0" ]; then
    log_pass "Home directory permissions are restrictive ($HOME_PERMS)"
else
    log_fail "Home directory is world-readable/executable ($HOME_PERMS)"

    if [ "$MODE" = "apply" ]; then
        echo "  Removing 'other' permissions from home directory..."
        if chmod 750 "$HOME"; then
            NEW_PERMS=$(stat -f "%OLp" "$HOME" 2>/dev/null || stat -c "%a" "$HOME" 2>/dev/null)
            log_fixed "Changed home directory permissions to $NEW_PERMS"
        else
            echo "  Error: Failed to change home directory permissions"
        fi
    else
        echo "  To fix: chmod 750 ~"
    fi
fi
echo ""

# -----------------------------------------------------------------------------
# CHECK 3: FILE-7524 - sshd_config Permissions
# -----------------------------------------------------------------------------
echo "--- FILE-7524: sshd_config Permissions ---"
log_check "Checking /etc/ssh/sshd_config permissions..."

SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    SSHD_PERMS=$(stat -f "%OLp" "$SSHD_CONFIG" 2>/dev/null || stat -c "%a" "$SSHD_CONFIG" 2>/dev/null)

    if [ "$SSHD_PERMS" = "600" ]; then
        log_pass "sshd_config permissions are restrictive ($SSHD_PERMS)"
    else
        log_fail "sshd_config permissions too permissive ($SSHD_PERMS)"

        if [ "$MODE" = "apply" ]; then
            echo "  Restricting sshd_config permissions (requires sudo)..."
            if sudo chmod 600 "$SSHD_CONFIG"; then
                log_fixed "Changed sshd_config permissions to 600"
            else
                echo "  Error: Failed to change sshd_config permissions"
            fi
        else
            echo "  To fix: sudo chmod 600 /etc/ssh/sshd_config"
        fi
    fi
else
    log_skip "sshd_config not found (SSH server not installed)"
fi
echo ""

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
echo "========================================"
echo "Summary"
echo "========================================"

if [ "$MODE" = "check" ]; then
    if [ "$CHANGES_NEEDED" -eq 0 ]; then
        echo -e "${GREEN}All checks passed. No hardening needed.${NC}"
        exit 0
    else
        echo -e "${YELLOW}$CHANGES_NEEDED issue(s) found.${NC}"
        echo ""
        echo "Run with --apply to fix these issues:"
        echo "  $0 --apply"
        exit 1
    fi
else
    if [ "$CHANGES_APPLIED" -gt 0 ]; then
        echo -e "${GREEN}Applied $CHANGES_APPLIED hardening change(s).${NC}"
    fi

    REMAINING=$((CHANGES_NEEDED - CHANGES_APPLIED))
    if [ "$REMAINING" -gt 0 ]; then
        echo -e "${YELLOW}$REMAINING issue(s) could not be fixed automatically.${NC}"
        exit 1
    else
        echo -e "${GREEN}All hardening changes applied successfully.${NC}"
        echo ""
        echo "Re-run Lynis to verify improved hardening score:"
        echo "  ./scripts/scan-vulnerabilities.sh -q -d .scans"
        exit 0
    fi
fi
