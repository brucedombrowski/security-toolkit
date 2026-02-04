#!/bin/bash
#
# Toolkit Information Library
#
# Purpose: Centralized toolkit identification and configuration
# NIST Controls:
#   - CM-8 (System Component Inventory): Toolkit version identification
#   - AU-3 (Content of Audit Records): Source attribution
#
# Usage:
#   source "$SCRIPT_DIR/lib/toolkit-info.sh"
#   init_toolkit_info "$REPO_ROOT"
#
#   # Then use variables:
#   echo "Version: $TOOLKIT_VERSION"
#   echo "Commit: $TOOLKIT_COMMIT"
#   echo "Source: $TOOLKIT_SOURCE"
#
# Configuration Priority:
#   1. release.config.json (if exists)
#   2. Git remote origin URL (auto-detected)
#   3. Fallback default

# ============================================================================
# Default Values (can be overridden by config or git remote)
# ============================================================================

TOOLKIT_NAME="Security Verification Toolkit"
TOOLKIT_VERSION="unknown"
TOOLKIT_COMMIT="unknown"
TOOLKIT_SOURCE="https://github.com/OWNER/REPO"

# ============================================================================
# Initialization Function
# ============================================================================

# Initialize toolkit information from config or git
# Arguments:
#   $1 - Repository root directory (optional, defaults to parent of script dir)
#
# Environment Variables:
#   TOOLKIT_VERSION_OVERRIDE - If set, use this version instead of git describe
#                              (used by release.sh to set version before tag exists)
init_toolkit_info() {
    local repo_root="${1:-}"

    # If no repo root provided, try to determine from SCRIPT_DIR
    if [ -z "$repo_root" ]; then
        if [ -n "${SCRIPT_DIR:-}" ]; then
            repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
        elif [ -n "${SECURITY_REPO_DIR:-}" ]; then
            repo_root="$SECURITY_REPO_DIR"
        else
            # Can't determine, use defaults
            return 0
        fi
    fi

    # Get version: override > git tags > unknown
    if [ -n "${TOOLKIT_VERSION_OVERRIDE:-}" ]; then
        TOOLKIT_VERSION="v${TOOLKIT_VERSION_OVERRIDE}"
    else
        TOOLKIT_VERSION=$(git -C "$repo_root" describe --tags --always 2>/dev/null || echo "unknown")
    fi

    # Get commit hash
    TOOLKIT_COMMIT=$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # Get source URL (priority: config file > git remote > default)
    TOOLKIT_SOURCE=$(get_toolkit_source "$repo_root")
}

# ============================================================================
# Source URL Detection
# ============================================================================

# Get toolkit source URL from config or git remote
# Arguments:
#   $1 - Repository root directory
# Returns: Source URL string
get_toolkit_source() {
    local repo_root="$1"
    local config_file="$repo_root/release.config.json"
    local source_url=""

    # Priority 1: Read from release.config.json
    if [ -f "$config_file" ] && command -v jq &> /dev/null; then
        local owner repo
        owner=$(jq -r '.github.owner // empty' "$config_file" 2>/dev/null)
        repo=$(jq -r '.github.repo // empty' "$config_file" 2>/dev/null)

        if [ -n "$owner" ] && [ -n "$repo" ]; then
            source_url="https://github.com/${owner}/${repo}"
        fi
    fi

    # Priority 2: Auto-detect from git remote
    if [ -z "$source_url" ]; then
        local remote_url
        remote_url=$(git -C "$repo_root" config --get remote.origin.url 2>/dev/null || true)

        if [ -n "$remote_url" ]; then
            # Convert SSH URLs to HTTPS
            # git@github.com:user/repo.git -> https://github.com/user/repo
            if [[ "$remote_url" =~ ^git@([^:]+):(.+)\.git$ ]]; then
                source_url="https://${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
            elif [[ "$remote_url" =~ ^git@([^:]+):(.+)$ ]]; then
                source_url="https://${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
            # Already HTTPS URL - just remove .git suffix
            elif [[ "$remote_url" =~ ^https://(.+)\.git$ ]]; then
                source_url="https://${BASH_REMATCH[1]}"
            elif [[ "$remote_url" =~ ^https:// ]]; then
                source_url="$remote_url"
            fi
        fi
    fi

    # Priority 3: Fallback default
    if [ -z "$source_url" ]; then
        source_url="https://github.com/OWNER/REPO"
    fi

    echo "$source_url"
}

# ============================================================================
# Formatted Output Helpers
# ============================================================================

# Get formatted toolkit identification string
# Returns: "Security Verification Toolkit v1.0.0 (abc1234)"
get_toolkit_id() {
    echo "$TOOLKIT_NAME $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
}

# Get toolkit header for reports
# Arguments:
#   $1 - Output function (e.g., "echo" or custom function name)
print_toolkit_header() {
    local output_fn="${1:-echo}"
    $output_fn "Toolkit: $TOOLKIT_NAME $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
    $output_fn "Source: $TOOLKIT_SOURCE"
}

# ============================================================================
# Output Directory Helpers
# ============================================================================

# Determine the appropriate .scans directory for output
# Priority:
#   1. SECURITY_TOOLKIT_OUTPUT_DIR env var (if set)
#   2. $TARGET_DIR/.scans (if target is writable)
#   3. $SECURITY_REPO_DIR/.scans (toolkit directory fallback)
#
# Arguments:
#   $1 - Target directory being scanned
#
# Returns: Path to .scans directory (echoed)
#
# Example:
#   SCANS_DIR=$(get_scans_dir "$TARGET_DIR")
#   mkdir -p "$SCANS_DIR"
#
get_scans_dir() {
    local target_dir="${1:-.}"

    # Priority 1: Environment variable override
    if [ -n "${SECURITY_TOOLKIT_OUTPUT_DIR:-}" ]; then
        echo "${SECURITY_TOOLKIT_OUTPUT_DIR}/.scans"
        return 0
    fi

    # Priority 2: Target directory (if writable)
    local target_scans="$target_dir/.scans"
    if mkdir -p "$target_scans" 2>/dev/null; then
        # Test write access
        local test_file="$target_scans/.write-test-$$"
        if touch "$test_file" 2>/dev/null; then
            rm -f "$test_file"
            echo "$target_scans"
            return 0
        fi
    fi

    # Priority 3: Toolkit directory fallback
    local toolkit_scans="${SECURITY_REPO_DIR:-.}/.scans"
    mkdir -p "$toolkit_scans" 2>/dev/null || true
    echo "$toolkit_scans"
}
