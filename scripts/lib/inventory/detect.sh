#!/bin/bash
#
# Detection Helper Library for Host Inventory Collection
#
# Purpose: Reusable functions for detecting installed software
# Used by: collect-host-inventory.sh and inventory collector modules
#
# Functions:
#   detect_tool()           - Detect CLI tool version
#   detect_macos_app()      - Detect macOS app from .app bundle
#   detect_macos_app_paths() - Detect macOS app from multiple paths
#   detect_linux_tool()     - Detect Linux tool with snap/flatpak/package fallback
#   section_header()        - Print section header
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Safe filter dispatcher - validates filter against allowlist before execution
# Usage: apply_safe_filter "filter_command"
# Reads from stdin, writes to stdout
# Returns 1 if filter is not in allowlist
apply_safe_filter() {
    local filter="$1"

    # Allowlist of safe filter patterns (exact match or prefix match)
    case "$filter" in
        "head -1"|"head -n 1"|"tail -1"|"tail -n 1")
            eval "$filter"
            ;;
        "grep -oE"*|"grep -o"*|"grep -E"*)
            # grep with pattern extraction - validate no shell metacharacters in pattern
            if echo "$filter" | grep -qE '[;&|`$()]'; then
                echo "installed"
                return 1
            fi
            eval "$filter" | head -1
            ;;
        "awk"*|"sed"*|"cut"*)
            # Common text processing - validate no dangerous patterns
            if echo "$filter" | grep -qE '[;&|`$()]'; then
                echo "installed"
                return 1
            fi
            eval "$filter"
            ;;
        *)
            # Unknown filter - reject and return safe default
            echo "installed"
            return 1
            ;;
    esac
}

# Detect CLI tool version
# Usage: detect_tool "name" "command" ["version_args"] ["version_filter"]
# Example: detect_tool "Python" "python3" "--version"
# Example: detect_tool "Perl" "perl" "--version" "grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1"
#
# Security: filter parameter is validated against an allowlist of safe commands.
# Only internal collector scripts should call this function.
detect_tool() {
    local name="$1"
    local cmd="$2"
    local args="${3:---version}"
    local filter="${4:-head -1}"

    if command -v "$cmd" >/dev/null 2>&1; then
        local version
        version=$("$cmd" $args 2>/dev/null | apply_safe_filter "$filter" 2>/dev/null || echo "installed")
        output "  $name: $version"
    else
        output "  $name: not installed"
    fi
}

# Detect CLI tool version with stderr capture (for tools like ssh -V that output to stderr)
# Usage: detect_tool_stderr "name" "command" ["version_args"]
detect_tool_stderr() {
    local name="$1"
    local cmd="$2"
    local args="${3:--V}"

    if command -v "$cmd" >/dev/null 2>&1; then
        local version
        version=$("$cmd" $args 2>&1 | head -1)
        output "  $name: $version"
    else
        output "  $name: not installed"
    fi
}

# Detect macOS app from .app bundle
# Usage: detect_macos_app "name" "/path/to/App.app"
detect_macos_app() {
    local name="$1"
    local path="$2"

    if [ -d "$path" ]; then
        local version
        version=$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  $name: $version"
    else
        output "  $name: not installed"
    fi
}

# Detect macOS app from multiple possible paths
# Usage: detect_macos_app_paths "name" "/path1/App.app" "/path2/App.app" ...
# Returns 0 if found, 1 if not found
detect_macos_app_paths() {
    local name="$1"
    shift
    local paths=("$@")

    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            local version
            version=$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
            output "  $name: $version"
            return 0
        fi
    done
    output "  $name: not installed"
    return 1
}

# Internal helper: find macOS IDE version from multiple paths (returns version string)
# Usage: version=$(find_macos_ide_version "${paths[@]}")
find_macos_ide_version() {
    local paths=("$@")

    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            local version
            version=$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
            if [ -n "$version" ]; then
                echo "$version"
                return 0
            fi
        fi
    done
    return 1
}

# Detect Linux tool with snap/flatpak/package manager fallback
# Usage: detect_linux_tool "name" "cmd" "snap_name" "flatpak_name" "dpkg_pattern" "rpm_pattern"
# Example: detect_linux_tool "Firefox" "firefox" "firefox" "org.mozilla.firefox" "firefox" "firefox"
detect_linux_tool() {
    local name="$1"
    local cmd="$2"
    local snap_name="${3:-}"
    local flatpak_name="${4:-}"
    local dpkg_pattern="${5:-}"
    local rpm_pattern="${6:-}"

    # Try command first
    if command -v "$cmd" >/dev/null 2>&1; then
        local version
        version=$("$cmd" --version 2>/dev/null | head -1)
        output "  $name: $version"
        return 0
    fi

    # Try snap
    if [ -n "$snap_name" ] && command -v snap >/dev/null 2>&1; then
        local snap_ver
        snap_ver=$(snap list 2>/dev/null | grep "^$snap_name " | awk '{print $2}')
        if [ -n "$snap_ver" ]; then
            output "  $name: $snap_ver (snap)"
            return 0
        fi
    fi

    # Try flatpak
    if [ -n "$flatpak_name" ] && command -v flatpak >/dev/null 2>&1; then
        local flatpak_ver
        flatpak_ver=$(flatpak list --app 2>/dev/null | grep "$flatpak_name" | awk '{print $3}')
        if [ -n "$flatpak_ver" ]; then
            output "  $name: $flatpak_ver (flatpak)"
            return 0
        fi
    fi

    # Try dpkg
    if [ -n "$dpkg_pattern" ] && command -v dpkg >/dev/null 2>&1; then
        local dpkg_ver
        dpkg_ver=$(dpkg -l 2>/dev/null | grep -i "$dpkg_pattern" | head -1 | awk '{print $3}')
        if [ -n "$dpkg_ver" ]; then
            output "  $name: $dpkg_ver"
            return 0
        fi
    fi

    # Try rpm
    if [ -n "$rpm_pattern" ] && command -v rpm >/dev/null 2>&1; then
        local rpm_ver
        rpm_ver=$(rpm -qa 2>/dev/null | grep -i "$rpm_pattern" | head -1 | sed 's/.*-\([0-9].*\)/\1/')
        if [ -n "$rpm_ver" ]; then
            output "  $name: $rpm_ver"
            return 0
        fi
    fi

    output "  $name: not installed"
    return 1
}

# Internal helper: find Linux browser version (returns version string, no output)
# Usage: version=$(find_linux_browser_version "cmd" "snap_name" "flatpak_name" "dpkg_pattern" "rpm_pattern")
find_linux_browser_version() {
    local cmd="$1"
    local snap_name="${2:-}"
    local flatpak_name="${3:-}"
    local dpkg_pattern="${4:-}"
    local rpm_pattern="${5:-}"

    # Try command first
    if command -v "$cmd" >/dev/null 2>&1; then
        "$cmd" --version 2>/dev/null | head -1
        return 0
    fi

    # Try snap
    if [ -n "$snap_name" ] && command -v snap >/dev/null 2>&1; then
        local snap_ver
        snap_ver=$(snap list 2>/dev/null | grep "^$snap_name " | awk '{print $2}')
        if [ -n "$snap_ver" ]; then
            echo "$snap_ver (snap)"
            return 0
        fi
    fi

    # Try flatpak
    if [ -n "$flatpak_name" ] && command -v flatpak >/dev/null 2>&1; then
        local flatpak_ver
        flatpak_ver=$(flatpak list --app 2>/dev/null | grep "$flatpak_name" | awk '{print $3}')
        if [ -n "$flatpak_ver" ]; then
            echo "$flatpak_ver (flatpak)"
            return 0
        fi
    fi

    # Try dpkg
    if [ -n "$dpkg_pattern" ] && command -v dpkg >/dev/null 2>&1; then
        local dpkg_ver
        dpkg_ver=$(dpkg -l 2>/dev/null | grep -i "$dpkg_pattern" | head -1 | awk '{print $3}')
        if [ -n "$dpkg_ver" ]; then
            echo "$dpkg_ver"
            return 0
        fi
    fi

    # Try rpm
    if [ -n "$rpm_pattern" ] && command -v rpm >/dev/null 2>&1; then
        local rpm_ver
        rpm_ver=$(rpm -qa 2>/dev/null | grep -i "$rpm_pattern" | head -1 | sed 's/.*-\([0-9].*\)/\1/')
        if [ -n "$rpm_ver" ]; then
            echo "$rpm_ver"
            return 0
        fi
    fi

    return 1
}

# Print section header
# Usage: section_header "Section Name"
section_header() {
    local title="$1"
    local underline
    underline=$(printf '%*s' "${#title}" | tr ' ' '-')
    output ""
    output "$title:"
    output "$underline-"
}
