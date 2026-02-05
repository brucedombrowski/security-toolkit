#!/bin/bash
#
# QuickStart UI Library
#
# Purpose: Colors, banner, TUI/CLI menu functions, print helpers
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# TUI Detection
# ============================================================================

TUI_CMD=""
if command -v gum &>/dev/null; then
    TUI_CMD="gum"
fi

# Check if TUI should be used (disabled - using CLI menu only)
use_tui() {
    # TUI disabled - always use CLI menu
    return 1
}

# ============================================================================
# Colors (disabled if not a terminal)
# ============================================================================

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    GRAY='\033[0;90m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    GRAY=''
    BOLD=''
    NC=''
fi

# ============================================================================
# Print Helpers
# ============================================================================

print_banner() {
    local version="${TOOLKIT_VERSION:-unknown}"
    echo ""
    local width=64
    local ver_text="Version: ${version}"
    local ver_len=${#ver_text}
    local pad_left=$(( (width - ver_len) / 2 ))
    local pad_right=$(( width - ver_len - pad_left ))
    local ver_line=$(printf "%${pad_left}s%s%${pad_right}s" "" "$ver_text" "")

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}            Security Toolkit - QuickStart                       ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}${ver_line}${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Security verification for local and remote systems:           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • PII Detection (SSN, Phone Numbers, etc.)                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • Secrets Scanning (API Keys, Passwords, Tokens)            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • Malware Detection (ClamAV)                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • Vulnerability Assessment (Lynis, Nmap)                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • CISA KEV Cross-Reference                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo -e "${BLUE}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_fail() {
    echo -e "${RED}✗${NC} $1"
}

# ============================================================================
# TUI Functions (gum only, CLI fallback handled by use_tui check)
# ============================================================================

# Show a TUI menu and return the selected option
# Usage: tui_menu "title" "prompt" height width menu_height "tag1" "item1" "tag2" "item2" ...
tui_menu() {
    local title="$1"
    local prompt="$2"
    local height="$3"
    local width="$4"
    local menu_height="$5"
    shift 5

    # Build array of display items and tags
    local -a items=()
    while [ $# -ge 2 ]; do
        items+=("$1|$2")
        shift 2
    done

    echo -e "${BOLD}$title${NC}" >&2
    [ -n "$prompt" ] && echo "$prompt" >&2
    echo "" >&2

    local result
    result=$(printf '%s\n' "${items[@]}" | gum choose --height="$menu_height" | cut -d'|' -f1)
    local exit_code=$?

    if [ $exit_code -ne 0 ] || [ -z "$result" ]; then
        echo ""
        return 1
    fi

    echo "$result"
    return 0
}

# Show a TUI input box
# Usage: tui_input "title" "prompt" default_value
tui_input() {
    local title="$1"
    local prompt="$2"
    local default="$3"

    echo -e "${BOLD}$title${NC}" >&2
    local result
    result=$(gum input --placeholder "$prompt" --value "$default")
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo ""
        return 1
    fi

    echo "$result"
    return 0
}

# Show a TUI checklist for multiple selections
# Usage: tui_checklist "title" "prompt" height width list_height "tag1" "item1" "on/off" ...
tui_checklist() {
    local title="$1"
    local prompt="$2"
    local height="$3"
    local width="$4"
    local list_height="$5"
    shift 5

    # Build array of items, tracking which are pre-selected
    local -a items=()
    local -a selected=()
    while [ $# -ge 3 ]; do
        local tag="$1"
        local desc="$2"
        local state="$3"
        items+=("$tag|$desc")
        if [ "$state" = "on" ] || [ "$state" = "ON" ]; then
            selected+=("$tag|$desc")
        fi
        shift 3
    done

    echo -e "${BOLD}$title${NC}" >&2
    [ -n "$prompt" ] && echo "$prompt" >&2
    echo "" >&2

    # Build selected args
    local -a gum_args=(--no-limit --height="$list_height")
    for sel in "${selected[@]}"; do
        gum_args+=(--selected="$sel")
    done

    local result
    result=$(printf '%s\n' "${items[@]}" | gum choose "${gum_args[@]}" | cut -d'|' -f1 | tr '\n' ' ')
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo ""
        return 1
    fi

    echo "$result"
    return 0
}

# Show a TUI yes/no confirmation
# Usage: tui_yesno "title" "prompt"
tui_yesno() {
    local title="$1"
    local prompt="$2"

    echo -e "${BOLD}$title${NC}" >&2
    gum confirm "$prompt"
    return $?
}

# Show a TUI message box
# Usage: tui_msgbox "title" "message"
tui_msgbox() {
    local title="$1"
    local message="$2"

    echo ""
    gum style --border normal --padding "1 2" --border-foreground 212 "$title" "" "$message"
    echo ""
    read -rp "Press Enter to continue..."
}
