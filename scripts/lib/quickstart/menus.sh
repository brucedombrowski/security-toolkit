#!/bin/bash
#
# QuickStart Menu Flow Library
#
# Purpose: Scan environment and authentication mode selection
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Level 1: Scan Environment Selection
# ============================================================================

select_scan_environment_tui() {
    local choice
    choice=$(tui_menu "Scan Environment" "Select scan environment:" 12 70 2 \
        "local" "Local Scan - Scan this machine or local directories" \
        "remote" "Remote Scan - Scan a remote host over the network")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi
    SCAN_MODE="$choice"
}

select_scan_environment_cli() {
    while true; do
        echo -e "${BOLD}Select Scan Environment${NC}"
        echo ""
        echo "  1) Local Scan  - Scan this machine or local directories"
        echo "  2) Remote Scan - Scan a remote host over the network"
        echo ""
        echo -n "Select [1-2]: "
        read -r choice

        case "$choice" in
            1) SCAN_MODE="local"; break ;;
            2) SCAN_MODE="remote"; break ;;
            *)
                print_error "Invalid selection, please enter 1 or 2"
                echo ""
                ;;
        esac
    done
    log_transcript "ENVIRONMENT: $SCAN_MODE scan"
}

select_scan_environment() {
    if use_tui; then
        select_scan_environment_tui
    else
        select_scan_environment_cli
    fi
    echo ""
}

# ============================================================================
# Level 2: Authentication Mode
# ============================================================================

select_auth_mode_tui() {
    local desc_cred desc_uncred
    if [ "$SCAN_MODE" = "local" ]; then
        desc_cred="Run with elevated privileges (sudo) for deeper checks"
        desc_uncred="Run as current user (limited access to system files)"
    else
        desc_cred="SSH with credentials for authenticated scanning"
        desc_uncred="Network-only scan (port scan, service detection)"
    fi

    local choice
    choice=$(tui_menu "Authentication Mode" "Select authentication level:" 12 70 2 \
        "cred" "Credentialed - $desc_cred" \
        "uncred" "Uncredentialed - $desc_uncred")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi
    [ "$choice" = "cred" ] && AUTH_MODE="credentialed" || AUTH_MODE="uncredentialed"
}

select_auth_mode_cli() {
    while true; do
        echo -e "${BOLD}Select Authentication Mode${NC}"
        echo ""
        if [ "$SCAN_MODE" = "local" ]; then
            echo "  1) Credentialed   - Run with sudo for deeper system checks"
            echo "  2) Uncredentialed - Run as current user (limited access)"
        else
            echo "  1) Credentialed   - SSH login for authenticated scanning"
            echo "  2) Uncredentialed - Network-only scan (no login required)"
        fi
        echo ""
        echo -n "Select [1-2]: "
        read -r choice

        case "$choice" in
            1) AUTH_MODE="credentialed"; break ;;
            2) AUTH_MODE="uncredentialed"; break ;;
            *)
                print_error "Invalid selection, please enter 1 or 2"
                echo ""
                ;;
        esac
    done
    log_transcript "AUTHENTICATION: $AUTH_MODE"
}

select_auth_mode() {
    if use_tui; then
        select_auth_mode_tui
    else
        select_auth_mode_cli
    fi
    echo ""
}
