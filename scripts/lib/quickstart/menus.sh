#!/bin/bash
#
# QuickStart Menu Flow Library
#
# Purpose: Scan type selection and authentication mode
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Level 1: Scan Type Selection (Machine vs Content)
# ============================================================================

select_scan_type_cli() {
    while true; do
        echo -e "${BOLD}What are you scanning?${NC}"
        echo ""
        echo "  1) Machine/Host      - Vulnerability assessment of a system"
        echo "                         (ports, services, CVEs, security config)"
        echo ""
        echo "  2) Repository/Files  - Content analysis of a directory"
        echo "                         (PII, secrets, malware, sensitive data)"
        echo ""
        echo -n "Select [1-2]: "
        read -r choice </dev/tty

        case "$choice" in
            1) SCAN_TYPE="host"; break ;;
            2) SCAN_TYPE="content"; break ;;
            *)
                print_error "Invalid selection, please enter 1 or 2"
                echo ""
                ;;
        esac
    done
    log_transcript "SCAN TYPE: $SCAN_TYPE"
    echo ""
}

select_scan_type() {
    # Check if set from config file
    if [ -n "$SCAN_TYPE" ]; then
        echo "Scan type: $SCAN_TYPE (from config)"
        return
    fi

    # Legacy config migration
    if [ -n "$SCAN_MODE" ] && [ -z "$SCAN_TYPE" ]; then
        if [ "$SCAN_MODE" = "remote" ]; then
            SCAN_TYPE="host"
            TARGET_LOCATION="remote"
        else
            SCAN_TYPE="content"
            TARGET_LOCATION="local"
        fi
        echo "Note: Migrated legacy SCAN_MODE=$SCAN_MODE to SCAN_TYPE=$SCAN_TYPE"
        return
    fi

    select_scan_type_cli
}

# ============================================================================
# Level 2: Target Selection
# ============================================================================

# For Machine/Host scans - get IP or hostname
select_host_target_cli() {
    echo -e "${BOLD}Target Host${NC}"
    echo ""

    # Get project name first
    if [ -z "$PROJECT_NAME" ]; then
        echo -n "  Project/target name (e.g., 'Production-Web'): "
        read -r PROJECT_NAME </dev/tty
        if [ -z "$PROJECT_NAME" ]; then
            PROJECT_NAME="HostScan"
        fi
    else
        echo "  Project name: $PROJECT_NAME (from config)"
    fi

    # Get target host
    if [ -z "$TARGET_HOST" ]; then
        echo ""
        echo -n "  Target IP or hostname: "
        read -r TARGET_HOST </dev/tty
        if [ -z "$TARGET_HOST" ]; then
            print_error "Target is required"
            exit 1
        fi
    else
        echo "  Target host: $TARGET_HOST (from config)"
    fi

    # Determine if local or remote
    if [ "$TARGET_HOST" = "localhost" ] || [ "$TARGET_HOST" = "127.0.0.1" ]; then
        TARGET_LOCATION="local"
    else
        TARGET_LOCATION="remote"
    fi

    log_transcript "TARGET: $TARGET_HOST ($TARGET_LOCATION)"
    echo ""
}

# For Repository/Content scans - get directory path
select_content_target_cli() {
    echo -e "${BOLD}Target Directory${NC}"
    echo ""

    if [ -z "$TARGET_DIR" ]; then
        echo "  1) Current directory ($(pwd))"
        echo "  2) Home directory ($HOME)"
        echo "  3) Specify a path"
        echo ""
        echo -n "  Select [1-3]: "
        read -r choice </dev/tty

        case "$choice" in
            1) TARGET_DIR="$(pwd)" ;;
            2) TARGET_DIR="$HOME" ;;
            3)
                echo -n "  Enter path: "
                read -r TARGET_DIR </dev/tty
                ;;
            *) TARGET_DIR="$(pwd)" ;;
        esac
    else
        echo "  Target directory: $TARGET_DIR (from config)"
    fi

    # Validate path exists
    if [ ! -d "$TARGET_DIR" ]; then
        print_error "Directory not found: $TARGET_DIR"
        exit 1
    fi

    # Set project name from directory if not set
    if [ -z "$PROJECT_NAME" ]; then
        PROJECT_NAME=$(basename "$TARGET_DIR")
        [ "$TARGET_DIR" = "/" ] && PROJECT_NAME="system-root" || true
    fi

    TARGET_LOCATION="local"
    log_transcript "TARGET: $TARGET_DIR"
    echo ""
}

# ============================================================================
# Level 3: Authentication Mode
# ============================================================================

select_host_auth_cli() {
    while true; do
        echo -e "${BOLD}Authentication Mode${NC}"
        echo ""
        if [ "$TARGET_LOCATION" = "local" ]; then
            echo "  1) Credentialed   - Run with sudo for deeper system checks"
            echo "  2) Uncredentialed - Run as current user (limited access)"
        else
            echo "  1) Credentialed   - SSH login for authenticated scanning"
            echo "                      (host inventory, security config, Lynis)"
            echo ""
            echo "  2) Uncredentialed - Network-only scan (no login required)"
            echo "                      (port scan, service detection, CVE lookup)"
            echo ""
            echo -e "  ${GRAY}Tip: Windows targets often don't have SSH - use option 2 for network scan${NC}"
        fi
        echo ""
        echo -n "Select [1-2]: "
        read -r choice </dev/tty

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

    # For credentialed remote scans, get SSH username
    if [ "$AUTH_MODE" = "credentialed" ] && [ "$TARGET_LOCATION" = "remote" ]; then
        echo ""
        echo -e "  ${CYAN}Note: SSH-based scans require SSH access to the target.${NC}"
        echo -e "  ${CYAN}For Windows targets without SSH, select 'Uncredentialed' for network-only scans.${NC}"
        echo -e "  ${CYAN}See: docs/WINDOWS-TARGET-SETUP.md${NC}"
        echo ""
        if [ -z "$REMOTE_USER" ]; then
            echo -n "  Username for $TARGET_HOST: "
            read -r REMOTE_USER </dev/tty
            if [ -z "$REMOTE_USER" ]; then
                REMOTE_USER="$USER"
                echo "  Using current username: $REMOTE_USER"
            fi
        else
            echo "  Username: $REMOTE_USER (from config)"
        fi
        log_transcript "SSH USER: $REMOTE_USER"
    fi

    echo ""
}

select_content_auth_cli() {
    while true; do
        echo -e "${BOLD}Privilege Level${NC}"
        echo ""
        echo "  1) Admin/Elevated  - Run with sudo (scan protected directories)"
        echo "  2) Standard user   - Run as current user"
        echo ""
        echo -n "Select [1-2]: "
        read -r choice </dev/tty

        case "$choice" in
            1) AUTH_MODE="credentialed"; PRIVILEGE_LEVEL="admin"; break ;;
            2) AUTH_MODE="uncredentialed"; PRIVILEGE_LEVEL="standard"; break ;;
            *)
                print_error "Invalid selection, please enter 1 or 2"
                echo ""
                ;;
        esac
    done
    log_transcript "PRIVILEGE: $PRIVILEGE_LEVEL"
    echo ""
}

select_auth_mode() {
    # Check if set from config
    if [ -n "$AUTH_MODE" ]; then
        echo "Auth mode: $AUTH_MODE (from config)"
        return
    fi

    if [ "$SCAN_TYPE" = "host" ]; then
        select_host_auth_cli
    else
        select_content_auth_cli
    fi
}

# ============================================================================
# Legacy Compatibility Functions
# ============================================================================

# These maintain backward compatibility with old menu structure

select_scan_environment() {
    # Legacy function - redirect to new scan type selection
    select_scan_type
}
