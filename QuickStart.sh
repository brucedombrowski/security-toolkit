#!/bin/bash
#
# Security Toolkit QuickStart
#
# Purpose: Easy entry point for new users to demo the security toolkit
# Usage: ./QuickStart.sh
#
# This interactive script:
#   1. Checks system dependencies
#   2. Asks what you want to scan
#   3. Runs the appropriate scans
#   4. Shows a summary of results

set -eu

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"
LIB_DIR="$SCRIPTS_DIR/lib/quickstart"

# ============================================================================
# Command-line Arguments
# ============================================================================

FORCE_CLI=false
CONFIG_FILE=""

for arg in "$@"; do
    case "$arg" in
        --no-tui|--cli)
            FORCE_CLI=true
            ;;
        --config=*)
            CONFIG_FILE="${arg#--config=}"
            ;;
        *.conf|*.config)
            CONFIG_FILE="$arg"
            ;;
        -h|--help)
            echo "Usage: ./QuickStart.sh [OPTIONS] [config_file]"
            echo ""
            echo "Options:"
            echo "  --no-tui, --cli    Force CLI mode (disable TUI even if available)"
            echo "  --config=FILE      Load configuration from file"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Config file format (shell variables):"
            echo "  REMOTE_HOST=10.0.0.223"
            echo "  REMOTE_USER=payload"
            echo "  PROJECT_NAME=Payload"
            echo "  SCAN_MODE=remote"
            echo "  AUTH_MODE=credentialed"
            echo ""
            echo "Example: ./QuickStart.sh myhost.conf"
            exit 0
            ;;
    esac
done

# Load config file if specified
if [ -n "$CONFIG_FILE" ]; then
    # If file doesn't exist, check .scans/ directory
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$SCRIPT_DIR/.scans/$CONFIG_FILE" ]; then
            CONFIG_FILE="$SCRIPT_DIR/.scans/$CONFIG_FILE"
        fi
    fi
    if [ -f "$CONFIG_FILE" ]; then
        echo "Loading config from: $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        echo "Warning: Config file not found: $CONFIG_FILE"
    fi
fi

# ============================================================================
# Menu Configuration Variables (preserve values from config file)
# ============================================================================

SCAN_MODE="${SCAN_MODE:-}"              # "local" or "remote"
AUTH_MODE="${AUTH_MODE:-}"              # "credentialed" or "uncredentialed"
PRIVILEGE_LEVEL="${PRIVILEGE_LEVEL:-}"  # "admin" or "standard"
SCAN_SCOPE="${SCAN_SCOPE:-}"            # "full" or "directory"
REMOTE_HOST="${REMOTE_HOST:-}"          # Remote hostname/IP
REMOTE_USER="${REMOTE_USER:-}"          # Remote username (for credentialed)
PROJECT_NAME="${PROJECT_NAME:-}"        # User-provided project/target alias
REMOTE_OS="${REMOTE_OS:-}"              # Detected remote OS
TARGET_DIR=""                           # Target directory for scans

# Remote scan options (preserve config values, default to false)
RUN_NMAP_PORTS="${RUN_NMAP_PORTS:-false}"
RUN_NMAP_SERVICES="${RUN_NMAP_SERVICES:-false}"
RUN_NMAP_OS="${RUN_NMAP_OS:-false}"
RUN_NMAP_VULN="${RUN_NMAP_VULN:-false}"
RUN_REMOTE_INVENTORY="${RUN_REMOTE_INVENTORY:-false}"
RUN_REMOTE_SECURITY="${RUN_REMOTE_SECURITY:-false}"
RUN_REMOTE_LYNIS="${RUN_REMOTE_LYNIS:-false}"
RUN_REMOTE_MALWARE="${RUN_REMOTE_MALWARE:-false}"
RUN_REMOTE_OPENVAS="${RUN_REMOTE_OPENVAS:-false}"
LYNIS_MODE="${LYNIS_MODE:-quick}"
OPENVAS_SCAN_TYPE="${OPENVAS_SCAN_TYPE:-quick}"
SKIP_SCAN_SELECTION="${SKIP_SCAN_SELECTION:-false}"

# Local scan options
RUN_PII=false
RUN_SECRETS=false
RUN_MAC=false
RUN_MALWARE=false
RUN_KEV=false
RUN_LYNIS=false
RUN_OPENVAS=false
LYNIS_PRIVILEGED=false
LYNIS_QUICK=false
MALWARE_FULL_SYSTEM=false

# Output
PDF_ATTESTATION_PATH=""
SCANS_PASSED=0
SCANS_FAILED=0
SCANS_SKIPPED=0

# ============================================================================
# Source Toolkit Info
# ============================================================================

TOOLKIT_VERSION="unknown"
TOOLKIT_COMMIT="unknown"
if [ -f "$SCRIPTS_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPTS_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SCRIPT_DIR"
fi

# ============================================================================
# Source Libraries
# ============================================================================

source "$LIB_DIR/ui.sh"
source "$LIB_DIR/deps.sh"
source "$LIB_DIR/session.sh"
source "$LIB_DIR/menus.sh"
source "$LIB_DIR/local.sh"
source "$LIB_DIR/remote.sh"
source "$LIB_DIR/openvas.sh"
source "$LIB_DIR/attestation.sh"

# ============================================================================
# Initialize Session Transcript
# ============================================================================

init_transcript

# ============================================================================
# Main
# ============================================================================

main() {
    # Clear screen for fresh start
    clear

    print_banner
    check_dependencies

    # Menu flow: Environment -> Auth -> Scans -> Config
    # Skip prompts if set from config file
    if [ -z "$SCAN_MODE" ]; then
        select_scan_environment
    else
        echo "Scan mode: $SCAN_MODE (from config)"
    fi

    if [ -z "$AUTH_MODE" ]; then
        select_auth_mode
    else
        echo "Auth mode: $AUTH_MODE (from config)"
    fi

    select_scans

    if [ "$SCAN_MODE" = "local" ]; then
        # Check if any scan needs a target directory
        # Lynis always scans whole system, so skip target selection if only Lynis
        local needs_target=false
        [ "$RUN_PII" = true ] && needs_target=true
        [ "$RUN_SECRETS" = true ] && needs_target=true
        [ "$RUN_MAC" = true ] && needs_target=true
        [ "$RUN_MALWARE" = true ] && [ "$MALWARE_FULL_SYSTEM" = false ] && needs_target=true
        [ "$RUN_KEV" = true ] && needs_target=true

        if [ "$needs_target" = true ]; then
            select_local_config
        else
            # Lynis-only scan - no target needed
            TARGET_DIR="/"
            echo ""
            echo -e "${CYAN}Lynis scans the entire system - no target selection needed.${NC}"
            echo ""
        fi

        # Set privilege level based on auth mode
        if [ "$AUTH_MODE" = "credentialed" ]; then
            PRIVILEGE_LEVEL="admin"
        else
            PRIVILEGE_LEVEL="standard"
        fi
    else
        select_remote_config
        if [ "$AUTH_MODE" = "uncredentialed" ]; then
            print_warning "Remote uncredentialed scan: Only network-based checks available"
            echo ""
        fi
    fi

    # Initialize unique scan session directory
    # Output always goes to .scans in current working directory
    local base_dir
    local target_name
    base_dir="$(pwd)"
    if [ "$SCAN_MODE" = "remote" ]; then
        target_name="$PROJECT_NAME"  # Use project name, not IP
    else
        target_name=$(basename "$TARGET_DIR")
        # Handle root directory specially
        if [ "$TARGET_DIR" = "/" ]; then
            target_name="system-root"
        fi
    fi
    init_scan_session "$base_dir" "$target_name"

    run_scans
    generate_pdf_attestation "$SCAN_OUTPUT_DIR"
    generate_malware_attestation "$SCAN_OUTPUT_DIR"
    generate_vuln_attestation "$SCAN_OUTPUT_DIR"
    print_summary

    # Finalize session transcript
    finalize_transcript "$SCAN_OUTPUT_DIR"

    # Open scan folder
    open_scan_folder "$SCAN_OUTPUT_DIR"

    # Exit with appropriate code
    if [ "$SCANS_FAILED" -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main
main "$@"
