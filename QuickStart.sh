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

# New unified architecture
SCAN_TYPE="${SCAN_TYPE:-}"              # "host" or "content"
TARGET_HOST="${TARGET_HOST:-}"          # Target IP/hostname (for host scans)
TARGET_DIR="${TARGET_DIR:-}"            # Target directory (for content scans)
TARGET_LOCATION="${TARGET_LOCATION:-}"  # "local" or "remote"
AUTH_MODE="${AUTH_MODE:-}"              # "credentialed" or "uncredentialed"
PRIVILEGE_LEVEL="${PRIVILEGE_LEVEL:-}"  # "admin" or "standard"
PROJECT_NAME="${PROJECT_NAME:-}"        # User-provided project/target alias

# Legacy variables (for backward compatibility)
SCAN_MODE="${SCAN_MODE:-}"              # "local" or "remote" (maps to SCAN_TYPE)
SCAN_SCOPE="${SCAN_SCOPE:-}"            # "full" or "directory"
REMOTE_HOST="${REMOTE_HOST:-}"          # Alias for TARGET_HOST
REMOTE_USER="${REMOTE_USER:-}"          # Remote username (for credentialed)
REMOTE_OS="${REMOTE_OS:-}"              # Detected remote OS

# Host scan options (network-based)
RUN_NMAP_PORTS="${RUN_NMAP_PORTS:-false}"
RUN_NMAP_SERVICES="${RUN_NMAP_SERVICES:-false}"
RUN_NMAP_OS="${RUN_NMAP_OS:-false}"
RUN_NMAP_VULN="${RUN_NMAP_VULN:-false}"

# Host scan options (SSH/credentialed)
RUN_HOST_INVENTORY="${RUN_HOST_INVENTORY:-false}"
RUN_HOST_SECURITY="${RUN_HOST_SECURITY:-false}"
RUN_HOST_LYNIS="${RUN_HOST_LYNIS:-false}"
RUN_HOST_MALWARE="${RUN_HOST_MALWARE:-false}"
LYNIS_MODE="${LYNIS_MODE:-quick}"
MALWARE_SCAN_PATHS="${MALWARE_SCAN_PATHS:-~/}"  # Space-separated paths for ClamAV

# Legacy remote scan options (for backward compatibility)
RUN_REMOTE_INVENTORY="${RUN_REMOTE_INVENTORY:-false}"
RUN_REMOTE_SECURITY="${RUN_REMOTE_SECURITY:-false}"
RUN_REMOTE_LYNIS="${RUN_REMOTE_LYNIS:-false}"
RUN_REMOTE_MALWARE="${RUN_REMOTE_MALWARE:-false}"

SKIP_SCAN_SELECTION="${SKIP_SCAN_SELECTION:-false}"

# Local scan options
RUN_PII=false
RUN_SECRETS=false
RUN_MAC=false
RUN_MALWARE=false
RUN_KEV=false
RUN_LYNIS=false
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
source "$SCRIPTS_DIR/lib/progress.sh"

# Scan type modules
source "$LIB_DIR/host-scan.sh"
source "$LIB_DIR/content-scan.sh"

# Legacy modules (for backward compatibility during transition)
source "$LIB_DIR/local.sh"
source "$LIB_DIR/remote.sh"

source "$LIB_DIR/attestation.sh"

# ============================================================================
# Initialize Session Transcript
# ============================================================================

init_transcript

# ============================================================================
# Main
# ============================================================================

main() {
    # Clear screen for fresh start (use both methods for compatibility)
    clear 2>/dev/null || printf '\033[2J\033[H'

    print_banner
    check_dependencies

    # =========================================================================
    # New Flow: Scan Type -> Target -> Auth -> Scans -> Run
    # =========================================================================

    # Step 1: What are you scanning? (Machine or Content)
    select_scan_type

    # Step 2: Target selection based on scan type
    if [ "$SCAN_TYPE" = "host" ]; then
        # Machine/Host scanning
        select_host_target_cli
    else
        # Content/Repository scanning
        select_content_target_cli
    fi

    # Step 3: Authentication mode
    select_auth_mode

    # Step 4: Select specific scans
    if [ "$SCAN_TYPE" = "host" ]; then
        select_host_scans
    else
        select_content_scans
    fi

    # =========================================================================
    # Initialize Output Directory
    # =========================================================================

    local base_dir
    local target_name
    base_dir="$(pwd)"

    if [ "$SCAN_TYPE" = "host" ]; then
        target_name="$PROJECT_NAME"
    else
        target_name=$(basename "$TARGET_DIR")
        [ "$TARGET_DIR" = "/" ] && target_name="system-root"
    fi
    init_scan_session "$base_dir" "$target_name"

    # =========================================================================
    # Run Scans
    # =========================================================================

    if [ "$SCAN_TYPE" = "host" ]; then
        run_host_scans
    else
        run_content_scans
    fi

    # =========================================================================
    # Generate Reports and Summary
    # =========================================================================

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
