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
        SCRIPT_BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [ -f "$SCRIPT_BASE/.scans/$CONFIG_FILE" ]; then
            CONFIG_FILE="$SCRIPT_BASE/.scans/$CONFIG_FILE"
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
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

# Source toolkit info for version
TOOLKIT_VERSION="unknown"
if [ -f "$SCRIPTS_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPTS_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SCRIPT_DIR"
fi

# TUI detection (dialog or whiptail)
TUI_CMD=""
if command -v dialog &>/dev/null; then
    TUI_CMD="dialog"
elif command -v whiptail &>/dev/null; then
    TUI_CMD="whiptail"
fi

# Check if TUI should be used (available, terminal is interactive, and not forced CLI)
use_tui() {
    [ "$FORCE_CLI" = false ] && [ -n "$TUI_CMD" ] && [ -t 0 ] && [ -t 1 ]
}

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

# ============================================================================
# Helper Functions
# ============================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}            Security Toolkit - QuickStart                       ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                      Version: ${TOOLKIT_VERSION}                            ${CYAN}║${NC}"
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

# ============================================================================
# TUI Functions (dialog/whiptail)
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

    local result
    result=$($TUI_CMD --title "$title" --menu "$prompt" "$height" "$width" "$menu_height" "$@" 3>&1 1>&2 2>&3)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        # User cancelled
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

    local result
    result=$($TUI_CMD --title "$title" --inputbox "$prompt" 10 60 "$default" 3>&1 1>&2 2>&3)
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

    local result
    result=$($TUI_CMD --title "$title" --checklist "$prompt" "$height" "$width" "$list_height" "$@" 3>&1 1>&2 2>&3)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo ""
        return 1
    fi

    echo "$result"
    return 0
}

# Show a TUI yes/no dialog
# Usage: tui_yesno "title" "prompt"
tui_yesno() {
    local title="$1"
    local prompt="$2"

    $TUI_CMD --title "$title" --yesno "$prompt" 10 60
    return $?
}

# Show a TUI message box
# Usage: tui_msgbox "title" "message"
tui_msgbox() {
    local title="$1"
    local message="$2"

    $TUI_CMD --title "$title" --msgbox "$message" 12 70
}

check_dependency() {
    local cmd="$1"
    local name="$2"
    local install_hint="$3"

    if command -v "$cmd" &>/dev/null; then
        print_success "$name found"
        return 0
    else
        print_warning "$name not found - $install_hint"
        return 1
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v brew &>/dev/null; then
        echo "brew"
    elif command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo ""
    fi
}

# Get install command for a package
get_install_cmd() {
    local pkg_mgr="$1"
    local package="$2"

    case "$pkg_mgr" in
        brew)   echo "brew install $package" ;;
        apt)    echo "sudo apt install -y $package" ;;
        dnf)    echo "sudo dnf install -y $package" ;;
        yum)    echo "sudo yum install -y $package" ;;
        pacman) echo "sudo pacman -S --noconfirm $package" ;;
        *)      echo "" ;;
    esac
}

# Offer to install missing packages
offer_install() {
    local pkg_mgr="$1"
    shift
    local packages=("$@")

    if [ ${#packages[@]} -eq 0 ]; then
        return 0
    fi

    if [ -z "$pkg_mgr" ]; then
        return 0  # No package manager detected
    fi

    echo ""
    echo -e "${BOLD}Would you like to install missing optional dependencies?${NC}"
    echo "  Packages: ${packages[*]}"
    echo ""
    echo -n "Install now? [y/N]: "
    read -r answer

    if [[ "$answer" =~ ^[Yy] ]]; then
        for pkg in "${packages[@]}"; do
            local cmd
            cmd=$(get_install_cmd "$pkg_mgr" "$pkg")
            if [ -n "$cmd" ]; then
                echo ""
                print_step "Installing $pkg..."
                if eval "$cmd"; then
                    print_success "$pkg installed"
                else
                    print_warning "Failed to install $pkg"
                fi
            fi
        done
        echo ""
    fi
}

# ============================================================================
# Dependency Check (Categorized by Use Case)
# ============================================================================

# Dependencies categorized by scan type
declare_dependency_categories() {
    # General (always needed)
    DEPS_GENERAL_CMD=("bash" "grep" "git")
    DEPS_GENERAL_NAME=("Bash" "grep" "Git")
    DEPS_GENERAL_DESC=("Shell interpreter" "Pattern matching" "Version control")

    # Local scanning
    DEPS_LOCAL_CMD=("clamscan" "lynis")
    DEPS_LOCAL_NAME=("ClamAV" "Lynis")
    DEPS_LOCAL_DESC=("Malware detection" "Security auditing")
    DEPS_LOCAL_PKG=("clamav" "lynis")

    # Remote scanning
    DEPS_REMOTE_CMD=("nmap" "ssh")
    DEPS_REMOTE_NAME=("Nmap" "SSH")
    DEPS_REMOTE_DESC=("Network vulnerability scanning" "Remote host access")
    DEPS_REMOTE_PKG=("nmap" "openssh")

    # UI enhancement
    DEPS_UI_CMD=("dialog")
    DEPS_UI_NAME=("dialog")
    DEPS_UI_DESC=("TUI menus")
    DEPS_UI_PKG=("dialog")
}

check_dependencies() {
    print_step "Checking dependencies..."
    echo ""

    declare_dependency_categories

    local all_good=true
    local missing_local=()
    local missing_remote=()
    local missing_ui=()
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)

    # Check required (General)
    echo -e "${BOLD}[General - Required]${NC}"
    for i in "${!DEPS_GENERAL_CMD[@]}"; do
        check_dependency "${DEPS_GENERAL_CMD[$i]}" "${DEPS_GENERAL_NAME[$i]}" "${DEPS_GENERAL_DESC[$i]}" || all_good=false
    done
    echo ""

    # Check local scanning dependencies
    echo -e "${BOLD}[Local Scanning]${NC}"
    for i in "${!DEPS_LOCAL_CMD[@]}"; do
        if ! check_dependency "${DEPS_LOCAL_CMD[$i]}" "${DEPS_LOCAL_NAME[$i]}" "${DEPS_LOCAL_DESC[$i]}"; then
            missing_local+=("${DEPS_LOCAL_PKG[$i]}")
        fi
    done
    echo ""

    # Check remote scanning dependencies
    echo -e "${BOLD}[Remote Scanning]${NC}"
    for i in "${!DEPS_REMOTE_CMD[@]}"; do
        if ! check_dependency "${DEPS_REMOTE_CMD[$i]}" "${DEPS_REMOTE_NAME[$i]}" "${DEPS_REMOTE_DESC[$i]}"; then
            missing_remote+=("${DEPS_REMOTE_PKG[$i]}")
        fi
    done
    echo ""

    # Check UI dependencies
    echo -e "${BOLD}[User Interface]${NC}"
    if [ -n "$TUI_CMD" ]; then
        if [ "$FORCE_CLI" = true ]; then
            print_success "$TUI_CMD found (TUI disabled via --no-tui)"
        else
            print_success "$TUI_CMD found (TUI enabled)"
        fi
    else
        print_warning "dialog/whiptail not found - using CLI mode"
        missing_ui+=("dialog")
    fi
    echo ""

    if [ "$all_good" = false ]; then
        print_error "Missing required dependencies. Please install them and try again."
        exit 1
    fi

    # Offer to install missing dependencies by category
    if [ -n "$pkg_mgr" ] && [ -t 0 ]; then
        local total_missing=()
        [ ${#missing_local[@]} -gt 0 ] && total_missing+=("${missing_local[@]}")
        [ ${#missing_remote[@]} -gt 0 ] && total_missing+=("${missing_remote[@]}")
        [ ${#missing_ui[@]} -gt 0 ] && total_missing+=("${missing_ui[@]}")

        if [ ${#total_missing[@]} -gt 0 ]; then
            echo -e "${BOLD}Missing optional dependencies:${NC}"
            [ ${#missing_local[@]} -gt 0 ] && echo "  Local:  ${missing_local[*]}"
            [ ${#missing_remote[@]} -gt 0 ] && echo "  Remote: ${missing_remote[*]}"
            [ ${#missing_ui[@]} -gt 0 ] && echo "  UI:     ${missing_ui[*]}"
            echo ""

            echo "Install options:"
            echo "  1) All missing packages"
            echo "  2) Local scanning only (${missing_local[*]:-none})"
            echo "  3) Remote scanning only (${missing_remote[*]:-none})"
            echo "  4) None (skip)"
            echo ""
            echo -n "Select [1-4]: "
            read -r install_choice

            case "$install_choice" in
                1) offer_install "$pkg_mgr" "${total_missing[@]}" ;;
                2) [ ${#missing_local[@]} -gt 0 ] && offer_install "$pkg_mgr" "${missing_local[@]}" ;;
                3) [ ${#missing_remote[@]} -gt 0 ] && offer_install "$pkg_mgr" "${missing_remote[@]}" ;;
                *) echo "Skipping installation." ;;
            esac

            # Re-check TUI after potential install
            if command -v dialog &>/dev/null; then
                TUI_CMD="dialog"
            elif command -v whiptail &>/dev/null; then
                TUI_CMD="whiptail"
            fi
        fi
    fi

    print_success "Dependency check complete"
    echo ""
}

# ============================================================================
# Menu Configuration Variables
# ============================================================================

# These use := to preserve values from config file
SCAN_MODE="${SCAN_MODE:-}"              # "local" or "remote"
AUTH_MODE="${AUTH_MODE:-}"              # "credentialed" or "uncredentialed"
PRIVILEGE_LEVEL="${PRIVILEGE_LEVEL:-}"  # "admin" or "standard"
SCAN_SCOPE="${SCAN_SCOPE:-}"            # "full" or "directory"
REMOTE_HOST="${REMOTE_HOST:-}"          # Remote hostname/IP
REMOTE_USER="${REMOTE_USER:-}"          # Remote username (for credentialed)
PROJECT_NAME="${PROJECT_NAME:-}"        # User-provided project/target alias (no IP in filenames)
REMOTE_OS="${REMOTE_OS:-}"              # Detected remote OS (Linux, Darwin, etc.)
SSH_CONTROL_PATH="${SSH_CONTROL_PATH:-}" # SSH multiplexing socket path
SSH_OPTS="${SSH_OPTS:-}"                # SSH options for connection reuse

# Remote scan options (preserve config values, default to false)
RUN_NMAP_PORTS="${RUN_NMAP_PORTS:-false}"             # Port scan
RUN_NMAP_SERVICES="${RUN_NMAP_SERVICES:-false}"       # Service version detection
RUN_NMAP_OS="${RUN_NMAP_OS:-false}"                   # OS fingerprinting
RUN_NMAP_VULN="${RUN_NMAP_VULN:-false}"               # Vulnerability scripts
RUN_REMOTE_INVENTORY="${RUN_REMOTE_INVENTORY:-false}" # Host inventory via SSH
RUN_REMOTE_SECURITY="${RUN_REMOTE_SECURITY:-false}"   # Security check via SSH
RUN_REMOTE_LYNIS="${RUN_REMOTE_LYNIS:-false}"         # Lynis audit via SSH
LYNIS_MODE="${LYNIS_MODE:-quick}"                     # "quick" or "full"
RUN_REMOTE_MALWARE="${RUN_REMOTE_MALWARE:-false}"     # Malware scan via SSH
SKIP_SCAN_SELECTION="${SKIP_SCAN_SELECTION:-false}"   # Skip interactive scan selection

# Output
PDF_ATTESTATION_PATH=""    # Path to generated PDF attestation
SCAN_OUTPUT_DIR=""         # Unique output directory for this scan session
SCAN_SESSION_ID=""         # Unique identifier for this scan session

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
    echo -e "${BOLD}Select Scan Environment${NC}"
    echo ""
    echo "  1) Local Scan  - Scan this machine or local directories"
    echo "  2) Remote Scan - Scan a remote host over the network"
    echo ""
    echo -n "Select [1-2]: "
    read -r choice

    case "$choice" in
        1) SCAN_MODE="local" ;;
        2) SCAN_MODE="remote" ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
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
        1) AUTH_MODE="credentialed" ;;
        2) AUTH_MODE="uncredentialed" ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
}

select_auth_mode() {
    if use_tui; then
        select_auth_mode_tui
    else
        select_auth_mode_cli
    fi
    echo ""
}

# ============================================================================
# Level 3: Local Configuration (Privilege & Scope)
# ============================================================================

select_local_config_tui() {
    # Scope selection
    local choice
    choice=$(tui_menu "Scan Scope" "What do you want to scan?" 14 70 3 \
        "full" "Full Machine - Complete system audit (slower)" \
        "home" "Home Directory - User files and configs" \
        "dir" "Specific Directory - Choose a folder to scan")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi

    case "$choice" in
        full)
            SCAN_SCOPE="full"
            TARGET_DIR="/"
            ;;
        home)
            SCAN_SCOPE="directory"
            TARGET_DIR="$HOME"
            ;;
        dir)
            SCAN_SCOPE="directory"
            TARGET_DIR=$(tui_input "Target Directory" "Enter directory path:" "$(pwd)")
            if [ -z "$TARGET_DIR" ]; then
                print_error "Cancelled"
                exit 1
            fi
            ;;
    esac

    # Expand ~ if used
    TARGET_DIR="${TARGET_DIR/#\~/$HOME}"

    # Validate path
    if [ ! -d "$TARGET_DIR" ]; then
        tui_msgbox "Error" "Directory not found: $TARGET_DIR"
        exit 1
    fi
}

select_local_config_cli() {
    echo -e "${BOLD}Select Scan Scope${NC}"
    echo ""
    echo "  1) Full Machine      - Complete system audit (slower)"
    echo "  2) Home Directory    - User files and configs (~)"
    echo "  3) Specific Directory - Choose a folder"
    echo ""
    echo -n "Select [1-3]: "
    read -r choice

    case "$choice" in
        1)
            SCAN_SCOPE="full"
            TARGET_DIR="/"
            ;;
        2)
            SCAN_SCOPE="directory"
            TARGET_DIR="$HOME"
            ;;
        3)
            SCAN_SCOPE="directory"
            echo ""
            echo -n "Enter directory path: "
            read -r TARGET_DIR
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac

    # Expand ~ if used
    TARGET_DIR="${TARGET_DIR/#\~/$HOME}"

    # Validate path
    if [ ! -d "$TARGET_DIR" ]; then
        print_error "Directory not found: $TARGET_DIR"
        exit 1
    fi
}

select_local_config() {
    if use_tui; then
        select_local_config_tui
    else
        select_local_config_cli
    fi
    echo ""
    print_success "Target: $TARGET_DIR"
    echo ""
}

# ============================================================================
# Level 3: Remote Configuration
# ============================================================================

select_remote_config_tui() {
    # Project name first (used in filenames instead of IP for security)
    PROJECT_NAME=$(tui_input "Project Name" "Enter a name for this scan (used in filenames):" "")
    if [ -z "$PROJECT_NAME" ]; then
        print_error "Project name required"
        exit 1
    fi
    # Sanitize project name for filenames
    PROJECT_NAME=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9_-]/_/g')

    REMOTE_HOST=$(tui_input "Remote Host" "Enter hostname or IP address:" "")
    if [ -z "$REMOTE_HOST" ]; then
        print_error "Cancelled"
        exit 1
    fi

    if [ "$AUTH_MODE" = "credentialed" ]; then
        REMOTE_USER=$(tui_input "SSH Username" "Enter username for $REMOTE_HOST:" "")
        if [ -z "$REMOTE_USER" ]; then
            print_error "Username required"
            exit 1
        fi
        # Note: We don't prompt for password here - let SSH handle it securely
        tui_msgbox "SSH Authentication" "You will be prompted for SSH credentials when connecting.\n\nEnsure you have SSH access to $REMOTE_USER@$REMOTE_HOST"
    fi

    TARGET_DIR="$REMOTE_HOST"
}

select_remote_config_cli() {
    # Project name first (used in filenames instead of IP for security)
    echo -n "Enter project name (used in filenames): "
    read -r PROJECT_NAME
    if [ -z "$PROJECT_NAME" ]; then
        print_error "Project name required"
        exit 1
    fi
    # Sanitize project name for filenames
    PROJECT_NAME=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9_-]/_/g')

    echo -n "Enter remote hostname or IP: "
    read -r REMOTE_HOST

    if [ -z "$REMOTE_HOST" ]; then
        print_error "Hostname required"
        exit 1
    fi

    if [ "$AUTH_MODE" = "credentialed" ]; then
        echo -n "Enter SSH username: "
        read -r REMOTE_USER
        if [ -z "$REMOTE_USER" ]; then
            print_error "Username required"
            exit 1
        fi
        echo ""
        echo "Note: You will be prompted for SSH credentials when connecting."
    fi

    TARGET_DIR="$REMOTE_HOST"
}

select_remote_config() {
    # Skip prompts if all values set from config
    if [ -n "$REMOTE_HOST" ] && [ -n "$REMOTE_USER" ] && [ -n "$PROJECT_NAME" ]; then
        echo "Remote config from file:"
    elif use_tui; then
        select_remote_config_tui
    else
        select_remote_config_cli
    fi
    echo ""
    print_success "Target: $REMOTE_HOST"
    [ -n "$REMOTE_USER" ] && print_success "User: $REMOTE_USER"
    [ -n "$PROJECT_NAME" ] && print_success "Project: $PROJECT_NAME"
    echo ""
}

# ============================================================================
# Scan Session Management
# ============================================================================

# Create unique output directory for this scan session
init_scan_session() {
    local base_dir="$1"
    local target_name="$2"

    # Generate session ID: Scan<YYYYMMDDHHMMSS>
    local timestamp
    timestamp=$(date -u +"%Y%m%d%H%M%S")

    SCAN_SESSION_ID="Scan${timestamp}"
    SCAN_OUTPUT_DIR="$base_dir/.scans/$SCAN_SESSION_ID"

    # Create the directory
    mkdir -p "$SCAN_OUTPUT_DIR"
    chmod 700 "$SCAN_OUTPUT_DIR"

    # Write session metadata (IP stored here only, not in filenames)
    {
        echo "Session: $SCAN_SESSION_ID"
        echo "Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "Project: $target_name"
        if [ "$SCAN_MODE" = "remote" ]; then
            echo "Host: $REMOTE_HOST"  # Actual IP/hostname stored here only
            echo "User: $REMOTE_USER"
        else
            echo "Path: $TARGET_DIR"
        fi
        echo "Mode: $SCAN_MODE"
        echo "Auth: $AUTH_MODE"
    } > "$SCAN_OUTPUT_DIR/session.txt"
    chmod 600 "$SCAN_OUTPUT_DIR/session.txt"

    print_success "Scan session: $SCAN_SESSION_ID"
    echo ""
}

# ============================================================================
# Remote Scan Selection
# ============================================================================

# Start SSH control master for connection multiplexing (single password prompt)
start_ssh_control_master() {
    # Create control socket path
    SSH_CONTROL_PATH="/tmp/ssh-quickstart-$$-$(date +%s)"
    SSH_OPTS="-o ControlPath=$SSH_CONTROL_PATH -o ControlMaster=auto -o ControlPersist=300"

    print_step "Establishing SSH connection to $REMOTE_USER@$REMOTE_HOST..."
    echo "  (You will only need to enter your password once)"
    echo ""

    # Start the control master connection
    if ssh -o ConnectTimeout=10 -o ControlMaster=yes -o ControlPath="$SSH_CONTROL_PATH" -o ControlPersist=300 -N -f "$REMOTE_USER@$REMOTE_HOST" 2>/dev/null; then
        print_success "SSH connection established (will be reused for all scans)"
        return 0
    else
        print_error "Failed to establish SSH connection"
        SSH_CONTROL_PATH=""
        SSH_OPTS=""
        return 1
    fi
}

# Stop SSH control master (cleanup)
stop_ssh_control_master() {
    if [ -n "$SSH_CONTROL_PATH" ] && [ -S "$SSH_CONTROL_PATH" ]; then
        ssh -o ControlPath="$SSH_CONTROL_PATH" -O exit "$REMOTE_USER@$REMOTE_HOST" 2>/dev/null || true
        rm -f "$SSH_CONTROL_PATH" 2>/dev/null || true
    fi
}

# Run SSH command using control master
ssh_cmd() {
    if [ -n "$SSH_OPTS" ]; then
        ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" "$@"
    else
        ssh "$REMOTE_USER@$REMOTE_HOST" "$@"
    fi
}

# Run SSH command with TTY allocation (needed for sudo password prompts)
ssh_cmd_sudo() {
    if [ -n "$SSH_OPTS" ]; then
        ssh -t $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" "$@"
    else
        ssh -t "$REMOTE_USER@$REMOTE_HOST" "$@"
    fi
}

# Test SSH connectivity and detect remote OS
test_ssh_connection() {
    # Set up SSH multiplexing first
    if ! start_ssh_control_master; then
        return 1
    fi

    # Detect remote OS using the multiplexed connection
    REMOTE_OS=$(ssh_cmd "uname -s" 2>/dev/null || echo "Unknown")
    print_success "Remote OS: $REMOTE_OS"
    echo ""

    # Register cleanup on exit
    trap stop_ssh_control_master EXIT

    return 0
}

# Scan selection for remote credentialed (SSH) scans
select_remote_scans_ssh_tui() {
    local selections
    selections=$(tui_checklist "Remote Scan Selection (SSH)" "Select scans to run on $REMOTE_HOST:" 18 70 7 \
        "inventory" "Host inventory (system info, packages)" "on" \
        "security" "Security configuration check" "on" \
        "malware" "Malware scan (ClamAV, if installed)" "on" \
        "lynis-quick" "Lynis audit - quick (~2 min)" "off" \
        "lynis-full" "Lynis audit - full (~10-15 min)" "off" \
        "ports" "Port scan (nmap from local)" "off" \
        "services" "Service version detection (nmap)" "off")

    if [ -z "$selections" ]; then
        print_error "No scans selected"
        exit 1
    fi

    # Parse selections
    [[ "$selections" =~ inventory ]] && RUN_REMOTE_INVENTORY=true
    [[ "$selections" =~ security ]] && RUN_REMOTE_SECURITY=true
    [[ "$selections" =~ malware ]] && RUN_REMOTE_MALWARE=true
    [[ "$selections" =~ lynis-quick ]] && RUN_REMOTE_LYNIS=true && LYNIS_MODE="quick"
    [[ "$selections" =~ lynis-full ]] && RUN_REMOTE_LYNIS=true && LYNIS_MODE="full"
    [[ "$selections" =~ ports ]] && RUN_NMAP_PORTS=true
    [[ "$selections" =~ services ]] && RUN_NMAP_SERVICES=true
}

select_remote_scans_ssh_cli() {
    echo -e "${BOLD}Select Remote Scans (SSH)${NC}"
    echo ""
    echo "Select scans (y/n for each):"
    echo -n "  Host inventory (system info, packages)? [Y/n]: "
    read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_REMOTE_INVENTORY=true
    echo -n "  Security configuration check? [Y/n]: "
    read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_REMOTE_SECURITY=true
    echo -n "  Malware scan (ClamAV, if installed)? [Y/n]: "
    read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_REMOTE_MALWARE=true
    echo -n "  Lynis security audit (if installed)? [y/N]: "
    read -r ans
    if [[ "$ans" =~ ^[Yy] ]]; then
        RUN_REMOTE_LYNIS=true
        echo -n "    Full scan (~10-15 min) or quick (~2 min)? [f/Q]: "
        read -r mode_ans
        [[ "$mode_ans" =~ ^[Ff] ]] && LYNIS_MODE="full" || LYNIS_MODE="quick"
    fi
    echo -n "  Port scan (nmap from local)? [y/N]: "
    read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_PORTS=true
    echo -n "  Service version detection (nmap)? [y/N]: "
    read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_SERVICES=true
    echo ""
}

# Scan selection for remote uncredentialed (Nmap) scans
select_remote_scans_nmap_tui() {
    local choice
    choice=$(tui_menu "Network Scan Type" "Select scan type for $REMOTE_HOST:" 16 70 4 \
        "quick" "Quick scan - Top 100 ports only" \
        "standard" "Standard scan - Top 1000 ports + services" \
        "full" "Full scan - All ports + OS detection + vuln scripts" \
        "custom" "Custom - Select individual options")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi

    case "$choice" in
        quick)
            RUN_NMAP_PORTS=true
            ;;
        standard)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            ;;
        full)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            RUN_NMAP_OS=true
            RUN_NMAP_VULN=true
            ;;
        custom)
            local selections
            selections=$(tui_checklist "Custom Network Scan" "Select scan options:" 16 70 4 \
                "ports" "Port scan (TCP)" "on" \
                "services" "Service version detection (-sV)" "on" \
                "os" "OS fingerprinting (-O, requires root)" "off" \
                "vuln" "Vulnerability scripts (--script vuln)" "off")

            [[ "$selections" =~ ports ]] && RUN_NMAP_PORTS=true
            [[ "$selections" =~ services ]] && RUN_NMAP_SERVICES=true
            [[ "$selections" =~ os ]] && RUN_NMAP_OS=true
            [[ "$selections" =~ vuln ]] && RUN_NMAP_VULN=true
            ;;
    esac
}

select_remote_scans_nmap_cli() {
    echo -e "${BOLD}Select Network Scan Type${NC}"
    echo ""
    echo "  1) Quick scan    - Top 100 ports only (fast)"
    echo "  2) Standard scan - Top 1000 ports + service detection"
    echo "  3) Full scan     - All ports + OS + vulnerability scripts"
    echo "  4) Custom        - Select individual options"
    echo ""
    echo -n "Select [1-4]: "
    read -r choice

    case "$choice" in
        1)
            RUN_NMAP_PORTS=true
            ;;
        2)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            ;;
        3)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            RUN_NMAP_OS=true
            RUN_NMAP_VULN=true
            ;;
        4)
            echo ""
            echo "Select options (y/n for each):"
            echo -n "  Port scan (TCP)? [Y/n]: "
            read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_NMAP_PORTS=true
            echo -n "  Service version detection? [Y/n]: "
            read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_NMAP_SERVICES=true
            echo -n "  OS fingerprinting (requires sudo)? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_OS=true
            echo -n "  Vulnerability scripts? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_VULN=true
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
    echo ""
}

select_remote_scans() {
    if [ "$AUTH_MODE" = "credentialed" ]; then
        # Test SSH connection first
        if ! test_ssh_connection; then
            exit 1
        fi

        if [ "$SKIP_SCAN_SELECTION" = "true" ]; then
            echo "Using scan selections from config file"
        elif use_tui; then
            select_remote_scans_ssh_tui
        else
            select_remote_scans_ssh_cli
        fi
    else
        # Uncredentialed = Nmap only
        if [ "$SKIP_SCAN_SELECTION" = "true" ]; then
            echo "Using scan selections from config file"
        elif use_tui; then
            select_remote_scans_nmap_tui
        else
            select_remote_scans_nmap_cli
        fi
    fi
}

# ============================================================================
# Remote Scan Execution
# ============================================================================

# Run SSH-based remote scans
run_remote_ssh_scans() {
    local passed=0
    local failed=0
    local skipped=0

    # Use the session output directory
    local output_dir="$SCAN_OUTPUT_DIR"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H%M%SZ")

    echo -e "${BOLD}Running remote scans via SSH...${NC}"
    echo ""

    # Remote Host Inventory
    if [ "$RUN_REMOTE_INVENTORY" = true ]; then
        print_step "Collecting remote host inventory..."
        local inv_file="$output_dir/remote-inventory-$timestamp.txt"

        {
            echo "Remote Host Inventory"
            echo "====================="
            echo "Host: $REMOTE_HOST"
            echo "User: $REMOTE_USER"
            echo "Collected: $timestamp"
            echo "Remote OS: $REMOTE_OS"
            echo ""

            echo "--- System Information ---"
            ssh_cmd "uname -a" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- Hostname ---"
            ssh_cmd "hostname -f 2>/dev/null || hostname" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- OS Release ---"
            ssh_cmd "cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || echo 'Unknown'" 2>/dev/null
            echo ""

            echo "--- CPU Information ---"
            ssh_cmd "lscpu 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'Unknown'" 2>/dev/null
            echo ""

            echo "--- Memory ---"
            ssh_cmd "free -h 2>/dev/null || vm_stat 2>/dev/null || echo 'Unknown'" 2>/dev/null
            echo ""

            echo "--- Disk Usage ---"
            ssh_cmd "df -h" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- Network Interfaces ---"
            ssh_cmd "ip addr 2>/dev/null || ifconfig 2>/dev/null" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- Installed Packages (sample) ---"
            ssh_cmd "dpkg -l 2>/dev/null | head -50 || rpm -qa 2>/dev/null | head -50 || brew list 2>/dev/null | head -50 || echo 'Unknown package manager'" 2>/dev/null
            echo ""

            echo "--- Running Services ---"
            ssh_cmd "systemctl list-units --type=service --state=running 2>/dev/null | head -30 || launchctl list 2>/dev/null | head -30 || echo 'Unknown'" 2>/dev/null

        } > "$inv_file" 2>&1

        if [ -s "$inv_file" ]; then
            print_success "Remote inventory saved: $inv_file"
            ((passed++))
        else
            print_warning "Remote inventory collection had issues"
            ((failed++))
        fi
    fi

    # Remote Security Check
    if [ "$RUN_REMOTE_SECURITY" = true ]; then
        print_step "Checking remote security configuration..."
        local sec_file="$output_dir/remote-security-$timestamp.txt"

        {
            echo "Remote Security Configuration Check"
            echo "===================================="
            echo "Host: $REMOTE_HOST"
            echo "Checked: $timestamp"
            echo ""

            echo "--- SSH Configuration ---"
            ssh_cmd "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null || echo 'Cannot read sshd_config'" 2>/dev/null
            echo ""

            echo "--- Firewall Status ---"
            ssh_cmd "sudo ufw status 2>/dev/null || sudo iptables -L -n 2>/dev/null | head -20 || sudo firewall-cmd --state 2>/dev/null || echo 'Firewall status unknown'" 2>/dev/null
            echo ""

            echo "--- Users with Shell Access ---"
            ssh_cmd "grep -E '/bin/(bash|sh|zsh)$' /etc/passwd 2>/dev/null || dscl . -list /Users 2>/dev/null || echo 'Cannot enumerate users'" 2>/dev/null
            echo ""

            echo "--- Sudo Configuration ---"
            ssh_cmd "sudo cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'Cannot read sudoers'" 2>/dev/null
            echo ""

            echo "--- Listening Ports ---"
            ssh_cmd "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || lsof -i -P -n | grep LISTEN 2>/dev/null || echo 'Cannot list ports'" 2>/dev/null
            echo ""

            echo "--- Failed Login Attempts (last 10) ---"
            ssh_cmd "sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10 || sudo grep 'Failed password' /var/log/secure 2>/dev/null | tail -10 || echo 'Cannot read auth logs'" 2>/dev/null
            echo ""

            echo "--- Kernel Security Parameters ---"
            ssh_cmd "sysctl -a 2>/dev/null | grep -E '(randomize|protect|secure)' | head -20 || echo 'Cannot read sysctl'" 2>/dev/null

        } > "$sec_file" 2>&1

        if [ -s "$sec_file" ]; then
            print_success "Remote security check saved: $sec_file"
            ((passed++))
        else
            print_warning "Remote security check had issues"
            ((failed++))
        fi
    fi

    # Remote Lynis Audit
    if [ "$RUN_REMOTE_LYNIS" = true ]; then
        print_step "Running Lynis audit on remote host..."

        # Check if Lynis is installed remotely
        if ssh_cmd "command -v lynis" &>/dev/null; then
            local lynis_file="$output_dir/remote-lynis-$timestamp.txt"
            local lynis_opts=""
            [[ "$LYNIS_MODE" == "quick" ]] && lynis_opts="--quick"

            if [[ "$LYNIS_MODE" == "quick" ]]; then
                echo "  Lynis quick audit running (~2-5 minutes)..."
            else
                echo "  Lynis full audit running (~10-15 minutes)..."
            fi
            if ssh_cmd_sudo "sudo lynis audit system $lynis_opts" > "$lynis_file" 2>&1; then
                print_success "Remote Lynis audit saved: $lynis_file"
                ((passed++))
            else
                print_warning "Remote Lynis audit had issues (check $lynis_file)"
                ((failed++))
            fi
        else
            print_warning "Lynis not installed on remote host"
            echo -n "  Install Lynis now? [y/N]: "
            read -r install_ans
            if [[ "$install_ans" =~ ^[Yy] ]]; then
                echo "  Installing Lynis on remote host..."
                if ssh_cmd_sudo "sudo apt install -y lynis" 2>&1; then
                    print_success "Lynis installed"
                    # Now run the audit
                    local lynis_file="$output_dir/remote-lynis-$timestamp.txt"
                    local lynis_opts=""
                    [[ "$LYNIS_MODE" == "quick" ]] && lynis_opts="--quick"

                    if [[ "$LYNIS_MODE" == "quick" ]]; then
                        echo "  Lynis quick audit running (~2-5 minutes)..."
                    else
                        echo "  Lynis full audit running (~10-15 minutes)..."
                    fi
                    if ssh_cmd_sudo "sudo lynis audit system $lynis_opts" > "$lynis_file" 2>&1; then
                        print_success "Remote Lynis audit saved: $lynis_file"
                        ((passed++))
                    else
                        print_warning "Remote Lynis audit had issues"
                        ((failed++))
                    fi
                else
                    print_error "Lynis installation failed"
                    ((skipped++))
                fi
            else
                ((skipped++))
            fi
        fi
    fi

    # Remote Malware Scan (ClamAV)
    if [ "$RUN_REMOTE_MALWARE" = true ]; then
        print_step "Running malware scan on remote host..."
        local malware_file="$output_dir/remote-malware-$timestamp.txt"

        # Check if clamscan is available on remote
        if ssh_cmd "command -v clamscan" &>/dev/null; then
            {
                echo "Remote Malware Scan (ClamAV)"
                echo "============================="
                echo "Host: $REMOTE_HOST"
                echo "Scanned: $timestamp"
                echo ""

                echo "--- ClamAV Version ---"
                ssh_cmd "clamscan --version" 2>/dev/null || echo "(failed to get version)"
                echo ""

                echo "--- Scan Results ---"
                echo "Scanning home directory with common exclusions..."
                echo ""
                # Scan home directory, show only infected files, limit output
                ssh_cmd "clamscan --recursive --infected \
                    --exclude-dir='.git' \
                    --exclude-dir='node_modules' \
                    --exclude-dir='.cache' \
                    --exclude-dir='.local/share/Trash' \
                    ~/ 2>&1" 2>/dev/null || echo "(scan completed with warnings)"

            } > "$malware_file" 2>&1

            # Check for infections in the output
            if grep -q "Infected files: 0" "$malware_file" 2>/dev/null; then
                print_success "No malware detected"
                REMOTE_MALWARE_RESULT="PASS"
                ((passed++))
            elif grep -q "FOUND" "$malware_file" 2>/dev/null; then
                print_fail "Malware detected! Check $malware_file"
                REMOTE_MALWARE_RESULT="FAIL"
                ((failed++))
            else
                print_success "Malware scan completed: $malware_file"
                REMOTE_MALWARE_RESULT="PASS"
                ((passed++))
            fi
        else
            print_warning "ClamAV not installed on remote host"
            echo -n "  Install ClamAV now? [y/N]: "
            read -r install_ans
            if [[ "$install_ans" =~ ^[Yy] ]]; then
                echo "  Installing ClamAV on remote host..."
                if ssh_cmd_sudo "sudo apt install -y clamav" 2>&1; then
                    print_success "ClamAV installed"
                    echo "  Updating virus database (this may take a minute)..."
                    ssh_cmd_sudo "sudo freshclam" 2>&1 || true
                    # Now run the scan
                    {
                        echo "Remote Malware Scan (ClamAV)"
                        echo "============================="
                        echo "Host: $REMOTE_HOST"
                        echo "Scanned: $timestamp"
                        echo ""
                        echo "--- ClamAV Version ---"
                        ssh_cmd "clamscan --version" 2>/dev/null || echo "(version check failed)"
                        echo ""
                        echo "--- Scan Results ---"
                        ssh_cmd "clamscan --recursive --infected \
                            --exclude-dir='.git' \
                            --exclude-dir='node_modules' \
                            --exclude-dir='.cache' \
                            ~/ 2>&1" 2>/dev/null || echo "(scan completed)"
                    } > "$malware_file" 2>&1

                    if grep -q "Infected files: 0" "$malware_file" 2>/dev/null; then
                        print_success "No malware detected"
                        REMOTE_MALWARE_RESULT="PASS"
                        ((passed++))
                    elif grep -q "FOUND" "$malware_file" 2>/dev/null; then
                        print_fail "Malware detected! Check $malware_file"
                        REMOTE_MALWARE_RESULT="FAIL"
                        ((failed++))
                    else
                        print_success "Malware scan completed: $malware_file"
                        REMOTE_MALWARE_RESULT="PASS"
                        ((passed++))
                    fi
                else
                    print_error "ClamAV installation failed"
                    REMOTE_MALWARE_RESULT="SKIP"
                    ((skipped++))
                fi
            else
                {
                    echo "Remote Malware Scan (ClamAV)"
                    echo "============================="
                    echo "Host: $REMOTE_HOST"
                    echo "Checked: $timestamp"
                    echo ""
                    echo "ClamAV not installed - user declined installation."
                } > "$malware_file" 2>&1
                REMOTE_MALWARE_RESULT="SKIP"
                ((skipped++))
            fi
        fi
    fi

    # Also run local nmap if selected
    if [ "$RUN_NMAP_PORTS" = true ] || [ "$RUN_NMAP_SERVICES" = true ]; then
        run_nmap_scan "$output_dir" "$timestamp"
        if [ $? -eq 0 ]; then
            ((passed++))
        else
            ((failed++))
        fi
    fi

    echo ""

    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}

# Run Nmap network scan
run_nmap_scan() {
    local output_dir="$1"
    local timestamp="$2"
    local nmap_file="$output_dir/nmap-$timestamp.txt"

    print_step "Running Nmap scan against $REMOTE_HOST..."

    if ! command -v nmap &>/dev/null; then
        print_error "Nmap not installed"
        return 1
    fi

    # Build nmap command
    # -Pn skips host discovery (ping) - many hosts block ICMP
    local nmap_args=("-v" "-Pn")

    if [ "$RUN_NMAP_PORTS" = true ]; then
        # Default is top 1000, use -F for fast (top 100)
        if [ "$RUN_NMAP_SERVICES" != true ] && [ "$RUN_NMAP_OS" != true ]; then
            nmap_args+=("-F")  # Fast scan for quick mode
        fi
    fi

    if [ "$RUN_NMAP_SERVICES" = true ]; then
        nmap_args+=("-sV")  # Service version detection
    fi

    if [ "$RUN_NMAP_OS" = true ]; then
        nmap_args+=("-O")  # OS detection (requires root)
        echo "  Note: OS detection requires sudo"
    fi

    if [ "$RUN_NMAP_VULN" = true ]; then
        nmap_args+=("--script=vuln")  # Vulnerability scripts
    fi

    nmap_args+=("$REMOTE_HOST")

    echo "  Running: nmap ${nmap_args[*]}"
    echo ""

    {
        echo "Nmap Scan Results"
        echo "================="
        echo "Target: $REMOTE_HOST"
        echo "Scanned: $timestamp"
        echo "Command: nmap ${nmap_args[*]}"
        echo ""
    } > "$nmap_file"

    # Run nmap (with sudo if OS detection requested)
    if [ "$RUN_NMAP_OS" = true ]; then
        sudo nmap "${nmap_args[@]}" >> "$nmap_file" 2>&1
    else
        nmap "${nmap_args[@]}" >> "$nmap_file" 2>&1
    fi

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        print_success "Nmap scan saved: $nmap_file"

        # Show quick summary
        echo ""
        echo "  Open ports found:"
        grep -E "^[0-9]+/(tcp|udp)" "$nmap_file" | head -10 | while read -r line; do
            echo "    $line"
        done
        local port_count
        port_count=$(grep -cE "^[0-9]+/(tcp|udp).*open" "$nmap_file" 2>/dev/null || echo "0")
        echo "  Total: $port_count open ports"
        return 0
    else
        print_error "Nmap scan failed (exit code: $exit_code)"
        return 1
    fi
}

# Run uncredentialed (Nmap only) scans
run_remote_nmap_scans() {
    local passed=0
    local failed=0
    local skipped=0

    # Use the session output directory
    local output_dir="$SCAN_OUTPUT_DIR"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H%M%SZ")

    echo -e "${BOLD}Running network scan (uncredentialed)...${NC}"
    echo ""

    if run_nmap_scan "$output_dir" "$timestamp"; then
        ((passed++))
    else
        ((failed++))
    fi

    echo ""

    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}

# ============================================================================
# Legacy Target Selection (kept for compatibility)
# ============================================================================

select_target_tui() {
    local choice
    choice=$(tui_menu "Target Selection" "What would you like to scan?" 15 70 4 \
        "1" "Local directory - Scan a specific folder" \
        "2" "Current directory - $(pwd)" \
        "3" "Home directory - Scan entire home (slower)" \
        "4" "Custom path - Enter a specific path")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi

    case "$choice" in
        1)
            TARGET_DIR=$(tui_input "Directory Path" "Enter directory path to scan:" "$(pwd)")
            if [ -z "$TARGET_DIR" ]; then
                print_error "Cancelled"
                exit 1
            fi
            ;;
        2)
            TARGET_DIR="$(pwd)"
            ;;
        3)
            TARGET_DIR="$HOME"
            tui_msgbox "Note" "Scanning home directory may take a while..."
            ;;
        4)
            TARGET_DIR=$(tui_input "Custom Path" "Enter full path to scan:" "")
            if [ -z "$TARGET_DIR" ]; then
                print_error "Cancelled"
                exit 1
            fi
            ;;
    esac

    # Expand ~ if used
    TARGET_DIR="${TARGET_DIR/#\~/$HOME}"

    # Validate path
    if [ ! -d "$TARGET_DIR" ]; then
        tui_msgbox "Error" "Directory not found: $TARGET_DIR"
        exit 1
    fi
}

select_target_cli() {
    echo -e "${BOLD}What would you like to scan?${NC}"
    echo ""
    echo "  1) Local directory    - Scan a specific folder (e.g., a project)"
    echo "  2) Current directory  - Scan $(pwd)"
    echo "  3) Home directory     - Scan your entire home folder (slower)"
    echo "  4) Custom path        - Enter a specific path"
    echo ""
    echo -n "Select option [1-4]: "

    read -r choice

    case "$choice" in
        1)
            echo ""
            echo -n "Enter directory path: "
            read -r TARGET_DIR
            ;;
        2)
            TARGET_DIR="$(pwd)"
            ;;
        3)
            TARGET_DIR="$HOME"
            print_warning "Scanning home directory may take a while..."
            ;;
        4)
            echo ""
            echo -n "Enter full path: "
            read -r TARGET_DIR
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac

    # Expand ~ if used
    TARGET_DIR="${TARGET_DIR/#\~/$HOME}"

    # Validate path
    if [ ! -d "$TARGET_DIR" ]; then
        print_error "Directory not found: $TARGET_DIR"
        exit 1
    fi

    echo ""
    print_success "Target: $TARGET_DIR"
    echo ""
}

select_target() {
    if use_tui; then
        select_target_tui
        echo ""
        print_success "Target: $TARGET_DIR"
        echo ""
    else
        select_target_cli
    fi
}

# ============================================================================
# Scan Selection
# ============================================================================

select_scans_tui() {
    local choice
    choice=$(tui_menu "Scan Selection" "Which scans would you like to run?" 16 70 5 \
        "1" "Quick scan - PII + Secrets only (fastest)" \
        "2" "Standard scan - PII + Secrets + MAC addresses" \
        "3" "Full scan - All scans including malware" \
        "4" "System malware - Full system malware scan only" \
        "5" "Custom - Select individual scans")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi

    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false
    RUN_LYNIS=false
    LYNIS_PRIVILEGED=false
    MALWARE_FULL_SYSTEM=false

    case "$choice" in
        1)
            RUN_PII=true
            RUN_SECRETS=true
            ;;
        2)
            RUN_PII=true
            RUN_SECRETS=true
            RUN_MAC=true
            ;;
        3)
            RUN_PII=true
            RUN_SECRETS=true
            RUN_MAC=true
            RUN_MALWARE=true
            RUN_KEV=true
            RUN_LYNIS=true
            # Ask about privileged mode for Lynis
            if tui_yesno "Lynis Privileged Mode" "Run Lynis with sudo for deeper system checks?\n\n(Recommended for comprehensive audits)"; then
                LYNIS_PRIVILEGED=true
            fi
            ;;
        4)
            RUN_MALWARE=true
            MALWARE_FULL_SYSTEM=true
            tui_msgbox "System Malware Scan" "This scan will check:\n\n- Home directory (~)\n- Applications (/Applications)\n- Temp files (/tmp)\n\nThis may take several minutes."
            ;;
        5)
            # Custom scan selection via checklist
            local selections
            selections=$(tui_checklist "Custom Scan Selection" "Select scans to run (space to toggle):" 20 70 7 \
                "pii" "PII detection (SSN, phone, etc.)" "on" \
                "secrets" "Secrets detection (API keys, passwords)" "on" \
                "mac" "MAC address scan" "off" \
                "malware" "Malware scan (requires ClamAV)" "off" \
                "lynis" "Lynis security audit (requires Lynis)" "off" \
                "kev" "CISA KEV vulnerability check" "off")

            if [ -z "$selections" ]; then
                print_error "No scans selected"
                exit 1
            fi

            # Parse selections (dialog returns quoted strings)
            [[ "$selections" =~ pii ]] && RUN_PII=true
            [[ "$selections" =~ secrets ]] && RUN_SECRETS=true
            [[ "$selections" =~ mac ]] && RUN_MAC=true
            [[ "$selections" =~ malware ]] && RUN_MALWARE=true
            [[ "$selections" =~ lynis ]] && RUN_LYNIS=true
            [[ "$selections" =~ kev ]] && RUN_KEV=true

            # If malware selected, ask about full system
            if [ "$RUN_MALWARE" = true ]; then
                if tui_yesno "Full System Scan" "Scan full system (not just target directory)?"; then
                    MALWARE_FULL_SYSTEM=true
                fi
            fi

            # If Lynis selected, ask about privileged mode
            if [ "$RUN_LYNIS" = true ]; then
                if tui_yesno "Lynis Privileged Mode" "Run Lynis with sudo for deeper system checks?\n\n(Recommended for comprehensive audits)"; then
                    LYNIS_PRIVILEGED=true
                fi
            fi
            ;;
    esac
}

select_scans_cli() {
    echo -e "${BOLD}Which scans would you like to run?${NC}"
    echo ""
    echo "  1) Quick scan     - PII + Secrets only (fastest)"
    echo "  2) Standard scan  - PII + Secrets + MAC addresses"
    echo "  3) Full scan      - All scans including malware + Lynis"
    echo "  4) System malware - Full system malware scan only (thorough)"
    echo "  5) Custom         - Select individual scans"
    echo ""
    echo -n "Select option [1-5]: "

    read -r choice

    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false
    RUN_LYNIS=false
    LYNIS_PRIVILEGED=false
    MALWARE_FULL_SYSTEM=false

    case "$choice" in
        1)
            RUN_PII=true
            RUN_SECRETS=true
            ;;
        2)
            RUN_PII=true
            RUN_SECRETS=true
            RUN_MAC=true
            ;;
        3)
            RUN_PII=true
            RUN_SECRETS=true
            RUN_MAC=true
            RUN_MALWARE=true
            RUN_KEV=true
            RUN_LYNIS=true
            echo ""
            echo -n "  Run Lynis with sudo (deeper checks)? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && LYNIS_PRIVILEGED=true
            ;;
        4)
            # System-wide malware scan only
            RUN_MALWARE=true
            MALWARE_FULL_SYSTEM=true
            echo ""
            echo -e "${YELLOW}Note: System malware scan will check:${NC}"
            echo "  - Home directory (~)"
            echo "  - Applications (/Applications)"
            echo "  - Temp files (/tmp)"
            echo "This may take several minutes depending on file count."
            ;;
        5)
            echo ""
            echo "Select scans (y/n for each):"
            echo -n "  PII detection? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_PII=true
            echo -n "  Secrets detection? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_SECRETS=true
            echo -n "  MAC address scan? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_MAC=true
            echo -n "  Malware scan (requires ClamAV)? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_MALWARE=true
            if [ "$RUN_MALWARE" = true ]; then
                echo -n "    Scan full system (not just target)? [y/N]: "
                read -r ans && [[ "$ans" =~ ^[Yy] ]] && MALWARE_FULL_SYSTEM=true
            fi
            echo -n "  Lynis security audit (requires Lynis)? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_LYNIS=true
            if [ "$RUN_LYNIS" = true ]; then
                echo -n "    Run with sudo (deeper checks)? [y/N]: "
                read -r ans && [[ "$ans" =~ ^[Yy] ]] && LYNIS_PRIVILEGED=true
            fi
            echo -n "  CISA KEV check? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_KEV=true
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac

    echo ""
}

select_scans() {
    # Remote scans have different options
    if [ "$SCAN_MODE" = "remote" ]; then
        select_remote_scans
        return
    fi

    # Local scans
    if use_tui; then
        select_scans_tui
        echo ""
    else
        select_scans_cli
    fi
}

# ============================================================================
# Run Scans
# ============================================================================

run_scans() {
    # Route to appropriate scan runner based on mode
    if [ "$SCAN_MODE" = "remote" ]; then
        if [ "$AUTH_MODE" = "credentialed" ]; then
            run_remote_ssh_scans
        else
            run_remote_nmap_scans
        fi
        return
    fi

    # Local scans
    local passed=0
    local failed=0
    local skipped=0

    echo -e "${BOLD}Running scans...${NC}"
    echo ""

    # PII Scan
    if [ "$RUN_PII" = true ]; then
        print_step "PII Detection..."
        if "$SCRIPTS_DIR/check-pii.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "PII scan passed"
            ((passed++))
        else
            print_warning "PII scan found potential issues"
            ((failed++))
        fi
    fi

    # Secrets Scan
    if [ "$RUN_SECRETS" = true ]; then
        print_step "Secrets Detection..."
        if "$SCRIPTS_DIR/check-secrets.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "Secrets scan passed"
            ((passed++))
        else
            print_warning "Secrets scan found potential issues"
            ((failed++))
        fi
    fi

    # MAC Address Scan
    if [ "$RUN_MAC" = true ]; then
        print_step "MAC Address Scan..."
        if "$SCRIPTS_DIR/check-mac-addresses.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "MAC address scan passed"
            ((passed++))
        else
            print_warning "MAC address scan found potential issues"
            ((failed++))
        fi
    fi

    # Malware Scan
    if [ "$RUN_MALWARE" = true ]; then
        if command -v clamscan &>/dev/null; then
            # Capture exit code before if-test (can't use $? inside else block)
            local malware_exit=0
            if [ "$MALWARE_FULL_SYSTEM" = true ]; then
                print_step "Full System Malware Scan (this may take a while)..."
                "$SCRIPTS_DIR/check-malware.sh" --full-system || malware_exit=$?
                if [ "$malware_exit" -eq 0 ]; then
                    print_success "Full system malware scan passed"
                    ((passed++))
                elif [ "$malware_exit" -eq 2 ]; then
                    print_warning "Malware scan skipped (dependency missing)"
                    ((skipped++))
                else
                    print_warning "Full system malware scan found potential issues"
                    ((failed++))
                fi
            else
                print_step "Malware Scan (this may take a while)..."
                "$SCRIPTS_DIR/check-malware.sh" "$TARGET_DIR" || malware_exit=$?
                if [ "$malware_exit" -eq 0 ]; then
                    print_success "Malware scan passed"
                    ((passed++))
                elif [ "$malware_exit" -eq 2 ]; then
                    print_warning "Malware scan skipped (dependency missing)"
                    ((skipped++))
                else
                    print_warning "Malware scan found potential issues"
                    ((failed++))
                fi
            fi
            echo ""
        else
            print_warning "Skipping malware scan (ClamAV not installed)"
            ((skipped++))
        fi
    fi

    # KEV Check
    if [ "$RUN_KEV" = true ]; then
        print_step "CISA KEV Check..."
        # Note: check-kev.sh expects a scan file, not a directory.
        # Call without args to use most recent scan in .scans/
        local kev_exit=0
        "$SCRIPTS_DIR/check-kev.sh" > /dev/null 2>&1 || kev_exit=$?
        if [ "$kev_exit" -eq 0 ]; then
            print_success "KEV check passed (no known exploited vulnerabilities)"
            ((passed++))
        elif [ "$kev_exit" -eq 2 ]; then
            # Exit code 2 = error (no scan file, missing deps, etc.)
            print_warning "KEV check skipped (no vulnerability scan file found)"
            ((skipped++))
        else
            # Exit code 1 = KEV matches found
            print_warning "KEV check found known exploited vulnerabilities"
            ((failed++))
        fi
    fi

    # Lynis Security Audit
    if [ "$RUN_LYNIS" = true ]; then
        if command -v lynis &>/dev/null; then
            local lynis_exit=0
            if [ "$LYNIS_PRIVILEGED" = true ]; then
                print_step "Lynis Security Audit [privileged] (this may take a while)..."
                echo "  Note: You may be prompted for your password"
                sudo "$SCRIPTS_DIR/scan-vulnerabilities.sh" --lynis-only "$TARGET_DIR" || lynis_exit=$?
            else
                print_step "Lynis Security Audit (this may take a while)..."
                "$SCRIPTS_DIR/scan-vulnerabilities.sh" --lynis-only "$TARGET_DIR" || lynis_exit=$?
            fi
            if [ "$lynis_exit" -eq 0 ]; then
                print_success "Lynis audit passed"
                ((passed++))
            else
                print_warning "Lynis audit found potential issues"
                ((failed++))
            fi
            echo ""
        else
            print_warning "Skipping Lynis audit (Lynis not installed - brew install lynis)"
            ((skipped++))
        fi
    fi

    echo ""

    # Store results for summary
    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}

# ============================================================================
# PDF Attestation Generation
# ============================================================================

generate_pdf_attestation() {
    local output_dir="$1"

    # Check for pdflatex
    if ! command -v pdflatex &>/dev/null; then
        print_warning "PDF attestation skipped (pdflatex not installed)"
        echo "  Install with: brew install basictex (macOS) or apt install texlive-latex-base (Linux)"
        return 0
    fi

    # Check for attestation script
    local attestation_script="$SCRIPTS_DIR/generate-scan-attestation.sh"
    if [ ! -x "$attestation_script" ]; then
        print_warning "PDF attestation skipped (script not found)"
        return 0
    fi

    print_step "Generating PDF attestation..."

    # Set up required environment variables for attestation script
    local file_timestamp
    file_timestamp=$(date -u +"%Y-%m-%d-T%H%M%SZ")

    export TARGET_DIR="${TARGET_DIR:-$(pwd)}"
    export FILE_TIMESTAMP="$file_timestamp"
    export TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    export DATE_STAMP=$(date -u +"%Y-%m-%d")
    export TOOLKIT_VERSION="${TOOLKIT_VERSION:-unknown}"
    export TOOLKIT_COMMIT="${TOOLKIT_COMMIT:-unknown}"
    export TOOLKIT_SOURCE="${SCRIPT_DIR:-unknown}"
    export TOOLKIT_NAME="Security Toolkit"

    # Set scan results based on what was run
    if [ "$SCAN_MODE" = "remote" ]; then
        # Use PROJECT_NAME for clean display, no IP addresses in PDF
        export TARGET_DIR="$PROJECT_NAME"
        export SCAN_SCOPE="Remote - credentialed SSH scan"

        # Get actual checksum from remote inventory file
        local remote_inv_file
        remote_inv_file=$(ls -t "$output_dir"/remote-inventory-*.txt 2>/dev/null | head -1)
        if [ -n "$remote_inv_file" ] && [ -f "$remote_inv_file" ]; then
            export INVENTORY_CHECKSUM=$(shasum -a 256 "$remote_inv_file" 2>/dev/null | awk '{print $1}' || echo "N/A")
        else
            export INVENTORY_CHECKSUM="N/A"
        fi
        export PII_RESULT="SKIP"
        export PII_FINDINGS="Not applicable for remote scans"
        export SECRETS_RESULT="SKIP"
        export SECRETS_FINDINGS="Not applicable for remote scans"
        export MAC_RESULT="SKIP"
        export MAC_FINDINGS="Not applicable for remote scans"
        # Use actual malware scan result if available
        export MALWARE_RESULT="${REMOTE_MALWARE_RESULT:-SKIP}"
        if [ "$MALWARE_RESULT" = "PASS" ]; then
            export MALWARE_FINDINGS="No malware detected on remote host"
        elif [ "$MALWARE_RESULT" = "FAIL" ]; then
            export MALWARE_FINDINGS="Malware detected - see remote-malware-*.txt"
        else
            export MALWARE_FINDINGS="ClamAV not available on remote host"
        fi
        export HOST_RESULT="PASS"
        export HOST_FINDINGS="Remote security check completed"
        export VULN_RESULT="${RUN_NMAP_PORTS:+PASS}"
        export VULN_RESULT="${VULN_RESULT:-SKIP}"
        export VULN_FINDINGS="Nmap network scan"
    else
        # Local scan - set scope
        export SCAN_SCOPE="Local - $TARGET_DIR"

        # Get inventory checksum if available
        local inv_file
        inv_file=$(ls -t "$output_dir"/host-inventory-*.txt 2>/dev/null | head -1)
        if [ -n "$inv_file" ] && [ -f "$inv_file" ]; then
            export INVENTORY_CHECKSUM=$(shasum -a 256 "$inv_file" 2>/dev/null | awk '{print $1}' || echo "N/A")
        else
            export INVENTORY_CHECKSUM="N/A"
        fi

        # Set results based on what was selected and run
        export PII_RESULT="${RUN_PII:+PASS}"
        export PII_RESULT="${PII_RESULT:-SKIP}"
        export PII_FINDINGS="${RUN_PII:+PII scan completed}"
        export PII_FINDINGS="${PII_FINDINGS:-Not selected}"

        export SECRETS_RESULT="${RUN_SECRETS:+PASS}"
        export SECRETS_RESULT="${SECRETS_RESULT:-SKIP}"
        export SECRETS_FINDINGS="${RUN_SECRETS:+Secrets scan completed}"
        export SECRETS_FINDINGS="${SECRETS_FINDINGS:-Not selected}"

        export MAC_RESULT="${RUN_MAC:+PASS}"
        export MAC_RESULT="${MAC_RESULT:-SKIP}"
        export MAC_FINDINGS="${RUN_MAC:+MAC scan completed}"
        export MAC_FINDINGS="${MAC_FINDINGS:-Not selected}"

        export MALWARE_RESULT="${RUN_MALWARE:+PASS}"
        export MALWARE_RESULT="${MALWARE_RESULT:-SKIP}"
        export MALWARE_FINDINGS="${RUN_MALWARE:+Malware scan completed}"
        export MALWARE_FINDINGS="${MALWARE_FINDINGS:-Not selected}"

        export HOST_RESULT="PASS"
        export HOST_FINDINGS="QuickStart local scan"

        export VULN_RESULT="${RUN_LYNIS:+PASS}"
        export VULN_RESULT="${VULN_RESULT:-SKIP}"
        export VULN_FINDINGS="${RUN_LYNIS:+Lynis audit completed}"
        export VULN_FINDINGS="${VULN_FINDINGS:-Not selected}"
    fi

    # Overall status
    if [ "$SCANS_FAILED" -gt 0 ]; then
        export OVERALL_STATUS="FAIL"
    else
        export OVERALL_STATUS="PASS"
    fi
    export PASS_COUNT="$SCANS_PASSED"
    export FAIL_COUNT="$SCANS_FAILED"
    export SKIP_COUNT="$SCANS_SKIPPED"

    # Generate the attestation
    local pdf_output
    if pdf_output=$("$attestation_script" "$output_dir" 2>&1); then
        print_success "PDF attestation generated"
        # Extract PDF path from output
        local pdf_path
        pdf_path=$(echo "$pdf_output" | grep -o "$output_dir/scan-attestation-[^[:space:]]*\.pdf" | head -1)
        if [ -n "$pdf_path" ] && [ -f "$pdf_path" ]; then
            PDF_ATTESTATION_PATH="$pdf_path"
        fi
    else
        local exit_code=$?
        if [ $exit_code -eq 2 ]; then
            print_warning "PDF attestation skipped (optional dependency missing)"
        else
            print_warning "PDF attestation failed"
        fi
    fi
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                         Scan Summary                            ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Show target info based on scan mode
    if [ "$SCAN_MODE" = "remote" ]; then
        echo "  Target:  $REMOTE_HOST (remote)"
        [ -n "$REMOTE_USER" ] && echo "  User:    $REMOTE_USER"
        [ -n "$REMOTE_OS" ] && echo "  OS:      $REMOTE_OS"
    else
        echo "  Target:  $TARGET_DIR"
    fi
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $SCANS_PASSED"
    echo -e "  ${YELLOW}Issues:${NC}  $SCANS_FAILED"
    echo -e "  ${BLUE}Skipped:${NC} $SCANS_SKIPPED"
    echo ""

    if [ "$SCANS_FAILED" -gt 0 ]; then
        echo -e "${YELLOW}Some scans found potential issues.${NC}"
        echo ""
        if [ "$SCAN_MODE" != "remote" ]; then
            echo "To see detailed results, run:"
            echo "  $SCRIPTS_DIR/run-all-scans.sh \"$TARGET_DIR\""
            echo ""
        fi
    else
        echo -e "${GREEN}All scans passed!${NC}"
    fi

    echo ""
    echo "Results saved to:"
    echo "  $SCAN_OUTPUT_DIR"
    if [ -n "$PDF_ATTESTATION_PATH" ] && [ -f "$PDF_ATTESTATION_PATH" ]; then
        echo ""
        echo -e "${GREEN}PDF Attestation:${NC}"
        echo "  $PDF_ATTESTATION_PATH"
    fi

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "For more options, see: ./scripts/run-all-scans.sh --help"
    echo "Documentation: README.md"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    print_banner
    check_dependencies

    # New menu flow: Environment -> Auth -> Config -> Scans
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

    if [ "$SCAN_MODE" = "local" ]; then
        select_local_config
        # Set privilege level based on auth mode
        if [ "$AUTH_MODE" = "credentialed" ]; then
            PRIVILEGE_LEVEL="admin"
            LYNIS_PRIVILEGED=true
        else
            PRIVILEGE_LEVEL="standard"
            LYNIS_PRIVILEGED=false
        fi
    else
        select_remote_config
        if [ "$AUTH_MODE" = "uncredentialed" ]; then
            print_warning "Remote uncredentialed scan: Only network-based checks available"
            echo ""
        fi
    fi

    select_scans

    # Initialize unique scan session directory
    local base_dir
    local target_name
    if [ "$SCAN_MODE" = "remote" ]; then
        base_dir="$(pwd)"
        target_name="$PROJECT_NAME"  # Use project name, not IP
    else
        base_dir="$TARGET_DIR"
        target_name=$(basename "$TARGET_DIR")
    fi
    init_scan_session "$base_dir" "$target_name"

    run_scans
    generate_pdf_attestation "$SCAN_OUTPUT_DIR"
    print_summary

    # Open scan folder in file browser (interactive mode only, when TTY available)
    if [ -t 1 ] && [ -d "$SCAN_OUTPUT_DIR" ]; then
        echo ""
        echo -e "${BOLD}Opening scan folder...${NC}"
        case "$(uname -s)" in
            Darwin)
                open "$SCAN_OUTPUT_DIR" 2>/dev/null || true
                ;;
            Linux)
                if command -v xdg-open &>/dev/null; then
                    xdg-open "$SCAN_OUTPUT_DIR" 2>/dev/null || true
                fi
                ;;
            MINGW*|MSYS*|CYGWIN*)
                explorer "$(cygpath -w "$SCAN_OUTPUT_DIR" 2>/dev/null || echo "$SCAN_OUTPUT_DIR")" 2>/dev/null || true
                ;;
        esac
    fi

    # Exit with appropriate code
    if [ "$SCANS_FAILED" -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main
main "$@"
