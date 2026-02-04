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
for arg in "$@"; do
    case "$arg" in
        --no-tui|--cli)
            FORCE_CLI=true
            ;;
        -h|--help)
            echo "Usage: ./QuickStart.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-tui, --cli    Force CLI mode (disable TUI even if available)"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Interactive demo for the Security Toolkit."
            echo "If dialog or whiptail is installed, a TUI interface is used."
            exit 0
            ;;
    esac
done

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

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
    echo -e "${CYAN}║${NC}${BOLD}            Security Toolkit - QuickStart Demo                 ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Scan your projects for:                                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • PII (Social Security Numbers, Phone Numbers, etc.)        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • Secrets (API Keys, Passwords, Tokens)                     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • Malware (via ClamAV)                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    • Known Exploited Vulnerabilities (CISA KEV)                ${CYAN}║${NC}"
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

# ============================================================================
# Dependency Check
# ============================================================================

check_dependencies() {
    print_step "Checking dependencies..."
    echo ""

    local all_good=true

    # Required
    check_dependency "bash" "Bash" "Required" || all_good=false
    check_dependency "grep" "grep" "Required" || all_good=false
    check_dependency "git" "Git" "Required for version info" || all_good=false

    # Optional but recommended
    check_dependency "clamscan" "ClamAV" "Install for malware scanning (brew install clamav)" || true
    check_dependency "nmap" "Nmap" "Install for vulnerability scanning (brew install nmap)" || true

    # TUI status
    if [ -n "$TUI_CMD" ]; then
        if [ "$FORCE_CLI" = true ]; then
            print_success "$TUI_CMD found (TUI disabled via --no-tui)"
        else
            print_success "$TUI_CMD found (TUI enabled)"
        fi
    else
        print_warning "dialog/whiptail not found - using CLI mode (brew install dialog)"
    fi

    echo ""

    if [ "$all_good" = false ]; then
        print_error "Missing required dependencies. Please install them and try again."
        exit 1
    fi

    print_success "Dependency check complete"
    echo ""
}

# ============================================================================
# Target Selection
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
            ;;
        4)
            RUN_MALWARE=true
            MALWARE_FULL_SYSTEM=true
            tui_msgbox "System Malware Scan" "This scan will check:\n\n- Home directory (~)\n- Applications (/Applications)\n- Temp files (/tmp)\n\nThis may take several minutes."
            ;;
        5)
            # Custom scan selection via checklist
            local selections
            selections=$(tui_checklist "Custom Scan Selection" "Select scans to run (space to toggle):" 18 70 6 \
                "pii" "PII detection (SSN, phone, etc.)" "on" \
                "secrets" "Secrets detection (API keys, passwords)" "on" \
                "mac" "MAC address scan" "off" \
                "malware" "Malware scan (requires ClamAV)" "off" \
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
            [[ "$selections" =~ kev ]] && RUN_KEV=true

            # If malware selected, ask about full system
            if [ "$RUN_MALWARE" = true ]; then
                if tui_yesno "Full System Scan" "Scan full system (not just target directory)?"; then
                    MALWARE_FULL_SYSTEM=true
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
    echo "  3) Full scan      - All scans including malware (requires ClamAV)"
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

    echo ""

    # Store results for summary
    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                         Scan Summary                            ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Target:  $TARGET_DIR"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $SCANS_PASSED"
    echo -e "  ${YELLOW}Issues:${NC}  $SCANS_FAILED"
    echo -e "  ${BLUE}Skipped:${NC} $SCANS_SKIPPED"
    echo ""

    if [ "$SCANS_FAILED" -gt 0 ]; then
        echo -e "${YELLOW}Some scans found potential issues.${NC}"
        echo ""
        echo "To see detailed results, run:"
        echo "  $SCRIPTS_DIR/run-all-scans.sh \"$TARGET_DIR\""
        echo ""
        echo "Results are saved to:"
        echo "  $TARGET_DIR/.scans/"
    else
        echo -e "${GREEN}All scans passed!${NC}"
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
    select_target
    select_scans
    run_scans
    print_summary

    # Exit with appropriate code
    if [ "$SCANS_FAILED" -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main
main "$@"
