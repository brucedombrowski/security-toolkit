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

select_target() {
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

# ============================================================================
# Scan Selection
# ============================================================================

select_scans() {
    echo -e "${BOLD}Which scans would you like to run?${NC}"
    echo ""
    echo "  1) Quick scan     - PII + Secrets only (fastest)"
    echo "  2) Standard scan  - PII + Secrets + MAC addresses"
    echo "  3) Full scan      - All scans including malware (requires ClamAV)"
    echo "  4) Custom         - Select individual scans"
    echo ""
    echo -n "Select option [1-4]: "

    read -r choice

    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false

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
            print_step "Malware Scan (this may take a while)..."
            echo ""
            # Run malware scan with visible output so user sees progress
            # Capture exit code before if-test (can't use $? inside else block)
            local malware_exit=0
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
            echo ""
        else
            print_warning "Skipping malware scan (ClamAV not installed)"
            ((skipped++))
        fi
    fi

    # KEV Check
    if [ "$RUN_KEV" = true ]; then
        print_step "CISA KEV Check..."
        if "$SCRIPTS_DIR/check-kev.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "KEV check passed"
            ((passed++))
        else
            print_warning "KEV check found potential issues"
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
