#!/bin/bash
#
# QuickStart Dependencies Library
#
# Purpose: Dependency checking, package manager detection, install offers
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Dependency Check Helpers
# ============================================================================

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
# Dependency Categories
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

    # UI enhancement (gum for TUI, otherwise CLI mode)
    DEPS_UI_CMD=("gum")
    DEPS_UI_NAME=("gum")
    DEPS_UI_DESC=("Modern TUI (brew install gum)")
    DEPS_UI_PKG=("gum")
}

# ============================================================================
# Main Dependency Check
# ============================================================================

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
        print_warning "No TUI found - using CLI mode"
        echo "         For better UI: brew install gum"
        missing_ui+=("gum")
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
            if command -v gum &>/dev/null; then
                TUI_CMD="gum"
            fi
        fi
    fi

    print_success "Dependency check complete"
    echo ""
}
