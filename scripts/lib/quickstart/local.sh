#!/bin/bash
#
# QuickStart Local Scanning Library
#
# Purpose: Local scan selection and execution
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Local Configuration Selection
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
    read -r choice </dev/tty

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
            read -r TARGET_DIR </dev/tty
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
    while true; do
        echo -e "${BOLD}What would you like to scan?${NC}"
        echo ""
        echo "  1) Local directory    - Scan a specific folder (e.g., a project)"
        echo "  2) Current directory  - Scan $(pwd)"
        echo "  3) Home directory     - Scan your entire home folder (slower)"
        echo "  4) Custom path        - Enter a specific path"
        echo ""
        echo -n "Select option [1-4]: "

        read -r choice </dev/tty

        case "$choice" in
            1)
                echo ""
                echo -n "Enter directory path: "
                read -r TARGET_DIR </dev/tty
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
                read -r TARGET_DIR </dev/tty
                ;;
            *)
                print_error "Invalid selection, please enter 1-4"
                echo ""
                continue
                ;;
        esac

        # Expand ~ if used
        TARGET_DIR="${TARGET_DIR/#\~/$HOME}"

        # Validate path
        if [ ! -d "$TARGET_DIR" ]; then
            print_error "Directory not found: $TARGET_DIR"
            echo ""
            continue
        fi

        break
    done

    echo ""
    print_success "Target: $TARGET_DIR"
    log_transcript "TARGET: $TARGET_DIR"
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
# Local Scan Selection
# ============================================================================

select_scans_tui() {
    # Initialize all scan flags
    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false
    RUN_LYNIS=false
    LYNIS_PRIVILEGED=false
    MALWARE_FULL_SYSTEM=false

    # Direct checklist for scan selection
    local selections
    selections=$(tui_checklist "Scan Selection" "Select scans to run (space to toggle):" 22 70 6 \
        "pii" "PII detection (SSN, phone, email, etc.)" "on" \
        "secrets" "Secrets detection (API keys, passwords)" "on" \
        "mac" "MAC address detection" "off" \
        "malware" "Malware scan (ClamAV)" "off" \
        "lynis" "System hardening audit (Lynis)" "off" \
        "kev" "CISA KEV cross-reference" "off")

    if [ -z "$selections" ]; then
        print_error "No scans selected"
        exit 1
    fi

    # Parse selections
    [[ "$selections" =~ pii ]] && RUN_PII=true
    [[ "$selections" =~ secrets ]] && RUN_SECRETS=true
    [[ "$selections" =~ mac ]] && RUN_MAC=true
    [[ "$selections" =~ malware ]] && RUN_MALWARE=true
    [[ "$selections" =~ lynis ]] && RUN_LYNIS=true
    [[ "$selections" =~ kev ]] && RUN_KEV=true

    # If malware selected, ask about full system scan
    if [ "$RUN_MALWARE" = true ]; then
        if tui_yesno "Full System Malware Scan" "Scan full system (~/Applications, /tmp)?\n\nSelect 'No' to scan target directory only."; then
            MALWARE_FULL_SYSTEM=true
        fi
    fi

    # If Lynis selected, ask about privileged mode
    if [ "$RUN_LYNIS" = true ]; then
        if tui_yesno "Privileged Scan" "Run Lynis with sudo for deeper system checks?\n\n(Recommended for comprehensive audits)"; then
            LYNIS_PRIVILEGED=true
        fi
    fi
}

select_scans_cli() {
    # Initialize all scan flags
    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false
    RUN_LYNIS=false
    LYNIS_PRIVILEGED=false
    LYNIS_QUICK=false
    MALWARE_FULL_SYSTEM=false

    echo -e "${BOLD}Select scans to run:${NC}"
    echo "  (Enter 'y' to enable, or just press Enter to skip)"
    echo ""
    echo -n "  PII detection (SSN, phone, email)? [y/N]: "
    read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && RUN_PII=true
    echo -n "  Secrets detection (API keys, passwords)? [y/N]: "
    read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && RUN_SECRETS=true
    echo -n "  MAC address detection? [y/N]: "
    read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && RUN_MAC=true
    echo -n "  Malware scan (ClamAV)? [y/N]: "
    read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && RUN_MALWARE=true
    if [ "$RUN_MALWARE" = true ]; then
        echo -n "    Scan full system (~/Applications, /tmp)? [y/N]: "
        read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && MALWARE_FULL_SYSTEM=true
    fi
    echo -n "  System hardening audit (Lynis)? [y/N]: "
    read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && RUN_LYNIS=true
    if [ "$RUN_LYNIS" = true ]; then
        echo -n "    Run with sudo (deeper checks)? [y/N]: "
        read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && LYNIS_PRIVILEGED=true
        echo -n "    Quick scan or full scan? [q/F]: "
        read -r ans </dev/tty; [[ "$ans" =~ ^[Qq] ]] && LYNIS_QUICK=true || LYNIS_QUICK=false
    fi

    echo -n "  CISA KEV cross-reference? [y/N]: "
    read -r ans </dev/tty; [[ "$ans" =~ ^[Yy] ]] && RUN_KEV=true

    # Verify at least one scan selected
    if [ "$RUN_PII" = false ] && [ "$RUN_SECRETS" = false ] && [ "$RUN_MAC" = false ] && \
       [ "$RUN_MALWARE" = false ] && [ "$RUN_LYNIS" = false ] && [ "$RUN_KEV" = false ]; then
        print_error "No scans selected"
        exit 1
    fi

    # Show note about Lynis ownership prompt if running privileged
    if [ "$RUN_LYNIS" = true ] && [ "$LYNIS_PRIVILEGED" = true ]; then
        echo ""
        echo -e "${YELLOW}Note:${NC} Lynis may show a file ownership warning when running with sudo."
        echo "      This is normal for Homebrew/package manager installs where Lynis"
        echo "      files are owned by your user, not root. Press ENTER to continue."
    fi

    # Log selections to transcript
    log_transcript ""
    log_transcript "SCAN SELECTIONS"
    log_transcript "---------------"
    log_transcript "PII Detection: $RUN_PII"
    log_transcript "Secrets Detection: $RUN_SECRETS"
    log_transcript "MAC Address Detection: $RUN_MAC"
    log_transcript "Malware Scan: $RUN_MALWARE (Full System: $MALWARE_FULL_SYSTEM)"
    log_transcript "System Hardening Audit: $RUN_LYNIS (Privileged: $LYNIS_PRIVILEGED, Quick: $LYNIS_QUICK)"
    log_transcript "CISA KEV Check: $RUN_KEV"
    log_transcript ""

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
# Local Scan Execution
# ============================================================================

run_local_scans() {
    local passed=0
    local failed=0
    local skipped=0

    echo -e "${BOLD}Running scans...${NC}"
    echo ""

    # PII Scan
    if [ "$RUN_PII" = true ]; then
        spinner_start "PII Detection"
        if "$SCRIPTS_DIR/check-pii.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            spinner_stop
            print_success "PII scan passed"
            passed=$((passed + 1))
        else
            spinner_stop
            print_warning "PII scan found potential issues"
            failed=$((failed + 1))
        fi
    fi

    # Secrets Scan
    if [ "$RUN_SECRETS" = true ]; then
        spinner_start "Secrets Detection"
        if "$SCRIPTS_DIR/check-secrets.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            spinner_stop
            print_success "Secrets scan passed"
            passed=$((passed + 1))
        else
            spinner_stop
            print_warning "Secrets scan found potential issues"
            failed=$((failed + 1))
        fi
    fi

    # MAC Address Scan
    if [ "$RUN_MAC" = true ]; then
        spinner_start "MAC Address Scan"
        if "$SCRIPTS_DIR/check-mac-addresses.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            spinner_stop
            print_success "MAC address scan passed"
            passed=$((passed + 1))
        else
            spinner_stop
            print_warning "MAC address scan found potential issues"
            failed=$((failed + 1))
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
                    passed=$((passed + 1))
                elif [ "$malware_exit" -eq 2 ]; then
                    print_warning "Malware scan skipped (dependency missing)"
                    skipped=$((skipped + 1))
                else
                    print_warning "Full system malware scan found potential issues"
                    failed=$((failed + 1))
                fi
            else
                print_step "Malware Scan (this may take a while)..."
                "$SCRIPTS_DIR/check-malware.sh" "$TARGET_DIR" || malware_exit=$?
                if [ "$malware_exit" -eq 0 ]; then
                    print_success "Malware scan passed"
                    passed=$((passed + 1))
                elif [ "$malware_exit" -eq 2 ]; then
                    print_warning "Malware scan skipped (dependency missing)"
                    skipped=$((skipped + 1))
                else
                    print_warning "Malware scan found potential issues"
                    failed=$((failed + 1))
                fi
            fi
            echo ""
        else
            print_warning "Skipping malware scan (ClamAV not installed)"
            skipped=$((skipped + 1))
        fi
    fi

    # KEV Check
    if [ "$RUN_KEV" = true ]; then
        spinner_start "CISA KEV Check"
        # Note: check-kev.sh expects a scan file, not a directory.
        # Call without args to use most recent scan in .scans/
        local kev_exit=0
        "$SCRIPTS_DIR/check-kev.sh" > /dev/null 2>&1 || kev_exit=$?
        spinner_stop
        if [ "$kev_exit" -eq 0 ]; then
            print_success "KEV check passed (no known exploited vulnerabilities)"
            passed=$((passed + 1))
        elif [ "$kev_exit" -eq 2 ]; then
            # Exit code 2 = error (no scan file, missing deps, etc.)
            print_warning "KEV check skipped (no vulnerability scan file found)"
            skipped=$((skipped + 1))
        else
            # Exit code 1 = KEV matches found
            print_warning "KEV check found known exploited vulnerabilities"
            failed=$((failed + 1))
        fi
    fi

    # Lynis Security Audit
    if [ "$RUN_LYNIS" = true ]; then
        if command -v lynis &>/dev/null; then
            local lynis_exit=0
            local lynis_opts="--lynis-only"
            local lynis_desc="full"
            if [ "$LYNIS_QUICK" = true ]; then
                lynis_opts="--lynis-only --quick"
                lynis_desc="quick"
            fi
            if [ "$LYNIS_PRIVILEGED" = true ]; then
                print_step "Lynis Security Audit [$lynis_desc, privileged]..."
                echo "  Note: You may be prompted for your password"
                sudo "$SCRIPTS_DIR/scan-vulnerabilities.sh" $lynis_opts -d "$SCAN_OUTPUT_DIR" "$TARGET_DIR" || lynis_exit=$?
            else
                print_step "Lynis Security Audit [$lynis_desc]..."
                "$SCRIPTS_DIR/scan-vulnerabilities.sh" $lynis_opts -d "$SCAN_OUTPUT_DIR" "$TARGET_DIR" || lynis_exit=$?
            fi
            if [ "$lynis_exit" -eq 0 ]; then
                print_success "Lynis audit passed"
                passed=$((passed + 1))
            else
                print_warning "Lynis audit found potential issues"
                failed=$((failed + 1))
            fi
            echo ""
        else
            print_warning "Skipping Lynis audit (Lynis not installed - brew install lynis)"
            skipped=$((skipped + 1))
        fi
    fi

    echo ""

    # Store results for summary
    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}

# ============================================================================
# Main Scan Router
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
    run_local_scans
}
