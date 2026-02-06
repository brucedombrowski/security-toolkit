#!/bin/bash
#
# QuickStart Content/Repository Scanning Module
#
# Purpose: Content analysis of directories and repositories
# Used by: QuickStart.sh
#
# Scan types:
#   - PII detection (SSN, phone, email, etc.)
#   - Secrets detection (API keys, passwords, tokens)
#   - Malware scanning (ClamAV)
#   - MAC address detection
#   - CISA KEV cross-reference
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Content Scan Variables
# ============================================================================

RUN_PII="${RUN_PII:-false}"
RUN_SECRETS="${RUN_SECRETS:-false}"
RUN_MAC="${RUN_MAC:-false}"
RUN_MALWARE="${RUN_MALWARE:-false}"
RUN_KEV="${RUN_KEV:-false}"
MALWARE_FULL_SYSTEM="${MALWARE_FULL_SYSTEM:-false}"

# ============================================================================
# Content Scan Selection
# ============================================================================

select_content_scans_tui() {
    # Initialize all scan flags
    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false
    MALWARE_FULL_SYSTEM=false

    # Direct checklist for scan selection
    local selections
    selections=$(tui_checklist "Content Scans" "Select scans to run (space to toggle):" 18 70 6 \
        "pii" "PII detection (SSN, phone, email, etc.)" "on" \
        "secrets" "Secrets detection (API keys, passwords)" "on" \
        "malware" "Malware scan (ClamAV)" "on" \
        "mac" "MAC address detection" "off" \
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
    [[ "$selections" =~ kev ]] && RUN_KEV=true

    # If malware selected, ask about full system scan
    if [ "$RUN_MALWARE" = true ]; then
        if tui_yesno "Full System Malware Scan" "Scan full system (~/Applications, /tmp)?\n\nSelect 'No' to scan target directory only."; then
            MALWARE_FULL_SYSTEM=true
        fi
    fi
}

select_content_scans_cli() {
    # Initialize all scan flags
    RUN_PII=false
    RUN_SECRETS=false
    RUN_MAC=false
    RUN_MALWARE=false
    RUN_KEV=false
    MALWARE_FULL_SYSTEM=false

    echo -e "${BOLD}Select Content Scans${NC}"
    echo ""
    echo "  (Enter 'y' to enable, or just press Enter to skip)"
    echo ""

    echo -n "  PII detection (SSN, phone, email)? [Y/n]: "
    read -r ans </dev/tty
    [[ ! "$ans" =~ ^[Nn] ]] && RUN_PII=true

    echo -n "  Secrets detection (API keys, passwords)? [Y/n]: "
    read -r ans </dev/tty
    [[ ! "$ans" =~ ^[Nn] ]] && RUN_SECRETS=true

    echo -n "  Malware scan (ClamAV)? [Y/n]: "
    read -r ans </dev/tty
    if [[ ! "$ans" =~ ^[Nn] ]]; then
        RUN_MALWARE=true
        echo -n "    Scan full system (~/Applications, /tmp)? [y/N]: "
        read -r ans </dev/tty
        [[ "$ans" =~ ^[Yy] ]] && MALWARE_FULL_SYSTEM=true
    fi

    echo -n "  MAC address detection? [y/N]: "
    read -r ans </dev/tty
    [[ "$ans" =~ ^[Yy] ]] && RUN_MAC=true

    echo -n "  CISA KEV cross-reference? [y/N]: "
    read -r ans </dev/tty
    [[ "$ans" =~ ^[Yy] ]] && RUN_KEV=true

    # Verify at least one scan selected
    if [ "$RUN_PII" = false ] && [ "$RUN_SECRETS" = false ] && \
       [ "$RUN_MAC" = false ] && [ "$RUN_MALWARE" = false ] && [ "$RUN_KEV" = false ]; then
        print_error "No scans selected"
        exit 1
    fi

    # Log selections to transcript
    log_transcript "CONTENT SCANS: pii=$RUN_PII secrets=$RUN_SECRETS mac=$RUN_MAC malware=$RUN_MALWARE kev=$RUN_KEV"

    echo ""
}

select_content_scans() {
    # Skip if configured from file
    if [ "$SKIP_SCAN_SELECTION" = "true" ]; then
        echo "Scan selection from config file"
        return
    fi

    if use_tui; then
        select_content_scans_tui
        echo ""
    else
        select_content_scans_cli
    fi
}

# ============================================================================
# Content Scan Execution
# ============================================================================

run_content_scans() {
    local output_dir="$SCAN_OUTPUT_DIR"
    local passed=0
    local failed=0
    local skipped=0

    echo ""
    echo -e "${BOLD}Running Content Scans on $TARGET_DIR${NC}"
    echo "=============================================="
    echo ""

    # PII Scan
    if [ "$RUN_PII" = true ]; then
        print_step "PII Detection..."
        if "$SCRIPTS_DIR/check-pii.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "PII scan passed"
            passed=$((passed + 1))
        else
            print_warning "PII scan found potential issues"
            failed=$((failed + 1))
        fi
    fi

    # Secrets Scan
    if [ "$RUN_SECRETS" = true ]; then
        print_step "Secrets Detection..."
        if "$SCRIPTS_DIR/check-secrets.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "Secrets scan passed"
            passed=$((passed + 1))
        else
            print_warning "Secrets scan found potential issues"
            failed=$((failed + 1))
        fi
    fi

    # MAC Address Scan
    if [ "$RUN_MAC" = true ]; then
        print_step "MAC Address Scan..."
        if "$SCRIPTS_DIR/check-mac-addresses.sh" "$TARGET_DIR" > /dev/null 2>&1; then
            print_success "MAC address scan passed"
            passed=$((passed + 1))
        else
            print_warning "MAC address scan found potential issues"
            failed=$((failed + 1))
        fi
    fi

    # Malware Scan
    if [ "$RUN_MALWARE" = true ]; then
        if command -v clamscan &>/dev/null; then
            local malware_exit=0
            if [ "$MALWARE_FULL_SYSTEM" = true ]; then
                print_step "Full System Malware Scan (this may take a while)..."
                "$SCRIPTS_DIR/check-malware.sh" --full-system || malware_exit=$?
            else
                print_step "Malware Scan (this may take a while)..."
                "$SCRIPTS_DIR/check-malware.sh" "$TARGET_DIR" || malware_exit=$?
            fi

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
            echo ""
        else
            print_warning "Skipping malware scan (ClamAV not installed)"
            skipped=$((skipped + 1))
        fi
    fi

    # KEV Check
    if [ "$RUN_KEV" = true ]; then
        print_step "CISA KEV Check..."
        local kev_exit=0
        "$SCRIPTS_DIR/check-kev.sh" > /dev/null 2>&1 || kev_exit=$?
        if [ "$kev_exit" -eq 0 ]; then
            print_success "KEV check passed (no known exploited vulnerabilities)"
            passed=$((passed + 1))
        elif [ "$kev_exit" -eq 2 ]; then
            print_warning "KEV check skipped (no vulnerability scan file found)"
            skipped=$((skipped + 1))
        else
            print_warning "KEV check found known exploited vulnerabilities"
            failed=$((failed + 1))
        fi
    fi

    echo ""

    # Update global counters
    SCANS_PASSED=$((SCANS_PASSED + passed))
    SCANS_FAILED=$((SCANS_FAILED + failed))
    SCANS_SKIPPED=$((SCANS_SKIPPED + skipped))
}
