#!/bin/bash
#
# Interactive TUI for Security Verification Toolkit
#
# Purpose: Menu-driven interface for running security scans
# NIST Controls: CA-2, CA-7 (Security Assessment)
#
# Usage: ./tui.sh [target_directory]
#
# Features:
#   - Select individual scans or run all
#   - View scan results
#   - Generate verification reports
#   - Configure scan options
#
# Compatibility: Bash 3.2+ (macOS default)
#

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source libraries
if [ -f "$SCRIPT_DIR/lib/progress.sh" ]; then
    source "$SCRIPT_DIR/lib/progress.sh"
fi

if [ -f "$SCRIPT_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPT_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SECURITY_REPO_DIR"
fi

# Terminal colors (if supported)
setup_colors() {
    if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
        BOLD=$(tput bold)
        DIM=$(tput dim)
        RESET=$(tput sgr0)
        RED=$(tput setaf 1)
        GREEN=$(tput setaf 2)
        YELLOW=$(tput setaf 3)
        BLUE=$(tput setaf 4)
        CYAN=$(tput setaf 6)
    else
        BOLD="" DIM="" RESET="" RED="" GREEN="" YELLOW="" BLUE="" CYAN=""
    fi
}

# Check for dialog/whiptail
detect_tui_backend() {
    if command -v dialog >/dev/null 2>&1; then
        TUI_BACKEND="dialog"
    elif command -v whiptail >/dev/null 2>&1; then
        TUI_BACKEND="whiptail"
    else
        TUI_BACKEND="bash"
    fi
}

# Clear screen and show header
show_header() {
    clear
    local version="${TOOLKIT_VERSION:-unknown}"
    echo "${BOLD}${BLUE}+================================================================+${RESET}"
    echo "${BOLD}${BLUE}|${RESET}       ${BOLD}Security Verification Toolkit${RESET} ${DIM}${version}${RESET}         ${BOLD}${BLUE}|${RESET}"
    echo "${BOLD}${BLUE}|${RESET}                 ${DIM}NIST 800-53 / 800-171 Compliance${RESET}               ${BOLD}${BLUE}|${RESET}"
    echo "${BOLD}${BLUE}+================================================================+${RESET}"
    echo ""
}

# Show target info
show_target_info() {
    echo "${CYAN}Target:${RESET} ${TARGET_DIR}"
    if [ -d "${TARGET_DIR}/.scans" ]; then
        local scan_count
        scan_count=$(find "${TARGET_DIR}/.scans" -name "*.txt" -o -name "*.log" 2>/dev/null | wc -l | tr -d ' ')
        echo "${CYAN}Scans Directory:${RESET} ${TARGET_DIR}/.scans (${scan_count} results)"
    else
        echo "${CYAN}Scans Directory:${RESET} ${DIM}Not yet created${RESET}"
    fi
    echo ""
}

# Define available scans using indexed arrays (Bash 3.2 compatible)
# Format: "script|name|control|description"
SCAN_DATA_0="check-pii.sh|PII Detection|SI-12|SSNs, phone numbers, IPs, credit cards"
SCAN_DATA_1="check-secrets.sh|Secrets Detection|SA-11|API keys, passwords, tokens"
SCAN_DATA_2="check-malware.sh|Malware Scanning|SI-3|ClamAV virus and trojan detection"
SCAN_DATA_3="check-mac-addresses.sh|MAC Address Scan|SC-8|IEEE 802.3 hardware identifiers"
SCAN_DATA_4="check-host-security.sh|Host Security|CM-6|OS security configuration"
SCAN_DATA_5="check-kev.sh|KEV Vulnerability Check|RA-5|CISA Known Exploited Vulnerabilities"
SCAN_DATA_6="scan-vulnerabilities.sh|Vulnerability Scan|RA-5|Nmap/Lynis assessment"

SCAN_COUNT=7

# Get scan data by index
get_scan_data() {
    local idx="$1"
    case "$idx" in
        0) echo "$SCAN_DATA_0" ;;
        1) echo "$SCAN_DATA_1" ;;
        2) echo "$SCAN_DATA_2" ;;
        3) echo "$SCAN_DATA_3" ;;
        4) echo "$SCAN_DATA_4" ;;
        5) echo "$SCAN_DATA_5" ;;
        6) echo "$SCAN_DATA_6" ;;
        *) echo "" ;;
    esac
}

# Parse scan data fields
get_scan_script() { echo "$1" | cut -d'|' -f1; }
get_scan_name() { echo "$1" | cut -d'|' -f2; }
get_scan_control() { echo "$1" | cut -d'|' -f3; }
get_scan_desc() { echo "$1" | cut -d'|' -f4; }

# Bash-based menu (fallback)
show_bash_menu() {
    local selection=""

    while true; do
        show_header
        show_target_info

        echo "${BOLD}Main Menu${RESET}"
        echo "${DIM}---------------------------------${RESET}"
        echo ""
        echo "  ${BOLD}1)${RESET} Run All Scans"
        echo "  ${BOLD}2)${RESET} Select Individual Scans"
        echo "  ${BOLD}3)${RESET} View Scan Results"
        echo "  ${BOLD}4)${RESET} Generate Verification Report"
        echo "  ${BOLD}5)${RESET} Change Target Directory"
        echo "  ${BOLD}6)${RESET} About / Help"
        echo ""
        echo "  ${BOLD}q)${RESET} Quit"
        echo ""
        printf "${BOLD}Select option: ${RESET}"
        read -r selection

        case "$selection" in
            1) run_all_scans ;;
            2) select_individual_scans ;;
            3) view_scan_results ;;
            4) generate_verification_report ;;
            5) change_target_directory ;;
            6) show_about ;;
            q|Q) echo ""; exit 0 ;;
            *) echo "${RED}Invalid option${RESET}"; sleep 1 ;;
        esac
    done
}

# Run all scans
run_all_scans() {
    show_header
    echo "${BOLD}Running All Scans${RESET}"
    echo "${DIM}---------------------------------${RESET}"
    echo ""
    echo "Target: ${TARGET_DIR}"
    echo ""

    local passed=0
    local failed=0
    local skipped=0
    local idx=0

    while [ $idx -lt $SCAN_COUNT ]; do
        local data
        data=$(get_scan_data $idx)
        local script name
        script=$(get_scan_script "$data")
        name=$(get_scan_name "$data")

        printf "  ${CYAN}%-25s${RESET} " "$name..."

        if [ ! -f "$SCRIPT_DIR/$script" ]; then
            echo "${YELLOW}SKIPPED${RESET} (not found)"
            skipped=$((skipped + 1))
            idx=$((idx + 1))
            continue
        fi

        if "$SCRIPT_DIR/$script" "$TARGET_DIR" >/dev/null 2>&1; then
            echo "${GREEN}PASS${RESET}"
            passed=$((passed + 1))
        else
            echo "${RED}FAIL${RESET}"
            failed=$((failed + 1))
        fi
        idx=$((idx + 1))
    done

    echo ""
    echo "${DIM}---------------------------------${RESET}"
    echo "Results: ${GREEN}$passed passed${RESET}, ${RED}$failed failed${RESET}, ${YELLOW}$skipped skipped${RESET}"
    echo ""

    if [ $failed -eq 0 ]; then
        echo "${GREEN}${BOLD}All scans passed!${RESET}"
    else
        echo "${YELLOW}Some scans require attention.${RESET}"
    fi

    echo ""
    printf "Press Enter to continue..."
    read -r
}

# Select and run individual scans
select_individual_scans() {
    # Track selected scans with a string of indices
    local selected=""
    local done_selecting=0

    while [ $done_selecting -eq 0 ]; do
        show_header
        echo "${BOLD}Select Scans to Run${RESET}"
        echo "${DIM}---------------------------------${RESET}"
        echo ""

        local idx=0
        while [ $idx -lt $SCAN_COUNT ]; do
            local data
            data=$(get_scan_data $idx)
            local name control desc
            name=$(get_scan_name "$data")
            control=$(get_scan_control "$data")
            desc=$(get_scan_desc "$data")

            local mark=" "
            if echo "$selected" | grep -q ":${idx}:"; then
                mark="${GREEN}*${RESET}"
            fi

            local num=$((idx + 1))
            printf "  ${BOLD}%d)${RESET} [%s] %-25s ${DIM}(%s)${RESET}\n" "$num" "$mark" "$name" "$control"
            printf "     ${DIM}%s${RESET}\n" "$desc"
            idx=$((idx + 1))
        done

        echo ""
        echo "  ${BOLD}a)${RESET} Select all"
        echo "  ${BOLD}c)${RESET} Clear selection"
        echo "  ${BOLD}r)${RESET} Run selected scans"
        echo "  ${BOLD}b)${RESET} Back to main menu"
        echo ""
        printf "${BOLD}Toggle scan (1-${SCAN_COUNT}) or action: ${RESET}"
        read -r choice

        case "$choice" in
            [1-7])
                local toggle_idx=$((choice - 1))
                if [ $toggle_idx -lt $SCAN_COUNT ]; then
                    if echo "$selected" | grep -q ":${toggle_idx}:"; then
                        # Remove from selection
                        selected=$(echo "$selected" | sed "s/:${toggle_idx}://g")
                    else
                        # Add to selection
                        selected="${selected}:${toggle_idx}:"
                    fi
                fi
                ;;
            a|A)
                selected=""
                idx=0
                while [ $idx -lt $SCAN_COUNT ]; do
                    selected="${selected}:${idx}:"
                    idx=$((idx + 1))
                done
                ;;
            c|C)
                selected=""
                ;;
            r|R)
                if [ -z "$selected" ]; then
                    echo "${YELLOW}No scans selected${RESET}"
                    sleep 1
                else
                    run_selected_scans "$selected"
                fi
                ;;
            b|B)
                done_selecting=1
                ;;
        esac
    done
}

# Run selected scans
run_selected_scans() {
    local selected="$1"

    show_header
    echo "${BOLD}Running Selected Scans${RESET}"
    echo "${DIM}---------------------------------${RESET}"
    echo ""

    local passed=0
    local failed=0
    local idx=0

    while [ $idx -lt $SCAN_COUNT ]; do
        if echo "$selected" | grep -q ":${idx}:"; then
            local data
            data=$(get_scan_data $idx)
            local script name
            script=$(get_scan_script "$data")
            name=$(get_scan_name "$data")

            printf "  ${CYAN}%-25s${RESET} " "$name..."

            if "$SCRIPT_DIR/$script" "$TARGET_DIR" >/dev/null 2>&1; then
                echo "${GREEN}PASS${RESET}"
                passed=$((passed + 1))
            else
                echo "${RED}FAIL${RESET}"
                failed=$((failed + 1))
            fi
        fi
        idx=$((idx + 1))
    done

    echo ""
    echo "Results: ${GREEN}$passed passed${RESET}, ${RED}$failed failed${RESET}"
    echo ""
    printf "Press Enter to continue..."
    read -r
}

# View scan results
view_scan_results() {
    show_header
    echo "${BOLD}Scan Results${RESET}"
    echo "${DIM}---------------------------------${RESET}"
    echo ""

    local scans_dir="${TARGET_DIR}/.scans"

    if [ ! -d "$scans_dir" ]; then
        echo "${YELLOW}No scan results found.${RESET}"
        echo "Run scans first to generate results."
        echo ""
        printf "Press Enter to continue..."
        read -r
        return
    fi

    echo "Available results in ${scans_dir}:"
    echo ""

    # Build file list
    local file_list=""
    local file_count=0
    while IFS= read -r file; do
        file_count=$((file_count + 1))
        file_list="${file_list}${file}|"
        local bname
        bname=$(basename "$file")
        local fsize
        fsize=$(du -h "$file" 2>/dev/null | cut -f1)
        printf "  ${BOLD}%2d)${RESET} %-40s ${DIM}(%s)${RESET}\n" "$file_count" "$bname" "$fsize"
    done < <(find "$scans_dir" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.pdf" \) 2>/dev/null | sort -r | head -20)

    if [ $file_count -eq 0 ]; then
        echo "  ${DIM}No result files found${RESET}"
        echo ""
        printf "Press Enter to continue..."
        read -r
        return
    fi

    echo ""
    echo "  ${BOLD}b)${RESET} Back to main menu"
    echo ""
    printf "${BOLD}Select file to view (1-${file_count}): ${RESET}"
    read -r choice

    case "$choice" in
        b|B) return ;;
        [0-9]*)
            if [ "$choice" -ge 1 ] 2>/dev/null && [ "$choice" -le "$file_count" ] 2>/dev/null; then
                # Extract nth file from pipe-separated list
                local file
                file=$(echo "$file_list" | cut -d'|' -f"$choice")
                if [ -n "$file" ]; then
                    case "$file" in
                        *.pdf)
                            if command -v open >/dev/null 2>&1; then
                                open "$file"
                            elif command -v xdg-open >/dev/null 2>&1; then
                                xdg-open "$file"
                            else
                                echo "${YELLOW}Cannot open PDF. Path: $file${RESET}"
                                sleep 2
                            fi
                            ;;
                        *)
                            less -R "$file"
                            ;;
                    esac
                fi
            fi
            ;;
    esac
}

# Generate verification report
generate_verification_report() {
    show_header
    echo "${BOLD}Generate Verification Report${RESET}"
    echo "${DIM}---------------------------------${RESET}"
    echo ""

    if [ ! -f "$SCRIPT_DIR/generate-verification-report.sh" ]; then
        echo "${YELLOW}Verification report generator not found.${RESET}"
        printf "Press Enter to continue..."
        read -r
        return
    fi

    echo "This will generate a PDF verification package including:"
    echo "  - Executive summary"
    echo "  - Requirements traceability matrix"
    echo "  - Scan results and attestations"
    echo "  - NIST control mapping"
    echo ""
    printf "Generate report? (y/n): "
    read -r confirm

    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        echo ""
        echo "Generating report..."
        if "$SCRIPT_DIR/generate-verification-report.sh" "$TARGET_DIR"; then
            echo ""
            echo "${GREEN}Report generated successfully!${RESET}"
        else
            echo ""
            echo "${RED}Report generation failed.${RESET}"
        fi
    fi

    echo ""
    printf "Press Enter to continue..."
    read -r
}

# Change target directory
change_target_directory() {
    show_header
    echo "${BOLD}Change Target Directory${RESET}"
    echo "${DIM}---------------------------------${RESET}"
    echo ""
    echo "Current target: ${TARGET_DIR}"
    echo ""
    printf "Enter new target directory (or 'b' to go back): "
    read -r new_dir

    if [ "$new_dir" = "b" ] || [ "$new_dir" = "B" ]; then
        return
    fi

    # Expand ~ and resolve path
    new_dir="${new_dir/#\~/$HOME}"

    if [ -d "$new_dir" ]; then
        TARGET_DIR="$(cd "$new_dir" && pwd)"
        echo ""
        echo "${GREEN}Target changed to: ${TARGET_DIR}${RESET}"
        sleep 1
    else
        echo ""
        echo "${RED}Directory does not exist: ${new_dir}${RESET}"
        sleep 2
    fi
}

# Show about/help
show_about() {
    show_header
    echo "${BOLD}About Security Verification Toolkit${RESET}"
    echo "${DIM}---------------------------------${RESET}"
    echo ""
    echo "Version: ${TOOLKIT_VERSION:-unknown}"
    echo "Commit:  ${TOOLKIT_COMMIT:-unknown}"
    echo ""
    echo "${BOLD}Purpose:${RESET}"
    echo "  Scan software projects for security compliance with federal standards"
    echo "  including NIST SP 800-53, NIST SP 800-171, and FIPS requirements."
    echo ""
    echo "${BOLD}Available Scans:${RESET}"

    local idx=0
    while [ $idx -lt $SCAN_COUNT ]; do
        local data
        data=$(get_scan_data $idx)
        local name control desc
        name=$(get_scan_name "$data")
        control=$(get_scan_control "$data")
        desc=$(get_scan_desc "$data")
        printf "  ${CYAN}%-22s${RESET} ${DIM}(%s)${RESET}\n" "$name" "$control"
        printf "    %s\n" "$desc"
        idx=$((idx + 1))
    done

    echo ""
    echo "${BOLD}Documentation:${RESET}"
    echo "  README.md              Usage guide"
    echo "  docs/COMPLIANCE.md     NIST control mapping"
    echo "  docs/LIBRARY-API.md    Library API reference"
    echo ""
    printf "Press Enter to continue..."
    read -r
}

# Dialog-based menu (if available)
show_dialog_menu() {
    local height=20
    local width=70
    local list_height=10

    while true; do
        local choice
        choice=$($TUI_BACKEND --title "Security Verification Toolkit" \
            --menu "Select an option:" $height $width $list_height \
            "1" "Run All Scans" \
            "2" "Select Individual Scans" \
            "3" "View Scan Results" \
            "4" "Generate Verification Report" \
            "5" "Change Target Directory" \
            "6" "About / Help" \
            "Q" "Quit" \
            3>&1 1>&2 2>&3) || true

        if [ -z "$choice" ]; then
            exit 0
        fi

        case "$choice" in
            1) run_all_scans ;;
            2) select_individual_scans ;;
            3) view_scan_results ;;
            4) generate_verification_report ;;
            5) change_target_directory ;;
            6) show_about ;;
            Q) exit 0 ;;
        esac
    done
}

# Main
main() {
    setup_colors
    detect_tui_backend

    # Check for --help first
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        cat << 'EOF'
Usage: tui.sh [OPTIONS] [TARGET_DIRECTORY]

Interactive TUI for the Security Verification Toolkit.

OPTIONS:
  -h, --help     Show this help message
  --bash         Force bash menu (skip dialog/whiptail)

ARGUMENTS:
  TARGET_DIRECTORY   Directory to scan (default: parent of script)

DESCRIPTION:
  Provides a menu-driven interface for:
  - Running individual or all security scans
  - Viewing scan results
  - Generating verification reports
  - Managing scan targets

  Uses dialog/whiptail if available, otherwise falls back
  to a bash-based text menu.

COMPATIBILITY:
  Bash 3.2+ (works with macOS default bash)
EOF
        exit 0
    fi

    # Force bash mode
    if [ "${1:-}" = "--bash" ]; then
        TUI_BACKEND="bash"
        shift || true
    fi

    # Set target directory
    if [ -n "${1:-}" ]; then
        if [ -d "$1" ]; then
            TARGET_DIR="$(cd "$1" && pwd)"
        else
            echo "Error: Directory not found: $1"
            exit 1
        fi
    else
        TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    fi

    # Launch appropriate menu
    if [ "$TUI_BACKEND" = "bash" ]; then
        show_bash_menu
    else
        show_dialog_menu
    fi
}

main "$@"
