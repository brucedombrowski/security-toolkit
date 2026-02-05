#!/bin/bash
#
# QuickStart Session Library
#
# Purpose: Session management, transcript logging, scan initialization
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Session Variables (set by init functions)
# ============================================================================

TRANSCRIPT_FILE=""
TRANSCRIPT_TIMESTAMP=""
TRANSCRIPT_DIR=""
SCAN_SESSION_ID=""
SCAN_OUTPUT_DIR=""

# ============================================================================
# Transcript Logging
# ============================================================================

# Initialize transcript logging
# Usage: init_transcript
init_transcript() {
    TRANSCRIPT_TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    TRANSCRIPT_DIR="$(pwd)/.scans"
    mkdir -p "$TRANSCRIPT_DIR"
    TRANSCRIPT_FILE="$TRANSCRIPT_DIR/session-transcript-${TRANSCRIPT_TIMESTAMP}.txt"

    # Start transcript
    {
        echo "Security Toolkit Session Transcript"
        echo "===================================="
        echo "Started: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: $(hostname)"
        echo "User: $(whoami)"
        echo "Working Directory: $(pwd)"
        echo ""
    } > "$TRANSCRIPT_FILE"
}

# Function to log to transcript (called explicitly for key events)
log_transcript() {
    if [ -n "$TRANSCRIPT_FILE" ]; then
        echo "$@" >> "$TRANSCRIPT_FILE"
    fi
}

# Finalize transcript and move to output directory
finalize_transcript() {
    local output_dir="$1"

    {
        echo ""
        echo "===================================="
        echo "Session Completed: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
        echo "Output Directory: $output_dir"
        echo "===================================="
    } >> "$TRANSCRIPT_FILE"

    # Move transcript to scan output directory
    if [ -d "$output_dir" ]; then
        mv "$TRANSCRIPT_FILE" "$output_dir/session-transcript.txt"
        TRANSCRIPT_FILE="$output_dir/session-transcript.txt"
        echo ""
        echo -e "${GREEN}✓${NC} Session transcript saved: session-transcript.txt"
    fi
}

# ============================================================================
# Scan Session Management
# ============================================================================

# Create unique output directory for this scan session
# Usage: init_scan_session "base_dir" "target_name"
# Sets: SCAN_SESSION_ID, SCAN_OUTPUT_DIR
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
# Summary Display
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

    # Log summary to transcript
    log_transcript ""
    log_transcript "SCAN SUMMARY"
    log_transcript "------------"
    log_transcript "Passed: $SCANS_PASSED"
    log_transcript "Issues: $SCANS_FAILED"
    log_transcript "Skipped: $SCANS_SKIPPED"
    log_transcript "Output: $SCAN_OUTPUT_DIR"
}

# ============================================================================
# Open Scan Folder
# ============================================================================

# Open the scan output folder in the system file browser
open_scan_folder() {
    local output_dir="$1"

    # Only open in interactive mode with TTY
    if [ -t 1 ] && [ -d "$output_dir" ]; then
        echo ""
        echo -e "${BOLD}Opening scan folder...${NC}"
        case "$(uname -s)" in
            Darwin)
                open "$output_dir" 2>/dev/null || true
                ;;
            Linux)
                if command -v xdg-open &>/dev/null; then
                    xdg-open "$output_dir" 2>/dev/null || true
                fi
                ;;
            MINGW*|MSYS*|CYGWIN*)
                explorer "$(cygpath -w "$output_dir" 2>/dev/null || echo "$output_dir")" 2>/dev/null || true
                ;;
        esac
    fi
}
