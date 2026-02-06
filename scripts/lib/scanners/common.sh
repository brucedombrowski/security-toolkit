#!/bin/bash
#
# Common Scanner Library
#
# Purpose: Shared logging, output helpers, and dependency checking for vulnerability scanners
# Used by: scan-vulnerabilities.sh and scanner modules
#
# Functions:
#   log_info()            - Log informational message
#   log_success()         - Log success message
#   log_warning()         - Log warning message
#   log_error()           - Log error message
#   check_root()          - Check if running as root
#   check_scanner_deps()  - Check for scanning tool dependencies
#   init_scanner_output() - Initialize output directory
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Colors for output
SCANNER_RED='\033[0;31m'
SCANNER_GREEN='\033[0;32m'
SCANNER_YELLOW='\033[1;33m'
SCANNER_BLUE='\033[0;34m'
SCANNER_NC='\033[0m'

# Scanner state (set by check_scanner_deps)
SCANNER_RUN_NMAP=${SCANNER_RUN_NMAP:-true}
SCANNER_RUN_LYNIS=${SCANNER_RUN_LYNIS:-true}

# Output configuration
SCANNER_OUTPUT_DIR=""
SCANNER_REPORT_FILE=""

# Log informational message
# Usage: log_info "message"
log_info() {
    echo -e "${SCANNER_BLUE}[INFO]${SCANNER_NC} $1"
}

# Log success message
# Usage: log_success "message"
log_success() {
    echo -e "${SCANNER_GREEN}[PASS]${SCANNER_NC} $1"
}

# Log warning message
# Usage: log_warning "message"
log_warning() {
    echo -e "${SCANNER_YELLOW}[WARN]${SCANNER_NC} $1"
}

# Log error message
# Usage: log_error "message"
log_error() {
    echo -e "${SCANNER_RED}[FAIL]${SCANNER_NC} $1"
}

# Check if running as root
# Usage: check_root
# Returns: 0 if root, 1 if not
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_warning "Not running as root. Some scans may have limited functionality."
        log_info "For comprehensive results, run with: sudo $0 $*"
        return 1
    fi
    return 0
}

# Check for required scanning tools
# Usage: check_scanner_deps
# Sets: SCANNER_RUN_NMAP, SCANNER_RUN_LYNIS
# Returns: 0 if at least one tool available, 2 if none found
check_scanner_deps() {
    local optional_tools=()

    echo "Checking dependencies..."
    echo ""

    # Nmap check
    if ! command -v nmap &> /dev/null; then
        optional_tools+=("nmap")
        SCANNER_RUN_NMAP=false
    else
        log_success "nmap: found"
    fi

    # Lynis check
    if ! command -v lynis &> /dev/null; then
        optional_tools+=("lynis")
        SCANNER_RUN_LYNIS=false
    else
        log_success "lynis: found"
    fi

    echo ""

    # Ensure at least one tool is available
    if ! $SCANNER_RUN_NMAP && ! $SCANNER_RUN_LYNIS; then
        log_error "No vulnerability scanning tools found!"
        echo ""
        echo "Install at least one of the following:"
        echo ""
        echo "  Nmap (network scanning):"
        echo "    macOS:  brew install nmap"
        echo "    Linux:  sudo apt install nmap"
        echo ""
        echo "  Lynis (system auditing):"
        echo "    macOS:  brew install lynis"
        echo "    Linux:  sudo apt install lynis"
        echo ""
        return 2
    fi

    if [ ${#optional_tools[@]} -gt 0 ]; then
        log_warning "Optional tools not found: ${optional_tools[*]}"
        echo "         Install for more comprehensive scanning."
    fi

    return 0
}

# Initialize output directory
# Usage: init_scanner_output "base_dir" "timestamp"
# Sets: SCANNER_OUTPUT_DIR, SCANNER_REPORT_FILE
init_scanner_output() {
    local base_dir="$1"
    local timestamp="$2"
    local security_repo_dir="${3:-}"

    if [ -z "$base_dir" ]; then
        # Default to .scans in Security repo or current directory
        if [ -n "$security_repo_dir" ] && [ -d "$security_repo_dir" ]; then
            SCANNER_OUTPUT_DIR="$security_repo_dir/.scans"
        else
            SCANNER_OUTPUT_DIR="$(pwd)/.scans"
        fi
    else
        # Use provided directory directly (don't append .scans)
        SCANNER_OUTPUT_DIR="$base_dir"
    fi

    mkdir -p "$SCANNER_OUTPUT_DIR"
    SCANNER_REPORT_FILE="$SCANNER_OUTPUT_DIR/vulnerability-scan-$timestamp.txt"

    log_info "Output directory: $SCANNER_OUTPUT_DIR"
    log_info "Report file: $SCANNER_REPORT_FILE"
}

# Print scanner section header
# Usage: print_scanner_section "SECTION TITLE"
print_scanner_section() {
    local title="$1"
    echo ""
    echo "================================================================================"
    echo "$title"
    echo "================================================================================"
    echo ""
}
