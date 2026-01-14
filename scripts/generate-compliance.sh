#!/bin/bash
#
# Security Compliance Statement Generator
#
# Purpose: Automated generation of security compliance statement PDFs
# Method: Runs all security scans, updates LaTeX template, compiles PDF
#
# Prerequisites:
#   - pdflatex (TeX Live or MiKTeX)
#   - ClamAV (for malware scanning)
#
# Usage: ./generate-compliance.sh <target_project_dir> [output_dir]
#
# Example:
#   ./generate-compliance.sh /path/to/PdfSigner
#   ./generate-compliance.sh /path/to/PdfSigner /path/to/output
#
# Exit codes:
#   0 = Success (PDF generated)
#   1 = Scan failures requiring review (PDF still generated with findings)
#   2 = Fatal error (missing dependencies, template not found, etc.)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths - use bundled template from Security repo
LATEX_TEMPLATE_DIR="${LATEX_TEMPLATE_DIR:-$SECURITY_REPO_DIR/templates}"
LATEX_TEMPLATE="$LATEX_TEMPLATE_DIR/security_compliance_statement.tex"

print_header() {
    echo -e "${BLUE}========================================"
    echo "Security Compliance Statement Generator"
    echo -e "========================================${NC}"
    echo ""
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

print_info() {
    echo -e "${BLUE}$1${NC}"
}

check_dependencies() {
    local missing=0

    print_info "Checking dependencies..."

    if ! command -v pdflatex &> /dev/null; then
        print_error "pdflatex not found. Install TeX Live or MiKTeX."
        missing=1
    fi

    if ! command -v clamscan &> /dev/null && ! [ -x "/opt/homebrew/bin/clamscan" ]; then
        print_warning "ClamAV not found. Malware scan will be skipped."
    fi

    if [ ! -f "$LATEX_TEMPLATE" ]; then
        print_error "LaTeX template not found at: $LATEX_TEMPLATE"
        print_info "Set LATEX_TEMPLATE_DIR environment variable to override."
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        exit 2
    fi

    print_success "All required dependencies found."
    echo ""
}

run_scans() {
    local target_dir="$1"
    local scan_output=""
    local scan_exit_code=0

    print_info "Running security scans against: $target_dir"
    echo ""

    # Run the consolidated scan script
    scan_output=$("$SCRIPT_DIR/run-all-scans.sh" "$target_dir" 2>&1) || scan_exit_code=$?

    echo "$scan_output"
    echo ""

    return $scan_exit_code
}

get_scan_results() {
    local target_dir="$1"

    # Run individual scans and capture results
    local pii_result="PASS"
    local malware_result="PASS"
    local secrets_result="PASS"
    local mac_result="PASS"
    local host_result="PASS"

    # PII scan
    if ! "$SCRIPT_DIR/check-pii.sh" "$target_dir" > /dev/null 2>&1; then
        pii_result="REVIEW"
    fi

    # Malware scan
    if ! "$SCRIPT_DIR/check-malware.sh" "$target_dir" > /dev/null 2>&1; then
        malware_result="REVIEW"
    fi

    # Secrets scan
    if ! "$SCRIPT_DIR/check-secrets.sh" "$target_dir" > /dev/null 2>&1; then
        secrets_result="REVIEW"
    fi

    # MAC address scan
    if ! "$SCRIPT_DIR/check-mac-addresses.sh" "$target_dir" > /dev/null 2>&1; then
        mac_result="REVIEW"
    fi

    # Host security scan
    if ! "$SCRIPT_DIR/check-host-security.sh" > /dev/null 2>&1; then
        host_result="REVIEW"
    fi

    echo "$pii_result,$malware_result,$secrets_result,$mac_result,$host_result"
}

update_latex_template() {
    local target_dir="$1"
    local output_dir="$2"
    local project_name=$(basename "$target_dir")
    local scan_date=$(date "+%B %d, %Y")
    local commit_hash=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    local commit_hash_full=$(git -C "$SECURITY_REPO_DIR" rev-parse HEAD 2>/dev/null || echo "unknown")

    print_info "Preparing LaTeX template..." >&2

    # Create working directory
    local work_dir=$(mktemp -d)
    cp "$LATEX_TEMPLATE_DIR"/* "$work_dir/" 2>/dev/null || true

    # Update template variables using sed
    local tex_file="$work_dir/security_compliance_statement.tex"

    # Update project name
    sed -i.bak "s/\\\\newcommand{\\\\SoftwareName}{[^}]*}/\\\\newcommand{\\\\SoftwareName}{$project_name}/" "$tex_file"

    # Update scan date
    sed -i.bak "s/\\\\newcommand{\\\\ScanDate}{[^}]*}/\\\\newcommand{\\\\ScanDate}{$scan_date}/" "$tex_file"

    # Update document date
    sed -i.bak "s/\\\\newcommand{\\\\DocumentDate}{[^}]*}/\\\\newcommand{\\\\DocumentDate}{$scan_date}/" "$tex_file"

    # Update commit hashes
    sed -i.bak "s/\\\\newcommand{\\\\SecurityToolkitCommit}{[^}]*}/\\\\newcommand{\\\\SecurityToolkitCommit}{$commit_hash}/" "$tex_file"
    sed -i.bak "s/\\\\newcommand{\\\\SecurityToolkitCommitFull}{[^}]*}/\\\\newcommand{\\\\SecurityToolkitCommitFull}{$commit_hash_full}/" "$tex_file"

    # Clean up backup files
    rm -f "$work_dir"/*.bak

    echo "$work_dir"
}

compile_pdf() {
    local work_dir="$1"
    local output_dir="$2"

    print_info "Compiling LaTeX to PDF..."

    cd "$work_dir"

    # Run pdflatex twice for references
    if ! pdflatex -interaction=nonstopmode security_compliance_statement.tex > /dev/null 2>&1; then
        print_error "First pdflatex pass failed"
        return 1
    fi

    if ! pdflatex -interaction=nonstopmode security_compliance_statement.tex > /dev/null 2>&1; then
        print_error "Second pdflatex pass failed"
        return 1
    fi

    # Copy PDF to output directory
    if [ -f "security_compliance_statement.pdf" ]; then
        cp "security_compliance_statement.pdf" "$output_dir/"
        print_success "PDF generated: $output_dir/security_compliance_statement.pdf"
    else
        print_error "PDF was not generated"
        return 1
    fi

    # Cleanup
    cd - > /dev/null
    rm -rf "$work_dir"

    return 0
}

# Main execution
main() {
    print_header

    # Parse arguments
    if [ -z "$1" ]; then
        echo "Usage: $0 <target_project_dir> [output_dir]"
        echo ""
        echo "Arguments:"
        echo "  target_project_dir  Directory of the project to scan"
        echo "  output_dir          Where to save the PDF (default: target_project_dir)"
        echo ""
        echo "Environment variables:"
        echo "  LATEX_TEMPLATE_DIR  Path to LaTeX template directory"
        echo "                      (default: ~/LaTeX/SecurityCompliance)"
        exit 2
    fi

    local target_dir="$1"
    local output_dir="${2:-$target_dir}"

    # Validate target directory
    if [ ! -d "$target_dir" ]; then
        print_error "Target directory does not exist: $target_dir"
        exit 2
    fi

    # Create output directory if needed
    mkdir -p "$output_dir"

    # Check dependencies
    check_dependencies

    # Run security scans
    local scan_exit_code=0
    run_scans "$target_dir" || scan_exit_code=$?

    # Update and compile LaTeX
    local work_dir=$(update_latex_template "$target_dir" "$output_dir")

    if compile_pdf "$work_dir" "$output_dir"; then
        echo ""
        if [ $scan_exit_code -eq 0 ]; then
            print_success "Security compliance statement generated successfully!"
            print_success "All scans passed."
            exit 0
        else
            print_warning "Security compliance statement generated with findings."
            print_warning "Review scan output above and update PDF as needed."
            exit 1
        fi
    else
        print_error "Failed to generate PDF"
        exit 2
    fi
}

main "$@"
