#!/bin/bash
#
# Security Toolkit Release Build Script
#
# Purpose: Orchestrate the complete release workflow
# Usage: ./release.sh <version> [--skip-tests]
#
# This script:
# 1. Validates the version format
# 2. Runs security scans on the toolkit itself
# 3. Generates compliance statement
# 4. Creates redacted example files
# 5. Tags the release
# 6. Pushes to repository
#
# Exit codes:
#   0 = Success
#   1 = Validation or scan failures
#   2 = Missing dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=================================="
    echo "Security Toolkit Release Build"
    echo -e "==================================${NC}"
    echo ""
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}→ $1${NC}"
}

# Get latest version tag
get_latest_version() {
    git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0"
}

# Generate test version
generate_test_version() {
    local latest=$(get_latest_version)
    local timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
    echo "0.0.0-test.$timestamp"
}

# Validate version format (semantic versioning)
validate_version() {
    local version="$1"
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        print_error "Invalid version format: $version"
        echo "Expected semantic versioning (e.g., 1.0.0, 1.0.0-beta, 0.0.0-test.20260115T164943Z)"
        return 1
    fi
    return 0
}

# Check if on main branch
check_main_branch() {
    local current_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)
    if [ "$current_branch" != "main" ]; then
        print_error "Not on main branch (currently on: $current_branch)"
        return 1
    fi
    print_success "On main branch"
}

# Check for uncommitted changes
check_clean_tree() {
    if ! git -C "$REPO_ROOT" diff-index --quiet HEAD --; then
        print_error "Working tree has uncommitted changes"
        echo "Please commit or stash changes before releasing"
        return 1
    fi
    print_success "Working tree is clean"
}

# Check dependencies
check_dependencies() {
    print_info "Checking dependencies..."
    
    local missing=0
    
    if ! command -v pdflatex &> /dev/null; then
        print_warning "pdflatex not found (compliance PDF generation will be skipped)"
    fi
    
    if ! command -v clamscan &> /dev/null; then
        print_warning "ClamAV not found (malware scanning will be skipped)"
    fi
    
    print_success "Dependency check complete"
}

# Run security scans on toolkit itself
run_scans() {
    print_info "Running security scans on toolkit..."
    print_warning "This may take a few minutes. Press Ctrl+C to skip."
    echo ""
    
    if [ ! -x "$REPO_ROOT/scripts/run-all-scans.sh" ]; then
        print_error "run-all-scans.sh not found or not executable"
        return 2
    fi
    
    # Run scans with timeout and show progress
    local scan_output
    local exit_code=0
    
    if ! scan_output=$(timeout 300 "$REPO_ROOT/scripts/run-all-scans.sh" "$REPO_ROOT" 2>&1); then
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_warning "Scans timed out (5 minutes). Use --skip-tests to bypass."
            return 1
        fi
    fi
    
    # Show scan output
    echo "$scan_output"
    echo ""
    
    if [ $exit_code -eq 0 ]; then
        print_success "All security scans passed"
    else
        print_warning "Scans completed with findings (review above)"
    fi
    
    return 0
}

# Generate compliance statement
generate_compliance() {
    print_info "Generating compliance statement..."
    
    if ! command -v pdflatex &> /dev/null; then
        print_warning "pdflatex not available, skipping PDF generation"
        return 0
    fi
    
    if ! "$REPO_ROOT/scripts/generate-compliance.sh" "$REPO_ROOT" "$REPO_ROOT"; then
        print_warning "Compliance statement generation completed with findings"
    else
        print_success "Compliance statement generated"
    fi
}

# Create redacted examples
create_examples() {
    print_info "Creating redacted example files..."
    
    if [ ! -x "$REPO_ROOT/redact.sh" ]; then
        print_warning "redact.sh not found, skipping example generation"
        return 0
    fi
    
    # Check if .scans directory exists
    if [ ! -d "$REPO_ROOT/.scans" ]; then
        print_warning "No .scans directory found, skipping example generation"
        return 0
    fi
    
    if "$REPO_ROOT/redact.sh" "$REPO_ROOT/.scans" "$REPO_ROOT/examples"; then
        print_success "Example files generated and redacted"
        
        # Add examples to staging
        git -C "$REPO_ROOT" add examples/ > /dev/null 2>&1 || true
    else
        print_warning "Example file generation encountered issues"
    fi
}

# Create release tag
create_tag() {
    local version="$1"
    local tag="v$version"
    
    print_info "Creating release tag: $tag"
    
    # Check if tag already exists
    if git -C "$REPO_ROOT" rev-parse "$tag" >/dev/null 2>&1; then
        print_error "Tag $tag already exists"
        return 1
    fi
    
    # Create annotated tag with version in message
    git -C "$REPO_ROOT" tag -a "$tag" -m "Release $version

Changelog:
- See CHANGELOG.md for details

Build Date: $(date '+%Y-%m-%d %H:%M:%S UTC')" || return 1
    
    print_success "Tag created: $tag"
}

# Push to repository
push_release() {
    local version="$1"
    local tag="v$version"
    
    print_info "Pushing release to repository..."
    
    # Push main branch
    if ! git -C "$REPO_ROOT" push origin main; then
        print_error "Failed to push main branch"
        return 1
    fi
    
    # Push tags
    if ! git -C "$REPO_ROOT" push origin "$tag"; then
        print_error "Failed to push tag $tag"
        return 1
    fi
    
    print_success "Release pushed successfully"
}

# Summary
print_summary() {
    local version="$1"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Release v$version completed successfully!  ${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review the release on GitHub: https://github.com/brucedombrowski/Security/releases/tag/v$version"
    echo "  2. Verify example files in: examples/"
    echo "  3. Check compliance statement: security_compliance_statement.pdf"
    echo ""
}

# Main execution
main() {
    print_header
    
    # Parse arguments - handle flags and version
    local version=""
    local skip_tests=""
    
    # Check first argument
    if [ -z "$1" ]; then
        # No arguments - generate test release
        version=$(generate_test_version)
        print_info "No version specified—generating test release: $version"
        echo ""
    elif [ "$1" = "--skip-tests" ]; then
        # Only flag provided - generate test release and skip tests
        version=$(generate_test_version)
        skip_tests="--skip-tests"
        print_info "Generating test release with tests skipped: $version"
        echo ""
    else
        # Version provided (may or may not have second argument)
        version="$1"
        skip_tests="${2:-}"
    fi
    
    # Validate version
    if ! validate_version "$version"; then
        exit 1
    fi
    print_success "Version format valid: $version"
    
    # Pre-release checks
    if ! check_main_branch; then exit 1; fi
    if ! check_clean_tree; then exit 1; fi
    
    check_dependencies
    
    # Run tests unless skipped
    if [ "$skip_tests" != "--skip-tests" ]; then
        if ! run_scans; then
            print_error "Security scans failed"
            exit 1
        fi
        
        if ! generate_compliance; then
            print_warning "Compliance generation had issues (continuing anyway)"
        fi
    else
        print_info "Skipping security tests (--skip-tests flag)"
    fi
    
    # Create examples
    create_examples
    
    # Create and push tag
    if ! create_tag "$version"; then
        exit 1
    fi
    
    if ! push_release "$version"; then
        # Try to delete local tag if push failed
        git -C "$REPO_ROOT" tag -d "v$version" > /dev/null 2>&1 || true
        exit 1
    fi
    
    print_summary "$version"
}

main "$@"
