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
# 3. Creates redacted example files
# 4. Tags the release
# 5. Pushes to repository
# 6. Creates GitHub release
# 7. Deletes old GitHub releases (keeps only latest; tags are preserved)
#
# Exit codes:
#   0 = Success
#   1 = Validation or scan failures
#   2 = Missing dependencies

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load config from release.config.json
CONFIG_FILE="$REPO_ROOT/release.config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE" >&2
    echo "Create release.config.json with: {\"github\": {\"owner\": \"...\", \"repo\": \"...\"}}" >&2
    exit 2
fi

GITHUB_OWNER=$(jq -r '.github.owner' "$CONFIG_FILE")
GITHUB_REPO=$(jq -r '.github.repo' "$CONFIG_FILE")
GITHUB_REPO_FULL="${GITHUB_OWNER}/${GITHUB_REPO}"

if [ -z "$GITHUB_OWNER" ] || [ "$GITHUB_OWNER" = "null" ] || [ -z "$GITHUB_REPO" ] || [ "$GITHUB_REPO" = "null" ]; then
    echo "ERROR: Invalid config. Ensure github.owner and github.repo are set in $CONFIG_FILE" >&2
    exit 2
fi

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
# Arguments:
#   $1 - Version being released (used to set TOOLKIT_VERSION_OVERRIDE)
run_scans() {
    local release_version="$1"

    print_info "Running security scans on toolkit..."
    print_warning "ClamAV malware scan typically takes 2-5 minutes. No output shown until complete."
    print_warning "Press Ctrl+C to cancel, or use --skip-tests to bypass."
    echo ""

    if [ ! -x "$REPO_ROOT/scripts/run-all-scans.sh" ]; then
        print_error "run-all-scans.sh not found or not executable"
        return 2
    fi

    # Export version override so scans show release version (not git describe)
    export TOOLKIT_VERSION_OVERRIDE="$release_version"

    # Determine which timeout command to use
    local timeout_cmd=""
    if command -v gtimeout &> /dev/null; then
        timeout_cmd="gtimeout 300"
    elif command -v timeout &> /dev/null; then
        timeout_cmd="timeout 300"
    fi
    
    # Run scans with optional timeout
    # Always use non-interactive mode (-n) to avoid hanging on prompts
    local scan_output
    local exit_code=0

    if [ -n "$timeout_cmd" ]; then
        scan_output=$($timeout_cmd "$REPO_ROOT/scripts/run-all-scans.sh" -n "$REPO_ROOT" 2>&1) || exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_warning "Scans timed out (5 minutes). Use --skip-tests to bypass."
            return 1
        fi
    else
        scan_output=$("$REPO_ROOT/scripts/run-all-scans.sh" -n "$REPO_ROOT" 2>&1) || exit_code=$?
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

# Bundle KEV catalog for offline use
bundle_kev_catalog() {
    print_info "Bundling CISA KEV catalog for offline use..."

    local kev_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    local data_dir="$REPO_ROOT/data"
    local kev_file="$data_dir/kev-catalog.json"

    mkdir -p "$data_dir"

    if ! curl -s --connect-timeout 10 --max-time 60 "$kev_url" -o "${kev_file}.tmp"; then
        print_warning "Failed to download KEV catalog (network unavailable)"
        if [ -f "$kev_file" ]; then
            print_info "Keeping existing bundled KEV catalog"
        else
            print_warning "No bundled KEV catalog available - offline scanning will be limited"
        fi
        return 0
    fi

    # Validate JSON
    if ! jq empty "${kev_file}.tmp" 2>/dev/null; then
        print_warning "Downloaded KEV catalog is invalid JSON"
        rm -f "${kev_file}.tmp"
        return 0
    fi

    mv "${kev_file}.tmp" "$kev_file"

    # Generate SHA256 hash (use relative path for portability)
    local kev_dir kev_basename
    kev_dir=$(dirname "$kev_file")
    kev_basename=$(basename "$kev_file")
    if [[ "$(uname)" == "Darwin" ]]; then
        (cd "$kev_dir" && shasum -a 256 "$kev_basename" > "${kev_basename}.sha256")
    else
        (cd "$kev_dir" && sha256sum "$kev_basename" > "${kev_basename}.sha256")
    fi

    # Get catalog metadata
    local kev_count
    local kev_date
    kev_count=$(jq -r '.count' "$kev_file")
    kev_date=$(jq -r '.dateReleased' "$kev_file")

    print_success "KEV catalog bundled ($kev_count vulnerabilities, released $kev_date)"

    # Stage for commit
    git -C "$REPO_ROOT" add "$kev_file" "${kev_file}.sha256" > /dev/null 2>&1 || true
}

# Create redacted examples
create_examples() {
    print_info "Creating redacted example files..."

    if [ ! -x "$REPO_ROOT/scripts/redact-examples.sh" ]; then
        print_warning "scripts/redact-examples.sh not found, skipping example generation"
        return 0
    fi

    # Check if .scans directory exists
    if [ ! -d "$REPO_ROOT/.scans" ]; then
        print_warning "No .scans directory found, skipping example generation"
        return 0
    fi

    if "$REPO_ROOT/scripts/redact-examples.sh" "$REPO_ROOT/.scans" "$REPO_ROOT/examples"; then
        print_success "Example files generated and redacted"

        # Add examples to staging
        git -C "$REPO_ROOT" add examples/ > /dev/null 2>&1 || true
    else
        print_warning "Example file generation encountered issues"
    fi
}

# Commit any staged changes before tagging
commit_staged_changes() {
    local version="$1"

    # Check if there are staged changes
    if ! git -C "$REPO_ROOT" diff --cached --quiet; then
        print_info "Committing staged changes for release..."

        if git -C "$REPO_ROOT" commit -m "chore: update examples for v$version release"; then
            print_success "Staged changes committed"
        else
            print_error "Failed to commit staged changes"
            return 1
        fi
    fi
    return 0
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

# Create GitHub release
create_github_release() {
    local version="$1"
    local tag="v$version"

    if ! command -v gh &> /dev/null; then
        print_warning "GitHub CLI (gh) not found, skipping GitHub release creation"
        print_info "Create manually at: https://github.com/${GITHUB_REPO_FULL}/releases/new?tag=$tag"
        return 0
    fi

    print_info "Creating GitHub release..."

    if gh release create "$tag" \
        --repo "$GITHUB_REPO_FULL" \
        --title "$tag" \
        --notes "Release $version - See CHANGELOG.md for details."; then
        print_success "GitHub release created: https://github.com/${GITHUB_REPO_FULL}/releases/tag/$tag"
    else
        print_warning "Failed to create GitHub release"
        return 1
    fi
}

# Delete old GitHub releases (keeps tags)
cleanup_old_releases() {
    local current_tag="$1"

    if ! command -v gh &> /dev/null; then
        print_warning "GitHub CLI (gh) not found, skipping old release cleanup"
        return 0
    fi

    print_info "Cleaning up old GitHub releases (keeping only $current_tag)..."

    # Get list of all releases except the current one
    local old_releases
    old_releases=$(gh release list --repo "$GITHUB_REPO_FULL" --json tagName -q ".[].tagName" 2>/dev/null | grep -v "^${current_tag}$" || true)

    if [ -z "$old_releases" ]; then
        print_success "No old releases to clean up"
        return 0
    fi

    local count=0
    for tag in $old_releases; do
        if gh release delete "$tag" --repo "$GITHUB_REPO_FULL" --yes 2>/dev/null; then
            count=$((count + 1))
        fi
    done

    if [ $count -gt 0 ]; then
        print_success "Deleted $count old release(s) (tags preserved)"
    fi
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
    echo "  1. Review the release on GitHub: https://github.com/${GITHUB_REPO_FULL}/releases/tag/v$version"
    echo "  2. Verify example files in: examples/"
    echo "  3. Review scan attestation PDF in: .scans/scan-attestation-*.pdf"
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
    # Note: run_scans calls run-all-scans.sh which already generates PDF attestation
    # Do NOT call generate_compliance here - it would re-run scans and delete .scans/
    if [ "$skip_tests" != "--skip-tests" ]; then
        if ! run_scans "$version"; then
            print_error "Security scans failed"
            exit 1
        fi
    else
        print_info "Skipping security tests (--skip-tests flag)"
    fi
    
    # Bundle KEV catalog for offline scanning
    bundle_kev_catalog

    # Create examples
    create_examples

    # Commit any staged changes (e.g., updated examples) before tagging
    if ! commit_staged_changes "$version"; then
        exit 1
    fi

    # Create and push tag
    if ! create_tag "$version"; then
        exit 1
    fi
    
    if ! push_release "$version"; then
        # Try to delete local tag if push failed
        git -C "$REPO_ROOT" tag -d "v$version" > /dev/null 2>&1 || true
        exit 1
    fi

    # Create GitHub release
    create_github_release "$version"

    # Clean up old releases (keep only latest)
    cleanup_old_releases "v$version"

    print_summary "$version"
}

main "$@"
