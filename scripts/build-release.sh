#!/bin/bash
#
# Security Toolkit Build Script - Platform-Specific Releases
#
# Purpose: Build distributable releases with optional bundled ClamAV
# Usage:
#   ./build-release.sh                           # Core release (no ClamAV)
#   ./build-release.sh --platform macos-arm64    # macOS Apple Silicon + ClamAV
#   ./build-release.sh --platform macos-x64      # macOS Intel + ClamAV
#   ./build-release.sh --platform linux-x64      # Linux x64 + ClamAV
#   ./build-release.sh --platform windows-x64    # Windows x64 + ClamAV
#   ./build-release.sh --all-platforms           # Build all platform releases
#
# Output: dist/security-toolkit-<version>[-<platform>].tar.gz (or .zip for Windows)
#
# Exit codes:
#   0 = Success
#   1 = Build failure
#   2 = Missing dependencies

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ClamAV download URLs (official releases)
# Update these URLs when new ClamAV versions are released
CLAMAV_VERSION="1.4.2"
CLAMAV_BASE_URL="https://www.clamav.net/downloads/production"

# Platform-specific ClamAV download info
declare -A CLAMAV_URLS=(
    ["macos-arm64"]="clamav-${CLAMAV_VERSION}.macos.arm64.pkg"
    ["macos-x64"]="clamav-${CLAMAV_VERSION}.macos.x86_64.pkg"
    ["linux-x64"]="clamav-${CLAMAV_VERSION}.linux.x86_64.tar.gz"
    ["windows-x64"]="clamav-${CLAMAV_VERSION}.win.x64.zip"
)

# Supported platforms
PLATFORMS=("macos-arm64" "macos-x64" "linux-x64" "windows-x64")

print_header() {
    echo -e "${BLUE}=================================="
    echo "Security Toolkit Build"
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

# Get version from git or CHANGELOG
get_version() {
    if git -C "$REPO_ROOT" describe --tags --abbrev=0 &>/dev/null; then
        git -C "$REPO_ROOT" describe --tags --abbrev=0 | sed 's/^v//'
    else
        # Fallback: extract from CHANGELOG.md
        grep -m1 '^\## \[' "$REPO_ROOT/CHANGELOG.md" | sed 's/.*\[\([^]]*\)\].*/\1/'
    fi
}

# Check required dependencies
check_dependencies() {
    local missing=()

    if ! command -v curl &>/dev/null; then
        missing+=("curl")
    fi

    if ! command -v tar &>/dev/null; then
        missing+=("tar")
    fi

    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing required dependencies: ${missing[*]}"
        exit 2
    fi
}

# Download ClamAV for a specific platform
download_clamav() {
    local platform="$1"
    local dest_dir="$2"
    local clamav_file="${CLAMAV_URLS[$platform]}"
    local download_url="${CLAMAV_BASE_URL}/${clamav_file}"
    local temp_dir
    temp_dir=$(mktemp -d)

    print_info "Downloading ClamAV ${CLAMAV_VERSION} for ${platform}..."

    local download_path="${temp_dir}/${clamav_file}"

    if ! curl -sSL --connect-timeout 30 --max-time 300 -o "$download_path" "$download_url"; then
        print_error "Failed to download ClamAV from $download_url"
        rm -rf "$temp_dir"
        return 1
    fi

    print_info "Extracting ClamAV binaries..."

    mkdir -p "$dest_dir"

    case "$platform" in
        macos-arm64|macos-x64)
            # macOS PKG files need special handling
            # Extract using pkgutil or xar
            if command -v pkgutil &>/dev/null; then
                local expand_dir="${temp_dir}/expanded"
                mkdir -p "$expand_dir"
                pkgutil --expand "$download_path" "$expand_dir" 2>/dev/null || {
                    # Fallback: try xar
                    if command -v xar &>/dev/null; then
                        (cd "$expand_dir" && xar -xf "$download_path")
                    else
                        print_warning "Cannot extract PKG, downloading portable tarball instead..."
                        # Fallback to Homebrew bottle or manual build
                        download_clamav_homebrew "$platform" "$dest_dir"
                        rm -rf "$temp_dir"
                        return $?
                    fi
                }
                # Find and copy binaries
                find "$expand_dir" -name "clamscan" -o -name "freshclam" -o -name "sigtool" 2>/dev/null | \
                    while read -r bin; do
                        cp "$bin" "$dest_dir/" 2>/dev/null || true
                    done
            else
                download_clamav_homebrew "$platform" "$dest_dir"
                rm -rf "$temp_dir"
                return $?
            fi
            ;;
        linux-x64)
            # Linux tarball
            tar -xzf "$download_path" -C "$temp_dir"
            # Find binaries in extracted directory
            local clamav_dir
            clamav_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "clamav-*" | head -1)
            if [ -n "$clamav_dir" ] && [ -d "$clamav_dir" ]; then
                cp "$clamav_dir/bin/clamscan" "$dest_dir/" 2>/dev/null || true
                cp "$clamav_dir/bin/freshclam" "$dest_dir/" 2>/dev/null || true
                cp "$clamav_dir/bin/sigtool" "$dest_dir/" 2>/dev/null || true
                # Copy required libraries
                if [ -d "$clamav_dir/lib" ]; then
                    mkdir -p "$dest_dir/lib"
                    cp -r "$clamav_dir/lib/"* "$dest_dir/lib/" 2>/dev/null || true
                fi
            fi
            ;;
        windows-x64)
            # Windows ZIP
            if command -v unzip &>/dev/null; then
                unzip -q "$download_path" -d "$temp_dir"
            else
                print_error "unzip required for Windows builds"
                rm -rf "$temp_dir"
                return 1
            fi
            # Find and copy executables
            find "$temp_dir" -name "clamscan.exe" -o -name "freshclam.exe" -o -name "sigtool.exe" 2>/dev/null | \
                while read -r exe; do
                    cp "$exe" "$dest_dir/" 2>/dev/null || true
                done
            # Copy required DLLs
            find "$temp_dir" -name "*.dll" 2>/dev/null | \
                while read -r dll; do
                    cp "$dll" "$dest_dir/" 2>/dev/null || true
                done
            ;;
    esac

    rm -rf "$temp_dir"

    # Verify we got the binaries
    local expected_binary="clamscan"
    [ "$platform" = "windows-x64" ] && expected_binary="clamscan.exe"

    if [ ! -f "$dest_dir/$expected_binary" ]; then
        print_error "ClamAV binaries not found after extraction"
        return 1
    fi

    print_success "ClamAV binaries extracted to $dest_dir"
    return 0
}

# Alternative: Download from Homebrew bottles (macOS)
download_clamav_homebrew() {
    local platform="$1"
    local dest_dir="$2"

    print_info "Attempting Homebrew bottle download for ${platform}..."

    # Get the bottle URL from Homebrew API
    local bottle_info
    bottle_info=$(curl -sSL "https://formulae.brew.sh/api/formula/clamav.json" 2>/dev/null)

    if [ -z "$bottle_info" ]; then
        print_error "Failed to fetch Homebrew bottle info"
        return 1
    fi

    local bottle_tag
    case "$platform" in
        macos-arm64) bottle_tag="arm64_sonoma" ;;
        macos-x64) bottle_tag="sonoma" ;;
        *) print_error "Homebrew bottles only available for macOS"; return 1 ;;
    esac

    local bottle_url
    bottle_url=$(echo "$bottle_info" | jq -r ".bottle.stable.files.${bottle_tag}.url // empty")

    if [ -z "$bottle_url" ]; then
        print_warning "No Homebrew bottle available for ${bottle_tag}"
        return 1
    fi

    local temp_dir
    temp_dir=$(mktemp -d)
    local bottle_file="${temp_dir}/clamav.tar.gz"

    if ! curl -sSL -o "$bottle_file" "$bottle_url"; then
        print_error "Failed to download Homebrew bottle"
        rm -rf "$temp_dir"
        return 1
    fi

    tar -xzf "$bottle_file" -C "$temp_dir"

    # Find binaries in Homebrew structure
    find "$temp_dir" -path "*/bin/clamscan" -o -path "*/bin/freshclam" -o -path "*/bin/sigtool" 2>/dev/null | \
        while read -r bin; do
            cp "$bin" "$dest_dir/" 2>/dev/null || true
        done

    rm -rf "$temp_dir"

    if [ -f "$dest_dir/clamscan" ]; then
        print_success "ClamAV binaries extracted from Homebrew bottle"
        return 0
    else
        print_error "Failed to extract ClamAV from Homebrew bottle"
        return 1
    fi
}

# Download virus definitions
download_virus_definitions() {
    local dest_dir="$1"
    local db_dir="${dest_dir}/db"

    mkdir -p "$db_dir"

    print_info "Downloading virus definitions..."

    # ClamAV database mirror
    local db_mirror="https://database.clamav.net"

    # Download main databases
    for db in main.cvd daily.cvd bytecode.cvd; do
        print_info "  Downloading ${db}..."
        if ! curl -sSL --connect-timeout 30 --max-time 600 -o "${db_dir}/${db}" "${db_mirror}/${db}"; then
            print_warning "Failed to download ${db} from primary mirror, trying fallback..."
            # Fallback mirror
            if ! curl -sSL --connect-timeout 30 --max-time 600 -o "${db_dir}/${db}" "https://db.local.clamav.net/${db}"; then
                print_error "Failed to download ${db}"
                return 1
            fi
        fi
    done

    # Verify databases exist and have content
    for db in main.cvd daily.cvd bytecode.cvd; do
        if [ ! -s "${db_dir}/${db}" ]; then
            print_error "Database ${db} is empty or missing"
            return 1
        fi
    done

    # Calculate total size
    local total_size
    total_size=$(du -sh "$db_dir" | cut -f1)

    print_success "Virus definitions downloaded (${total_size})"

    # Record download timestamp
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "${db_dir}/downloaded.txt"

    return 0
}

# Build core release (no ClamAV)
build_core_release() {
    local version="$1"
    local dist_dir="$2"
    local release_name="security-toolkit-${version}"
    local release_dir="${dist_dir}/${release_name}"
    local archive="${dist_dir}/${release_name}.tar.gz"

    print_info "Building core release: ${release_name}"

    mkdir -p "$release_dir"

    # Copy toolkit files
    cp -r "$REPO_ROOT/scripts" "$release_dir/"
    cp -r "$REPO_ROOT/data" "$release_dir/" 2>/dev/null || mkdir -p "$release_dir/data"
    cp -r "$REPO_ROOT/templates" "$release_dir/" 2>/dev/null || true
    cp -r "$REPO_ROOT/docs" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/README.md" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/LICENSE" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/CHANGELOG.md" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/INSTALLATION.md" "$release_dir/" 2>/dev/null || true

    # Remove any existing .scans, .git, etc.
    rm -rf "$release_dir/.git" "$release_dir/.scans" "$release_dir/.assessments"

    # Create archive
    (cd "$dist_dir" && tar -czf "$(basename "$archive")" "$release_name")
    rm -rf "$release_dir"

    local size
    size=$(du -h "$archive" | cut -f1)
    print_success "Core release built: ${archive} (${size})"

    echo "$archive"
}

# Build platform-specific release with ClamAV
build_platform_release() {
    local version="$1"
    local platform="$2"
    local dist_dir="$3"
    local release_name="security-toolkit-${version}-${platform}"
    local release_dir="${dist_dir}/${release_name}"

    print_info "Building platform release: ${release_name}"

    mkdir -p "$release_dir"

    # Copy toolkit files
    cp -r "$REPO_ROOT/scripts" "$release_dir/"
    cp -r "$REPO_ROOT/data" "$release_dir/" 2>/dev/null || mkdir -p "$release_dir/data"
    cp -r "$REPO_ROOT/templates" "$release_dir/" 2>/dev/null || true
    cp -r "$REPO_ROOT/docs" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/README.md" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/LICENSE" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/CHANGELOG.md" "$release_dir/" 2>/dev/null || true
    cp "$REPO_ROOT/INSTALLATION.md" "$release_dir/" 2>/dev/null || true

    # Remove any existing .scans, .git, etc.
    rm -rf "$release_dir/.git" "$release_dir/.scans" "$release_dir/.assessments"

    # Create clamav directory
    local clamav_dir="${release_dir}/clamav"
    mkdir -p "$clamav_dir"

    # Download ClamAV binaries
    if ! download_clamav "$platform" "$clamav_dir"; then
        print_error "Failed to download ClamAV for ${platform}"
        rm -rf "$release_dir"
        return 1
    fi

    # Download virus definitions
    if ! download_virus_definitions "$clamav_dir"; then
        print_error "Failed to download virus definitions"
        rm -rf "$release_dir"
        return 1
    fi

    # Add ClamAV license
    cat > "${clamav_dir}/LICENSE-CLAMAV.txt" << 'CLAMAV_LICENSE'
ClamAV is licensed under the GNU General Public License, version 2 (GPLv2).

Copyright (C) 2007-2024 Cisco Systems, Inc. and/or its affiliates.
All rights reserved.

ClamAV is distributed separately from this toolkit and is not linked
or combined with the toolkit code. The toolkit calls ClamAV as an
external subprocess, which constitutes "mere aggregation" under GPLv2.

For the full ClamAV license text, see:
https://github.com/Cisco-Talos/clamav/blob/main/COPYING
CLAMAV_LICENSE

    # Create platform info file
    cat > "${clamav_dir}/PLATFORM-INFO.txt" << EOF
Platform: ${platform}
ClamAV Version: ${CLAMAV_VERSION}
Build Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
DB Downloaded: $(cat "${clamav_dir}/db/downloaded.txt" 2>/dev/null || echo "unknown")
EOF

    # Create archive (ZIP for Windows, tar.gz for others)
    local archive
    if [ "$platform" = "windows-x64" ]; then
        archive="${dist_dir}/${release_name}.zip"
        if command -v zip &>/dev/null; then
            (cd "$dist_dir" && zip -rq "$(basename "$archive")" "$release_name")
        else
            print_warning "zip not available, creating tar.gz instead"
            archive="${dist_dir}/${release_name}.tar.gz"
            (cd "$dist_dir" && tar -czf "$(basename "$archive")" "$release_name")
        fi
    else
        archive="${dist_dir}/${release_name}.tar.gz"
        (cd "$dist_dir" && tar -czf "$(basename "$archive")" "$release_name")
    fi

    rm -rf "$release_dir"

    local size
    size=$(du -h "$archive" | cut -f1)
    print_success "Platform release built: ${archive} (${size})"

    echo "$archive"
}

# Generate checksums for all releases
generate_checksums() {
    local dist_dir="$1"
    local checksum_file="${dist_dir}/SHA256SUMS.txt"

    print_info "Generating checksums..."

    (
        cd "$dist_dir"
        for archive in *.tar.gz *.zip; do
            [ -f "$archive" ] || continue
            if [[ "$(uname)" == "Darwin" ]]; then
                shasum -a 256 "$archive"
            else
                sha256sum "$archive"
            fi
        done
    ) > "$checksum_file"

    print_success "Checksums written to ${checksum_file}"
}

# Print usage
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Build distributable releases of the security toolkit.

Options:
  --platform <PLATFORM>   Build platform-specific release with ClamAV
                          Platforms: macos-arm64, macos-x64, linux-x64, windows-x64
  --all-platforms         Build releases for all platforms
  --output-dir <DIR>      Output directory (default: dist/)
  --version <VERSION>     Override version (default: from git tag)
  --help                  Show this help message

Examples:
  $(basename "$0")                           # Build core release only
  $(basename "$0") --platform linux-x64      # Build Linux release with ClamAV
  $(basename "$0") --all-platforms           # Build all platform releases
EOF
}

# Main
main() {
    print_header

    local platform=""
    local all_platforms=false
    local output_dir="${REPO_ROOT}/dist"
    local version=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --platform)
                platform="$2"
                shift 2
                ;;
            --all-platforms)
                all_platforms=true
                shift
                ;;
            --output-dir)
                output_dir="$2"
                shift 2
                ;;
            --version)
                version="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Validate platform if specified
    if [ -n "$platform" ]; then
        local valid=false
        for p in "${PLATFORMS[@]}"; do
            if [ "$p" = "$platform" ]; then
                valid=true
                break
            fi
        done
        if [ "$valid" = false ]; then
            print_error "Invalid platform: $platform"
            echo "Valid platforms: ${PLATFORMS[*]}"
            exit 1
        fi
    fi

    check_dependencies

    # Get version
    if [ -z "$version" ]; then
        version=$(get_version)
    fi
    print_info "Building version: ${version}"

    # Create output directory
    mkdir -p "$output_dir"

    # Always build core release
    build_core_release "$version" "$output_dir"

    # Build platform-specific releases
    if [ "$all_platforms" = true ]; then
        for p in "${PLATFORMS[@]}"; do
            echo ""
            build_platform_release "$version" "$p" "$output_dir" || {
                print_warning "Failed to build ${p} release, continuing..."
            }
        done
    elif [ -n "$platform" ]; then
        echo ""
        build_platform_release "$version" "$platform" "$output_dir"
    fi

    # Generate checksums
    echo ""
    generate_checksums "$output_dir"

    # Summary
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Build Complete!                        ${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "Output directory: ${output_dir}"
    echo ""
    echo "Release files:"
    ls -lh "$output_dir"/*.tar.gz "$output_dir"/*.zip 2>/dev/null || true
}

main "$@"
