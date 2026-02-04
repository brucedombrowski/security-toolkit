#!/bin/bash
#
# ClamAV Offline Update Script (Sneakernet)
#
# Purpose: Update ClamAV virus definitions on airgapped systems
# Usage:
#   On connected machine:  ./update-clamav-offline.sh --download
#   On airgapped machine:  ./update-clamav-offline.sh --apply <update-file>
#
# This script enables virus definition updates for systems without network access
# by creating a portable update package that can be transferred via USB drive.
#
# Exit codes:
#   0 = Success
#   1 = Operation failed
#   2 = Missing dependencies or invalid arguments

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ClamAV database mirror
DB_MIRROR="https://database.clamav.net"
DB_FALLBACK="https://db.local.clamav.net"

print_header() {
    echo -e "${BLUE}=================================="
    echo "ClamAV Offline Update Tool"
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

# Download virus definitions and create update package
download_updates() {
    local output_dir="${1:-.}"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d')
    local package_name="clamav-db-update-${timestamp}"
    local temp_dir
    temp_dir=$(mktemp -d)
    local db_dir="${temp_dir}/${package_name}"

    mkdir -p "$db_dir"

    print_info "Downloading latest ClamAV virus definitions..."
    echo ""

    # Download each database file
    local success=true
    for db in main.cvd daily.cvd bytecode.cvd; do
        print_info "Downloading ${db}..."

        if curl -sSL --connect-timeout 30 --max-time 600 \
            --progress-bar \
            -o "${db_dir}/${db}" \
            "${DB_MIRROR}/${db}"; then
            local size
            size=$(du -h "${db_dir}/${db}" | cut -f1)
            print_success "${db} downloaded (${size})"
        else
            print_warning "Primary mirror failed, trying fallback..."
            if curl -sSL --connect-timeout 30 --max-time 600 \
                --progress-bar \
                -o "${db_dir}/${db}" \
                "${DB_FALLBACK}/${db}"; then
                local size
                size=$(du -h "${db_dir}/${db}" | cut -f1)
                print_success "${db} downloaded from fallback (${size})"
            else
                print_error "Failed to download ${db}"
                success=false
            fi
        fi
    done

    if [ "$success" = false ]; then
        rm -rf "$temp_dir"
        return 1
    fi

    # Verify databases exist and have content
    for db in main.cvd daily.cvd bytecode.cvd; do
        if [ ! -s "${db_dir}/${db}" ]; then
            print_error "Database ${db} is empty or missing"
            rm -rf "$temp_dir"
            return 1
        fi
    done

    # Create metadata file
    cat > "${db_dir}/UPDATE-INFO.txt" << EOF
ClamAV Virus Definition Update Package
=======================================

Download Date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Download Host: $(hostname)

Contents:
EOF

    # Add file info and checksums
    for db in main.cvd daily.cvd bytecode.cvd; do
        local size checksum
        size=$(du -h "${db_dir}/${db}" | cut -f1)
        if [[ "$(uname)" == "Darwin" ]]; then
            checksum=$(shasum -a 256 "${db_dir}/${db}" | cut -d' ' -f1)
        else
            checksum=$(sha256sum "${db_dir}/${db}" | cut -d' ' -f1)
        fi
        echo "  ${db}: ${size}" >> "${db_dir}/UPDATE-INFO.txt"
        echo "    SHA256: ${checksum}" >> "${db_dir}/UPDATE-INFO.txt"
    done

    cat >> "${db_dir}/UPDATE-INFO.txt" << EOF

Installation Instructions:
--------------------------
1. Copy this package to the airgapped system via USB drive
2. Run: ./scripts/update-clamav-offline.sh --apply ${package_name}.tar.gz
3. Verify update was applied successfully

Note: These definitions should be applied as soon as possible.
Older definitions provide less protection against recent threats.
EOF

    # Generate checksums file
    (
        cd "$db_dir"
        if [[ "$(uname)" == "Darwin" ]]; then
            shasum -a 256 main.cvd daily.cvd bytecode.cvd > SHA256SUMS.txt
        else
            sha256sum main.cvd daily.cvd bytecode.cvd > SHA256SUMS.txt
        fi
    )

    # Create the update package
    local package_file="${output_dir}/${package_name}.tar.gz"
    print_info "Creating update package..."

    (cd "$temp_dir" && tar -czf "${package_name}.tar.gz" "$package_name")
    mv "${temp_dir}/${package_name}.tar.gz" "$package_file"

    rm -rf "$temp_dir"

    local package_size
    package_size=$(du -h "$package_file" | cut -f1)

    echo ""
    print_success "Update package created: ${package_file} (${package_size})"
    echo ""
    echo "Next steps:"
    echo "  1. Copy ${package_file} to a USB drive"
    echo "  2. On the airgapped system, run:"
    echo "     ./scripts/update-clamav-offline.sh --apply ${package_file}"
    echo ""

    return 0
}

# Apply update package to local ClamAV installation
apply_updates() {
    local package_file="$1"

    if [ ! -f "$package_file" ]; then
        print_error "Update package not found: ${package_file}"
        return 1
    fi

    print_info "Applying ClamAV update package: ${package_file}"
    echo ""

    # Find the target database directory
    local target_db_dir=""

    # Check for bundled ClamAV first
    if [ -d "$REPO_ROOT/clamav/db" ]; then
        target_db_dir="$REPO_ROOT/clamav/db"
        print_info "Found bundled ClamAV database at: ${target_db_dir}"
    # Check user's toolkit cache
    elif [ -d "$HOME/.security-toolkit/clamav/db" ]; then
        target_db_dir="$HOME/.security-toolkit/clamav/db"
        print_info "Found toolkit cache database at: ${target_db_dir}"
    # Check system ClamAV locations
    elif [ -d "/opt/homebrew/var/lib/clamav" ]; then
        target_db_dir="/opt/homebrew/var/lib/clamav"
        print_info "Found Homebrew ClamAV database at: ${target_db_dir}"
    elif [ -d "/var/lib/clamav" ]; then
        target_db_dir="/var/lib/clamav"
        print_info "Found system ClamAV database at: ${target_db_dir}"
    elif [ -d "/usr/local/var/lib/clamav" ]; then
        target_db_dir="/usr/local/var/lib/clamav"
        print_info "Found ClamAV database at: ${target_db_dir}"
    fi

    if [ -z "$target_db_dir" ]; then
        print_error "No ClamAV database directory found"
        echo ""
        echo "Expected locations:"
        echo "  - Bundled: $REPO_ROOT/clamav/db/"
        echo "  - User cache: ~/.security-toolkit/clamav/db/"
        echo "  - Homebrew: /opt/homebrew/var/lib/clamav/"
        echo "  - System: /var/lib/clamav/"
        return 1
    fi

    # Extract update package
    local temp_dir
    temp_dir=$(mktemp -d)

    print_info "Extracting update package..."
    if ! tar -xzf "$package_file" -C "$temp_dir"; then
        print_error "Failed to extract update package"
        rm -rf "$temp_dir"
        return 1
    fi

    # Find the extracted directory
    local update_dir
    update_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "clamav-db-update-*" | head -1)

    if [ -z "$update_dir" ] || [ ! -d "$update_dir" ]; then
        print_error "Invalid update package structure"
        rm -rf "$temp_dir"
        return 1
    fi

    # Verify checksums
    print_info "Verifying checksums..."
    if [ -f "$update_dir/SHA256SUMS.txt" ]; then
        (
            cd "$update_dir"
            if [[ "$(uname)" == "Darwin" ]]; then
                if ! shasum -a 256 -c SHA256SUMS.txt; then
                    print_error "Checksum verification failed"
                    exit 1
                fi
            else
                if ! sha256sum -c SHA256SUMS.txt; then
                    print_error "Checksum verification failed"
                    exit 1
                fi
            fi
        ) || {
            rm -rf "$temp_dir"
            return 1
        }
        print_success "Checksums verified"
    else
        print_warning "No checksum file found, skipping verification"
    fi

    # Backup existing databases
    print_info "Backing up existing databases..."
    local backup_dir="${target_db_dir}/backup-$(date -u '+%Y%m%d-%H%M%S')"
    mkdir -p "$backup_dir"
    for db in main.cvd daily.cvd bytecode.cvd main.cld daily.cld; do
        if [ -f "${target_db_dir}/${db}" ]; then
            cp "${target_db_dir}/${db}" "$backup_dir/" 2>/dev/null || true
        fi
    done
    print_success "Backup created at: ${backup_dir}"

    # Install new databases
    print_info "Installing new virus definitions..."
    for db in main.cvd daily.cvd bytecode.cvd; do
        if [ -f "${update_dir}/${db}" ]; then
            cp "${update_dir}/${db}" "${target_db_dir}/"
            local size
            size=$(du -h "${target_db_dir}/${db}" | cut -f1)
            print_success "Installed ${db} (${size})"
        fi
    done

    # Update timestamp file
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "${target_db_dir}/downloaded.txt"

    # Show update info
    if [ -f "${update_dir}/UPDATE-INFO.txt" ]; then
        echo ""
        echo "Update package info:"
        head -10 "${update_dir}/UPDATE-INFO.txt" | sed 's/^/  /'
    fi

    rm -rf "$temp_dir"

    echo ""
    print_success "ClamAV virus definitions updated successfully!"
    echo ""
    echo "Database location: ${target_db_dir}"
    echo ""

    return 0
}

# Show database status
show_status() {
    print_info "Checking ClamAV database status..."
    echo ""

    local found=false

    # Check all possible locations
    for location in \
        "$REPO_ROOT/clamav/db" \
        "$HOME/.security-toolkit/clamav/db" \
        "/opt/homebrew/var/lib/clamav" \
        "/var/lib/clamav" \
        "/usr/local/var/lib/clamav"; do

        if [ -d "$location" ] && [ -f "$location/main.cvd" ]; then
            found=true
            echo "Location: ${location}"
            echo ""

            for db in main.cvd daily.cvd bytecode.cvd; do
                if [ -f "${location}/${db}" ]; then
                    local size mtime
                    size=$(du -h "${location}/${db}" | cut -f1)
                    if [[ "$(uname)" == "Darwin" ]]; then
                        mtime=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "${location}/${db}")
                    else
                        mtime=$(stat -c '%y' "${location}/${db}" | cut -d'.' -f1)
                    fi
                    echo "  ${db}: ${size} (modified: ${mtime})"
                fi
            done

            if [ -f "${location}/downloaded.txt" ]; then
                echo ""
                echo "  Last updated: $(cat "${location}/downloaded.txt")"
            fi

            echo ""
        fi
    done

    if [ "$found" = false ]; then
        print_warning "No ClamAV databases found"
        echo ""
        echo "To install ClamAV:"
        echo "  - Download a platform-specific release with bundled ClamAV"
        echo "  - Or install via package manager: brew install clamav"
    fi
}

# Print usage
usage() {
    cat << EOF
Usage: $(basename "$0") <command> [options]

Commands:
  --download [output-dir]    Download fresh virus definitions and create update package
                             (Run this on a machine with internet access)

  --apply <package-file>     Apply an update package to the local ClamAV installation
                             (Run this on the airgapped machine)

  --status                   Show current database status and locations

  --help                     Show this help message

Examples:
  # On connected machine: download latest definitions
  $(basename "$0") --download
  $(basename "$0") --download /media/usb-drive/

  # On airgapped machine: apply the update
  $(basename "$0") --apply clamav-db-update-2026-02-03.tar.gz

  # Check current database status
  $(basename "$0") --status

Workflow for Airgapped Systems:
  1. On a machine with internet access:
     ./scripts/update-clamav-offline.sh --download

  2. Copy the generated .tar.gz file to a USB drive

  3. On the airgapped machine:
     ./scripts/update-clamav-offline.sh --apply /media/usb/clamav-db-update-*.tar.gz

Note: Virus definitions should be updated regularly. Outdated definitions
provide less protection against recent malware threats.
EOF
}

# Main
main() {
    print_header

    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi

    case "$1" in
        --download)
            shift
            download_updates "${1:-.}"
            ;;
        --apply)
            shift
            if [ $# -eq 0 ]; then
                print_error "Missing package file argument"
                echo "Usage: $(basename "$0") --apply <package-file>"
                exit 2
            fi
            apply_updates "$1"
            ;;
        --status)
            show_status
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown command: $1"
            usage
            exit 2
            ;;
    esac
}

main "$@"
