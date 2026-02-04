#!/bin/bash
#
# Create Air-Gap Bundle for Security Toolkit
#
# Purpose: Package ClamAV and/or virus definitions for air-gapped systems
# NIST Control: SI-3 (Malicious Code Protection)
#
# Usage:
#   ./create-airgap-bundle.sh [--lite|--full] [output_dir]
#
# Options:
#   --lite    Bundle virus definitions only (~170MB)
#             Requires ClamAV to be installed on target system
#
#   --full    Bundle ClamAV binary + libraries + virus definitions (~200MB)
#             Completely self-contained, no dependencies on target
#
# Output:
#   Creates a tarball ready for transfer to air-gapped system
#
# Exit codes:
#   0 = Success
#   1 = Error (missing dependencies, etc.)

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
BUNDLE_TYPE="full"
OUTPUT_DIR="$REPO_DIR"
TIMESTAMP=$(date -u "+%Y%m%d-%H%M%S")

# ============================================================================
# Helper Functions
# ============================================================================

print_step() {
    echo -e "${CYAN}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

show_help() {
    cat << 'HELP'
Create Air-Gap Bundle for Security Toolkit

Usage: ./create-airgap-bundle.sh [OPTIONS] [output_dir]

Options:
  --lite     Bundle virus definitions only (~170MB)
             - Smaller download/transfer
             - Requires ClamAV installed on air-gapped system
             - Good for updating definitions on existing installs

  --full     Bundle ClamAV + libraries + virus definitions (~200MB)
             - Completely self-contained
             - No dependencies needed on target system
             - Includes wrapper script for easy use

  -h, --help Show this help message

Examples:
  ./create-airgap-bundle.sh --lite ~/Desktop
  ./create-airgap-bundle.sh --full /mnt/usb

Output:
  security-toolkit-airgap-{lite|full}-YYYYMMDD-HHMMSS.tar.gz

On the air-gapped system:
  tar -xzf security-toolkit-airgap-*.tar.gz
  cd security-toolkit-airgap-*/
  ./scan.sh /path/to/scan        # Full bundle only
  # OR use bundled DB with system ClamAV (lite bundle)
HELP
    exit 0
}

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --lite)
            BUNDLE_TYPE="lite"
            shift
            ;;
        --full)
            BUNDLE_TYPE="full"
            shift
            ;;
        -h|--help)
            show_help
            ;;
        -*)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            OUTPUT_DIR="$1"
            shift
            ;;
    esac
done

# ============================================================================
# Locate ClamAV Components
# ============================================================================

find_clamscan() {
    local clamscan=""

    if command -v clamscan &>/dev/null; then
        clamscan=$(command -v clamscan)
    elif [ -x "/opt/homebrew/bin/clamscan" ]; then
        clamscan="/opt/homebrew/bin/clamscan"
    elif [ -x "/usr/local/bin/clamscan" ]; then
        clamscan="/usr/local/bin/clamscan"
    elif [ -x "/usr/bin/clamscan" ]; then
        clamscan="/usr/bin/clamscan"
    fi

    # Resolve symlink to actual binary
    if [ -n "$clamscan" ] && [ -L "$clamscan" ]; then
        clamscan=$(readlink -f "$clamscan" 2>/dev/null || realpath "$clamscan" 2>/dev/null || echo "$clamscan")
    fi

    echo "$clamscan"
}

find_clamav_db() {
    local db_dir=""

    for dir in /opt/homebrew/var/lib/clamav /var/lib/clamav /usr/local/var/lib/clamav; do
        if [ -d "$dir" ] && { [ -f "$dir/main.cvd" ] || [ -f "$dir/daily.cvd" ] || [ -f "$dir/daily.cld" ]; }; then
            db_dir="$dir"
            break
        fi
    done

    echo "$db_dir"
}

find_clamav_libs() {
    local clamscan="$1"
    local libs=()

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - use otool
        while IFS= read -r lib; do
            # Skip system libraries
            case "$lib" in
                /usr/lib/*|/System/*) continue ;;
            esac
            if [ -f "$lib" ]; then
                libs+=("$lib")
            fi
        done < <(otool -L "$clamscan" 2>/dev/null | grep -o '/opt/[^ ]*' || true)

        # Also get libclamav from the same Cellar
        local cellar_dir
        cellar_dir=$(dirname "$(dirname "$clamscan")")
        if [ -d "$cellar_dir/lib" ]; then
            for lib in "$cellar_dir"/lib/*.dylib; do
                [ -f "$lib" ] && libs+=("$lib")
            done
        fi
    else
        # Linux - use ldd
        while IFS= read -r lib; do
            # Skip system libraries
            case "$lib" in
                /lib/*|/usr/lib/*) continue ;;
            esac
            if [ -f "$lib" ]; then
                libs+=("$lib")
            fi
        done < <(ldd "$clamscan" 2>/dev/null | grep -o '/[^ ]*' || true)
    fi

    printf '%s\n' "${libs[@]}"
}

# ============================================================================
# Main
# ============================================================================

echo ""
echo -e "${BOLD}Security Toolkit - Air-Gap Bundle Creator${NC}"
echo "==========================================="
echo ""

# Validate output directory
if [ ! -d "$OUTPUT_DIR" ]; then
    print_error "Output directory does not exist: $OUTPUT_DIR"
    exit 1
fi

# Find ClamAV components
print_step "Locating ClamAV components..."

CLAMSCAN=$(find_clamscan)
if [ -z "$CLAMSCAN" ] || [ ! -x "$CLAMSCAN" ]; then
    print_error "ClamAV (clamscan) not found"
    echo "Install with: brew install clamav (macOS) or apt install clamav (Linux)"
    exit 1
fi
print_success "clamscan: $CLAMSCAN"

DB_DIR=$(find_clamav_db)
if [ -z "$DB_DIR" ]; then
    print_error "ClamAV virus database not found"
    echo "Run 'freshclam' to download virus definitions"
    exit 1
fi
print_success "Database: $DB_DIR"

# Get ClamAV version
CLAMAV_VERSION=$($CLAMSCAN --version 2>/dev/null | head -1)
echo "  Version: $CLAMAV_VERSION"
echo ""

# Create temp directory for bundle
BUNDLE_NAME="security-toolkit-airgap-${BUNDLE_TYPE}-${TIMESTAMP}"
BUNDLE_DIR=$(mktemp -d)
BUNDLE_PATH="$BUNDLE_DIR/$BUNDLE_NAME"
mkdir -p "$BUNDLE_PATH"

print_step "Creating $BUNDLE_TYPE bundle..."
echo ""

# Copy virus database (both lite and full)
print_step "Copying virus definitions..."
mkdir -p "$BUNDLE_PATH/clamav-db"
for db_file in main.cvd main.cld daily.cvd daily.cld bytecode.cvd bytecode.cld; do
    if [ -f "$DB_DIR/$db_file" ]; then
        cp "$DB_DIR/$db_file" "$BUNDLE_PATH/clamav-db/"
        print_success "  $db_file ($(du -h "$DB_DIR/$db_file" | cut -f1))"
    fi
done

# For full bundle, also copy binary and libraries
if [ "$BUNDLE_TYPE" = "full" ]; then
    print_step "Copying ClamAV binary..."
    mkdir -p "$BUNDLE_PATH/bin"
    cp "$CLAMSCAN" "$BUNDLE_PATH/bin/"
    print_success "  clamscan"

    print_step "Copying libraries..."
    mkdir -p "$BUNDLE_PATH/lib"
    while IFS= read -r lib; do
        if [ -n "$lib" ] && [ -f "$lib" ]; then
            cp "$lib" "$BUNDLE_PATH/lib/"
            print_success "  $(basename "$lib")"
        fi
    done < <(find_clamav_libs "$CLAMSCAN")

    # Create wrapper script
    print_step "Creating wrapper script..."
    cat > "$BUNDLE_PATH/scan.sh" << 'WRAPPER'
#!/bin/bash
#
# Air-Gap ClamAV Scanner Wrapper
# Generated by Security Toolkit
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DYLD_LIBRARY_PATH="$SCRIPT_DIR/lib:$DYLD_LIBRARY_PATH"
export LD_LIBRARY_PATH="$SCRIPT_DIR/lib:$LD_LIBRARY_PATH"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <directory_to_scan>"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/project"
    echo "  $0 ."
    exit 1
fi

TARGET="$1"

echo "Air-Gap ClamAV Scanner"
echo "======================"
echo "Database: $SCRIPT_DIR/clamav-db"
echo "Target: $TARGET"
echo ""

"$SCRIPT_DIR/bin/clamscan" \
    --database="$SCRIPT_DIR/clamav-db" \
    --recursive \
    --verbose \
    "$TARGET"
WRAPPER
    chmod +x "$BUNDLE_PATH/scan.sh"
    print_success "  scan.sh"
fi

# Create README
print_step "Creating README..."
cat > "$BUNDLE_PATH/README.txt" << README
Security Toolkit - Air-Gap Bundle
=================================

Bundle Type: $BUNDLE_TYPE
Created: $(date -u "+%Y-%m-%d %H:%M:%S UTC")
ClamAV Version: $CLAMAV_VERSION
Source System: $(uname -s) $(uname -m)

Contents:
---------
README

if [ "$BUNDLE_TYPE" = "full" ]; then
    cat >> "$BUNDLE_PATH/README.txt" << README
- bin/clamscan     ClamAV scanner binary
- lib/             Required libraries
- clamav-db/       Virus definitions
- scan.sh          Easy-to-use wrapper script

Usage:
------
1. Extract this bundle on the air-gapped system
2. Run: ./scan.sh /path/to/scan

Example:
  tar -xzf $BUNDLE_NAME.tar.gz
  cd $BUNDLE_NAME
  ./scan.sh /home/user/documents
README
else
    cat >> "$BUNDLE_PATH/README.txt" << README
- clamav-db/       Virus definitions

Usage:
------
1. Extract this bundle on the air-gapped system
2. Use with installed ClamAV:
   clamscan --database=/path/to/$BUNDLE_NAME/clamav-db -r /path/to/scan

Example:
  tar -xzf $BUNDLE_NAME.tar.gz
  clamscan --database=./$BUNDLE_NAME/clamav-db -r /home/user/documents

Note: ClamAV must be installed on the target system for lite bundles.
README
fi

cat >> "$BUNDLE_PATH/README.txt" << README

Updating Virus Definitions:
---------------------------
To update, create a new bundle on an internet-connected system:
  ./scripts/create-airgap-bundle.sh --$BUNDLE_TYPE

Database Age:
README

# Add database dates
for db_file in main.cvd daily.cvd daily.cld bytecode.cvd; do
    if [ -f "$BUNDLE_PATH/clamav-db/$db_file" ]; then
        db_date=$(stat -f "%Sm" -t "%Y-%m-%d" "$BUNDLE_PATH/clamav-db/$db_file" 2>/dev/null || stat -c "%y" "$BUNDLE_PATH/clamav-db/$db_file" 2>/dev/null | cut -d' ' -f1)
        echo "  $db_file: $db_date" >> "$BUNDLE_PATH/README.txt"
    fi
done

print_success "  README.txt"
echo ""

# Create tarball
print_step "Creating tarball..."
TARBALL="$OUTPUT_DIR/$BUNDLE_NAME.tar.gz"
(cd "$BUNDLE_DIR" && tar -czf "$TARBALL" "$BUNDLE_NAME")

# Get final size
TARBALL_SIZE=$(du -h "$TARBALL" | cut -f1)

# Cleanup
rm -rf "$BUNDLE_DIR"

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}Bundle created successfully!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo "  Output: $TARBALL"
echo "  Size:   $TARBALL_SIZE"
echo "  Type:   $BUNDLE_TYPE"
echo ""
echo "Transfer this file to your air-gapped system."
echo ""
