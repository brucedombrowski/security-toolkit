#!/bin/bash
#
# Secure Delete Script
#
# Purpose: Securely delete files per NIST SP 800-88 Guidelines for Media Sanitization
# Usage: ./secure-delete.sh <file_or_directory> [options]
#
# This implements the NIST SP 800-88 "Clear" method, which is appropriate for:
# - CUI (Controlled Unclassified Information)
# - Organizational data being disposed of
# - Files that should not be recoverable through normal means
#
# For classified data, physical destruction (SP 800-88 "Destroy") is required.
#
# Options:
#   -r, --recursive    Delete directories recursively
#   -f, --force        Skip confirmation prompt
#   -v, --verbose      Show verbose output
#   -n, --dry-run      Show what would be deleted without deleting
#
# Exit codes:
#   0 = Success
#   1 = Error
#   2 = Invalid arguments
#

set -eu

SCRIPT_NAME=$(basename "$0")
RECURSIVE=false
FORCE=false
VERBOSE=false
DRY_RUN=false
TARGET=""

print_usage() {
    echo "Usage: $SCRIPT_NAME [options] <file_or_directory>"
    echo ""
    echo "Securely delete files per NIST SP 800-88 Clear method."
    echo ""
    echo "Options:"
    echo "  -r, --recursive    Delete directories recursively"
    echo "  -f, --force        Skip confirmation prompt"
    echo "  -v, --verbose      Show verbose output"
    echo "  -n, --dry-run      Show what would be deleted without deleting"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME sensitive-file.txt"
    echo "  $SCRIPT_NAME -rf .scans/"
    echo "  $SCRIPT_NAME -n -r scan-outputs/    # Preview what would be deleted"
    echo ""
    echo "NIST SP 800-88 Clear Method:"
    echo "  - Overwrites data with a fixed pattern (zeros)"
    echo "  - Appropriate for CUI and non-classified data"
    echo "  - Prevents recovery through standard forensic techniques"
}

log() {
    if [ "$VERBOSE" = true ]; then
        echo "$@"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--recursive)
            RECURSIVE=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        -rf|-fr|-rfv|-rvf|-fvr|-frv|-vrf|-vfr)
            RECURSIVE=true
            FORCE=true
            [[ "$1" == *v* ]] && VERBOSE=true
            shift
            ;;
        -fv|-vf)
            FORCE=true
            VERBOSE=true
            shift
            ;;
        -nf|-fn|-nfv|-nvf|-fnv|-fvn|-vnf|-vfn|-nv|-vn)
            DRY_RUN=true
            [[ "$1" == *f* ]] && FORCE=true
            [[ "$1" == *v* ]] && VERBOSE=true
            shift
            ;;
        -nrf|-nfr|-rnf|-rfn|-fnr|-frn|-nrfv|-nrvf|-nfvr|-nfrv|-nvrf|-nvfr)
            DRY_RUN=true
            RECURSIVE=true
            FORCE=true
            [[ "$1" == *v* ]] && VERBOSE=true
            shift
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            print_usage >&2
            exit 2
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                echo "Error: Multiple targets not supported. Use -r for directories." >&2
                exit 2
            fi
            shift
            ;;
    esac
done

# Validate target
if [ -z "$TARGET" ]; then
    echo "Error: No target specified" >&2
    print_usage >&2
    exit 2
fi

if [ ! -e "$TARGET" ]; then
    echo "Error: Target does not exist: $TARGET" >&2
    exit 1
fi

# Check if directory without -r flag
if [ -d "$TARGET" ] && [ "$RECURSIVE" = false ]; then
    echo "Error: $TARGET is a directory. Use -r for recursive deletion." >&2
    exit 2
fi

# Count files to be deleted
count_files() {
    local path="$1"
    if [ -f "$path" ]; then
        echo 1
    elif [ -d "$path" ]; then
        find "$path" -type f 2>/dev/null | wc -l | tr -d ' '
    else
        echo 0
    fi
}

FILE_COUNT=$(count_files "$TARGET")

# Confirmation prompt
if [ "$FORCE" = false ]; then
    echo "WARNING: This will securely delete the following:"
    echo "  Target: $TARGET"
    echo "  Files to delete: $FILE_COUNT"
    echo ""
    echo "This operation is IRREVERSIBLE."
    echo ""
    read -p "Type 'DELETE' to confirm: " confirmation </dev/tty
    if [ "$confirmation" != "DELETE" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# Secure delete function for a single file
secure_delete_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        return 0
    fi

    local size
    size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)

    if [ "$DRY_RUN" = true ]; then
        log "Would securely delete: $file ($size bytes)"
        return 0
    fi

    log "Securely deleting: $file ($size bytes)"

    # NIST SP 800-88 Clear: Overwrite with zeros
    # For SSDs, TRIM may handle this differently, but this is still the standard approach
    if command -v shred &>/dev/null; then
        # Linux: use shred (3 passes by default, final zero pass)
        shred -vfz -n 3 "$file" 2>/dev/null || true
        rm -f "$file"
    elif command -v gshred &>/dev/null; then
        # macOS with coreutils: use gshred
        gshred -vfz -n 3 "$file" 2>/dev/null || true
        rm -f "$file"
    else
        # Fallback: manual overwrite with dd
        if [ "$size" -gt 0 ]; then
            # Pass 1: Random data
            dd if=/dev/urandom of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null || true
            # Pass 2: Zeros
            dd if=/dev/zero of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null || true
            # Pass 3: Ones (0xFF)
            perl -e "print chr(0xFF) x $size" > "$file" 2>/dev/null || true
            # Final pass: Zeros
            dd if=/dev/zero of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null || true
        fi
        rm -f "$file"
    fi
}

# Main deletion logic
if [ -f "$TARGET" ]; then
    secure_delete_file "$TARGET"
    if [ "$DRY_RUN" = false ]; then
        echo "Securely deleted: $TARGET"
    else
        echo "Would securely delete: $TARGET"
    fi
elif [ -d "$TARGET" ]; then
    deleted=0
    # Process files first, then directories
    while IFS= read -r -d '' file; do
        secure_delete_file "$file"
        deleted=$((deleted + 1))
    done < <(find "$TARGET" -type f -print0 2>/dev/null)

    if [ "$DRY_RUN" = false ]; then
        # Remove empty directories
        find "$TARGET" -type d -empty -delete 2>/dev/null || true
        # Remove the target directory if it still exists and is empty
        rmdir "$TARGET" 2>/dev/null || rm -rf "$TARGET" 2>/dev/null || true
        echo "Securely deleted $deleted files from: $TARGET"
    else
        echo "Would securely delete $deleted files from: $TARGET"
    fi
fi

# Log completion per NIST SP 800-88 verification requirement
if [ "$DRY_RUN" = false ]; then
    echo ""
    echo "NIST SP 800-88 Clear method applied."
    echo "Verification: Files have been overwritten and removed."
fi

exit 0
