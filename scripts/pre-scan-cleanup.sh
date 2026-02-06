#!/bin/bash
#
# Pre-Scan Cleanup Script
#
# Purpose: Clean temporary files, caches, and logs before security scans
# Method: Native commands on macOS, BleachBit on Linux
#
# Benefits:
#   - Reduces scan time by eliminating unnecessary files
#   - Removes cached data that could contain sensitive information
#   - Clears browser history/cookies that might trigger false positives
#   - Ensures scans focus on actual project/system files
#
# Standards:
#   - NIST SP 800-53: SI-14 (Non-Persistence)
#   - NIST SP 800-88: Media Sanitization (for temp file cleanup)
#
# Exit codes:
#   0 = Cleanup completed successfully
#   1 = Error during cleanup
#   2 = Required tools not available (Linux only - BleachBit)
#
# Usage: ./pre-scan-cleanup.sh [OPTIONS]
#        -n, --dry-run     Show what would be cleaned without deleting
#        -a, --aggressive  Include additional cleaners (logs, recent docs)
#        -b, --browsers    Clean browser data only
#        -s, --system      Clean system caches only
#        -h, --help        Show this help message

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source shared libraries
AUDIT_AVAILABLE=0
TIMESTAMPS_AVAILABLE=0

if [ -f "$SCRIPT_DIR/lib/audit-log.sh" ]; then
    source "$SCRIPT_DIR/lib/audit-log.sh"
    AUDIT_AVAILABLE=1
fi

if [ -f "$SCRIPT_DIR/lib/timestamps.sh" ]; then
    source "$SCRIPT_DIR/lib/timestamps.sh"
    TIMESTAMPS_AVAILABLE=1
fi

# Get timestamps
if [ "$TIMESTAMPS_AVAILABLE" -eq 1 ]; then
    TIMESTAMP=$(get_iso_timestamp)
else
    TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
fi

# Help function
show_help() {
    cat << 'EOF'
Usage: pre-scan-cleanup.sh [OPTIONS]

Clean temporary files, caches, and logs before running security scans.
Uses native commands on macOS, BleachBit on Linux.

OPTIONS:
  -n, --dry-run     Preview what would be cleaned (no actual deletion)
  -a, --aggressive  Include additional cleaners (system logs, recent docs)
  -b, --browsers    Clean browser data only (caches, cookies, history)
  -s, --system      Clean system caches only (temp files, thumbnails)
  -q, --quiet       Minimal output (errors only)
  -h, --help        Show this help message

DEFAULT CLEANERS (always included):
  - System temp files and caches
  - Thumbnail caches
  - Trash
  - Crash reports

BROWSER CLEANERS (-b or default):
  - Chrome/Chromium cache, cookies, history
  - Firefox cache, cookies, history
  - Safari cache (macOS)

AGGRESSIVE CLEANERS (-a):
  - System logs older than 7 days
  - Recent document lists
  - Bash/Zsh history (USE WITH CAUTION)
  - Application support caches
  - Xcode derived data (macOS)

EXAMPLES:
  ./pre-scan-cleanup.sh              # Standard cleanup
  ./pre-scan-cleanup.sh -n           # Dry run (preview only)
  ./pre-scan-cleanup.sh -b           # Browsers only
  ./pre-scan-cleanup.sh -a           # Aggressive cleanup
  ./pre-scan-cleanup.sh -s -n        # Preview system cleanup

PLATFORMS:
  macOS:   Uses native rm/find commands (no dependencies)
  Linux:   Uses BleachBit (sudo apt install bleachbit)

NIST CONTROLS:
  SI-14  Non-Persistence (clearing cached/temporary data)
  SP 800-88  Media Sanitization guidelines

EOF
    exit 0
}

# Parse arguments
DRY_RUN=0
AGGRESSIVE=0
BROWSERS_ONLY=0
SYSTEM_ONLY=0
QUIET=0

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -a|--aggressive)
            AGGRESSIVE=1
            shift
            ;;
        -b|--browsers)
            BROWSERS_ONLY=1
            shift
            ;;
        -s|--system)
            SYSTEM_ONLY=1
            shift
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h for help"
            exit 1
            ;;
    esac
done

# Track cleanup statistics
TOTAL_FILES=0
TOTAL_BYTES=0
CLEANED_ITEMS=()

# Function to calculate directory size
get_dir_size() {
    local dir="$1"
    if [ -d "$dir" ]; then
        du -sk "$dir" 2>/dev/null | awk '{print $1}' || echo "0"
    else
        echo "0"
    fi
}

# Function to count files in directory
count_files() {
    local dir="$1"
    if [ -d "$dir" ]; then
        find "$dir" -type f 2>/dev/null | wc -l | tr -d ' '
    else
        echo "0"
    fi
}

# Function to clean a directory
clean_directory() {
    local dir="$1"
    local desc="$2"

    if [ -d "$dir" ]; then
        local size=$(get_dir_size "$dir")
        local files=$(count_files "$dir")

        if [ "${files:-0}" -gt 0 ] || [ "${size:-0}" -gt 0 ]; then
            if [ "$DRY_RUN" -eq 1 ]; then
                [ "$QUIET" -eq 0 ] && echo "  [DRY RUN] $desc: $files files, ${size}KB"
            else
                rm -rf "$dir"/* 2>/dev/null || true
                [ "$QUIET" -eq 0 ] && echo "  [CLEANED] $desc: $files files, ${size}KB"
            fi
            TOTAL_FILES=$((TOTAL_FILES + files))
            TOTAL_BYTES=$((TOTAL_BYTES + size))
            CLEANED_ITEMS+=("$desc")
        fi
    fi
}

# Function to clean files matching pattern
clean_pattern() {
    local base_dir="$1"
    local pattern="$2"
    local desc="$3"
    local days="${4:-0}"  # Optional: only files older than N days

    if [ -d "$base_dir" ]; then
        local find_cmd="find \"$base_dir\" -name \"$pattern\" -type f"
        [ "$days" -gt 0 ] && find_cmd="$find_cmd -mtime +$days"

        local files=$(eval "$find_cmd" 2>/dev/null | wc -l | tr -d ' ')
        local size=$(eval "$find_cmd -exec du -sk {} + 2>/dev/null" | awk '{sum+=$1} END {print sum+0}')

        if [ "$files" -gt 0 ]; then
            if [ "$DRY_RUN" -eq 1 ]; then
                [ "$QUIET" -eq 0 ] && echo "  [DRY RUN] $desc: $files files, ${size}KB"
            else
                eval "$find_cmd -delete 2>/dev/null" || true
                [ "$QUIET" -eq 0 ] && echo "  [CLEANED] $desc: $files files, ${size}KB"
            fi
            TOTAL_FILES=$((TOTAL_FILES + files))
            TOTAL_BYTES=$((TOTAL_BYTES + size))
            CLEANED_ITEMS+=("$desc")
        fi
    fi
}

# Audit log start
if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
    init_audit_log "$SECURITY_REPO_DIR" "cleanup"

    # Build options string for audit
    OPTIONS=""
    [ "$DRY_RUN" -eq 1 ] && OPTIONS="$OPTIONS dry-run"
    [ "$AGGRESSIVE" -eq 1 ] && OPTIONS="$OPTIONS aggressive"
    [ "$BROWSERS_ONLY" -eq 1 ] && OPTIONS="$OPTIONS browsers-only"
    [ "$SYSTEM_ONLY" -eq 1 ] && OPTIONS="$OPTIONS system-only"
    OPTIONS="${OPTIONS:- default}"

    audit_log "CLEANUP_START" "platform=$(uname) options=$OPTIONS dry_run=$DRY_RUN"
fi

# Aggressive mode warning
if [ "$AGGRESSIVE" -eq 1 ] && [ "$QUIET" -eq 0 ]; then
    echo "WARNING: Aggressive mode enabled - this will clear:"
    echo "  - Shell history (bash/zsh)"
    echo "  - Recent documents list"
    echo "  - System logs (older than 7 days)"
    echo "  - Xcode derived data"
    echo ""
    if [ "$DRY_RUN" -eq 0 ]; then
        echo -n "Continue? [y/N] "
        read -r confirm </dev/tty
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 0
        fi
    fi
fi

# Header
if [ "$QUIET" -eq 0 ]; then
    echo "=============================================="
    echo "Pre-Scan Cleanup"
    echo "=============================================="
    echo "Timestamp: $TIMESTAMP"
    echo "Platform: $(uname)"
    echo "Mode: $([ "$DRY_RUN" -eq 1 ] && echo "DRY RUN (preview)" || echo "EXECUTE")"
    echo ""
fi

# ============================================================================
# macOS Native Cleanup
# ============================================================================
if [[ "$(uname)" == "Darwin" ]]; then

    # ----- SYSTEM CACHES (unless browsers-only) -----
    if [ "$BROWSERS_ONLY" -eq 0 ]; then
        [ "$QUIET" -eq 0 ] && echo "System Caches:"

        # User caches
        clean_directory ~/Library/Caches "User Library Caches"

        # Crash reports
        clean_directory ~/Library/Logs/DiagnosticReports "Crash Reports (User)"
        clean_directory /Library/Logs/DiagnosticReports "Crash Reports (System)"

        # Temporary files
        clean_directory /tmp "System Temp (/tmp)"
        clean_directory /private/var/tmp "System Temp (/var/tmp)"

        # Trash (use AppleScript to empty all volumes including external drives)
        if [ "$DRY_RUN" -eq 1 ]; then
            trash_count=$(ls -A ~/.Trash 2>/dev/null | wc -l | tr -d ' ')
            [ "$QUIET" -eq 0 ] && echo "  [DRY RUN] Trash: $trash_count items (all volumes)"
        else
            osascript -e 'tell application "Finder" to empty trash' 2>/dev/null || true
            [ "$QUIET" -eq 0 ] && echo "  [CLEANED] Trash: emptied (all volumes)"
        fi

        # Thumbnail cache
        clean_directory ~/Library/Caches/com.apple.QuickLook.thumbnailcache "QuickLook Thumbnails"

        # .DS_Store files (project directories only)
        clean_pattern ~ ".DS_Store" "DS_Store files"

        [ "$QUIET" -eq 0 ] && echo ""
    fi

    # ----- BROWSER CACHES (unless system-only) -----
    if [ "$SYSTEM_ONLY" -eq 0 ]; then
        [ "$QUIET" -eq 0 ] && echo "Browser Caches:"

        # Chrome
        clean_directory ~/Library/Caches/Google/Chrome "Chrome Cache"
        clean_directory ~/Library/Application\ Support/Google/Chrome/Default/Cache "Chrome Default Cache"
        clean_directory ~/Library/Application\ Support/Google/Chrome/Default/Code\ Cache "Chrome Code Cache"

        # Firefox
        clean_directory ~/Library/Caches/Firefox "Firefox Cache"
        # Firefox profiles cache
        if [ -d ~/Library/Application\ Support/Firefox/Profiles ]; then
            for profile in ~/Library/Application\ Support/Firefox/Profiles/*/; do
                clean_directory "${profile}cache2" "Firefox Profile Cache"
            done
        fi

        # Safari
        clean_directory ~/Library/Caches/com.apple.Safari "Safari Cache"
        clean_directory ~/Library/Caches/com.apple.Safari.SafeBrowsing "Safari Safe Browsing Cache"

        # Edge
        clean_directory ~/Library/Caches/Microsoft\ Edge "Edge Cache"
        clean_directory ~/Library/Application\ Support/Microsoft\ Edge/Default/Cache "Edge Default Cache"

        # Brave
        clean_directory ~/Library/Caches/BraveSoftware/Brave-Browser "Brave Cache"

        [ "$QUIET" -eq 0 ] && echo ""
    fi

    # ----- AGGRESSIVE CLEANERS -----
    if [ "$AGGRESSIVE" -eq 1 ]; then
        [ "$QUIET" -eq 0 ] && echo "Aggressive Cleanup:"

        # Shell history
        if [ -f ~/.bash_history ]; then
            hist_size=$(du -sk ~/.bash_history 2>/dev/null | awk '{print $1}' || echo "0")
            if [ "$DRY_RUN" -eq 1 ]; then
                [ "$QUIET" -eq 0 ] && echo "  [DRY RUN] Bash history: ${hist_size}KB"
            else
                > ~/.bash_history
                [ "$QUIET" -eq 0 ] && echo "  [CLEANED] Bash history: ${hist_size}KB"
            fi
            TOTAL_BYTES=$((TOTAL_BYTES + hist_size))
        fi

        if [ -f ~/.zsh_history ]; then
            zhist_size=$(du -sk ~/.zsh_history 2>/dev/null | awk '{print $1}' || echo "0")
            if [ "$DRY_RUN" -eq 1 ]; then
                [ "$QUIET" -eq 0 ] && echo "  [DRY RUN] Zsh history: ${zhist_size}KB"
            else
                > ~/.zsh_history
                [ "$QUIET" -eq 0 ] && echo "  [CLEANED] Zsh history: ${zhist_size}KB"
            fi
            TOTAL_BYTES=$((TOTAL_BYTES + zhist_size))
        fi

        # Recent documents (LSSharedFileList)
        clean_directory ~/Library/Application\ Support/com.apple.sharedfilelist "Recent Documents"

        # Old system logs
        if [ -d /var/log ]; then
            old_logs=$(find /var/log -type f -mtime +7 2>/dev/null | wc -l | tr -d ' ')
            if [ "$old_logs" -gt 0 ]; then
                if [ "$DRY_RUN" -eq 1 ]; then
                    [ "$QUIET" -eq 0 ] && echo "  [DRY RUN] Old system logs (>7 days): $old_logs files"
                else
                    sudo find /var/log -type f -mtime +7 -delete 2>/dev/null || true
                    [ "$QUIET" -eq 0 ] && echo "  [CLEANED] Old system logs (>7 days): $old_logs files"
                fi
                TOTAL_FILES=$((TOTAL_FILES + old_logs))
            fi
        fi

        # Xcode derived data
        clean_directory ~/Library/Developer/Xcode/DerivedData "Xcode Derived Data"

        # iOS device support (can be huge)
        clean_directory ~/Library/Developer/Xcode/iOS\ DeviceSupport "Xcode iOS Device Support"

        # Homebrew cache
        clean_directory ~/Library/Caches/Homebrew "Homebrew Cache"

        # npm cache
        clean_directory ~/.npm/_cacache "npm Cache"

        # pip cache
        clean_directory ~/Library/Caches/pip "pip Cache"

        [ "$QUIET" -eq 0 ] && echo ""
    fi

# ============================================================================
# Linux Cleanup (using BleachBit)
# ============================================================================
elif [[ "$(uname)" == "Linux" ]]; then
    # Check for BleachBit on Linux
    if ! command -v bleachbit >/dev/null 2>&1; then
        echo "ERROR: BleachBit is not installed."
        echo ""
        echo "Install with:"
        echo "  Ubuntu/Debian:  sudo apt install bleachbit"
        echo "  Fedora:         sudo dnf install bleachbit"
        echo "  Arch:           sudo pacman -S bleachbit"
        echo ""
        echo "BleachBit is an open source system cleaner:"
        echo "  https://www.bleachbit.org/"
        exit 2
    fi

    BLEACHBIT_VERSION=$(bleachbit --version 2>/dev/null | head -1 || echo "unknown")
    [ "$QUIET" -eq 0 ] && echo "Using BleachBit: $BLEACHBIT_VERSION"
    [ "$QUIET" -eq 0 ] && echo ""

    # Build cleaner list
    CLEANERS=""

    # System cleaners
    if [ "$BROWSERS_ONLY" -eq 0 ]; then
        CLEANERS="$CLEANERS system.cache system.tmp system.trash thumbnails.cache"
        CLEANERS="$CLEANERS apt.autoclean apt.clean"
    fi

    # Browser cleaners
    if [ "$SYSTEM_ONLY" -eq 0 ]; then
        CLEANERS="$CLEANERS chromium.cache chromium.cookies chromium.history"
        CLEANERS="$CLEANERS google_chrome.cache google_chrome.cookies google_chrome.history"
        CLEANERS="$CLEANERS firefox.cache firefox.cookies firefox.url_history"
    fi

    # Aggressive cleaners
    if [ "$AGGRESSIVE" -eq 1 ]; then
        CLEANERS="$CLEANERS system.rotated_logs bash.history system.recent_documents"
    fi

    # Filter to valid cleaners
    AVAILABLE_CLEANERS=$(bleachbit --list-cleaners 2>/dev/null || echo "")
    VALID_CLEANERS=""
    for cleaner in $CLEANERS; do
        if echo "$AVAILABLE_CLEANERS" | grep -q "^$cleaner$"; then
            VALID_CLEANERS="$VALID_CLEANERS $cleaner"
        fi
    done

    if [ -z "$VALID_CLEANERS" ]; then
        echo "No valid cleaners found."
        exit 1
    fi

    # Run BleachBit
    if [ "$DRY_RUN" -eq 1 ]; then
        bleachbit --preview $VALID_CLEANERS 2>&1
    else
        bleachbit --clean $VALID_CLEANERS 2>&1
    fi
fi

# ============================================================================
# Summary
# ============================================================================
if [ "$QUIET" -eq 0 ]; then
    echo "=============================================="
    echo "Summary"
    echo "=============================================="

    # Convert KB to human readable
    if [ "$TOTAL_BYTES" -gt 1048576 ]; then
        SIZE_HUMAN="$((TOTAL_BYTES / 1048576)) GB"
    elif [ "$TOTAL_BYTES" -gt 1024 ]; then
        SIZE_HUMAN="$((TOTAL_BYTES / 1024)) MB"
    else
        SIZE_HUMAN="${TOTAL_BYTES} KB"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "DRY RUN - No files were deleted"
        echo "Would clean: $TOTAL_FILES files ($SIZE_HUMAN)"
        echo ""
        echo "Run without -n to execute cleanup."
    else
        echo "Cleaned: $TOTAL_FILES files ($SIZE_HUMAN)"
        echo "System ready for security scan."
    fi
    echo "=============================================="
fi

# Audit log completion
if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
    audit_log "CLEANUP_COMPLETE" "files_cleaned=$TOTAL_FILES bytes_freed=$TOTAL_BYTES dry_run=$DRY_RUN"
fi

exit 0
