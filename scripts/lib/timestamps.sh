#!/bin/bash
#
# Timestamp Library
#
# Purpose: Standardized timestamp formats for security scan scripts
# NIST Controls:
#   - AU-8 (Time Stamps): Consistent UTC-based timestamps for audit records
#
# Usage:
#   source "$SCRIPT_DIR/lib/timestamps.sh"
#   TIMESTAMP=$(get_iso_timestamp)
#   DATE_STAMP=$(get_date_stamp)
#   FILENAME_TS=$(get_filename_timestamp)
#
# Standard Formats:
#   ISO 8601 UTC:     2026-01-15T08:00:00Z     (audit logs, machine parsing)
#   Date Only:        2026-01-15               (log rotation, daily files)
#   Filename Safe:    2026-01-15-T080000Z      (filenames, no colons)
#   Compact:          20260115-080000          (git branches, backups)
#   Human Readable:   January 15, 2026         (PDF documents, displays)
#   Unix Epoch:       1736936400               (elapsed time calculations)
#
# All timestamps use UTC (-u flag) for consistency across systems and timezones.
# This is critical for security audit trails and compliance reporting.

# ============================================================================
# Primary Timestamp Functions
# ============================================================================

# Get ISO 8601 UTC timestamp (primary standard)
# Format: 2026-01-15T08:00:00Z
# Use: Audit logs, JSON output, machine-readable records
get_iso_timestamp() {
    date -u "+%Y-%m-%dT%H:%M:%SZ"
}

# Get date-only stamp
# Format: 2026-01-15
# Use: Log rotation, daily file naming, date displays
get_date_stamp() {
    date -u "+%Y-%m-%d"
}

# Get filesystem-safe timestamp (no colons)
# Format: 2026-01-15-T080000Z
# Use: Filenames on all platforms (Windows doesn't allow colons)
get_filename_timestamp() {
    date -u "+%Y-%m-%d-T%H%M%SZ"
}

# Get compact timestamp for labels
# Format: 20260115-080000
# Use: Git branch names, backup labels, compact identifiers
get_compact_timestamp() {
    date -u "+%Y%m%d-%H%M%S"
}

# Get human-readable date
# Format: January 15, 2026
# Use: PDF documents, compliance statements, user-facing displays
get_human_date() {
    date -u "+%B %d, %Y"
}

# Get Unix epoch timestamp (seconds since 1970-01-01)
# Format: 1736936400
# Use: Elapsed time calculations, sorting, comparisons
get_unix_timestamp() {
    date +%s
}

# ============================================================================
# Elapsed Time Helpers
# ============================================================================

# Calculate elapsed time between two Unix timestamps
# Arguments:
#   $1 - start timestamp (from get_unix_timestamp)
#   $2 - end timestamp (from get_unix_timestamp)
# Returns: elapsed seconds
calculate_elapsed_seconds() {
    local start="$1"
    local end="$2"
    echo $((end - start))
}

# Format elapsed seconds as human-readable duration
# Arguments:
#   $1 - elapsed seconds
# Returns: formatted string (e.g., "2m 30s" or "1h 5m 30s")
format_elapsed_time() {
    local seconds="$1"
    local hours=$((seconds / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))

    if [ "$hours" -gt 0 ]; then
        printf "%dh %dm %ds" "$hours" "$minutes" "$secs"
    elif [ "$minutes" -gt 0 ]; then
        printf "%dm %ds" "$minutes" "$secs"
    else
        printf "%ds" "$secs"
    fi
}

# ============================================================================
# Validation Functions
# ============================================================================

# Validate ISO 8601 timestamp format
# Arguments:
#   $1 - timestamp string to validate
# Returns: 0 if valid, 1 if invalid
validate_iso_timestamp() {
    local ts="$1"
    # Pattern: YYYY-MM-DDTHH:MM:SSZ
    if [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
        return 0
    else
        return 1
    fi
}

# Validate date stamp format
# Arguments:
#   $1 - date string to validate
# Returns: 0 if valid, 1 if invalid
validate_date_stamp() {
    local ds="$1"
    # Pattern: YYYY-MM-DD
    if [[ "$ds" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Constants (for direct use without function call overhead)
# ============================================================================

# Format strings for direct use with date command
TS_FORMAT_ISO="+%Y-%m-%dT%H:%M:%SZ"
TS_FORMAT_DATE="+%Y-%m-%d"
TS_FORMAT_FILENAME="+%Y-%m-%d-T%H%M%SZ"
TS_FORMAT_COMPACT="+%Y%m%d-%H%M%S"
TS_FORMAT_HUMAN="+%B %d, %Y"
TS_FORMAT_UNIX="+%s"
