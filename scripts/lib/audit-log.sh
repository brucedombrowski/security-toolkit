#!/bin/bash
#
# Audit Logging Library
#
# Purpose: Shared audit logging functions for security scan scripts
# NIST Controls:
#   - AU-2 (Audit Events): Defines auditable events for scanning operations
#   - AU-3 (Content of Audit Records): Structured logging with required fields
#
# Usage:
#   source "$SCRIPT_DIR/lib/audit-log.sh"
#   init_audit_log "/path/to/target" "pii-scan"
#   audit_log "SCAN_START" "target=/path/to/project"
#   audit_log "FINDING_DETECTED" "SSN pattern in src/data.txt:42"
#   audit_log "SCAN_COMPLETE" "status=FAIL findings=3"
#
# Output Format: JSON Lines (.jsonl) for machine parsing
#   Each line is a valid JSON object with:
#   - timestamp: ISO 8601 UTC format
#   - host: hostname of scanning machine
#   - user: username running the scan
#   - pid: process ID of scan
#   - scan_type: type of scan (pii, secrets, malware, etc.)
#   - event: event type (see Event Types below)
#   - details: event-specific information
#
# Event Types:
#   SCAN_START       - Scan initiated
#   SCAN_COMPLETE    - Scan finished (pass/fail)
#   FINDING_DETECTED - PII/secret/malware found
#   ALLOWLIST_MATCH  - Finding suppressed by allowlist
#   FILE_SKIPPED     - File excluded (symlink, binary, etc.)
#   CONFIG_CHANGE    - Allowlist or config modified
#   ERROR            - Script error occurred
#
# File Location:
#   <target>/.scans/audit-log-YYYY-MM-DD.jsonl
#   Logs are rotated daily (one file per day)
#   Already excluded from git via .scans/ gitignore rule

# Audit log configuration
AUDIT_LOG_FILE=""
AUDIT_LOG_SCAN_TYPE=""
AUDIT_LOG_ENABLED=1

# Initialize audit logging for a scan session
# Arguments:
#   $1 - target directory being scanned
#   $2 - scan type (pii, secrets, malware, host-security, vulnerabilities, etc.)
# Returns:
#   0 on success, 1 on failure
init_audit_log() {
    local target_dir="$1"
    local scan_type="$2"

    # Validate arguments
    if [ -z "$target_dir" ] || [ -z "$scan_type" ]; then
        echo "Warning: init_audit_log requires target_dir and scan_type" >&2
        AUDIT_LOG_ENABLED=0
        return 1
    fi

    # Ensure .scans directory exists
    local scans_dir="$target_dir/.scans"
    if [ ! -d "$scans_dir" ]; then
        mkdir -p "$scans_dir" 2>/dev/null || {
            echo "Warning: Could not create .scans directory for audit log" >&2
            AUDIT_LOG_ENABLED=0
            return 1
        }
    fi

    # Set audit log file path (daily rotation)
    local date_stamp=$(date -u +%Y-%m-%d)
    AUDIT_LOG_FILE="$scans_dir/audit-log-$date_stamp.jsonl"
    AUDIT_LOG_SCAN_TYPE="$scan_type"
    AUDIT_LOG_ENABLED=1

    # Log scan start
    audit_log "SCAN_START" "target=$target_dir"

    return 0
}

# Write an audit log entry
# Arguments:
#   $1 - event type (SCAN_START, FINDING_DETECTED, etc.)
#   $2 - details string (event-specific information)
# Returns:
#   0 on success, 1 if logging disabled or failed
audit_log() {
    local event_type="$1"
    local details="$2"

    # Skip if logging disabled
    if [ "$AUDIT_LOG_ENABLED" -ne 1 ] || [ -z "$AUDIT_LOG_FILE" ]; then
        return 1
    fi

    # Validate event type
    if [ -z "$event_type" ]; then
        return 1
    fi

    # Collect audit record fields (AU-3 compliance)
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local hostname=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")
    local username=$(whoami 2>/dev/null || echo "unknown")
    local process_id=$$

    # Escape all string fields for JSON safety
    # Replace backslashes first, then quotes, then control characters
    local escaped_hostname=$(printf '%s' "$hostname" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local escaped_username=$(printf '%s' "$username" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local escaped_scan_type=$(printf '%s' "$AUDIT_LOG_SCAN_TYPE" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local escaped_event=$(printf '%s' "$event_type" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local escaped_details=$(printf '%s' "$details" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | tr '\n' ' ')

    # Write JSON Lines format entry
    # Using printf for reliable JSON formatting
    printf '{"timestamp":"%s","host":"%s","user":"%s","pid":%d,"scan_type":"%s","event":"%s","details":"%s"}\n' \
        "$timestamp" \
        "$escaped_hostname" \
        "$escaped_username" \
        "$process_id" \
        "$escaped_scan_type" \
        "$escaped_event" \
        "$escaped_details" \
        >> "$AUDIT_LOG_FILE" 2>/dev/null

    return $?
}

# Finalize audit logging for a scan session
# Arguments:
#   $1 - status (PASS or FAIL)
#   $2 - summary (e.g., "findings=3" or "No issues detected")
# Returns:
#   0 on success
finalize_audit_log() {
    local status="$1"
    local summary="$2"

    audit_log "SCAN_COMPLETE" "status=$status $summary"

    # Clear state
    AUDIT_LOG_FILE=""
    AUDIT_LOG_SCAN_TYPE=""

    return 0
}

# Log a finding detection
# Arguments:
#   $1 - finding type (e.g., "SSN", "API_KEY", "MALWARE")
#   $2 - location (e.g., "src/config.js:42")
#   $3 - optional: additional details
audit_log_finding() {
    local finding_type="$1"
    local location="$2"
    local extra="${3:-}"

    local details="type=$finding_type location=$location"
    if [ -n "$extra" ]; then
        details="$details $extra"
    fi

    audit_log "FINDING_DETECTED" "$details"
}

# Log an allowlist match (finding suppressed)
# Arguments:
#   $1 - finding type
#   $2 - location
#   $3 - allowlist hash
audit_log_allowlist_match() {
    local finding_type="$1"
    local location="$2"
    local hash="$3"

    audit_log "ALLOWLIST_MATCH" "type=$finding_type location=$location hash=$hash"
}

# Log a skipped file
# Arguments:
#   $1 - file path
#   $2 - reason (symlink, binary, too_large, etc.)
audit_log_file_skipped() {
    local file_path="$1"
    local reason="$2"

    audit_log "FILE_SKIPPED" "file=$file_path reason=$reason"
}

# Log an error
# Arguments:
#   $1 - error message
#   $2 - optional: context
audit_log_error() {
    local message="$1"
    local context="${2:-}"

    local details="message=$message"
    if [ -n "$context" ]; then
        details="$details context=$context"
    fi

    audit_log "ERROR" "$details"
}

# Log a configuration change
# Arguments:
#   $1 - config type (allowlist, pattern, etc.)
#   $2 - action (add, remove, modify)
#   $3 - details
audit_log_config_change() {
    local config_type="$1"
    local action="$2"
    local change_details="$3"

    audit_log "CONFIG_CHANGE" "config=$config_type action=$action $change_details"
}

# Check if audit logging is enabled
# Returns:
#   0 if enabled, 1 if disabled
is_audit_log_enabled() {
    [ "$AUDIT_LOG_ENABLED" -eq 1 ] && [ -n "$AUDIT_LOG_FILE" ]
}

# Get the current audit log file path
# Returns:
#   Prints the path to stdout, or empty if not initialized
get_audit_log_path() {
    echo "$AUDIT_LOG_FILE"
}
