#!/bin/bash
#
# PII Verification Script
#
# Purpose: Automated scanning of repository files for potential PII patterns
# Method: Pattern matching using grep with regex
#
# Patterns checked:
#   - IP addresses (IPv4)
#   - Phone numbers (US formats + international with country code)
#   - Social Security Numbers
#   - Credit Card Numbers (validated with Luhn algorithm to reduce false positives)
#
# Exit codes:
#   0 = All checks passed (no PII found, or all reviewed/accepted)
#   1 = Potential PII detected (requires review)
#
# Usage: ./check-pii.sh [-i] [target_directory]
#        -i  Interactive mode: prompt to accept/reject each finding
#        If no target specified, uses parent directory of script location
#
# Allowlist:
#   Accepted findings are stored in <target>/.allowlists/pii-allowlist
#   Format: SHA256 hash of "file:line:content" per line
#   Allowlisted items are automatically skipped in future scans

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# Exclusion config file
PII_EXCLUDE_FILE=""

# Build find exclusion arguments from .pii-exclude file
# Populates global FIND_EXCLUSIONS array to avoid eval
FIND_EXCLUSIONS=()
build_exclusions() {
    local target_dir="$1"
    local exclude_file="$target_dir/.pii-exclude"
    FIND_EXCLUSIONS=()

    if [ -f "$exclude_file" ]; then
        PII_EXCLUDE_FILE="$exclude_file"
        while IFS= read -r line || [ -n "$line" ]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue

            # Trim whitespace
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"

            # Reject lines with shell metacharacters to prevent injection
            if [[ "$line" =~ [\;\|\&\$\`\(\)\{\}] ]]; then
                echo "Warning: Skipping unsafe pattern in .pii-exclude: $line" >&2
                continue
            fi

            # Directory patterns (end with /)
            if [[ "$line" == */ ]]; then
                local dir="${line%/}"
                FIND_EXCLUSIONS+=(-not -path "*/$dir/*")
            # File patterns (contain *)
            elif [[ "$line" == *"*"* ]]; then
                FIND_EXCLUSIONS+=(-not -name "$line")
            # Plain names (could be file or dir)
            else
                FIND_EXCLUSIONS+=(-not -path "*/$line/*" -not -name "$line")
            fi
        done < "$exclude_file"
    else
        # Fallback defaults if no config file
        FIND_EXCLUSIONS=(-not -path "*/.git/*" -not -path "*/.scans/*")
    fi
}

# Help function
show_help() {
    cat << 'EOF'
Usage: check-pii.sh [OPTIONS] [TARGET_DIRECTORY]

Scan files for potential Personally Identifiable Information (PII) patterns.

OPTIONS:
  -h, --help         Show this help message and exit
  -i, --interactive  Prompt to accept/reject each finding

ARGUMENTS:
  TARGET_DIRECTORY   Directory to scan (default: parent of script location)

PATTERNS DETECTED:
  - IPv4 addresses       192.168.x.x, 10.x.x.x, etc.
  - Phone numbers        US formats: (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx
  - International phones +XX XXX XXX XXXX (with country code)
  - Social Security      xxx-xx-xxxx format
  - Credit cards         16-digit patterns with Luhn algorithm validation

ALLOWLIST:
  Accepted findings are stored in <target>/.allowlists/pii-allowlist
  Each entry includes SHA256 hash and justification for audit trail.
  Allowlisted items are automatically skipped in future scans.

EXAMPLES:
  ./check-pii.sh                    # Scan parent directory
  ./check-pii.sh -i /path/to/code   # Interactive mode
  ./check-pii.sh .                  # Scan current directory

EXIT CODES:
  0  No PII found (or all findings allowlisted)
  1  Potential PII detected

NIST CONTROL: SI-12 (Information Management and Retention)
EOF
    exit 0
}

# Parse arguments
INTERACTIVE=0
TARGET_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -i|--interactive)
            INTERACTIVE=1
            shift
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

if [ -z "$TARGET_DIR" ]; then
    TARGET_DIR="$SECURITY_REPO_DIR"
fi

# Allowlist file location (in .allowlists/ directory, gitignored)
ALLOWLIST_DIR="$TARGET_DIR/.allowlists"
ALLOWLIST_FILE="$ALLOWLIST_DIR/pii-allowlist"

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit
REPO_NAME=$(basename "$TARGET_DIR")

# Files to scan (common text file types)
INCLUDE_PATTERNS=(
    "*.md" "*.txt" "*.tex" "*.rst"
    "*.sh" "*.bash" "*.zsh"
    "*.py" "*.js" "*.ts" "*.rb" "*.php" "*.go" "*.rs" "*.java" "*.cs" "*.c" "*.cpp" "*.h"
    "*.yaml" "*.yml" "*.json" "*.xml" "*.toml" "*.ini" "*.conf" "*.config"
    "*.html" "*.css" "*.scss"
    "*.sql"
    "*.env" "*.env.example"
)

FOUND_ISSUES=0
REVIEW_COUNT=0
ACCEPTED_COUNT=0
REJECTED_COUNT=0

# Function to extract content from a finding (strips file:line: prefix)
extract_content() {
    echo "$1" | cut -d: -f3-
}

# Function to compute hash for a finding (uses content only, not file:line)
# This makes allowlist entries stable across line number changes
hash_finding() {
    local content=$(extract_content "$1")
    echo -n "$content" | shasum -a 256 | awk '{print $1}'
}

# Function to check if a finding is allowlisted
is_allowlisted() {
    local finding="$1"
    local hash=$(hash_finding "$finding")
    if [ -f "$ALLOWLIST_FILE" ]; then
        if grep -q "^$hash" "$ALLOWLIST_FILE" 2>/dev/null; then
            # Log allowlist match for audit trail
            if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
                local file_path=$(echo "$finding" | cut -d: -f1)
                local line_num=$(echo "$finding" | cut -d: -f2)
                audit_log_allowlist_match "PII" "$file_path:$line_num" "$hash" || true
            fi
            return 0
        fi
    fi
    return 1
}

# Function to add a finding to the allowlist
add_to_allowlist() {
    local finding="$1"
    local reason="$2"
    local hash=$(hash_finding "$finding")

    # Create allowlist directory and file with header if they don't exist
    if [ ! -d "$ALLOWLIST_DIR" ]; then
        mkdir -p "$ALLOWLIST_DIR"
    fi
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        {
            echo "# PII Scan Allowlist"
            echo "# Format: SHA256_HASH # REASON # FINDING"
            echo "# Generated by Security Verification Toolkit"
            echo ""
        } > "$ALLOWLIST_FILE"
    fi

    # Add entry with hash, reason, and truncated finding for reference
    local truncated=$(echo "$finding" | cut -c1-80)
    echo "$hash # $reason # $truncated" >> "$ALLOWLIST_FILE"

    # Log config change for audit trail
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        audit_log_config_change "allowlist" "add" "hash=$hash reason=\"$reason\"" || true
    fi
}

# Function to prompt user for interactive review
prompt_review() {
    local finding="$1"
    local check_name="$2"

    # Parse the finding to extract file, line, and content
    local file_path=$(echo "$finding" | cut -d: -f1)
    local line_num=$(echo "$finding" | cut -d: -f2)
    local content=$(echo "$finding" | cut -d: -f3-)

    # Get relative path for cleaner display
    local rel_path="${file_path#$TARGET_DIR/}"

    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────────"
    echo "  │ REVIEW REQUIRED: $check_name"
    echo "  ├─────────────────────────────────────────────────────────────────"
    echo "  │ File: $rel_path"
    echo "  │ Line: $line_num"
    echo "  │"
    echo "  │ Content:"
    echo "  │   $content"
    echo "  └─────────────────────────────────────────────────────────────────"
    echo ""

    # Provide context-aware explanation based on content
    if echo "$content" | grep -qE "1\.3\.6\.1\.[0-9]"; then
        echo "  WHY THIS MATCHED:"
        echo "    This is an X.509 Object Identifier (OID), not an IP address."
        echo "    OIDs identify certificate purposes (Extended Key Usage)."
        echo "    Code uses these OIDs to filter certificates by purpose"
        echo "    (e.g., selecting only signing or encryption certificates)."
        echo "    Example: 1.3.6.1.5.5.7.3.4 = Email Protection EKU"
        echo ""
    elif echo "$content" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -qvE "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"; then
        echo "  WHY THIS MATCHED:"
        echo "    This appears to be a version number (e.g., 6.0.0.0), not an IP address."
        echo "    Version strings use similar dot notation but identify software releases."
        echo ""
    elif echo "$content" | grep -q "127\.0\.0\.1"; then
        echo "  WHY THIS MATCHED:"
        echo "    This is localhost (127.0.0.1) - the loopback address."
        echo "    It's commonly used in code to filter out local connections."
        echo "    This is NOT sensitive PII as it refers to the local machine, not a person."
        echo ""
    else
        echo "  WHY THIS MATCHED:"
        echo "    The pattern [0-9].[0-9].[0-9].[0-9] matches IPv4 address format."
        echo "    If this is actually an IP address, it could identify network infrastructure."
        echo "    Common false positives: OIDs, version numbers, file paths with numbers."
        echo ""
    fi

    echo "  OPTIONS:"
    echo "    [A]ccept  - This is NOT PII. Add to allowlist (custom reason)."
    echo "    [R]eject  - This IS PII or needs remediation. Flag as issue."
    echo "    [S]kip    - Unsure. Leave for later review."
    echo ""
    echo "  QUICK ACCEPT (common false positives):"
    echo "    [E]xample - Example/placeholder data (example.com, 192.0.2.x, etc.)"
    echo "    [O]ID     - X.509 Object Identifier (certificate EKU, etc.)"
    echo "    [V]ersion - Version number (e.g., 6.0.0.0)"
    echo "    [L]ocalhost - Loopback address (127.0.0.1)"
    echo "    [D]ocumentation - Documentation or comments"
    echo "    [X]Regex  - Sed/regex pattern for string substitution"
    echo ""

    while true; do
        echo -n "  Your decision [A/R/S/E/O/V/L/D/X]: "
        read -r response < /dev/tty
        case "$response" in
            [Ee]*)
                add_to_allowlist "$finding" "Example/placeholder data (not real PII)"
                echo "  → Added to allowlist: Example data"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0
                ;;
            [Oo]*)
                add_to_allowlist "$finding" "X.509 Object Identifier (OID)"
                echo "  → Added to allowlist: OID"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0
                ;;
            [Vv]*)
                add_to_allowlist "$finding" "Version number string"
                echo "  → Added to allowlist: Version number"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0
                ;;
            [Ll]*)
                add_to_allowlist "$finding" "Localhost/loopback address (127.0.0.1)"
                echo "  → Added to allowlist: Localhost"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0
                ;;
            [Dd]*)
                add_to_allowlist "$finding" "Documentation or pattern explanation"
                echo "  → Added to allowlist: Documentation"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0
                ;;
            [Xx]*)
                add_to_allowlist "$finding" "Placeholder pattern (build-time substitution)"
                echo "  → Added to allowlist: Placeholder pattern"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0
                ;;
            [Aa]*)
                echo ""
                echo "  Why is this acceptable? (This will be recorded in the allowlist)"
                echo -n "  Reason: "
                read -r reason < /dev/tty
                if [ -z "$reason" ]; then
                    echo "  ✗ Reason is required for audit trail. Please try again."
                    continue
                fi
                add_to_allowlist "$finding" "$reason"
                echo "  → Added to allowlist"
                ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
                return 0  # Accepted - not an issue
                ;;
            [Rr]*)
                echo "  → Flagged as potential PII"
                REJECTED_COUNT=$((REJECTED_COUNT + 1))
                return 1  # Rejected - is an issue
                ;;
            [Ss]*)
                echo "  → Skipped (will require review next time)"
                return 2  # Skipped - still needs review
                ;;
            *)
                echo "  Please enter A, R, S, E, O, V, L, D, or X"
                ;;
        esac
    done
}

echo "PII Verification Scan"
echo "====================="
echo "Timestamp: $TIMESTAMP"
echo "Toolkit: Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
echo "Target: $TARGET_DIR"
echo "Repository: $REPO_NAME"
echo ""

# Initialize audit logging
if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
    init_audit_log "$TARGET_DIR" "pii-scan" || true
fi

# Determine timeout command (GNU coreutils timeout may be gtimeout on macOS)
if command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout 1"
elif command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout 1"
else
    # No timeout available - run without it (slightly less protection against symlink attacks)
    TIMEOUT_CMD=""
fi

# Build include arguments for grep
INCLUDE_ARGS=""
for pattern in "${INCLUDE_PATTERNS[@]}"; do
    INCLUDE_ARGS="$INCLUDE_ARGS --include=$pattern"
done

# Luhn algorithm validation for credit card numbers
# Returns 0 if valid, 1 if invalid
# This reduces false positives by validating the checksum
luhn_validate() {
    local number="$1"
    # Remove spaces, dashes, and dots
    number=$(echo "$number" | tr -d ' .-')

    # Must be all digits
    if ! [[ "$number" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    local len=${#number}
    local sum=0
    local is_second=0

    # Process from right to left
    for (( i=len-1; i>=0; i-- )); do
        local digit=${number:$i:1}

        if [ $is_second -eq 1 ]; then
            digit=$((digit * 2))
            if [ $digit -gt 9 ]; then
                digit=$((digit - 9))
            fi
        fi

        sum=$((sum + digit))
        is_second=$((1 - is_second))
    done

    # Valid if sum is divisible by 10
    if [ $((sum % 10)) -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Function to run a check and log results
run_check() {
    local check_name="$1"
    local pattern="$2"
    local description="$3"

    echo "Checking: $check_name"

    # Run grep, capture output
    # CRITICAL-003: Protection against symlink attacks - use find to exclude symlinks, add per-file timeout
    # Exclusions loaded from .pii-exclude config file
    local results=""
    build_exclusions "$TARGET_DIR"

    # Build and execute find command with exclusions (array avoids eval)
    # Use process substitution to avoid subshell variable loss
    while read -r file; do
        local match
        match=$($TIMEOUT_CMD grep -H -n -E "$pattern" "$file" 2>/dev/null || true)
        [ -n "$match" ] && results="${results}${match}"$'\n'
    done < <(find "$TARGET_DIR" -type f -not -type l "${FIND_EXCLUSIONS[@]}" 2>/dev/null)

    local total_count=0
    local new_count=0
    local allowlisted_count=0
    local issue_count=0

    if [ -n "$results" ]; then
        total_count=$(echo "$results" | wc -l | tr -d ' ')

        # Process each finding
        while IFS= read -r line; do
            if [ -z "$line" ]; then
                continue
            fi

            # Check if already allowlisted
            if is_allowlisted "$line"; then
                allowlisted_count=$((allowlisted_count + 1))
                continue
            fi

            new_count=$((new_count + 1))

            # Log finding for audit trail
            if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
                local file_path=$(echo "$line" | cut -d: -f1)
                local line_num=$(echo "$line" | cut -d: -f2)
                audit_log_finding "$check_name" "$file_path:$line_num" || true
            fi

            # Interactive mode: prompt for each finding
            if [ "$INTERACTIVE" -eq 1 ]; then
                prompt_review "$line" "$check_name"
                local review_result=$?
                if [ $review_result -eq 1 ]; then
                    # Rejected - counts as an issue
                    issue_count=$((issue_count + 1))
                elif [ $review_result -eq 2 ]; then
                    # Skipped - still needs review
                    issue_count=$((issue_count + 1))
                fi
                # If accepted (0), not counted as issue
            else
                # Non-interactive: show findings
                if [ $new_count -le 10 ]; then
                    echo "$line"
                fi
                issue_count=$((issue_count + 1))
            fi
        done <<< "$results"
    fi

    # Report results
    if [ "$total_count" -eq 0 ]; then
        echo "  Result: PASS (0 matches)"
    elif [ "$new_count" -eq 0 ]; then
        echo "  Result: PASS ($allowlisted_count allowlisted)"
    elif [ "$INTERACTIVE" -eq 1 ]; then
        if [ "$issue_count" -eq 0 ]; then
            echo "  Result: PASS (all $new_count finding(s) accepted)"
        else
            echo "  Result: REVIEW - $issue_count unresolved finding(s)"
            FOUND_ISSUES=1
        fi
    else
        echo "  Result: REVIEW - $new_count new match(es) found"
        if [ "$new_count" -gt 10 ]; then
            echo "  ... and $((new_count - 10)) more"
        fi
        if [ "$allowlisted_count" -gt 0 ]; then
            echo "  ($allowlisted_count previously allowlisted)"
        fi
        FOUND_ISSUES=1
    fi
}

# Specialized check for credit cards with Luhn validation
# This reduces false positives by validating the credit card checksum
run_check_credit_card() {
    local check_name="$1"
    local pattern="$2"
    local description="$3"

    echo "Checking: $check_name"

    local results=""
    local exclusions
    exclusions=$(build_exclusions "$TARGET_DIR")

    # Build and execute find command with exclusions
    # Use process substitution to avoid subshell variable loss
    while read -r file; do
        local match
        match=$($TIMEOUT_CMD grep -H -n -o -E "$pattern" "$file" 2>/dev/null || true)
        [ -n "$match" ] && results="${results}${match}"$'\n'
    done < <(eval "find \"$TARGET_DIR\" -type f -not -type l $exclusions 2>/dev/null")

    local total_count=0
    local valid_count=0
    local allowlisted_count=0
    local issue_count=0

    if [ -n "$results" ]; then
        total_count=$(echo "$results" | wc -l | tr -d ' ')

        while IFS= read -r line; do
            if [ -z "$line" ]; then
                continue
            fi

            # Extract the matched number (after the last colon)
            local matched_num=$(echo "$line" | rev | cut -d: -f1 | rev)

            # Validate with Luhn algorithm
            if ! luhn_validate "$matched_num"; then
                # Invalid checksum, skip this false positive
                continue
            fi

            valid_count=$((valid_count + 1))

            # Reconstruct line for allowlist check (file:line:content format)
            local file_path=$(echo "$line" | cut -d: -f1)
            local line_num=$(echo "$line" | cut -d: -f2)
            local full_line="$file_path:$line_num:$matched_num"

            if is_allowlisted "$full_line"; then
                allowlisted_count=$((allowlisted_count + 1))
                continue
            fi

            # Log finding for audit trail
            if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
                audit_log_finding "$check_name" "$file_path:$line_num" || true
            fi

            if [ "$INTERACTIVE" -eq 1 ]; then
                prompt_review "$full_line" "$check_name"
                local review_result=$?
                if [ $review_result -ne 0 ]; then
                    issue_count=$((issue_count + 1))
                fi
            else
                if [ $((valid_count - allowlisted_count)) -le 10 ]; then
                    echo "  $file_path:$line_num: $matched_num (Luhn valid)"
                fi
                issue_count=$((issue_count + 1))
            fi
        done <<< "$results"
    fi

    # Report results
    local filtered=$((total_count - valid_count))
    if [ "$valid_count" -eq 0 ]; then
        if [ "$total_count" -gt 0 ]; then
            echo "  Result: PASS (0 valid, $filtered filtered by Luhn)"
        else
            echo "  Result: PASS (0 matches)"
        fi
    elif [ "$issue_count" -eq 0 ]; then
        echo "  Result: PASS ($allowlisted_count allowlisted, $filtered filtered by Luhn)"
    else
        echo "  Result: REVIEW - $issue_count valid card(s) found ($filtered filtered by Luhn)"
        FOUND_ISSUES=1
    fi
}

# ============================================================================
# PII PATTERN DEFINITIONS (NIST SI-12)
# ============================================================================
# Patterns balance detection sensitivity vs false positives.
# Known false positives: version numbers (1.2.3.4), OIDs, build numbers
# Use .pii-exclude or allowlist to suppress known-good matches.
# ============================================================================

run_check "IPv4 Addresses" \
    "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    "Searches for IP address patterns that could identify network infrastructure"

run_check "US Phone Numbers (dashed)" \
    "[0-9]{3}[-][0-9]{3}[-][0-9]{4}" \
    "Searches for phone numbers in XXX-XXX-XXXX format"

run_check "US Phone Numbers (dotted)" \
    "[0-9]{3}[.][0-9]{3}[.][0-9]{4}" \
    "Searches for phone numbers in XXX.XXX.XXXX format"

run_check "US Phone Numbers (parenthetical)" \
    "\([0-9]{3}\)[ ]*[0-9]{3}[-. ][0-9]{4}" \
    "Searches for phone numbers in (XXX) XXX-XXXX format"

run_check "International Phone Numbers" \
    "\+[0-9]{1,3}[ .-]?[0-9]{1,4}[ .-]?[0-9]{1,4}[ .-]?[0-9]{1,4}[ .-]?[0-9]{0,4}" \
    "Searches for international phone numbers with country code (+XX XXX...)"

run_check "Social Security Numbers" \
    "[0-9]{3}-[0-9]{2}-[0-9]{4}" \
    "Searches for SSN patterns in XXX-XX-XXXX format"

run_check_credit_card "Credit Card Numbers (Luhn validated)" \
    "[0-9]{4}[-. ]?[0-9]{4}[-. ]?[0-9]{4}[-. ]?[0-9]{4}" \
    "Searches for 16-digit credit card numbers validated with Luhn algorithm"

# Summary
echo ""
echo "====================="

if [ "$INTERACTIVE" -eq 1 ]; then
    echo "Interactive Review Summary:"
    echo "  Accepted (allowlisted): $ACCEPTED_COUNT"
    echo "  Rejected (flagged):     $REJECTED_COUNT"
    echo ""
fi

if [ -f "$ALLOWLIST_FILE" ]; then
    ALLOWLIST_COUNT=$(grep -c "^[a-f0-9]" "$ALLOWLIST_FILE" 2>/dev/null || echo "0")
    echo "Allowlist: $ALLOWLIST_FILE ($ALLOWLIST_COUNT entries)"
fi
if [ -n "$PII_EXCLUDE_FILE" ] && [ -f "$PII_EXCLUDE_FILE" ]; then
    EXCLUDE_COUNT=$(grep -cvE "^[[:space:]]*#|^[[:space:]]*$" "$PII_EXCLUDE_FILE" 2>/dev/null || echo "0")
    echo "Exclusions: $PII_EXCLUDE_FILE ($EXCLUDE_COUNT patterns)"
fi
echo ""

if [ $FOUND_ISSUES -eq 0 ]; then
    echo "OVERALL RESULT: PASS"
    if [ "$INTERACTIVE" -eq 1 ]; then
        echo "All findings reviewed and accepted."
    else
        echo "No PII patterns detected."
    fi
    # Finalize audit log with PASS status
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        finalize_audit_log "PASS" "findings=0" || true
    fi
else
    echo "OVERALL RESULT: REVIEW REQUIRED"
    echo "Potential PII patterns detected. Manual review required."
    if [ "$INTERACTIVE" -eq 0 ]; then
        echo ""
        echo "Run with -i flag for interactive review:"
        echo "  $0 -i $TARGET_DIR"
    fi
    # Finalize audit log with FAIL status
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        finalize_audit_log "FAIL" "findings=$FOUND_ISSUES" || true
    fi
fi

exit $FOUND_ISSUES
