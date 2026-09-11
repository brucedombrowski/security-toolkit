#!/bin/bash
#
# Application Security Verification Script
#
# Purpose: Audit installed applications for security hygiene
# Method: Check for EOL/deprecated software, duplicates, and unsigned apps
# Standards:
#   - NIST SP 800-53: CM-7 (Least Functionality)
#   - NIST SP 800-53: CM-11 (User-Installed Software)
#   - NIST SP 800-53: SI-2 (Flaw Remediation)
#
# Exit codes:
#   0 = All checks passed
#   1 = One or more checks failed
#
# Usage: ./check-applications.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit

echo "Application Security Verification"
echo "=================================="
echo "Timestamp: $TIMESTAMP"
echo "Host: $(hostname)"
echo "Toolkit: $TOOLKIT_NAME $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
echo "Source: $TOOLKIT_SOURCE"
echo ""

# Track overall status
OVERALL_STATUS="PASS"
FAIL_COUNT=0
WARN_COUNT=0

# Known EOL/deprecated software patterns (case-insensitive)
declare -a EOL_SOFTWARE=(
    "Silverlight:Microsoft Silverlight discontinued 2021"
    "Flash Player:Adobe Flash Player discontinued 2020"
    "Adobe Acrobat XI:Adobe Acrobat XI EOL 2017"
    "Java 6:Java 6 EOL, upgrade to Java 11+"
    "Java 7:Java 7 EOL, upgrade to Java 11+"
    "Java 1.6:Java 1.6 EOL, upgrade to Java 11+"
    "Java 1.7:Java 1.7 EOL, upgrade to Java 11+"
    "Python 2.7:Python 2.7 EOL 2020"
    "QuickTime Player 7:QuickTime 7 EOL, use system QuickTime"
    "iTunes Helper:iTunes superseded by Music/TV apps on macOS 10.15+"
)

# Function to check EOL software
check_eol_software() {
    echo "Checking for EOL/Deprecated Software..."
    echo "----------------------------------------"
    echo "NIST Control: CM-7 (Least Functionality), SI-2 (Flaw Remediation)"
    echo ""

    local found_eol=0
    local app_dirs=("/Applications" "$HOME/Applications")

    for eol_pattern in "${EOL_SOFTWARE[@]}"; do
        local pattern="${eol_pattern%%:*}"
        local reason="${eol_pattern#*:}"

        # Search for matching applications in both directories
        for app_dir in "${app_dirs[@]}"; do
            if [ ! -d "$app_dir" ]; then
                continue
            fi

            # Use find with -iname for case-insensitive matching
            while IFS= read -r app_path; do
                if [ -n "$app_path" ]; then
                    echo "  FAIL: Found EOL software"
                    echo "    Path: $app_path"
                    echo "    Issue: $reason"
                    echo "    Recommendation: Remove this application"
                    echo ""
                    found_eol=1
                    OVERALL_STATUS="FAIL"
                    FAIL_COUNT=$((FAIL_COUNT + 1))
                fi
            done < <(find "$app_dir" -maxdepth 2 -iname "*${pattern}*.app" 2>/dev/null || true)
        done
    done

    if [ $found_eol -eq 0 ]; then
        echo "  PASS: No known EOL/deprecated software detected"
        echo ""
    fi
}

# Function to detect duplicate applications
check_duplicate_apps() {
    echo "Checking for Duplicate Applications..."
    echo "--------------------------------------"
    echo "NIST Control: CM-7 (Least Functionality)"
    echo ""

    local found_duplicates=0
    local app_dirs=("/Applications" "$HOME/Applications")

    # Create temporary file to track seen applications (Bash 3.2 compatible)
    local temp_apps=$(mktemp)
    trap "rm -f $temp_apps" RETURN

    for app_dir in "${app_dirs[@]}"; do
        if [ ! -d "$app_dir" ]; then
            continue
        fi

        while IFS= read -r app_path; do
            if [ -n "$app_path" ]; then
                local app_name=$(basename "$app_path" .app)
                # Normalize name by removing version numbers and common suffixes
                local normalized_name=$(echo "$app_name" | sed -E 's/ [0-9]+(\.[0-9]+)*$//' | sed -E 's/ (Beta|Alpha|Preview|Classic)$//' | tr '[:upper:]' '[:lower:]')

                # Check if we've seen a similar name before
                local existing_path=$(grep "^${normalized_name}:" "$temp_apps" 2>/dev/null | cut -d':' -f2- || true)
                if [ -n "$existing_path" ]; then
                    echo "  WARNING: Potential duplicate application detected"
                    echo "    Name: $app_name"
                    echo "    Path: $app_path"
                    echo "    Similar to: $existing_path"
                    echo "    Recommendation: Review and remove duplicate if not needed"
                    echo ""
                    found_duplicates=1
                    WARN_COUNT=$((WARN_COUNT + 1))
                else
                    # Store normalized name and path
                    echo "${normalized_name}:${app_path}" >> "$temp_apps"
                fi
            fi
        done < <(find "$app_dir" -maxdepth 1 -name "*.app" 2>/dev/null || true)
    done

    if [ $found_duplicates -eq 0 ]; then
        echo "  PASS: No obvious duplicate applications detected"
        echo ""
    fi
}

# Function to check for unsigned/unnotarized apps (macOS only)
check_unsigned_apps() {
    echo "Checking for Unsigned/Unnotarized Applications..."
    echo "--------------------------------------------------"
    echo "NIST Control: CM-11 (User-Installed Software)"
    echo ""

    # Only run on macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        echo "  SKIP: This check is macOS-specific"
        echo ""
        return 0
    fi

    local found_unsigned=0
    local app_dirs=("/Applications" "$HOME/Applications")

    for app_dir in "${app_dirs[@]}"; do
        if [ ! -d "$app_dir" ]; then
            continue
        fi

        while IFS= read -r app_path; do
            if [ -n "$app_path" ]; then
                # Check code signature
                local codesign_output
                local codesign_exit=0
                codesign_output=$(codesign -dv --verbose=2 "$app_path" 2>&1) || codesign_exit=$?

                if [ $codesign_exit -ne 0 ]; then
                    echo "  FAIL: Unsigned application detected"
                    echo "    Path: $app_path"
                    echo "    Issue: Application is not code-signed"
                    echo "    Recommendation: Verify application source and re-download from official source"
                    echo ""
                    found_unsigned=1
                    OVERALL_STATUS="FAIL"
                    FAIL_COUNT=$((FAIL_COUNT + 1))
                else
                    # Check for notarization (macOS 10.14+)
                    if echo "$codesign_output" | grep -q "Notarization: none" 2>/dev/null; then
                        echo "  WARNING: Unnotarized application"
                        echo "    Path: $app_path"
                        echo "    Issue: Application is signed but not notarized by Apple"
                        echo "    Recommendation: Consider updating to notarized version"
                        echo ""
                        WARN_COUNT=$((WARN_COUNT + 1))
                    fi
                fi
            fi
        done < <(find "$app_dir" -maxdepth 1 -name "*.app" 2>/dev/null || true)
    done

    if [ $found_unsigned -eq 0 ]; then
        echo "  PASS: All applications are properly code-signed"
        echo ""
    fi
}

# Function to provide application inventory summary
application_inventory_summary() {
    echo "Application Inventory Summary"
    echo "-----------------------------"
    echo "NIST Control: CM-8 (System Component Inventory)"
    echo ""

    local app_dirs=("/Applications" "$HOME/Applications")
    local total_apps=0

    for app_dir in "${app_dirs[@]}"; do
        if [ ! -d "$app_dir" ]; then
            echo "  Directory not found: $app_dir"
            continue
        fi

        local app_count=$(find "$app_dir" -maxdepth 1 -name "*.app" 2>/dev/null | wc -l | tr -d ' ')
        total_apps=$((total_apps + app_count))

        echo "  $app_dir: $app_count applications"
    done

    echo ""
    echo "  Total Applications: $total_apps"
    echo ""
}

echo "Running application security checks..."
echo ""

# Run all checks
check_eol_software
check_duplicate_apps
check_unsigned_apps
application_inventory_summary

echo "=============================="
echo ""

if [ "$OVERALL_STATUS" = "PASS" ] && [ $WARN_COUNT -eq 0 ]; then
    echo "OVERALL RESULT: PASS"
    echo "All application security checks passed."
    exit 0
elif [ "$OVERALL_STATUS" = "PASS" ] && [ $WARN_COUNT -gt 0 ]; then
    echo "OVERALL RESULT: PASS (with $WARN_COUNT warning(s))"
    echo "No critical issues found, but some applications may need attention."
    exit 0
else
    echo "OVERALL RESULT: FAIL ($FAIL_COUNT check(s) failed, $WARN_COUNT warning(s))"
    echo "Remediate issues and re-run verification."
    exit 1
fi
