#!/bin/bash
#
# NVD CVE Lookup Script
#
# Purpose: Cross-reference installed software against the National Vulnerability Database
# Standards:
#   - NIST SP 800-53: RA-5 (Vulnerability Monitoring and Scanning)
#   - NIST SP 800-53: SI-2 (Flaw Remediation)
#   - NIST SP 800-171: 3.11.2 (Vulnerability Scanning)
#
# Exit codes:
#   0 = Pass (no known vulnerabilities found)
#   1 = Fail (vulnerabilities detected)
#   2 = Warning (scan completed with issues)
#
# Usage:
#   ./check-nvd-cves.sh [OPTIONS] [TARGET_DIR]
#
# Options:
#   -h, --help              Show this help message
#   -i, --inventory FILE    Use specific inventory file
#   -p, --priority-only     Only scan priority packages (faster)
#   -c, --clear-cache       Clear NVD cache before scanning
#   -v, --verbose           Show detailed output
#   --offline               Use cached data only (no API calls)
#   --min-cvss SCORE        Minimum CVSS score to report (default: 0)
#
# Environment Variables:
#   NVD_API_KEY             API key for higher rate limits (optional)

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# Source NVD-specific libraries (not included in init.sh)
source "$SCRIPT_DIR/lib/nvd/api.sh"
source "$SCRIPT_DIR/lib/nvd/matcher.sh"

# Default settings
INVENTORY_FILE=""
PRIORITY_ONLY=0
CLEAR_CACHE=0
VERBOSE=0
OFFLINE_MODE=0
MIN_CVSS=0
TARGET_DIR=""

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL_PACKAGES=0
PACKAGES_CHECKED=0
VULNERABILITIES_FOUND=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

show_help() {
    cat << EOF
NVD CVE Lookup - Cross-reference installed software against NVD

USAGE:
    $(basename "$0") [OPTIONS] [TARGET_DIR]

OPTIONS:
    -h, --help              Show this help message
    -i, --inventory FILE    Use specific inventory file
    -p, --priority-only     Only scan priority packages (faster)
    -c, --clear-cache       Clear NVD cache before scanning
    -v, --verbose           Show detailed output
    --offline               Use cached data only (no API calls)
    --min-cvss SCORE        Minimum CVSS score to report (default: 0)

ENVIRONMENT VARIABLES:
    NVD_API_KEY             API key for higher rate limits

NIST CONTROLS:
    RA-5    Vulnerability Monitoring and Scanning
    SI-2    Flaw Remediation
    3.11.2  Vulnerability Scanning (800-171)

EXAMPLES:
    # Scan current directory's inventory
    $(basename "$0")

    # Scan with specific inventory file
    $(basename "$0") -i /path/to/host-inventory.txt

    # Quick scan of priority packages only
    $(basename "$0") -p

    # Show only HIGH and CRITICAL vulnerabilities
    $(basename "$0") --min-cvss 7.0

EOF
    exit 0
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -i|--inventory)
            INVENTORY_FILE="$2"
            shift 2
            ;;
        -p|--priority-only)
            PRIORITY_ONLY=1
            shift
            ;;
        -c|--clear-cache)
            CLEAR_CACHE=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --offline)
            OFFLINE_MODE=1
            shift
            ;;
        --min-cvss)
            MIN_CVSS="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1" >&2
            show_help
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

# Set default target directory
if [ -z "$TARGET_DIR" ]; then
    TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

# Find inventory file if not specified
if [ -z "$INVENTORY_FILE" ]; then
    # Look for most recent inventory file
    SCANS_DIR="$TARGET_DIR/.scans"
    if [ -d "$SCANS_DIR" ]; then
        INVENTORY_FILE=$(find "$SCANS_DIR" -name "host-inventory-*.txt" -type f 2>/dev/null | sort -r | head -1)
    fi
fi

# Validate inventory file
if [ -z "$INVENTORY_FILE" ] || [ ! -f "$INVENTORY_FILE" ]; then
    echo -e "${YELLOW}Warning: No host inventory file found.${NC}"
    echo "Run collect-host-inventory.sh first or specify with -i flag."
    echo ""
    echo "Generating host inventory now..."
    "$SCRIPT_DIR/collect-host-inventory.sh" "$TARGET_DIR/.scans/host-inventory-$(date +%Y-%m-%d-T%H%M%SZ).txt" 2>/dev/null
    INVENTORY_FILE=$(find "$TARGET_DIR/.scans" -name "host-inventory-*.txt" -type f 2>/dev/null | sort -r | head -1)

    if [ -z "$INVENTORY_FILE" ] || [ ! -f "$INVENTORY_FILE" ]; then
        echo -e "${RED}Error: Could not generate host inventory.${NC}"
        exit 2
    fi
fi

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit
FILENAME_TS=$(get_filename_timestamp)
OUTPUT_DIR="$TARGET_DIR/.scans"
OUTPUT_FILE="$OUTPUT_DIR/nvd-cve-scan-${FILENAME_TS}.txt"

mkdir -p "$OUTPUT_DIR"

# Clear cache if requested
if [ "$CLEAR_CACHE" -eq 1 ]; then
    clear_nvd_cache
fi

# Initialize audit log
if [ "${AUDIT_AVAILABLE:-1}" -eq 1 ]; then
    init_audit_log "$TARGET_DIR" "nvd-cve-scan" 2>/dev/null || true
    audit_log "SCAN_START" "target=$TARGET_DIR inventory=$INVENTORY_FILE" 2>/dev/null || true
fi

# Output header
output_header() {
    cat << EOF
NVD CVE Vulnerability Lookup
============================
Timestamp: $TIMESTAMP
Toolkit: $(get_toolkit_version 2>/dev/null || echo "Security Verification Toolkit")
Target: $TARGET_DIR
Inventory: $INVENTORY_FILE

NIST Controls:
  - RA-5: Vulnerability Monitoring and Scanning
  - SI-2: Flaw Remediation
  - 3.11.2: Vulnerability Scanning (800-171)

EOF
}

# Print header
output_header | tee "$OUTPUT_FILE"

# Check NVD API availability
if [ "$OFFLINE_MODE" -eq 0 ]; then
    echo -n "Checking NVD API availability... "
    if check_nvd_api; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}UNAVAILABLE - using cached data only${NC}"
        OFFLINE_MODE=1
    fi
fi | tee -a "$OUTPUT_FILE"

echo "" | tee -a "$OUTPUT_FILE"
echo "Parsing installed packages from inventory..." | tee -a "$OUTPUT_FILE"

# Parse packages from inventory
PACKAGES=$(parse_inventory_packages "$INVENTORY_FILE")
TOTAL_PACKAGES=$(echo "$PACKAGES" | grep -c ":" || echo "0")

if [ "$PRIORITY_ONLY" -eq 1 ]; then
    PACKAGES=$(echo "$PACKAGES" | filter_known_packages)
    TOTAL_PACKAGES=$(echo "$PACKAGES" | grep -c ":" || echo "0")
    echo "Scanning $TOTAL_PACKAGES priority packages (--priority-only mode)" | tee -a "$OUTPUT_FILE"
else
    echo "Found $TOTAL_PACKAGES packages to check" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "Scanning for known vulnerabilities..." | tee -a "$OUTPUT_FILE"
echo "----------------------------------------" | tee -a "$OUTPUT_FILE"

# Track findings
declare -a FINDINGS=()

# Scan each package
while IFS=: read -r package version; do
    [ -z "$package" ] && continue
    [ -z "$version" ] && continue

    PACKAGES_CHECKED=$((PACKAGES_CHECKED + 1))

    # Show progress
    if [ "$VERBOSE" -eq 1 ]; then
        echo -n "  Checking $package $version... "
    fi

    # Convert to CPE and query NVD
    cpe=$(package_to_cpe "$package" "$version")

    # Query NVD (skip if offline and not cached)
    response=""
    if [ "$OFFLINE_MODE" -eq 0 ]; then
        response=$(query_nvd_by_keyword "$package" "$version" 2>/dev/null || echo "")
    else
        # Check cache only
        cache_key="${package}-${version}"
        cache_file="$NVD_CACHE_DIR/keyword-$(echo "$cache_key" | md5 -q 2>/dev/null || echo "$cache_key" | md5sum | cut -d' ' -f1).json"
        if [ -f "$cache_file" ]; then
            response=$(cat "$cache_file")
        fi
    fi

    if [ -z "$response" ]; then
        [ "$VERBOSE" -eq 1 ] && echo "skipped (no data)"
        continue
    fi

    # Check for vulnerabilities
    vuln_count=$(echo "$response" | jq '.totalResults // 0' 2>/dev/null || echo "0")

    if [ "$vuln_count" -gt 0 ]; then
        # Process each vulnerability
        echo "$response" | jq -r '.vulnerabilities[]? | @base64' 2>/dev/null | while read -r vuln_b64; do
            vuln=$(echo "$vuln_b64" | base64 -d 2>/dev/null || echo "$vuln_b64" | base64 -D 2>/dev/null)

            cve_id=$(echo "$vuln" | jq -r '.cve.id // "UNKNOWN"')
            cvss_score=$(echo "$vuln" | jq -r '
                .cve.metrics.cvssMetricV31[0].cvssData.baseScore //
                .cve.metrics.cvssMetricV30[0].cvssData.baseScore //
                .cve.metrics.cvssMetricV2[0].cvssData.baseScore //
                0
            ')
            severity=$(echo "$vuln" | jq -r '
                .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
                .cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
                "UNKNOWN"
            ' | tr '[:lower:]' '[:upper:]')
            description=$(echo "$vuln" | jq -r '.cve.descriptions[]? | select(.lang == "en") | .value' | head -1 | cut -c1-200)

            # Skip if below minimum CVSS
            if [ "$(echo "$cvss_score < $MIN_CVSS" | bc -l 2>/dev/null || echo "0")" = "1" ]; then
                continue
            fi

            VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))

            # Count by severity
            case "$severity" in
                CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
                HIGH) HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
                MEDIUM) MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
                LOW) LOW_COUNT=$((LOW_COUNT + 1)) ;;
            esac

            # Output finding
            {
                echo ""
                echo -e "${RED}[VULNERABILITY]${NC} $cve_id"
                echo "  Package:  $package $version"
                echo "  CVSS:     $cvss_score ($severity)"
                echo "  Summary:  ${description}..."
                echo "  Link:     https://nvd.nist.gov/vuln/detail/$cve_id"
            } | tee -a "$OUTPUT_FILE"

            # Audit log
            if [ "${AUDIT_AVAILABLE:-1}" -eq 1 ]; then
                audit_log "FINDING_DETECTED" "cve=$cve_id package=$package version=$version cvss=$cvss_score severity=$severity" 2>/dev/null || true
            fi
        done

        [ "$VERBOSE" -eq 1 ] && echo -e "${RED}$vuln_count CVE(s)${NC}"
    else
        [ "$VERBOSE" -eq 1 ] && echo -e "${GREEN}OK${NC}"
    fi
done <<< "$PACKAGES"

# Summary
echo "" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"
echo "NVD CVE Scan Summary" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"
echo "  Packages Scanned:  $PACKAGES_CHECKED" | tee -a "$OUTPUT_FILE"
echo "  Vulnerabilities:   $VULNERABILITIES_FOUND" | tee -a "$OUTPUT_FILE"

if [ "$VULNERABILITIES_FOUND" -gt 0 ]; then
    echo "" | tee -a "$OUTPUT_FILE"
    echo "  By Severity:" | tee -a "$OUTPUT_FILE"
    [ "$CRITICAL_COUNT" -gt 0 ] && echo -e "    ${RED}CRITICAL:${NC} $CRITICAL_COUNT" | tee -a "$OUTPUT_FILE"
    [ "$HIGH_COUNT" -gt 0 ] && echo -e "    ${RED}HIGH:${NC}     $HIGH_COUNT" | tee -a "$OUTPUT_FILE"
    [ "$MEDIUM_COUNT" -gt 0 ] && echo -e "    ${YELLOW}MEDIUM:${NC}   $MEDIUM_COUNT" | tee -a "$OUTPUT_FILE"
    [ "$LOW_COUNT" -gt 0 ] && echo "    LOW:      $LOW_COUNT" | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"

# Determine exit status
EXIT_CODE=0
RESULT="PASS"

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
    EXIT_CODE=1
    RESULT="FAIL"
    echo -e "${RED}RESULT: FAIL${NC}" | tee -a "$OUTPUT_FILE"
    echo "Critical or High severity vulnerabilities detected." | tee -a "$OUTPUT_FILE"
elif [ "$VULNERABILITIES_FOUND" -gt 0 ]; then
    EXIT_CODE=0
    RESULT="REVIEW"
    echo -e "${YELLOW}RESULT: REVIEW REQUIRED${NC}" | tee -a "$OUTPUT_FILE"
    echo "Medium or Low severity vulnerabilities detected." | tee -a "$OUTPUT_FILE"
else
    echo -e "${GREEN}RESULT: PASS${NC}" | tee -a "$OUTPUT_FILE"
    echo "No known vulnerabilities detected in scanned packages." | tee -a "$OUTPUT_FILE"
fi

echo "" | tee -a "$OUTPUT_FILE"
echo "Report saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"

# Finalize audit log
if [ "${AUDIT_AVAILABLE:-1}" -eq 1 ]; then
    audit_log "SCAN_COMPLETE" "status=$RESULT packages=$PACKAGES_CHECKED vulnerabilities=$VULNERABILITIES_FOUND" 2>/dev/null || true
    finalize_audit_log "$RESULT" "Found $VULNERABILITIES_FOUND vulnerabilities in $PACKAGES_CHECKED packages" 2>/dev/null || true
fi

# Cache stats
if [ "$VERBOSE" -eq 1 ]; then
    echo ""
    nvd_cache_stats
fi

exit $EXIT_CODE
