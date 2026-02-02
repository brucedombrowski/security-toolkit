#!/bin/bash
#
# CISA Known Exploited Vulnerabilities (KEV) Cross-Reference
#
# Purpose: Cross-reference scan findings against the CISA KEV catalog
#          to identify vulnerabilities with known active exploitation
#
# Usage: ./check-kev.sh [vulnerability-scan-file]
#        ./check-kev.sh                         # Uses most recent scan in .scans/
#        ./check-kev.sh .scans/vulnerability-scan-2026-01-16.txt
#
# Standards:
#   - BOD 22-01: Reducing Significant Risk of Known Exploited Vulnerabilities
#   - NIST SP 800-53: RA-5 (Vulnerability Monitoring and Scanning)
#
# Exit codes:
#   0 = No KEV matches found
#   1 = KEV matches found (requires action)
#   2 = Error (network, parse, etc.)

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# KEV Catalog URLs and paths
KEV_JSON_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_DIR="${SECURITY_REPO_DIR}/.cache"
KEV_CACHE_FILE="${KEV_CACHE_DIR}/kev-catalog.json"
KEV_CACHE_MAX_AGE=86400  # 24 hours in seconds

# Bundled KEV catalog for offline use (included in releases)
KEV_BUNDLED_FILE="${SECURITY_REPO_DIR}/data/kev-catalog.json"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit

usage() {
    echo "Usage: $0 [vulnerability-scan-file]"
    echo ""
    echo "Cross-reference vulnerability scan findings against CISA KEV catalog."
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -f, --force    Force refresh of KEV catalog (ignore cache)"
    echo "  -q, --quiet    Quiet mode (only output KEV matches)"
    echo ""
    echo "If no file specified, uses most recent vulnerability scan in .scans/"
    exit 0
}

FORCE_REFRESH=0
QUIET=0
SCAN_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -f|--force)
            FORCE_REFRESH=1
            shift
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        *)
            SCAN_FILE="$1"
            shift
            ;;
    esac
done

# Check for required tools
check_dependencies() {
    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo "Install with:"
        echo "  macOS: brew install ${missing[*]}"
        echo "  Linux: apt install ${missing[*]}"
        exit 2
    fi
}

# Update KEV catalog cache
update_kev_cache() {
    mkdir -p "$KEV_CACHE_DIR"

    local need_update=0

    if [ ! -f "$KEV_CACHE_FILE" ]; then
        need_update=1
    elif [ "$FORCE_REFRESH" -eq 1 ]; then
        need_update=1
    else
        # Check cache age
        local cache_age
        if [[ "$(uname)" == "Darwin" ]]; then
            cache_age=$(($(date +%s) - $(stat -f %m "$KEV_CACHE_FILE")))
        else
            cache_age=$(($(date +%s) - $(stat -c %Y "$KEV_CACHE_FILE")))
        fi

        if [ "$cache_age" -gt "$KEV_CACHE_MAX_AGE" ]; then
            need_update=1
        fi
    fi

    if [ "$need_update" -eq 1 ]; then
        [ "$QUIET" -eq 0 ] && echo -e "${CYAN}Updating KEV catalog from CISA...${NC}" || true

        if ! curl -s --connect-timeout 10 --max-time 30 "$KEV_JSON_URL" -o "${KEV_CACHE_FILE}.tmp"; then
            echo -e "${YELLOW}Warning: Failed to download KEV catalog (network unavailable)${NC}"
            # Fall back to existing cache
            if [ -f "$KEV_CACHE_FILE" ]; then
                echo -e "${YELLOW}Using cached version${NC}"
                return 0
            fi
            # Fall back to bundled catalog for offline use
            if [ -f "$KEV_BUNDLED_FILE" ]; then
                echo -e "${CYAN}Using bundled KEV catalog (offline mode)${NC}"
                cp "$KEV_BUNDLED_FILE" "$KEV_CACHE_FILE"
                if [ -f "${KEV_BUNDLED_FILE}.sha256" ]; then
                    cp "${KEV_BUNDLED_FILE}.sha256" "${KEV_CACHE_FILE}.sha256"
                fi
                return 0
            fi
            echo -e "${RED}Error: No KEV catalog available (no cache, no bundled file)${NC}"
            exit 2
        fi

        # Validate JSON
        if ! jq empty "${KEV_CACHE_FILE}.tmp" 2>/dev/null; then
            echo -e "${RED}Error: Invalid JSON in KEV catalog${NC}"
            rm -f "${KEV_CACHE_FILE}.tmp"
            exit 2
        fi

        mv "${KEV_CACHE_FILE}.tmp" "$KEV_CACHE_FILE"

        # Generate SHA256 hash for integrity verification
        if [[ "$(uname)" == "Darwin" ]]; then
            shasum -a 256 "$KEV_CACHE_FILE" > "${KEV_CACHE_FILE}.sha256"
        else
            sha256sum "$KEV_CACHE_FILE" > "${KEV_CACHE_FILE}.sha256"
        fi

        [ "$QUIET" -eq 0 ] && echo -e "${GREEN}KEV catalog updated successfully${NC}" || true
    else
        [ "$QUIET" -eq 0 ] && echo -e "${CYAN}Using cached KEV catalog (< 24 hours old)${NC}" || true
    fi
}

# Get KEV catalog hash
get_kev_hash() {
    if [ -f "${KEV_CACHE_FILE}.sha256" ]; then
        cat "${KEV_CACHE_FILE}.sha256" | awk '{print $1}'
    elif [ -f "$KEV_CACHE_FILE" ]; then
        if [[ "$(uname)" == "Darwin" ]]; then
            shasum -a 256 "$KEV_CACHE_FILE" | awk '{print $1}'
        else
            sha256sum "$KEV_CACHE_FILE" | awk '{print $1}'
        fi
    else
        echo "unavailable"
    fi
}

# Find scan file
find_scan_file() {
    if [ -n "$SCAN_FILE" ]; then
        if [ ! -f "$SCAN_FILE" ]; then
            echo -e "${RED}Error: Scan file not found: $SCAN_FILE${NC}"
            exit 2
        fi
        return 0
    fi

    # Look for most recent vulnerability scan
    local scans_dir="${SECURITY_REPO_DIR}/.scans"
    if [ -d "$scans_dir" ]; then
        SCAN_FILE=$(ls -t "$scans_dir"/vulnerability-scan-*.txt 2>/dev/null | head -1)
    fi

    # Also check for Lynis or Nmap output
    if [ -z "$SCAN_FILE" ] && [ -d "$scans_dir" ]; then
        SCAN_FILE=$(ls -t "$scans_dir"/*scan*.txt 2>/dev/null | head -1)
    fi

    if [ -z "$SCAN_FILE" ]; then
        echo -e "${RED}Error: No scan file found${NC}"
        echo "Run a vulnerability scan first:"
        echo "  ./scripts/scan-vulnerabilities.sh /path/to/target"
        echo ""
        echo "Or specify a file containing CVE references:"
        echo "  $0 /path/to/scan-output.txt"
        exit 2
    fi
}

# Extract CVEs from scan file
extract_cves() {
    grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$SCAN_FILE" 2>/dev/null | sort -u || true
}

# Check single CVE against KEV
check_cve_in_kev() {
    local cve="$1"
    jq -r ".vulnerabilities[] | select(.cveID == \"$cve\")" "$KEV_CACHE_FILE"
}

# Main
check_dependencies
update_kev_cache
find_scan_file

# Get catalog metadata
KEV_VERSION=$(jq -r '.catalogVersion' "$KEV_CACHE_FILE")
KEV_COUNT=$(jq -r '.count' "$KEV_CACHE_FILE")
KEV_DATE=$(jq -r '.dateReleased' "$KEV_CACHE_FILE")
KEV_HASH=$(get_kev_hash)

if [ "$QUIET" -eq 0 ]; then
    echo ""
    echo "==============================================================================="
    echo "  CISA Known Exploited Vulnerabilities (KEV) Cross-Reference"
    echo "==============================================================================="
    echo ""
    echo "Scan File: $SCAN_FILE"
    echo "KEV Catalog Version: $KEV_VERSION"
    echo "KEV Total Entries: $KEV_COUNT"
    echo "KEV Last Updated: $KEV_DATE"
    echo "KEV Catalog SHA256: $KEV_HASH"
    echo "Check Timestamp: $TIMESTAMP"
    echo ""
    echo "-------------------------------------------------------------------------------"
fi

# Extract and check CVEs
CVES=$(extract_cves)
if [ -z "$CVES" ]; then
    CVE_COUNT=0
else
    CVE_COUNT=$(echo "$CVES" | wc -l | tr -d ' ')
fi

if [ "$CVE_COUNT" -eq 0 ]; then
    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${YELLOW}No CVE references found in scan file.${NC}"
        echo ""
        echo "This check works best with vulnerability scan output containing CVE IDs."
        echo "Try running: ./scripts/scan-vulnerabilities.sh"
    fi
    exit 0
fi

[ "$QUIET" -eq 0 ] && echo "Found $CVE_COUNT unique CVE references in scan output" || true
[ "$QUIET" -eq 0 ] && echo "" || true

# Check each CVE
KEV_MATCHES=0
PAST_DUE=0
RANSOMWARE=0

TODAY=$(date +%Y-%m-%d)

while IFS= read -r cve; do
    [ -z "$cve" ] && continue

    KEV_ENTRY=$(check_cve_in_kev "$cve")

    if [ -n "$KEV_ENTRY" ]; then
        KEV_MATCHES=$((KEV_MATCHES + 1))

        PRODUCT=$(echo "$KEV_ENTRY" | jq -r '.product')
        VENDOR=$(echo "$KEV_ENTRY" | jq -r '.vendorProject')
        VULN_NAME=$(echo "$KEV_ENTRY" | jq -r '.vulnerabilityName')
        DATE_ADDED=$(echo "$KEV_ENTRY" | jq -r '.dateAdded')
        DUE_DATE=$(echo "$KEV_ENTRY" | jq -r '.dueDate')
        RANSOMWARE_USE=$(echo "$KEV_ENTRY" | jq -r '.knownRansomwareCampaignUse')
        SHORT_DESC=$(echo "$KEV_ENTRY" | jq -r '.shortDescription')

        # Check if past due
        IS_PAST_DUE="No"
        if [[ "$DUE_DATE" < "$TODAY" ]]; then
            IS_PAST_DUE="YES - OVERDUE"
            PAST_DUE=$((PAST_DUE + 1))
        fi

        # Check ransomware association
        if [ "$RANSOMWARE_USE" == "Known" ]; then
            RANSOMWARE=$((RANSOMWARE + 1))
        fi

        echo ""
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ⚠️  KNOWN EXPLOITED VULNERABILITY                                           ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${YELLOW}CVE:${NC}           $cve"
        echo -e "  ${YELLOW}Vendor:${NC}        $VENDOR"
        echo -e "  ${YELLOW}Product:${NC}       $PRODUCT"
        echo -e "  ${YELLOW}Vulnerability:${NC} $VULN_NAME"
        echo -e "  ${YELLOW}Date Added:${NC}    $DATE_ADDED"
        echo -e "  ${YELLOW}Due Date:${NC}      $DUE_DATE"

        if [[ "$IS_PAST_DUE" == "YES"* ]]; then
            echo -e "  ${RED}Past Due:${NC}      ${RED}$IS_PAST_DUE${NC}"
        else
            echo -e "  ${YELLOW}Past Due:${NC}      $IS_PAST_DUE"
        fi

        if [ "$RANSOMWARE_USE" == "Known" ]; then
            echo -e "  ${RED}Ransomware:${NC}    ${RED}KNOWN RANSOMWARE CAMPAIGN USE${NC}"
        else
            echo -e "  ${YELLOW}Ransomware:${NC}    $RANSOMWARE_USE"
        fi

        echo ""
        echo "  Description:"
        echo "  $SHORT_DESC" | fold -s -w 76 | sed 's/^/    /'
        echo ""
        echo "  Reference: https://nvd.nist.gov/vuln/detail/$cve"
        echo ""
    fi
done <<< "$CVES"

# Summary
echo ""
echo "==============================================================================="
echo "  SUMMARY"
echo "==============================================================================="
echo ""
echo "  CVEs in scan output:     $CVE_COUNT"
echo "  KEV matches:             $KEV_MATCHES"

if [ "$KEV_MATCHES" -gt 0 ]; then
    echo ""
    echo -e "  ${RED}⚠️  FINDINGS REQUIRING IMMEDIATE ACTION:${NC}"
    echo -e "  ${RED}    Past due date:         $PAST_DUE${NC}"
    echo -e "  ${RED}    Ransomware associated: $RANSOMWARE${NC}"
    echo ""
    echo "  Per BOD 22-01, federal agencies must remediate KEV entries by the due date."
    echo "  Non-federal organizations should treat KEV entries as high priority."
    echo ""
    echo "  Reference: https://www.cisa.gov/binding-operational-directive-22-01"
fi

echo ""
echo "==============================================================================="

# Exit code based on findings
if [ "$PAST_DUE" -gt 0 ]; then
    exit 1  # Critical - past due KEV entries
elif [ "$KEV_MATCHES" -gt 0 ]; then
    exit 1  # KEV matches found
else
    exit 0  # No KEV matches
fi
