#!/bin/bash
#
# NIST Control Definitions Library
#
# Purpose: NIST SP 800-53 and 800-171 control definitions for vulnerability scanning
# Used by: scan-vulnerabilities.sh and report generation
#
# Standards covered:
#   - NIST SP 800-53 Rev 5 (Security and Privacy Controls)
#   - NIST SP 800-171 Rev 2 (CUI Protection)
#   - FIPS 199/200 (Security Categorization)
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# =============================================================================
# NIST SP 800-53 Rev 5 Controls
# =============================================================================

# NIST 800-53 controls list (alphabetized)
NIST_800_53_CONTROLS="CA-2 CA-7 CM-6 CM-8 RA-3 RA-5 SA-11 SC-7 SI-2 SI-4 SI-7"

# Get NIST 800-53 control description
# Usage: get_nist_800_53_control "CA-2"
get_nist_800_53_control() {
    case "$1" in
        "CA-2")  echo "Control Assessments" ;;
        "CA-7")  echo "Continuous Monitoring" ;;
        "CM-6")  echo "Configuration Settings" ;;
        "CM-8")  echo "System Component Inventory" ;;
        "RA-3")  echo "Risk Assessment" ;;
        "RA-5")  echo "Vulnerability Monitoring and Scanning" ;;
        "SA-11") echo "Developer Testing and Evaluation" ;;
        "SC-7")  echo "Boundary Protection" ;;
        "SI-2")  echo "Flaw Remediation" ;;
        "SI-4")  echo "System Monitoring" ;;
        "SI-7")  echo "Software, Firmware, and Information Integrity" ;;
        *)       echo "Unknown control" ;;
    esac
}

# Get NIST 800-53 control family
# Usage: get_nist_800_53_family "CA-2"
get_nist_800_53_family() {
    case "$1" in
        CA-*) echo "Assessment, Authorization, and Monitoring" ;;
        CM-*) echo "Configuration Management" ;;
        RA-*) echo "Risk Assessment" ;;
        SA-*) echo "System and Services Acquisition" ;;
        SC-*) echo "System and Communications Protection" ;;
        SI-*) echo "System and Information Integrity" ;;
        *)    echo "Unknown family" ;;
    esac
}

# =============================================================================
# NIST SP 800-171 Rev 2 Controls
# =============================================================================

# NIST 800-171 controls list
NIST_800_171_CONTROLS="3.11.1 3.11.2 3.11.3 3.12.1 3.12.3 3.14.1 3.14.6 3.14.7"

# Get NIST 800-171 control description
# Usage: get_nist_800_171_control "3.11.1"
get_nist_800_171_control() {
    case "$1" in
        "3.11.1") echo "Periodically assess the risk to organizational operations" ;;
        "3.11.2") echo "Scan for vulnerabilities in organizational systems periodically" ;;
        "3.11.3") echo "Remediate vulnerabilities in accordance with risk assessments" ;;
        "3.12.1") echo "Periodically assess security controls to determine effectiveness" ;;
        "3.12.3") echo "Monitor security controls on an ongoing basis" ;;
        "3.14.1") echo "Identify, report, and correct system flaws in a timely manner" ;;
        "3.14.6") echo "Monitor organizational systems to detect attacks" ;;
        "3.14.7") echo "Identify unauthorized use of organizational systems" ;;
        *)        echo "Unknown control" ;;
    esac
}

# Get NIST 800-171 control family
# Usage: get_nist_800_171_family "3.11.1"
get_nist_800_171_family() {
    local prefix="${1%.*}"
    case "$prefix" in
        "3.11") echo "Risk Assessment" ;;
        "3.12") echo "Security Assessment" ;;
        "3.14") echo "System and Information Integrity" ;;
        *)      echo "Unknown family" ;;
    esac
}

# =============================================================================
# Scanner-to-Control Mapping
# =============================================================================

# Get NIST 800-53 controls for a specific scanner
# Usage: get_scanner_controls_800_53 "nmap"
get_scanner_controls_800_53() {
    case "$1" in
        "nmap")    echo "RA-5 SI-4 CM-8 SC-7" ;;
        "openvas") echo "RA-5 SI-2 RA-3" ;;
        "lynis")   echo "SI-7 CM-6 CA-2" ;;
        "all")     echo "$NIST_800_53_CONTROLS" ;;
        *)         echo "" ;;
    esac
}

# Get NIST 800-171 controls for a specific scanner
# Usage: get_scanner_controls_800_171 "nmap"
get_scanner_controls_800_171() {
    case "$1" in
        "nmap")    echo "3.11.2 3.14.6 3.14.7" ;;
        "openvas") echo "3.11.2 3.11.3 3.14.1" ;;
        "lynis")   echo "3.12.1 3.12.3" ;;
        "all")     echo "$NIST_800_171_CONTROLS" ;;
        *)         echo "" ;;
    esac
}

# Print NIST control header for a scanner
# Usage: print_nist_controls_header "nmap"
print_nist_controls_header() {
    local scanner="$1"
    local controls_53 controls_171

    controls_53=$(get_scanner_controls_800_53 "$scanner")
    controls_171=$(get_scanner_controls_800_171 "$scanner")

    echo "NIST Controls:"
    for control in $controls_53; do
        echo "  - $control: $(get_nist_800_53_control "$control")"
    done
    echo ""
    echo "NIST SP 800-171:"
    for control in $controls_171; do
        echo "  - $control: $(get_nist_800_171_control "$control")"
    done
    echo ""
}

# =============================================================================
# Backward compatibility aliases
# =============================================================================

# Alias for backward compatibility with original script
get_nist_control() {
    get_nist_800_53_control "$1"
}

get_nist_171_control() {
    get_nist_800_171_control "$1"
}

NIST_CONTROLS_LIST="$NIST_800_53_CONTROLS"
NIST_171_CONTROLS_LIST="$NIST_800_171_CONTROLS"
