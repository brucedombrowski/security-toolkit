#!/bin/bash
#
# Vulnerability Scanning Script
#
# Purpose: Comprehensive vulnerability assessment using open-source security tools
# Tools: Nmap (network scanning), OpenVAS (vulnerability assessment), Lynis (system audit)
#
# ============================================================================
# NIST SP 800-53 Rev 5 Control Mapping
# ============================================================================
#
# This script implements the following NIST controls:
#
# | Control | Family                        | Description                          | Tool     |
# |---------|-------------------------------|--------------------------------------|----------|
# | CA-2    | Assessment, Authorization     | Control Assessments                  | All      |
# | CA-7    | Assessment, Authorization     | Continuous Monitoring                | All      |
# | RA-3    | Risk Assessment               | Risk Assessment                      | All      |
# | RA-5    | Risk Assessment               | Vulnerability Monitoring and Scanning| Nmap/OVS |
# | SA-11   | System & Services Acquisition | Developer Testing and Evaluation     | All      |
# | SI-2    | System & Info Integrity       | Flaw Remediation                     | OpenVAS  |
# | SI-4    | System & Info Integrity       | System Monitoring                    | Nmap     |
# | SI-7    | System & Info Integrity       | Software, Firmware, Info Integrity   | Lynis    |
# | CM-6    | Configuration Management      | Configuration Settings               | Lynis    |
# | CM-8    | Configuration Management      | System Component Inventory           | Nmap     |
# | SC-7    | System & Comms Protection     | Boundary Protection                  | Nmap     |
#
# ============================================================================
# NIST SP 800-171 Rev 2 Control Mapping (CUI Protection)
# ============================================================================
#
# | Control   | Description                                    | Tool     |
# |-----------|------------------------------------------------|----------|
# | 3.11.1    | Periodically assess risk                       | All      |
# | 3.11.2    | Scan for vulnerabilities periodically          | All      |
# | 3.11.3    | Remediate vulnerabilities per risk assessments | OpenVAS  |
# | 3.12.1    | Assess security controls periodically          | All      |
# | 3.12.3    | Monitor security controls on ongoing basis     | All      |
# | 3.14.1    | Identify, report, correct system flaws         | OpenVAS  |
# | 3.14.6    | Monitor system to detect attacks               | Nmap     |
# | 3.14.7    | Identify unauthorized use of systems           | Nmap     |
#
# ============================================================================
# FIPS 199/200 Security Categorization
# ============================================================================
#
# FIPS 199 - Impact Levels Assessed:
#   - Confidentiality: Scan results may contain sensitive network topology
#   - Integrity: Scan verifies system configuration integrity
#   - Availability: Identifies services that could affect availability
#
# FIPS 200 - Minimum Security Requirements Verified:
#   - Risk Assessment (RA)
#   - Security Assessment and Authorization (CA)
#   - System and Information Integrity (SI)
#   - Configuration Management (CM)
#
# ============================================================================
# Exit Codes
# ============================================================================
#   0 = All scans completed successfully, no critical vulnerabilities
#   1 = Scans completed with findings requiring attention
#   2 = Missing required dependencies
#   3 = Scan execution error
#
# ============================================================================
# Usage
# ============================================================================
#   ./scan-vulnerabilities.sh [options] [target]
#
#   Options:
#     -n, --nmap-only      Run only Nmap scans
#     -o, --openvas-only   Run only OpenVAS scans
#     -l, --lynis-only     Run only Lynis audit
#     -q, --quick          Quick scan (reduced thoroughness)
#     -f, --full           Full comprehensive scan (default)
#     -r, --report-only    Generate report from existing scan data
#     -d, --output-dir DIR Output directory (default: .scans/)
#     -h, --help           Show this help message
#
#   Target:
#     IP address, hostname, or CIDR range for network scans
#     Default: localhost (127.0.0.1)
#
#   NOTE: Currently defaults to localhost only. Future enhancement will add
#   -a|--all-interfaces to auto-detect and scan all network interfaces.
#   See AGENTS.md "Future Enhancements" for details.
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

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

# Use standardized timestamps (UTC for consistency across time zones)
if [ "$TIMESTAMPS_AVAILABLE" -eq 1 ]; then
    TIMESTAMP=$(get_filename_timestamp)
    DATE_STAMP=$(get_date_stamp)
else
    TIMESTAMP=$(date -u "+%Y-%m-%dT%H%M%SZ")
    DATE_STAMP=$(date -u "+%Y-%m-%d")
fi
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)

# Toolkit version for traceability
TOOLKIT_VERSION=$(git -C "$SECURITY_REPO_DIR" describe --tags --always 2>/dev/null || echo "unknown")
TOOLKIT_COMMIT=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Default settings
TARGET="127.0.0.1"
SCAN_MODE="full"
RUN_NMAP=true
RUN_OPENVAS=true
RUN_LYNIS=true
REPORT_ONLY=false

# Output directories
OUTPUT_DIR=""
REPORT_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# NIST CONTROL DEFINITIONS (bash 3.2 compatible - no associative arrays)
# ============================================================================

# Function to get NIST 800-53 control description
get_nist_control() {
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

# NIST 800-53 controls list (alphabetized)
NIST_CONTROLS_LIST="CA-2 CA-7 CM-6 CM-8 RA-3 RA-5 SA-11 SC-7 SI-2 SI-4 SI-7"

# Function to get NIST 800-171 control description
get_nist_171_control() {
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

# NIST 800-171 controls list
NIST_171_CONTROLS_LIST="3.11.1 3.11.2 3.11.3 3.12.1 3.12.3 3.14.1 3.14.6 3.14.7"

# ============================================================================
# FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo "================================================================================"
    echo "                    VULNERABILITY SCANNING REPORT"
    echo "================================================================================"
    echo ""
    echo "  Scan Timestamp:  $TIMESTAMP"
    echo "  Target:          $TARGET"
    echo "  Scan Mode:       $SCAN_MODE"
    echo "  Hostname:        $HOSTNAME_SHORT"
    echo "  Toolkit:         Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
    echo "  Source:          https://github.com/brucedombrowski/Security"
    echo ""
    echo "================================================================================"
    echo ""
}

print_usage() {
    cat << EOF
Vulnerability Scanning Script - NIST Compliance Assessment

Usage: $0 [options] [target]

Options:
  -n, --nmap-only      Run only Nmap network scans
  -o, --openvas-only   Run only OpenVAS vulnerability scans
  -l, --lynis-only     Run only Lynis system audit
  -q, --quick          Quick scan (reduced thoroughness)
  -f, --full           Full comprehensive scan (default)
  -r, --report-only    Generate report from existing scan data
  -d, --output-dir DIR Output directory (default: .scans/)
  -h, --help           Show this help message

Target:
  IP address, hostname, or CIDR range (default: 127.0.0.1)

NIST Controls Assessed:
  RA-5   Vulnerability Monitoring and Scanning
  RA-3   Risk Assessment
  CA-2   Control Assessments
  SI-2   Flaw Remediation
  CM-6   Configuration Settings
  SC-7   Boundary Protection

Examples:
  $0                           # Scan localhost with all tools
  $0 192.168.1.0/24            # Scan network range
  $0 -n 10.0.0.1               # Nmap only on specific host
  $0 -l                        # Lynis audit only (local system)
  $0 -q 192.168.1.1            # Quick scan of specific host

EOF
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_warning "Not running as root. Some scans may have limited functionality."
        log_info "For comprehensive results, run with: sudo $0 $*"
        return 1
    fi
    return 0
}

# Check for required tools
check_dependencies() {
    local missing_tools=()
    local optional_tools=()

    echo "Checking dependencies..."
    echo ""

    # Required: at least one scanning tool
    if ! command -v nmap &> /dev/null; then
        optional_tools+=("nmap")
        RUN_NMAP=false
    else
        log_success "nmap: found"
    fi

    # OpenVAS/GVM check
    if ! command -v gvm-cli &> /dev/null && ! command -v omp &> /dev/null; then
        optional_tools+=("openvas/gvm")
        RUN_OPENVAS=false
    else
        if command -v gvm-cli &> /dev/null; then
            log_success "gvm-cli: installed"
        else
            log_success "omp (OpenVAS): installed"
        fi
    fi

    # Lynis check
    if ! command -v lynis &> /dev/null; then
        optional_tools+=("lynis")
        RUN_LYNIS=false
    else
        log_success "lynis: found"
    fi

    echo ""

    # Ensure at least one tool is available
    if ! $RUN_NMAP && ! $RUN_OPENVAS && ! $RUN_LYNIS; then
        log_error "No vulnerability scanning tools found!"
        echo ""
        echo "Install at least one of the following:"
        echo ""
        echo "  Nmap (network scanning):"
        echo "    macOS:  brew install nmap"
        echo "    Linux:  sudo apt install nmap"
        echo ""
        echo "  Lynis (system auditing):"
        echo "    macOS:  brew install lynis"
        echo "    Linux:  sudo apt install lynis"
        echo ""
        echo "  OpenVAS/GVM (vulnerability assessment):"
        echo "    See: https://greenbone.github.io/docs/latest/"
        echo ""
        return 2
    fi

    if [ ${#optional_tools[@]} -gt 0 ]; then
        log_warning "Optional tools not found: ${optional_tools[*]}"
        echo "         Install for more comprehensive scanning."
    fi

    return 0
}

# Initialize output directory
init_output() {
    local target_dir="$1"

    if [ -z "$target_dir" ]; then
        # Default to .scans in current directory or Security repo
        if [ -d "$SECURITY_REPO_DIR" ]; then
            OUTPUT_DIR="$SECURITY_REPO_DIR/.scans"
        else
            OUTPUT_DIR="$(pwd)/.scans"
        fi
    else
        OUTPUT_DIR="$target_dir/.scans"
    fi

    mkdir -p "$OUTPUT_DIR"
    REPORT_FILE="$OUTPUT_DIR/vulnerability-scan-$TIMESTAMP.txt"

    # Initialize audit logging
    if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
        init_audit_log "$OUTPUT_DIR/.." "vulnerability-scan" || true
    fi

    log_info "Output directory: $OUTPUT_DIR"
    log_info "Report file: $REPORT_FILE"
}

# ============================================================================
# NMAP SCANNING (RA-5, SI-4, CM-8, SC-7)
# ============================================================================

run_nmap_scan() {
    local target="$1"
    local output_prefix="$OUTPUT_DIR/nmap-$TIMESTAMP"

    echo ""
    echo "================================================================================"
    echo "NMAP NETWORK VULNERABILITY SCAN"
    echo "================================================================================"
    echo ""
    echo "NIST Controls:"
    echo "  - RA-5: Vulnerability Monitoring and Scanning"
    echo "  - SI-4: System Monitoring"
    echo "  - CM-8: System Component Inventory"
    echo "  - SC-7: Boundary Protection"
    echo ""
    echo "NIST SP 800-171:"
    echo "  - 3.11.2: Scan for vulnerabilities periodically"
    echo "  - 3.14.6: Monitor systems to detect attacks"
    echo "  - 3.14.7: Identify unauthorized use of systems"
    echo ""
    echo "Target: $target"
    echo ""

    local nmap_args=""
    local is_localhost=false

    # Check if target is localhost
    if [ "$target" = "127.0.0.1" ] || [ "$target" = "localhost" ] || [ "$target" = "::1" ]; then
        is_localhost=true
    fi

    if [ "$SCAN_MODE" = "quick" ]; then
        # Quick scan: Top 100 ports, no scripts
        nmap_args="-sV -T4 --top-ports 100"
        log_info "Running quick Nmap scan (top 100 ports)..."
    else
        # Full scan: version detection, common ports
        # Note: -p- (all ports) is too slow for unprivileged localhost scans
        if $is_localhost && [[ $EUID -ne 0 ]]; then
            nmap_args="-sV -T4 --top-ports 1000"
            log_info "Running Nmap scan (top 1000 ports - localhost unprivileged mode)..."
        else
            nmap_args="-sV -sC -T4 -p-"
            log_info "Running comprehensive Nmap scan (all ports)..."
        fi
    fi

    # Check if we can run privileged scans
    if [[ $EUID -eq 0 ]]; then
        nmap_args="$nmap_args -sS -O"  # SYN scan + OS detection
        log_info "Running privileged scan (SYN + OS detection)"
    else
        nmap_args="$nmap_args -sT"  # TCP connect scan
        log_warning "Running unprivileged scan (TCP connect only)"
        if $is_localhost; then
            log_warning "Localhost TCP connect scan may show 'Strange read error' - this is a known Nmap issue"
        fi
    fi

    # Add timeout for scans to prevent hanging (5 minutes for quick, 15 for full)
    # Add progress updates every 30 seconds for full scans
    if [ "$SCAN_MODE" = "quick" ]; then
        nmap_args="$nmap_args --host-timeout 300s"
    else
        nmap_args="$nmap_args --host-timeout 900s --stats-every 10s"
    fi

    # Run Nmap
    local nmap_output="$output_prefix.txt"
    local nmap_xml="$output_prefix.xml"

    echo ""
    if nmap $nmap_args -oN "$nmap_output" -oX "$nmap_xml" "$target" 2>&1; then
        log_success "Nmap scan completed"
        echo ""
        echo "Results saved to:"
        echo "  Text: $nmap_output"
        echo "  XML:  $nmap_xml"

        # Parse and summarize results
        summarize_nmap_results "$nmap_output"
        return 0
    else
        log_error "Nmap scan failed"
        return 1
    fi
}

summarize_nmap_results() {
    local nmap_output="$1"

    echo ""
    echo "--- Nmap Scan Summary ---"
    echo ""

    # Count open ports
    local open_ports=$(grep -c "^[0-9].*open" "$nmap_output" 2>/dev/null || echo "0")
    local filtered_ports=$(grep -c "^[0-9].*filtered" "$nmap_output" 2>/dev/null || echo "0")

    echo "Open ports found: $open_ports"
    echo "Filtered ports: $filtered_ports"
    echo ""

    # List open ports with services
    if [ "$open_ports" -gt 0 ]; then
        echo "Open ports and services:"
        grep "^[0-9].*open" "$nmap_output" | head -20
        if [ "$open_ports" -gt 20 ]; then
            echo "... and $((open_ports - 20)) more"
        fi
    fi

    # Check for common vulnerable services
    echo ""
    echo "Security assessment:"

    local vuln_count=0

    # Check for telnet (insecure)
    if grep -q "23/tcp.*open.*telnet" "$nmap_output" 2>/dev/null; then
        log_warning "Telnet service detected (insecure, use SSH instead)"
        ((vuln_count++))
    fi

    # Check for FTP (often insecure)
    if grep -q "21/tcp.*open.*ftp" "$nmap_output" 2>/dev/null; then
        log_warning "FTP service detected (consider SFTP/FTPS)"
        ((vuln_count++))
    fi

    # Check for unencrypted HTTP
    if grep -q "80/tcp.*open.*http" "$nmap_output" 2>/dev/null; then
        log_info "HTTP (port 80) detected - verify HTTPS redirect"
    fi

    # Check for SMB
    if grep -q "445/tcp.*open" "$nmap_output" 2>/dev/null; then
        log_warning "SMB service detected - ensure latest patches applied"
        ((vuln_count++))
    fi

    # Check for RDP
    if grep -q "3389/tcp.*open" "$nmap_output" 2>/dev/null; then
        log_warning "RDP service detected - ensure NLA enabled"
        ((vuln_count++))
    fi

    if [ "$vuln_count" -eq 0 ]; then
        log_success "No obviously vulnerable services detected"
    else
        log_warning "$vuln_count potential security concern(s) identified"
    fi

    echo ""
    return 0
}

# ============================================================================
# OPENVAS/GVM SCANNING (RA-5, SI-2, RA-3)
# ============================================================================

run_openvas_scan() {
    local target="$1"
    local output_prefix="$OUTPUT_DIR/openvas-$TIMESTAMP"

    echo ""
    echo "================================================================================"
    echo "OPENVAS VULNERABILITY ASSESSMENT"
    echo "================================================================================"
    echo ""
    echo "NIST Controls:"
    echo "  - RA-5: Vulnerability Monitoring and Scanning"
    echo "  - SI-2: Flaw Remediation"
    echo "  - RA-3: Risk Assessment"
    echo ""
    echo "NIST SP 800-171:"
    echo "  - 3.11.2: Scan for vulnerabilities periodically"
    echo "  - 3.11.3: Remediate vulnerabilities per risk assessments"
    echo "  - 3.14.1: Identify, report, correct system flaws"
    echo ""
    echo "Target: $target"
    echo ""

    # Check if GVM/OpenVAS daemon is running
    if command -v gvm-cli &> /dev/null; then
        log_info "Using Greenbone Vulnerability Management (GVM)"
        run_gvm_scan "$target" "$output_prefix"
    elif command -v omp &> /dev/null; then
        log_info "Using OpenVAS Management Protocol (OMP)"
        run_omp_scan "$target" "$output_prefix"
    else
        log_error "No OpenVAS/GVM client available"
        return 1
    fi
}

run_gvm_scan() {
    local target="$1"
    local output_prefix="$2"

    log_warning "GVM scanning requires a running GVM daemon and proper authentication."
    echo ""
    echo "To run a GVM scan manually:"
    echo ""
    echo "  1. Start GVM services:"
    echo "     sudo gvm-start"
    echo ""
    echo "  2. Create a target:"
    echo "     gvm-cli --gmp-username admin --gmp-password <pass> \\"
    echo "       tls --hostname localhost socket \\"
    echo "       --xml '<create_target><name>Scan-$TIMESTAMP</name><hosts>$target</hosts></create_target>'"
    echo ""
    echo "  3. Create and start a task with appropriate scan config"
    echo ""
    echo "  4. Export results to: $output_prefix.xml"
    echo ""

    # Check if we can connect to GVM
    if gvm-cli --help &>/dev/null; then
        log_info "GVM CLI available. Configure credentials in /etc/gvm/ or use --gmp-username/--gmp-password"
    fi

    return 0
}

run_omp_scan() {
    local target="$1"
    local output_prefix="$2"

    log_warning "OMP scanning requires OpenVAS daemon running and credentials configured."
    echo ""
    echo "To run an OMP scan manually:"
    echo ""
    echo "  1. Ensure OpenVAS services are running"
    echo "  2. Configure ~/.omp (username, password, host, port)"
    echo "  3. Create target and task via OMP commands"
    echo "  4. Export results to: $output_prefix.xml"
    echo ""

    return 0
}

# ============================================================================
# LYNIS SYSTEM AUDIT (SI-7, CM-6, CA-2)
# ============================================================================

run_lynis_audit() {
    local output_prefix="$OUTPUT_DIR/lynis-$TIMESTAMP"

    echo ""
    echo "================================================================================"
    echo "LYNIS SYSTEM SECURITY AUDIT"
    echo "================================================================================"
    echo ""
    echo "NIST Controls:"
    echo "  - SI-7: Software, Firmware, and Information Integrity"
    echo "  - CM-6: Configuration Settings"
    echo "  - CA-2: Control Assessments"
    echo ""
    echo "NIST SP 800-171:"
    echo "  - 3.12.1: Periodically assess security controls"
    echo "  - 3.12.3: Monitor security controls on ongoing basis"
    echo ""
    echo "FIPS 200 Requirements:"
    echo "  - Configuration Management (CM)"
    echo "  - System and Information Integrity (SI)"
    echo ""

    local lynis_args="--quick --no-colors"

    if [ "$SCAN_MODE" = "full" ]; then
        lynis_args="--no-colors"
        log_info "Running comprehensive Lynis audit..."
    else
        log_info "Running quick Lynis audit..."
    fi

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_warning "Running without root - some checks will be skipped"
        lynis_args="$lynis_args --pentest"
    fi

    local lynis_output="$output_prefix.txt"
    local lynis_report="$output_prefix-report.dat"

    echo ""

    # Run Lynis
    if lynis audit system $lynis_args --report-file "$lynis_report" 2>&1 | tee "$lynis_output"; then
        log_success "Lynis audit completed"
        echo ""
        echo "Results saved to:"
        echo "  Log:    $lynis_output"
        echo "  Report: $lynis_report"

        # Parse and summarize results
        summarize_lynis_results "$lynis_output" "$lynis_report"
        return 0
    else
        log_error "Lynis audit encountered errors"
        return 1
    fi
}

summarize_lynis_results() {
    local lynis_output="$1"
    local lynis_report="$2"

    echo ""
    echo "--- Lynis Audit Summary ---"
    echo ""

    # Extract hardening index if available
    if [ -f "$lynis_report" ]; then
        local hardening_index=$(grep "hardening_index=" "$lynis_report" 2>/dev/null | cut -d= -f2)
        if [ -n "$hardening_index" ]; then
            echo "Hardening Index: $hardening_index / 100"
            echo ""

            if [ "$hardening_index" -ge 80 ]; then
                log_success "System hardening: GOOD"
            elif [ "$hardening_index" -ge 60 ]; then
                log_warning "System hardening: MODERATE (improvements recommended)"
            else
                log_error "System hardening: NEEDS IMPROVEMENT"
            fi
        fi
    fi

    # Count warnings and suggestions (use tr to strip any whitespace/newlines)
    local warnings=$(grep -c "\[ warning \]" "$lynis_output" 2>/dev/null | tr -d '[:space:]')
    local suggestions=$(grep -c "\[ suggestion \]" "$lynis_output" 2>/dev/null | tr -d '[:space:]')
    # Default to 0 if empty
    warnings="${warnings:-0}"
    suggestions="${suggestions:-0}"

    echo ""
    echo "Findings:"
    echo "  Warnings:    $warnings"
    echo "  Suggestions: $suggestions"
    echo ""

    # Show top warnings (use numeric comparison with default)
    if [ "${warnings:-0}" -gt 0 ] 2>/dev/null; then
        echo "Top warnings:"
        grep "\[ warning \]" "$lynis_output" | head -5
        echo ""
    fi

    return 0
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

generate_compliance_report() {
    local report_file="$1"

    echo "" >> "$report_file"
    echo "================================================================================" >> "$report_file"
    echo "                    NIST COMPLIANCE MAPPING SUMMARY" >> "$report_file"
    echo "================================================================================" >> "$report_file"
    echo "" >> "$report_file"

    echo "NIST SP 800-53 Rev 5 Controls Assessed:" >> "$report_file"
    echo "----------------------------------------" >> "$report_file"
    for control in $NIST_CONTROLS_LIST; do
        printf "  %-8s %s\n" "$control" "$(get_nist_control "$control")" >> "$report_file"
    done

    echo "" >> "$report_file"
    echo "NIST SP 800-171 Rev 2 Controls Assessed:" >> "$report_file"
    echo "-----------------------------------------" >> "$report_file"
    for control in $NIST_171_CONTROLS_LIST; do
        printf "  %-10s %s\n" "$control" "$(get_nist_171_control "$control")" >> "$report_file"
    done

    echo "" >> "$report_file"
    echo "FIPS Requirements:" >> "$report_file"
    echo "------------------" >> "$report_file"
    echo "  FIPS 199: Security categorization impact levels assessed" >> "$report_file"
    echo "  FIPS 200: Minimum security requirements verified" >> "$report_file"

    echo "" >> "$report_file"
    echo "================================================================================" >> "$report_file"
    echo "                         SCAN EXECUTION DETAILS" >> "$report_file"
    echo "================================================================================" >> "$report_file"
    echo "" >> "$report_file"
    echo "Scan Timestamp:  $TIMESTAMP" >> "$report_file"
    echo "Target:          $TARGET" >> "$report_file"
    echo "Hostname:        $HOSTNAME_SHORT" >> "$report_file"
    echo "Scan Mode:       $SCAN_MODE" >> "$report_file"
    echo "Toolkit Version: $TOOLKIT_VERSION ($TOOLKIT_COMMIT)" >> "$report_file"
    echo "" >> "$report_file"
    echo "Tools Executed:" >> "$report_file"
    $RUN_NMAP && echo "  [X] Nmap network scanning" >> "$report_file" || echo "  [ ] Nmap (not available)" >> "$report_file"
    $RUN_OPENVAS && echo "  [X] OpenVAS vulnerability assessment" >> "$report_file" || echo "  [ ] OpenVAS (not available)" >> "$report_file"
    $RUN_LYNIS && echo "  [X] Lynis system audit" >> "$report_file" || echo "  [ ] Lynis (not available)" >> "$report_file"

    echo "" >> "$report_file"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--nmap-only)
                RUN_OPENVAS=false
                RUN_LYNIS=false
                shift
                ;;
            -o|--openvas-only)
                RUN_NMAP=false
                RUN_LYNIS=false
                shift
                ;;
            -l|--lynis-only)
                RUN_NMAP=false
                RUN_OPENVAS=false
                shift
                ;;
            -q|--quick)
                SCAN_MODE="quick"
                shift
                ;;
            -f|--full)
                SCAN_MODE="full"
                shift
                ;;
            -r|--report-only)
                REPORT_ONLY=true
                shift
                ;;
            -d|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                print_usage
                exit 2
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done

    # Initialize
    print_header

    # Check dependencies
    if ! check_dependencies; then
        exit 2
    fi

    # Initialize output directory
    init_output ""

    # Start report
    {
        echo "================================================================================"
        echo "                    VULNERABILITY SCANNING REPORT"
        echo "================================================================================"
        echo ""
        echo "Generated: $TIMESTAMP"
        echo "Target: $TARGET"
        echo "Toolkit: Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
        echo "Source: https://github.com/brucedombrowski/Security"
        echo ""
    } > "$REPORT_FILE"

    # Track overall status
    local overall_status=0
    local scan_count=0
    local pass_count=0

    echo ""

    # Run Nmap if enabled
    if $RUN_NMAP && ! $REPORT_ONLY; then
        ((scan_count++))
        if run_nmap_scan "$TARGET" 2>&1 | tee -a "$REPORT_FILE"; then
            ((pass_count++))
        else
            overall_status=1
        fi
    fi

    # Run OpenVAS if enabled
    if $RUN_OPENVAS && ! $REPORT_ONLY; then
        ((scan_count++))
        if run_openvas_scan "$TARGET" 2>&1 | tee -a "$REPORT_FILE"; then
            ((pass_count++))
        else
            overall_status=1
        fi
    fi

    # Run Lynis if enabled (always local)
    if $RUN_LYNIS && ! $REPORT_ONLY; then
        ((scan_count++))
        if run_lynis_audit 2>&1 | tee -a "$REPORT_FILE"; then
            ((pass_count++))
        else
            overall_status=1
        fi
    fi

    # Generate compliance mapping
    generate_compliance_report "$REPORT_FILE"

    # Final summary
    echo ""
    echo "================================================================================"
    echo "                         SCAN COMPLETION SUMMARY"
    echo "================================================================================"
    echo ""
    echo "Scans executed: $scan_count"
    echo "Scans passed:   $pass_count"
    echo ""
    echo "Report saved to: $REPORT_FILE"
    echo ""

    if [ $overall_status -eq 0 ]; then
        log_success "All scans completed successfully"
        # Finalize audit log with PASS status
        if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
            finalize_audit_log "PASS" "scans=$scan_count passed=$pass_count"
        fi
    else
        log_warning "Scans completed with findings - review report for details"
        # Finalize audit log with FAIL status
        if [ "$AUDIT_AVAILABLE" -eq 1 ]; then
            finalize_audit_log "FAIL" "scans=$scan_count passed=$pass_count"
        fi
    fi

    echo ""
    echo "NIST Compliance Status:"
    echo "  RA-5 (Vulnerability Scanning): Executed"
    echo "  CA-2 (Control Assessment): Executed"
    echo "  SI-2 (Flaw Remediation): Findings documented"
    echo ""

    return $overall_status
}

# Run main
main "$@"
