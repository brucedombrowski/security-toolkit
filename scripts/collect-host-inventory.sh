#!/bin/bash
#
# Host Inventory Collection Script
#
# Purpose: Collect detailed host system information for audit/compliance
# Output: OS version, kernel, network interfaces (with MAC addresses), installed packages
#
# SENSITIVE: This script collects MAC addresses and system inventory.
#            Output is classified as CONTROLLED UNCLASSIFIED INFORMATION (CUI)
#            and handled according to NIST SP 800-171 and 32 CFR Part 2002
#
# CUI Protections:
#   - File created with mode 600 (owner read/write only)
#   - Process umask set to 0077 (restrictive permissions)
#   - User warned about CUI classification and handling requirements
#   - Secure deletion guidance provided
#
# Standards:
#   - NIST SP 800-53: CM-8 (System Component Inventory), AC-3 (Access Control)
#   - NIST SP 800-171: CUI protection requirements
#   - 32 CFR Part 2002: CUI handling standards
#   - NIST SP 800-88: Secure deletion of digital media
#
# Exit codes:
#   0 = Success
#   1 = Error collecting inventory
#
# Usage: ./collect-host-inventory.sh [output_file]
#        If output_file specified, inventory is written to file
#        Otherwise, output goes to stdout

set -eu

# CRITICAL-004: Set restrictive umask before any file operations
# This ensures all created files have mode 600 (owner only)
umask 0077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ============================================================================
# SOURCE LIBRARIES
# ============================================================================

# Source toolkit info library
if [ -f "$SCRIPT_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPT_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SECURITY_REPO_DIR"
fi

# Ensure toolkit variables have defaults (set -u safety)
TOOLKIT_NAME="${TOOLKIT_NAME:-Security Verification Toolkit}"
TOOLKIT_VERSION="${TOOLKIT_VERSION:-unknown}"
TOOLKIT_COMMIT="${TOOLKIT_COMMIT:-unknown}"
TOOLKIT_SOURCE="${TOOLKIT_SOURCE:-unknown}"

# Source inventory libraries
source "$SCRIPT_DIR/lib/inventory/output.sh"
source "$SCRIPT_DIR/lib/inventory/detect.sh"

# Source collectors
source "$SCRIPT_DIR/lib/inventory/collectors/os-info.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/network.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/packages.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/security-tools.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/languages.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/ides.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/browsers.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/backup.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/remote-desktop.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/productivity.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/containers.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/web-servers.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/databases.sh"
source "$SCRIPT_DIR/lib/inventory/collectors/ai-software.sh"

# ============================================================================
# INITIALIZATION
# ============================================================================

# Use UTC for consistent timestamps across time zones
TIMESTAMP=$(date -u "+%Y-%m-%dT%H:%M:%SZ")

# Optional output file (use ${1:-} for set -u safety)
OUTPUT_FILE="${1:-}"

# Initialize output file if specified
if [ -n "$OUTPUT_FILE" ]; then
    init_output "$OUTPUT_FILE"
fi

# ============================================================================
# CUI WARNING AND HEADER
# ============================================================================

# CRITICAL-004: Display CUI warning to user at runtime
show_cui_warning

# Output CUI header to inventory
output_cui_header "$TIMESTAMP" "$TOOLKIT_NAME" "$TOOLKIT_VERSION" "$TOOLKIT_COMMIT" "$TOOLKIT_SOURCE"

# ============================================================================
# COLLECT INVENTORY DATA
# ============================================================================

collect_os_info
collect_network
collect_packages
collect_security_tools
collect_languages
collect_ides
collect_browsers
collect_backup
collect_remote_desktop
collect_productivity
collect_containers
collect_web_servers
collect_databases
collect_ai_software

# ============================================================================
# CUI FOOTER
# ============================================================================

output_cui_footer

if [ -n "$OUTPUT_FILE" ]; then
    echo "Inventory saved to: $OUTPUT_FILE"
fi

exit 0
