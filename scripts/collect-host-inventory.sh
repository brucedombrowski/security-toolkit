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

set -e

# CRITICAL-004: Set restrictive umask before any file operations
# This ensures all created files have mode 600 (owner only)
umask 0077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Use UTC for consistent timestamps across time zones
TIMESTAMP=$(date -u "+%Y-%m-%dT%H:%M:%SZ")
TOOLKIT_VERSION=$(git -C "$SECURITY_REPO_DIR" describe --tags --always 2>/dev/null || echo "unknown")
TOOLKIT_COMMIT=$(git -C "$SECURITY_REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Optional output file
OUTPUT_FILE="$1"

# Function to output (to file or stdout)
output() {
    if [ -n "$OUTPUT_FILE" ]; then
        echo "$1" >> "$OUTPUT_FILE"
    else
        echo "$1"
    fi
}

# Initialize output file if specified
if [ -n "$OUTPUT_FILE" ]; then
    # CRITICAL-004: Create with restrictive permissions (mode 600)
    # Using umask 0077 already set above, but explicit chmod for clarity and safety
    > "$OUTPUT_FILE"
    chmod 600 "$OUTPUT_FILE" 2>/dev/null || true
    
    # Verify permissions were set correctly (NIST SP 800-171 AC-3)
    file_mode=$(stat -f "%OLp" "$OUTPUT_FILE" 2>/dev/null || stat -c "%a" "$OUTPUT_FILE" 2>/dev/null)
    if [ "$file_mode" != "600" ]; then
        echo "WARNING: File permissions may not be fully restricted (mode: $file_mode, expected 600)" >&2
    fi
fi

# CRITICAL-004: Display CUI warning to user at runtime
echo "" >&2
echo "╔══════════════════════════════════════════════════════════════════════════╗" >&2
echo "║ ⚠️  SECURITY WARNING: CONTROLLED UNCLASSIFIED INFORMATION (CUI)           ║" >&2
echo "╚══════════════════════════════════════════════════════════════════════════╝" >&2
echo "" >&2
echo "Host inventory file contains CUI per NIST SP 800-171 and 32 CFR Part 2002:" >&2
echo "" >&2
echo "  Location: ${OUTPUT_FILE:-(stdout)}" >&2
if [ -n "$OUTPUT_FILE" ]; then
    echo "  Permissions: 600 (owner read/write only)" >&2
fi
echo "" >&2
echo "This file includes sensitive system information:" >&2
echo "  • MAC addresses (network topology identification)" >&2
echo "  • Hardware serial numbers (device identity)" >&2
echo "  • Installed software versions (attack surface analysis)" >&2
echo "  • System configuration details (security control details)" >&2
echo "" >&2
echo "REQUIRED HANDLING:" >&2
echo "  1. Keep file permission-restricted (600) - verify with: ls -l" >&2
echo "  2. Never upload to public cloud storage or repositories" >&2
echo "  3. Never commit to version control (even private)" >&2
echo "  4. Store on encrypted media or encrypted filesystems" >&2
echo "  5. Delete securely when no longer needed" >&2
echo "" >&2
if [ -n "$OUTPUT_FILE" ]; then
    echo "For secure deletion instructions, see: scripts/secure-delete.sh" >&2
fi
echo "" >&2

output "////////////////////////////////////////////////////////////////////////////////"
output "//                                                                            //"
output "//                 CONTROLLED UNCLASSIFIED INFORMATION (CUI)                  //"
output "//                                                                            //"
output "//  CUI Category: CTI (Controlled Technical Information)                      //"
output "//  Dissemination: FEDCON - Federal Contractors                               //"
output "//  Safeguarding: Per NIST SP 800-171                                         //"
output "//                                                                            //"
output "////////////////////////////////////////////////////////////////////////////////"
output ""
output "Host System Inventory"
output "====================="
output "Generated: $TIMESTAMP"
output "Hostname: $(hostname)"
output "Toolkit: Security Verification Toolkit $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
output "Source: https://github.com/brucedombrowski/Security"
output ""
output "HANDLING NOTICE:"
output "  This document contains Controlled Unclassified Information (CUI)."
output "  Contents include MAC addresses, serial numbers, and system inventory."
output "  - Do not post to public repositories or websites"
output "  - Limit distribution to authorized personnel"
output "  - Store on encrypted media or systems"
output "  - Destroy with: scripts/secure-delete.sh <file> (NIST SP 800-88)"
output ""

# ============================================================================
# OS AND KERNEL INFORMATION
# ============================================================================

output "Operating System Information:"
output "-----------------------------"
if [[ "$(uname)" == "Darwin" ]]; then
    output "  Platform: macOS"
    output "  OS Version: $(sw_vers -productVersion)"
    output "  Build: $(sw_vers -buildVersion)"
    output "  Kernel: $(uname -r)"
    output "  Architecture: $(uname -m)"
    output "  Hardware Model: $(sysctl -n hw.model 2>/dev/null || echo 'Unknown')"
    output "  Serial Number: $(system_profiler SPHardwareDataType 2>/dev/null | grep "Serial Number" | awk -F': ' '{print $2}' || echo 'Unknown')"
elif [[ "$(uname)" == "Linux" ]]; then
    output "  Platform: Linux"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        output "  Distribution: $NAME"
        output "  Version: $VERSION"
        output "  Version ID: $VERSION_ID"
    fi
    output "  Kernel: $(uname -r)"
    output "  Architecture: $(uname -m)"
    # Try to get hardware info
    if [ -f /sys/class/dmi/id/product_name ]; then
        output "  Hardware Model: $(cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'Unknown')"
    fi
    if [ -f /sys/class/dmi/id/product_serial ]; then
        output "  Serial Number: $(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo 'Unknown')"
    fi
fi
output ""

# ============================================================================
# NETWORK INTERFACES WITH MAC ADDRESSES
# ============================================================================

output "Network Interfaces:"
output "-------------------"
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS: Use ifconfig
    for iface in $(ifconfig -l); do
        # Skip loopback
        if [ "$iface" = "lo0" ]; then
            continue
        fi
        # Get MAC address
        mac=$(ifconfig "$iface" 2>/dev/null | grep -i "ether" | awk '{print $2}')
        # Get IP addresses
        ipv4=$(ifconfig "$iface" 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
        ipv6=$(ifconfig "$iface" 2>/dev/null | grep "inet6 " | grep -v "fe80" | awk '{print $2}' | head -1)
        # Get status
        status=$(ifconfig "$iface" 2>/dev/null | grep -q "status: active" && echo "active" || echo "inactive")
        # Get media type
        media=$(ifconfig "$iface" 2>/dev/null | grep "media:" | sed 's/.*media: //' | head -1)

        if [ -n "$mac" ]; then
            output "  $iface:"
            output "    MAC Address: $mac"
            [ -n "$ipv4" ] && output "    IPv4: $ipv4"
            [ -n "$ipv6" ] && output "    IPv6: $ipv6"
            output "    Status: $status"
            [ -n "$media" ] && output "    Media: $media"
        fi
    done
elif [[ "$(uname)" == "Linux" ]]; then
    # Linux: Use ip command
    if command -v ip >/dev/null 2>&1; then
        for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "^lo$"); do
            mac=$(ip link show "$iface" 2>/dev/null | grep "link/ether" | awk '{print $2}')
            ipv4=$(ip -4 addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
            ipv6=$(ip -6 addr show "$iface" 2>/dev/null | grep "inet6 " | grep -v "fe80" | awk '{print $2}' | head -1)
            state=$(ip link show "$iface" 2>/dev/null | grep -oP "state \K\w+")
            driver=$(ethtool -i "$iface" 2>/dev/null | grep "driver:" | awk '{print $2}')

            if [ -n "$mac" ]; then
                output "  $iface:"
                output "    MAC Address: $mac"
                [ -n "$ipv4" ] && output "    IPv4: $ipv4"
                [ -n "$ipv6" ] && output "    IPv6: $ipv6"
                output "    State: $state"
                [ -n "$driver" ] && output "    Driver: $driver"
            fi
        done
    else
        # Fallback to ifconfig
        output "  (Using legacy ifconfig - install iproute2 for detailed output)"
        ifconfig -a 2>/dev/null | grep -E "^[a-z]|ether|inet " || output "  Unable to enumerate interfaces"
    fi
fi
output ""

# ============================================================================
# INSTALLED SOFTWARE PACKAGES
# ============================================================================

output "Installed Software Packages:"
output "----------------------------"
if [[ "$(uname)" == "Darwin" ]]; then
    # Homebrew packages
    if command -v brew >/dev/null 2>&1; then
        output "  Homebrew Packages:"
        brew list --versions 2>/dev/null | while read line; do
            output "    $line"
        done
        output ""
        output "  Homebrew Casks:"
        brew list --cask --versions 2>/dev/null | while read line; do
            output "    $line"
        done
    else
        output "  Homebrew: not installed"
    fi
    output ""

    # System applications (from /Applications)
    output "  Applications (/Applications):"
    for app in /Applications/*.app; do
        if [ -d "$app" ]; then
            app_name=$(basename "$app" .app)
            # Try to get version from Info.plist
            version=$(defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
            output "    $app_name: $version"
        fi
    done

elif [[ "$(uname)" == "Linux" ]]; then
    # Debian/Ubuntu
    if command -v dpkg >/dev/null 2>&1; then
        output "  Debian/Ubuntu Packages (dpkg):"
        dpkg-query -W -f='    ${Package}: ${Version}\n' 2>/dev/null | head -100
        PKG_COUNT=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | wc -l)
        if [ "$PKG_COUNT" -gt 100 ]; then
            output "    ... and $((PKG_COUNT - 100)) more packages (total: $PKG_COUNT)"
        fi
    # RHEL/CentOS/Fedora
    elif command -v rpm >/dev/null 2>&1; then
        output "  RPM Packages:"
        rpm -qa --queryformat '    %{NAME}: %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort | head -100
        PKG_COUNT=$(rpm -qa 2>/dev/null | wc -l)
        if [ "$PKG_COUNT" -gt 100 ]; then
            output "    ... and $((PKG_COUNT - 100)) more packages (total: $PKG_COUNT)"
        fi
    fi
fi
output ""

# ============================================================================
# SECURITY-RELEVANT SOFTWARE VERSIONS
# ============================================================================

output "Security-Relevant Software:"
output "---------------------------"

# ClamAV
if command -v clamscan >/dev/null 2>&1; then
    output "  ClamAV: $(clamscan --version 2>/dev/null | head -1)"
else
    output "  ClamAV: not installed"
fi

# OpenSSL
if command -v openssl >/dev/null 2>&1; then
    output "  OpenSSL: $(openssl version 2>/dev/null)"
else
    output "  OpenSSL: not installed"
fi

# SSH
if command -v ssh >/dev/null 2>&1; then
    output "  SSH: $(ssh -V 2>&1)"
fi

# GPG
if command -v gpg >/dev/null 2>&1; then
    output "  GPG: $(gpg --version 2>/dev/null | head -1)"
else
    output "  GPG: not installed"
fi

# Git
if command -v git >/dev/null 2>&1; then
    output "  Git: $(git --version 2>/dev/null)"
else
    output "  Git: not installed"
fi

# Python
if command -v python3 >/dev/null 2>&1; then
    output "  Python: $(python3 --version 2>/dev/null)"
elif command -v python >/dev/null 2>&1; then
    output "  Python: $(python --version 2>/dev/null)"
fi

# Node.js
if command -v node >/dev/null 2>&1; then
    output "  Node.js: $(node --version 2>/dev/null)"
fi

# Java
if command -v java >/dev/null 2>&1; then
    output "  Java: $(java -version 2>&1 | head -1)"
fi

# .NET
if command -v dotnet >/dev/null 2>&1; then
    output "  .NET: $(dotnet --version 2>/dev/null)"
fi

output ""
output "====================="
output "Inventory collection complete."
output ""
output "////////////////////////////////////////////////////////////////////////////////"
output "//                                                                            //"
output "//                 CONTROLLED UNCLASSIFIED INFORMATION (CUI)                  //"
output "//                                                                            //"
output "//  Reference: 32 CFR Part 2002, NIST SP 800-171                              //"
output "//  Unauthorized disclosure subject to administrative/civil penalties         //"
output "//                                                                            //"
output "////////////////////////////////////////////////////////////////////////////////"

if [ -n "$OUTPUT_FILE" ]; then
    echo "Inventory saved to: $OUTPUT_FILE"
fi

exit 0
