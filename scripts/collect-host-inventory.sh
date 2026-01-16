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

output "Security Tools:"
output "---------------"

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
else
    output "  SSH: not installed"
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

output ""
output "Programming Languages:"
output "----------------------"

# Python
if command -v python3 >/dev/null 2>&1; then
    output "  Python: $(python3 --version 2>/dev/null)"
elif command -v python >/dev/null 2>&1; then
    output "  Python: $(python --version 2>/dev/null)"
else
    output "  Python: not installed"
fi

# Node.js
if command -v node >/dev/null 2>&1; then
    output "  Node.js: $(node --version 2>/dev/null)"
else
    output "  Node.js: not installed"
fi

# Java
if command -v java >/dev/null 2>&1; then
    output "  Java: $(java -version 2>&1 | head -1)"
else
    output "  Java: not installed"
fi

# .NET
if command -v dotnet >/dev/null 2>&1; then
    output "  .NET: $(dotnet --version 2>/dev/null)"
else
    output "  .NET: not installed"
fi

# Ruby
if command -v ruby >/dev/null 2>&1; then
    output "  Ruby: $(ruby --version 2>/dev/null)"
else
    output "  Ruby: not installed"
fi

# Go
if command -v go >/dev/null 2>&1; then
    output "  Go: $(go version 2>/dev/null)"
else
    output "  Go: not installed"
fi

# Rust
if command -v rustc >/dev/null 2>&1; then
    output "  Rust: $(rustc --version 2>/dev/null)"
else
    output "  Rust: not installed"
fi

# Perl
if command -v perl >/dev/null 2>&1; then
    output "  Perl: $(perl --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
else
    output "  Perl: not installed"
fi

# PHP
if command -v php >/dev/null 2>&1; then
    output "  PHP: $(php --version 2>/dev/null | head -1)"
else
    output "  PHP: not installed"
fi

output ""
output "Web Browsers:"
output "-------------"

# Chrome
if [[ "$(uname)" == "Darwin" ]]; then
    if [ -d "/Applications/Google Chrome.app" ]; then
        chrome_ver=$(defaults read "/Applications/Google Chrome.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Chrome: $chrome_ver"
    else
        output "  Chrome: not installed"
    fi

    # Firefox
    if [ -d "/Applications/Firefox.app" ]; then
        firefox_ver=$(defaults read "/Applications/Firefox.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Firefox: $firefox_ver"
    else
        output "  Firefox: not installed"
    fi

    # Safari (always installed on macOS)
    safari_ver=$(defaults read "/Applications/Safari.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
    output "  Safari: $safari_ver"

    # Microsoft Edge
    if [ -d "/Applications/Microsoft Edge.app" ]; then
        edge_ver=$(defaults read "/Applications/Microsoft Edge.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Edge: $edge_ver"
    else
        output "  Edge: not installed"
    fi

    # Brave
    if [ -d "/Applications/Brave Browser.app" ]; then
        brave_ver=$(defaults read "/Applications/Brave Browser.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Brave: $brave_ver"
    else
        output "  Brave: not installed"
    fi
elif [[ "$(uname)" == "Linux" ]]; then
    # Chrome
    if command -v google-chrome >/dev/null 2>&1; then
        output "  Chrome: $(google-chrome --version 2>/dev/null)"
    elif command -v chromium >/dev/null 2>&1; then
        output "  Chromium: $(chromium --version 2>/dev/null)"
    elif command -v chromium-browser >/dev/null 2>&1; then
        output "  Chromium: $(chromium-browser --version 2>/dev/null)"
    else
        output "  Chrome/Chromium: not installed"
    fi

    # Firefox
    if command -v firefox >/dev/null 2>&1; then
        output "  Firefox: $(firefox --version 2>/dev/null)"
    else
        output "  Firefox: not installed"
    fi

    # Edge
    if command -v microsoft-edge >/dev/null 2>&1; then
        output "  Edge: $(microsoft-edge --version 2>/dev/null)"
    else
        output "  Edge: not installed"
    fi

    # Brave
    if command -v brave-browser >/dev/null 2>&1; then
        output "  Brave: $(brave-browser --version 2>/dev/null)"
    else
        output "  Brave: not installed"
    fi
fi

output ""
output "Backup and Restore Software:"
output "----------------------------"

if [[ "$(uname)" == "Darwin" ]]; then
    # Time Machine status
    if command -v tmutil >/dev/null 2>&1; then
        tm_status=$(tmutil status 2>/dev/null | grep -q "Running = 1" && echo "running" || echo "idle")
        tm_dest=$(tmutil destinationinfo 2>/dev/null | grep "Name" | head -1 | awk -F': ' '{print $2}' || echo "not configured")
        output "  Time Machine: $tm_status (destination: $tm_dest)"
    else
        output "  Time Machine: not available"
    fi

    # Arq Backup
    if [ -d "/Applications/Arq.app" ] || [ -d "/Applications/Arq 7.app" ]; then
        arq_ver=$(defaults read "/Applications/Arq.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || \
                  defaults read "/Applications/Arq 7.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Arq Backup: $arq_ver"
    else
        output "  Arq Backup: not installed"
    fi

    # Carbon Copy Cloner
    if [ -d "/Applications/Carbon Copy Cloner.app" ]; then
        ccc_ver=$(defaults read "/Applications/Carbon Copy Cloner.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Carbon Copy Cloner: $ccc_ver"
    else
        output "  Carbon Copy Cloner: not installed"
    fi

    # SuperDuper!
    if [ -d "/Applications/SuperDuper!.app" ]; then
        sd_ver=$(defaults read "/Applications/SuperDuper!.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  SuperDuper!: $sd_ver"
    else
        output "  SuperDuper!: not installed"
    fi

    # Backblaze
    if [ -d "/Applications/Backblaze.app" ]; then
        bb_ver=$(defaults read "/Applications/Backblaze.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Backblaze: $bb_ver"
    else
        output "  Backblaze: not installed"
    fi

elif [[ "$(uname)" == "Linux" ]]; then
    # rsync
    if command -v rsync >/dev/null 2>&1; then
        output "  rsync: $(rsync --version 2>/dev/null | head -1)"
    else
        output "  rsync: not installed"
    fi

    # Borg Backup
    if command -v borg >/dev/null 2>&1; then
        output "  Borg Backup: $(borg --version 2>/dev/null)"
    else
        output "  Borg Backup: not installed"
    fi

    # Restic
    if command -v restic >/dev/null 2>&1; then
        output "  Restic: $(restic version 2>/dev/null)"
    else
        output "  Restic: not installed"
    fi

    # Duplicity
    if command -v duplicity >/dev/null 2>&1; then
        output "  Duplicity: $(duplicity --version 2>/dev/null)"
    else
        output "  Duplicity: not installed"
    fi

    # Timeshift
    if command -v timeshift >/dev/null 2>&1; then
        output "  Timeshift: $(timeshift --version 2>/dev/null | head -1)"
    else
        output "  Timeshift: not installed"
    fi
fi

output ""
output "Remote Desktop / Control Software:"
output "-----------------------------------"

if [[ "$(uname)" == "Darwin" ]]; then
    # Screen Sharing (built-in)
    screen_sharing=$(launchctl list 2>/dev/null | grep -q "com.apple.screensharing" && echo "enabled" || echo "disabled")
    output "  Screen Sharing (built-in): $screen_sharing"

    # Remote Desktop (ARD)
    if [ -d "/System/Library/CoreServices/RemoteManagement/ARDAgent.app" ]; then
        ard_status=$(launchctl list 2>/dev/null | grep -q "com.apple.RemoteDesktop" && echo "enabled" || echo "disabled")
        output "  Apple Remote Desktop: $ard_status"
    fi

    # TeamViewer
    if [ -d "/Applications/TeamViewer.app" ]; then
        tv_ver=$(defaults read "/Applications/TeamViewer.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  TeamViewer: $tv_ver"
    else
        output "  TeamViewer: not installed"
    fi

    # AnyDesk
    if [ -d "/Applications/AnyDesk.app" ]; then
        ad_ver=$(defaults read "/Applications/AnyDesk.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  AnyDesk: $ad_ver"
    else
        output "  AnyDesk: not installed"
    fi

    # Zoom
    if [ -d "/Applications/zoom.us.app" ]; then
        zoom_ver=$(defaults read "/Applications/zoom.us.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Zoom: $zoom_ver"
    else
        output "  Zoom: not installed"
    fi

    # Microsoft Remote Desktop
    if [ -d "/Applications/Microsoft Remote Desktop.app" ]; then
        msrd_ver=$(defaults read "/Applications/Microsoft Remote Desktop.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Microsoft Remote Desktop: $msrd_ver"
    else
        output "  Microsoft Remote Desktop: not installed"
    fi

    # VNC Viewer
    if [ -d "/Applications/VNC Viewer.app" ]; then
        vnc_ver=$(defaults read "/Applications/VNC Viewer.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  VNC Viewer: $vnc_ver"
    else
        output "  VNC Viewer: not installed"
    fi

elif [[ "$(uname)" == "Linux" ]]; then
    # SSH (already checked in security tools)
    sshd_status=$(systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown")
    output "  SSH Server: $sshd_status"

    # VNC
    if command -v vncserver >/dev/null 2>&1; then
        output "  VNC Server: $(vncserver -version 2>&1 | head -1 || echo "installed")"
    else
        output "  VNC Server: not installed"
    fi

    # xrdp
    if command -v xrdp >/dev/null 2>&1; then
        xrdp_status=$(systemctl is-active xrdp 2>/dev/null || echo "unknown")
        output "  xrdp: $xrdp_status"
    else
        output "  xrdp: not installed"
    fi

    # TeamViewer
    if command -v teamviewer >/dev/null 2>&1; then
        output "  TeamViewer: $(teamviewer --version 2>/dev/null | head -1 || echo "installed")"
    else
        output "  TeamViewer: not installed"
    fi

    # AnyDesk
    if command -v anydesk >/dev/null 2>&1; then
        output "  AnyDesk: $(anydesk --version 2>/dev/null || echo "installed")"
    else
        output "  AnyDesk: not installed"
    fi

    # RustDesk
    if command -v rustdesk >/dev/null 2>&1; then
        output "  RustDesk: $(rustdesk --version 2>/dev/null || echo "installed")"
    else
        output "  RustDesk: not installed"
    fi
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
