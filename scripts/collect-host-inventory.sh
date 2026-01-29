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

# Source toolkit info library
if [ -f "$SCRIPT_DIR/lib/toolkit-info.sh" ]; then
    source "$SCRIPT_DIR/lib/toolkit-info.sh"
    init_toolkit_info "$SECURITY_REPO_DIR"
fi

# Use UTC for consistent timestamps across time zones
TIMESTAMP=$(date -u "+%Y-%m-%dT%H:%M:%SZ")

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
output "Toolkit: $TOOLKIT_NAME $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
output "Source: $TOOLKIT_SOURCE"
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

# Bash
if command -v bash >/dev/null 2>&1; then
    output "  Bash: $(bash --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
else
    output "  Bash: not installed"
fi

# Zsh
if command -v zsh >/dev/null 2>&1; then
    output "  Zsh: $(zsh --version 2>/dev/null)"
else
    output "  Zsh: not installed"
fi

# Lua
if command -v lua >/dev/null 2>&1; then
    output "  Lua: $(lua -v 2>&1 | head -1)"
else
    output "  Lua: not installed"
fi

# R
if command -v R >/dev/null 2>&1; then
    output "  R: $(R --version 2>/dev/null | head -1)"
else
    output "  R: not installed"
fi

# Swift
if command -v swift >/dev/null 2>&1; then
    output "  Swift: $(swift --version 2>/dev/null | head -1)"
else
    output "  Swift: not installed"
fi

# Kotlin
if command -v kotlin >/dev/null 2>&1; then
    output "  Kotlin: $(kotlin -version 2>&1 | head -1)"
else
    output "  Kotlin: not installed"
fi

# Scala
if command -v scala >/dev/null 2>&1; then
    output "  Scala: $(scala -version 2>&1 | head -1)"
else
    output "  Scala: not installed"
fi

# Groovy
if command -v groovy >/dev/null 2>&1; then
    output "  Groovy: $(groovy --version 2>/dev/null | head -1)"
else
    output "  Groovy: not installed"
fi

# TypeScript
if command -v tsc >/dev/null 2>&1; then
    output "  TypeScript: $(tsc --version 2>/dev/null)"
else
    output "  TypeScript: not installed"
fi

# Elixir
if command -v elixir >/dev/null 2>&1; then
    output "  Elixir: $(elixir --version 2>/dev/null | grep Elixir | head -1)"
else
    output "  Elixir: not installed"
fi

# Haskell (GHC)
if command -v ghc >/dev/null 2>&1; then
    output "  Haskell (GHC): $(ghc --version 2>/dev/null)"
else
    output "  Haskell (GHC): not installed"
fi

# Julia
if command -v julia >/dev/null 2>&1; then
    output "  Julia: $(julia --version 2>/dev/null)"
else
    output "  Julia: not installed"
fi

output ""
output "Development Tools / IDEs:"
output "-------------------------"

# Helper function to find IDE on macOS - checks multiple paths
find_macos_ide() {
    local paths=("$@")

    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            local version
            version=$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
            if [ -n "$version" ]; then
                echo "$version"
                return 0
            fi
        fi
    done
    return 1
}

if [[ "$(uname)" == "Darwin" ]]; then
    # VS Code - check multiple possible locations
    vscode_paths=(
        "/Applications/Visual Studio Code.app"
        "$HOME/Applications/Visual Studio Code.app"
        "/Applications/Visual Studio Code - Insiders.app"
    )
    vscode_ver=$(find_macos_ide "${vscode_paths[@]}" || true)
    if [ -n "$vscode_ver" ]; then
        output "  VS Code: $vscode_ver"
    else
        output "  VS Code: not installed"
    fi

    # Visual Studio for Mac
    vs_paths=(
        "/Applications/Visual Studio.app"
        "$HOME/Applications/Visual Studio.app"
    )
    vs_ver=$(find_macos_ide "${vs_paths[@]}" || true)
    if [ -n "$vs_ver" ]; then
        output "  Visual Studio: $vs_ver"
    else
        output "  Visual Studio: not installed"
    fi

    # Xcode
    xcode_paths=(
        "/Applications/Xcode.app"
        "/Applications/Xcode-beta.app"
    )
    xcode_ver=$(find_macos_ide "${xcode_paths[@]}" || true)
    if [ -n "$xcode_ver" ]; then
        output "  Xcode: $xcode_ver"
    else
        output "  Xcode: not installed"
    fi

    # JetBrains IntelliJ IDEA
    idea_paths=(
        "/Applications/IntelliJ IDEA.app"
        "/Applications/IntelliJ IDEA CE.app"
        "/Applications/IntelliJ IDEA Ultimate.app"
        "$HOME/Applications/IntelliJ IDEA.app"
        "$HOME/Applications/IntelliJ IDEA CE.app"
    )
    idea_ver=$(find_macos_ide "${idea_paths[@]}" || true)
    if [ -n "$idea_ver" ]; then
        output "  IntelliJ IDEA: $idea_ver"
    else
        output "  IntelliJ IDEA: not installed"
    fi

    # JetBrains PyCharm
    pycharm_paths=(
        "/Applications/PyCharm.app"
        "/Applications/PyCharm CE.app"
        "$HOME/Applications/PyCharm.app"
        "$HOME/Applications/PyCharm CE.app"
    )
    pycharm_ver=$(find_macos_ide "${pycharm_paths[@]}" || true)
    if [ -n "$pycharm_ver" ]; then
        output "  PyCharm: $pycharm_ver"
    else
        output "  PyCharm: not installed"
    fi

    # JetBrains WebStorm
    webstorm_paths=(
        "/Applications/WebStorm.app"
        "$HOME/Applications/WebStorm.app"
    )
    webstorm_ver=$(find_macos_ide "${webstorm_paths[@]}" || true)
    if [ -n "$webstorm_ver" ]; then
        output "  WebStorm: $webstorm_ver"
    else
        output "  WebStorm: not installed"
    fi

    # JetBrains GoLand
    goland_paths=(
        "/Applications/GoLand.app"
        "$HOME/Applications/GoLand.app"
    )
    goland_ver=$(find_macos_ide "${goland_paths[@]}" || true)
    if [ -n "$goland_ver" ]; then
        output "  GoLand: $goland_ver"
    else
        output "  GoLand: not installed"
    fi

    # JetBrains Rider
    rider_paths=(
        "/Applications/Rider.app"
        "$HOME/Applications/Rider.app"
    )
    rider_ver=$(find_macos_ide "${rider_paths[@]}" || true)
    if [ -n "$rider_ver" ]; then
        output "  Rider: $rider_ver"
    else
        output "  Rider: not installed"
    fi

    # JetBrains CLion
    clion_paths=(
        "/Applications/CLion.app"
        "$HOME/Applications/CLion.app"
    )
    clion_ver=$(find_macos_ide "${clion_paths[@]}" || true)
    if [ -n "$clion_ver" ]; then
        output "  CLion: $clion_ver"
    else
        output "  CLion: not installed"
    fi

    # JetBrains DataGrip
    datagrip_paths=(
        "/Applications/DataGrip.app"
        "$HOME/Applications/DataGrip.app"
    )
    datagrip_ver=$(find_macos_ide "${datagrip_paths[@]}" || true)
    if [ -n "$datagrip_ver" ]; then
        output "  DataGrip: $datagrip_ver"
    else
        output "  DataGrip: not installed"
    fi

    # Eclipse
    eclipse_paths=(
        "/Applications/Eclipse.app"
        "$HOME/Applications/Eclipse.app"
        "/Applications/Eclipse IDE.app"
    )
    eclipse_ver=$(find_macos_ide "${eclipse_paths[@]}" || true)
    if [ -n "$eclipse_ver" ]; then
        output "  Eclipse: $eclipse_ver"
    else
        output "  Eclipse: not installed"
    fi

    # Sublime Text
    sublime_paths=(
        "/Applications/Sublime Text.app"
        "$HOME/Applications/Sublime Text.app"
    )
    sublime_ver=$(find_macos_ide "${sublime_paths[@]}" || true)
    if [ -n "$sublime_ver" ]; then
        output "  Sublime Text: $sublime_ver"
    else
        output "  Sublime Text: not installed"
    fi

    # Atom
    atom_paths=(
        "/Applications/Atom.app"
        "$HOME/Applications/Atom.app"
    )
    atom_ver=$(find_macos_ide "${atom_paths[@]}" || true)
    if [ -n "$atom_ver" ]; then
        output "  Atom: $atom_ver"
    else
        output "  Atom: not installed"
    fi

    # Android Studio
    android_paths=(
        "/Applications/Android Studio.app"
        "$HOME/Applications/Android Studio.app"
    )
    android_ver=$(find_macos_ide "${android_paths[@]}" || true)
    if [ -n "$android_ver" ]; then
        output "  Android Studio: $android_ver"
    else
        output "  Android Studio: not installed"
    fi

elif [[ "$(uname)" == "Linux" ]]; then
    # VS Code - check command, snap, flatpak
    if command -v code >/dev/null 2>&1; then
        output "  VS Code: $(code --version 2>/dev/null | head -1)"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "^code "; then
        vscode_snap=$(snap list 2>/dev/null | grep "^code " | awk '{print $2}')
        output "  VS Code: $vscode_snap (snap)"
    elif command -v flatpak >/dev/null 2>&1 && flatpak list --app 2>/dev/null | grep -q "com.visualstudio.code"; then
        output "  VS Code: (flatpak)"
    else
        output "  VS Code: not installed"
    fi

    # JetBrains IDEs (check via jetbrains-toolbox or direct install)
    # IntelliJ IDEA
    if command -v idea >/dev/null 2>&1; then
        output "  IntelliJ IDEA: installed"
    elif [ -d "$HOME/.local/share/JetBrains/Toolbox/apps/IDEA" ] || [ -d "/opt/intellij-idea" ]; then
        output "  IntelliJ IDEA: installed"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "intellij"; then
        output "  IntelliJ IDEA: (snap)"
    else
        output "  IntelliJ IDEA: not installed"
    fi

    # PyCharm
    if command -v pycharm >/dev/null 2>&1; then
        output "  PyCharm: installed"
    elif [ -d "$HOME/.local/share/JetBrains/Toolbox/apps/PyCharm" ] || [ -d "/opt/pycharm" ]; then
        output "  PyCharm: installed"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "pycharm"; then
        output "  PyCharm: (snap)"
    else
        output "  PyCharm: not installed"
    fi

    # WebStorm
    if command -v webstorm >/dev/null 2>&1; then
        output "  WebStorm: installed"
    elif [ -d "$HOME/.local/share/JetBrains/Toolbox/apps/WebStorm" ]; then
        output "  WebStorm: installed"
    else
        output "  WebStorm: not installed"
    fi

    # GoLand
    if command -v goland >/dev/null 2>&1; then
        output "  GoLand: installed"
    elif [ -d "$HOME/.local/share/JetBrains/Toolbox/apps/GoLand" ]; then
        output "  GoLand: installed"
    else
        output "  GoLand: not installed"
    fi

    # Rider
    if command -v rider >/dev/null 2>&1; then
        output "  Rider: installed"
    elif [ -d "$HOME/.local/share/JetBrains/Toolbox/apps/Rider" ]; then
        output "  Rider: installed"
    else
        output "  Rider: not installed"
    fi

    # CLion
    if command -v clion >/dev/null 2>&1; then
        output "  CLion: installed"
    elif [ -d "$HOME/.local/share/JetBrains/Toolbox/apps/CLion" ]; then
        output "  CLion: installed"
    else
        output "  CLion: not installed"
    fi

    # Eclipse
    if command -v eclipse >/dev/null 2>&1; then
        output "  Eclipse: $(eclipse -version 2>/dev/null | head -1 || echo "installed")"
    elif [ -d "/opt/eclipse" ] || [ -d "$HOME/eclipse" ]; then
        output "  Eclipse: installed"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "eclipse"; then
        output "  Eclipse: (snap)"
    else
        output "  Eclipse: not installed"
    fi

    # Sublime Text
    if command -v subl >/dev/null 2>&1; then
        output "  Sublime Text: $(subl --version 2>/dev/null || echo "installed")"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "sublime-text"; then
        sublime_snap=$(snap list 2>/dev/null | grep "sublime-text" | awk '{print $2}')
        output "  Sublime Text: $sublime_snap (snap)"
    else
        output "  Sublime Text: not installed"
    fi

    # Atom
    if command -v atom >/dev/null 2>&1; then
        output "  Atom: $(atom --version 2>/dev/null | head -1)"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "^atom "; then
        output "  Atom: (snap)"
    else
        output "  Atom: not installed"
    fi

    # Notepadqq (Notepad++ alternative for Linux)
    if command -v notepadqq >/dev/null 2>&1; then
        output "  Notepadqq: $(notepadqq --version 2>/dev/null || echo "installed")"
    else
        output "  Notepadqq: not installed"
    fi

    # Android Studio
    if command -v android-studio >/dev/null 2>&1 || [ -d "/opt/android-studio" ] || [ -d "$HOME/android-studio" ]; then
        output "  Android Studio: installed"
    elif command -v snap >/dev/null 2>&1 && snap list 2>/dev/null | grep -q "android-studio"; then
        output "  Android Studio: (snap)"
    else
        output "  Android Studio: not installed"
    fi
fi

output ""
output "Web Browsers:"
output "-------------"

# Helper function to find browser on macOS - checks multiple paths
find_macos_browser() {
    local name="$1"
    shift
    local paths=("$@")

    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            local version
            version=$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
            if [ -n "$version" ]; then
                echo "$version"
                return 0
            fi
        fi
    done
    return 1
}

# Helper function to find browser on Linux - checks command, snap, flatpak, and package managers
find_linux_browser() {
    local name="$1"
    local cmd="$2"
    local snap_name="$3"
    local flatpak_name="$4"
    local dpkg_pattern="$5"
    local rpm_pattern="$6"

    # Try command first
    if command -v "$cmd" >/dev/null 2>&1; then
        "$cmd" --version 2>/dev/null | head -1
        return 0
    fi

    # Try snap
    if [ -n "$snap_name" ] && command -v snap >/dev/null 2>&1; then
        local snap_ver
        snap_ver=$(snap list 2>/dev/null | grep "^$snap_name " | awk '{print $2}')
        if [ -n "$snap_ver" ]; then
            echo "$snap_ver (snap)"
            return 0
        fi
    fi

    # Try flatpak
    if [ -n "$flatpak_name" ] && command -v flatpak >/dev/null 2>&1; then
        local flatpak_ver
        flatpak_ver=$(flatpak list --app 2>/dev/null | grep "$flatpak_name" | awk '{print $3}')
        if [ -n "$flatpak_ver" ]; then
            echo "$flatpak_ver (flatpak)"
            return 0
        fi
    fi

    # Try dpkg
    if [ -n "$dpkg_pattern" ] && command -v dpkg >/dev/null 2>&1; then
        local dpkg_ver
        dpkg_ver=$(dpkg -l 2>/dev/null | grep -i "$dpkg_pattern" | head -1 | awk '{print $3}')
        if [ -n "$dpkg_ver" ]; then
            echo "$dpkg_ver"
            return 0
        fi
    fi

    # Try rpm
    if [ -n "$rpm_pattern" ] && command -v rpm >/dev/null 2>&1; then
        local rpm_ver
        rpm_ver=$(rpm -qa 2>/dev/null | grep -i "$rpm_pattern" | head -1 | sed 's/.*-\([0-9].*\)/\1/')
        if [ -n "$rpm_ver" ]; then
            echo "$rpm_ver"
            return 0
        fi
    fi

    return 1
}

if [[ "$(uname)" == "Darwin" ]]; then
    # Chrome - check multiple possible locations
    chrome_paths=(
        "/Applications/Google Chrome.app"
        "$HOME/Applications/Google Chrome.app"
        "/Applications/Chromium.app"
        "$HOME/Applications/Chromium.app"
    )
    chrome_ver=$(find_macos_browser "Chrome" "${chrome_paths[@]}" || true)
    if [ -n "$chrome_ver" ]; then
        output "  Chrome: $chrome_ver"
    else
        output "  Chrome: not installed"
    fi

    # Firefox - check multiple possible locations
    firefox_paths=(
        "/Applications/Firefox.app"
        "$HOME/Applications/Firefox.app"
        "/Applications/Firefox Developer Edition.app"
        "/Applications/Firefox Nightly.app"
    )
    firefox_ver=$(find_macos_browser "Firefox" "${firefox_paths[@]}" || true)
    if [ -n "$firefox_ver" ]; then
        output "  Firefox: $firefox_ver"
    else
        output "  Firefox: not installed"
    fi

    # Safari (always installed on macOS)
    safari_ver=$(defaults read "/Applications/Safari.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
    output "  Safari: $safari_ver"

    # Microsoft Edge - check multiple possible locations
    edge_paths=(
        "/Applications/Microsoft Edge.app"
        "$HOME/Applications/Microsoft Edge.app"
    )
    edge_ver=$(find_macos_browser "Edge" "${edge_paths[@]}" || true)
    if [ -n "$edge_ver" ]; then
        output "  Edge: $edge_ver"
    else
        output "  Edge: not installed"
    fi

    # Brave - check multiple possible locations
    brave_paths=(
        "/Applications/Brave Browser.app"
        "$HOME/Applications/Brave Browser.app"
    )
    brave_ver=$(find_macos_browser "Brave" "${brave_paths[@]}" || true)
    if [ -n "$brave_ver" ]; then
        output "  Brave: $brave_ver"
    else
        output "  Brave: not installed"
    fi

    # Opera - check multiple possible locations
    opera_paths=(
        "/Applications/Opera.app"
        "$HOME/Applications/Opera.app"
    )
    opera_ver=$(find_macos_browser "Opera" "${opera_paths[@]}" || true)
    if [ -n "$opera_ver" ]; then
        output "  Opera: $opera_ver"
    else
        output "  Opera: not installed"
    fi

    # Vivaldi - check multiple possible locations
    vivaldi_paths=(
        "/Applications/Vivaldi.app"
        "$HOME/Applications/Vivaldi.app"
    )
    vivaldi_ver=$(find_macos_browser "Vivaldi" "${vivaldi_paths[@]}" || true)
    if [ -n "$vivaldi_ver" ]; then
        output "  Vivaldi: $vivaldi_ver"
    else
        output "  Vivaldi: not installed"
    fi

elif [[ "$(uname)" == "Linux" ]]; then
    # Chrome - check command, snap, flatpak, package managers
    chrome_ver=$(find_linux_browser "Chrome" "google-chrome" "chromium" "com.google.Chrome" "google-chrome" "google-chrome")
    if [ -z "$chrome_ver" ]; then
        # Also try chromium variants
        chrome_ver=$(find_linux_browser "Chromium" "chromium" "chromium" "" "chromium" "chromium")
        if [ -z "$chrome_ver" ]; then
            chrome_ver=$(find_linux_browser "Chromium" "chromium-browser" "" "" "" "")
        fi
    fi
    if [ -n "$chrome_ver" ]; then
        output "  Chrome/Chromium: $chrome_ver"
    else
        output "  Chrome/Chromium: not installed"
    fi

    # Firefox - check command, snap, flatpak, package managers
    firefox_ver=$(find_linux_browser "Firefox" "firefox" "firefox" "org.mozilla.firefox" "firefox" "firefox")
    if [ -n "$firefox_ver" ]; then
        output "  Firefox: $firefox_ver"
    else
        output "  Firefox: not installed"
    fi

    # Edge - check command and package managers
    edge_ver=$(find_linux_browser "Edge" "microsoft-edge" "" "" "microsoft-edge" "microsoft-edge")
    if [ -z "$edge_ver" ]; then
        edge_ver=$(find_linux_browser "Edge" "microsoft-edge-stable" "" "" "" "")
    fi
    if [ -n "$edge_ver" ]; then
        output "  Edge: $edge_ver"
    else
        output "  Edge: not installed"
    fi

    # Brave - check command, snap, flatpak, package managers
    brave_ver=$(find_linux_browser "Brave" "brave-browser" "brave" "com.brave.Browser" "brave-browser" "brave-browser")
    if [ -n "$brave_ver" ]; then
        output "  Brave: $brave_ver"
    else
        output "  Brave: not installed"
    fi

    # Opera - check command, snap, flatpak, package managers
    opera_ver=$(find_linux_browser "Opera" "opera" "opera" "com.opera.Opera" "opera" "opera")
    if [ -n "$opera_ver" ]; then
        output "  Opera: $opera_ver"
    else
        output "  Opera: not installed"
    fi

    # Vivaldi - check command and package managers
    vivaldi_ver=$(find_linux_browser "Vivaldi" "vivaldi" "vivaldi" "com.vivaldi.Vivaldi" "vivaldi" "vivaldi")
    if [ -z "$vivaldi_ver" ]; then
        vivaldi_ver=$(find_linux_browser "Vivaldi" "vivaldi-stable" "" "" "" "")
    fi
    if [ -n "$vivaldi_ver" ]; then
        output "  Vivaldi: $vivaldi_ver"
    else
        output "  Vivaldi: not installed"
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
output "Productivity Software:"
output "----------------------"

if [[ "$(uname)" == "Darwin" ]]; then
    # Microsoft Word
    if [ -d "/Applications/Microsoft Word.app" ]; then
        word_ver=$(defaults read "/Applications/Microsoft Word.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Microsoft Word: $word_ver"
    else
        output "  Microsoft Word: not installed"
    fi

    # Microsoft Excel
    if [ -d "/Applications/Microsoft Excel.app" ]; then
        excel_ver=$(defaults read "/Applications/Microsoft Excel.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Microsoft Excel: $excel_ver"
    else
        output "  Microsoft Excel: not installed"
    fi

    # Microsoft PowerPoint
    if [ -d "/Applications/Microsoft PowerPoint.app" ]; then
        ppt_ver=$(defaults read "/Applications/Microsoft PowerPoint.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Microsoft PowerPoint: $ppt_ver"
    else
        output "  Microsoft PowerPoint: not installed"
    fi

    # Microsoft Outlook
    if [ -d "/Applications/Microsoft Outlook.app" ]; then
        outlook_ver=$(defaults read "/Applications/Microsoft Outlook.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Microsoft Outlook: $outlook_ver"
    else
        output "  Microsoft Outlook: not installed"
    fi

    # Microsoft Teams
    if [ -d "/Applications/Microsoft Teams.app" ] || [ -d "/Applications/Microsoft Teams (work or school).app" ]; then
        teams_ver=$(defaults read "/Applications/Microsoft Teams.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || \
                    defaults read "/Applications/Microsoft Teams (work or school).app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Microsoft Teams: $teams_ver"
    else
        output "  Microsoft Teams: not installed"
    fi

    # Apple Pages
    if [ -d "/Applications/Pages.app" ]; then
        pages_ver=$(defaults read "/Applications/Pages.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Apple Pages: $pages_ver"
    else
        output "  Apple Pages: not installed"
    fi

    # Apple Numbers
    if [ -d "/Applications/Numbers.app" ]; then
        numbers_ver=$(defaults read "/Applications/Numbers.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Apple Numbers: $numbers_ver"
    else
        output "  Apple Numbers: not installed"
    fi

    # Apple Keynote
    if [ -d "/Applications/Keynote.app" ]; then
        keynote_ver=$(defaults read "/Applications/Keynote.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Apple Keynote: $keynote_ver"
    else
        output "  Apple Keynote: not installed"
    fi

    # LibreOffice
    if [ -d "/Applications/LibreOffice.app" ]; then
        libre_ver=$(defaults read "/Applications/LibreOffice.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  LibreOffice: $libre_ver"
    else
        output "  LibreOffice: not installed"
    fi

    # Slack
    if [ -d "/Applications/Slack.app" ]; then
        slack_ver=$(defaults read "/Applications/Slack.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Slack: $slack_ver"
    else
        output "  Slack: not installed"
    fi

    # Cisco Webex
    if [ -d "/Applications/Webex.app" ]; then
        webex_ver=$(defaults read "/Applications/Webex.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Cisco Webex: $webex_ver"
    else
        output "  Cisco Webex: not installed"
    fi

    # Discord
    if [ -d "/Applications/Discord.app" ]; then
        discord_ver=$(defaults read "/Applications/Discord.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Discord: $discord_ver"
    else
        output "  Discord: not installed"
    fi

    # Skype
    if [ -d "/Applications/Skype.app" ]; then
        skype_ver=$(defaults read "/Applications/Skype.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Skype: $skype_ver"
    else
        output "  Skype: not installed"
    fi

elif [[ "$(uname)" == "Linux" ]]; then
    # LibreOffice
    if command -v libreoffice >/dev/null 2>&1; then
        output "  LibreOffice: $(libreoffice --version 2>/dev/null | head -1)"
    else
        output "  LibreOffice: not installed"
    fi

    # Slack
    if command -v slack >/dev/null 2>&1; then
        output "  Slack: $(slack --version 2>/dev/null || echo "installed")"
    else
        output "  Slack: not installed"
    fi

    # Microsoft Teams
    if command -v teams >/dev/null 2>&1; then
        output "  Microsoft Teams: $(teams --version 2>/dev/null || echo "installed")"
    else
        output "  Microsoft Teams: not installed"
    fi

    # Webex
    if command -v webex >/dev/null 2>&1; then
        output "  Cisco Webex: $(webex --version 2>/dev/null || echo "installed")"
    else
        output "  Cisco Webex: not installed"
    fi

    # Discord
    if command -v discord >/dev/null 2>&1; then
        output "  Discord: $(discord --version 2>/dev/null || echo "installed")"
    else
        output "  Discord: not installed"
    fi

    # Skype
    if command -v skype >/dev/null 2>&1 || command -v skypeforlinux >/dev/null 2>&1; then
        output "  Skype: $(skypeforlinux --version 2>/dev/null || skype --version 2>/dev/null || echo "installed")"
    else
        output "  Skype: not installed"
    fi
fi

output ""
output "Containers and Virtualization:"
output "------------------------------"

# Docker
if command -v docker >/dev/null 2>&1; then
    output "  Docker: $(docker --version 2>/dev/null | head -1)"
else
    output "  Docker: not installed"
fi

# Podman
if command -v podman >/dev/null 2>&1; then
    output "  Podman:"

    # Check if podman machine is running (macOS) or podman is accessible
    if podman info >/dev/null 2>&1; then
        # Capture full podman version output (Client and Server)
        while IFS= read -r line; do
            output "    $line"
        done <<< "$(podman version 2>/dev/null)"
        # List running containers with IPs
        container_count=$(podman ps -q 2>/dev/null | wc -l | tr -d ' ')
        if [ "$container_count" -gt 0 ]; then
            output "    Running Containers: $container_count"
            # Get container details (name, image, IP)
            while IFS= read -r container_id; do
                if [ -n "$container_id" ]; then
                    name=$(podman inspect -f '{{.Name}}' "$container_id" 2>/dev/null | sed 's/^\///')
                    image=$(podman inspect -f '{{.Config.Image}}' "$container_id" 2>/dev/null)
                    ip=$(podman inspect -f '{{.NetworkSettings.IPAddress}}' "$container_id" 2>/dev/null)
                    output "      - $name ($image): $ip"
                fi
            done <<< "$(podman ps -q 2>/dev/null)"
        else
            output "    Running Containers: 0"
        fi

        # List podman networks
        output "    Networks:"
        while IFS= read -r network; do
            if [ -n "$network" ] && [ "$network" != "NETWORK ID" ]; then
                net_name=$(echo "$network" | awk '{print $1}')
                net_driver=$(echo "$network" | awk '{print $2}')
                output "      - $net_name ($net_driver)"
            fi
        done <<< "$(podman network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null)"
    else
        output "    Status: not running (podman machine not started)"
    fi

    # pasta (Linux rootless networking - replacement for slirp4netns)
    if command -v pasta >/dev/null 2>&1; then
        output "    pasta:"
        while IFS= read -r line; do
            [ -n "$line" ] && output "      $line"
        done <<< "$(pasta --version 2>/dev/null)"
    fi

    # slirp4netns (Linux rootless networking)
    if command -v slirp4netns >/dev/null 2>&1; then
        output "    slirp4netns:"
        while IFS= read -r line; do
            [ -n "$line" ] && output "      $line"
        done <<< "$(slirp4netns --version 2>/dev/null)"
    fi
else
    output "  Podman: not installed"
fi

# Kubernetes (kubectl)
if command -v kubectl >/dev/null 2>&1; then
    output "  kubectl: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
else
    output "  kubectl: not installed"
fi

# Minikube
if command -v minikube >/dev/null 2>&1; then
    output "  Minikube: $(minikube version --short 2>/dev/null || minikube version 2>/dev/null | head -1)"
else
    output "  Minikube: not installed"
fi

# Helm
if command -v helm >/dev/null 2>&1; then
    output "  Helm: $(helm version --short 2>/dev/null)"
else
    output "  Helm: not installed"
fi

# Vagrant
if command -v vagrant >/dev/null 2>&1; then
    output "  Vagrant: $(vagrant --version 2>/dev/null)"
else
    output "  Vagrant: not installed"
fi

if [[ "$(uname)" == "Darwin" ]]; then
    # VirtualBox
    if [ -d "/Applications/VirtualBox.app" ]; then
        vbox_ver=$(defaults read "/Applications/VirtualBox.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  VirtualBox: $vbox_ver"
    else
        output "  VirtualBox: not installed"
    fi

    # VMware Fusion
    if [ -d "/Applications/VMware Fusion.app" ]; then
        vmware_ver=$(defaults read "/Applications/VMware Fusion.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  VMware Fusion: $vmware_ver"
    else
        output "  VMware Fusion: not installed"
    fi

    # Parallels
    if [ -d "/Applications/Parallels Desktop.app" ]; then
        parallels_ver=$(defaults read "/Applications/Parallels Desktop.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "unknown")
        output "  Parallels Desktop: $parallels_ver"
    else
        output "  Parallels Desktop: not installed"
    fi

elif [[ "$(uname)" == "Linux" ]]; then
    # VirtualBox
    if command -v VBoxManage >/dev/null 2>&1; then
        output "  VirtualBox: $(VBoxManage --version 2>/dev/null)"
    else
        output "  VirtualBox: not installed"
    fi

    # VMware Workstation
    if command -v vmware >/dev/null 2>&1; then
        output "  VMware Workstation: $(vmware --version 2>/dev/null | head -1)"
    else
        output "  VMware Workstation: not installed"
    fi

    # QEMU
    if command -v qemu-system-x86_64 >/dev/null 2>&1; then
        output "  QEMU: $(qemu-system-x86_64 --version 2>/dev/null | head -1)"
    elif command -v qemu-img >/dev/null 2>&1; then
        output "  QEMU: $(qemu-img --version 2>/dev/null | head -1)"
    else
        output "  QEMU: not installed"
    fi

    # libvirt/KVM
    if command -v virsh >/dev/null 2>&1; then
        output "  libvirt: $(virsh --version 2>/dev/null)"
    else
        output "  libvirt: not installed"
    fi

    # LXC/LXD
    if command -v lxc >/dev/null 2>&1; then
        output "  LXC/LXD: $(lxc --version 2>/dev/null)"
    else
        output "  LXC/LXD: not installed"
    fi
fi

output ""
output "Web Servers:"
output "------------"

# Apache
if command -v httpd >/dev/null 2>&1; then
    output "  Apache (httpd): $(httpd -v 2>/dev/null | head -1)"
elif command -v apache2 >/dev/null 2>&1; then
    output "  Apache: $(apache2 -v 2>/dev/null | head -1)"
elif command -v apachectl >/dev/null 2>&1; then
    output "  Apache: $(apachectl -v 2>/dev/null | head -1)"
else
    output "  Apache: not installed"
fi

# Nginx
if command -v nginx >/dev/null 2>&1; then
    output "  Nginx: $(nginx -v 2>&1)"
else
    output "  Nginx: not installed"
fi

# Caddy
if command -v caddy >/dev/null 2>&1; then
    output "  Caddy: $(caddy version 2>/dev/null)"
else
    output "  Caddy: not installed"
fi

# Lighttpd
if command -v lighttpd >/dev/null 2>&1; then
    output "  Lighttpd: $(lighttpd -v 2>/dev/null | head -1)"
else
    output "  Lighttpd: not installed"
fi

# Traefik
if command -v traefik >/dev/null 2>&1; then
    output "  Traefik: $(traefik version 2>/dev/null | head -1)"
else
    output "  Traefik: not installed"
fi

output ""
output "Database Servers:"
output "-----------------"

# PostgreSQL
if command -v psql >/dev/null 2>&1; then
    output "  PostgreSQL: $(psql --version 2>/dev/null)"
else
    output "  PostgreSQL: not installed"
fi

# MySQL
if command -v mysql >/dev/null 2>&1; then
    output "  MySQL: $(mysql --version 2>/dev/null)"
else
    output "  MySQL: not installed"
fi

# SQLite
if command -v sqlite3 >/dev/null 2>&1; then
    output "  SQLite: $(sqlite3 --version 2>/dev/null)"
else
    output "  SQLite: not installed"
fi

# MongoDB
if command -v mongod >/dev/null 2>&1; then
    output "  MongoDB: $(mongod --version 2>/dev/null | head -1)"
else
    output "  MongoDB: not installed"
fi

# Redis
if command -v redis-server >/dev/null 2>&1; then
    output "  Redis: $(redis-server --version 2>/dev/null)"
else
    output "  Redis: not installed"
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
