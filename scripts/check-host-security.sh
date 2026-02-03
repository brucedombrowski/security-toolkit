#!/bin/bash
#
# Host OS Security Verification Script
#
# Purpose: Verify host system security posture for execution environment
# Method: Check macOS security settings, installed security tools, and system state
# Standards:
#   - NIST SP 800-53: CM-6 (Configuration Settings)
#   - NIST SP 800-53: SI-2 (Flaw Remediation)
#   - CIS macOS Benchmark (where applicable)
#
# Exit codes:
#   0 = All checks passed
#   1 = One or more checks failed
#
# Usage: ./check-host-security.sh
#        (No target directory - checks the current host)

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit

echo "Host OS Security Verification"
echo "=============================="
echo "Timestamp: $TIMESTAMP"
echo "Host: $(hostname)"
echo "Toolkit: $TOOLKIT_NAME $TOOLKIT_VERSION ($TOOLKIT_COMMIT)"
echo "Source: $TOOLKIT_SOURCE"
echo ""

# Track overall status
OVERALL_STATUS="PASS"
FAIL_COUNT=0

# Function to run a check
run_check() {
    local check_name="$1"
    local check_command="$2"
    local expected="$3"

    echo "Checking: $check_name"

    local result=""
    result=$(eval "$check_command" 2>/dev/null || echo "ERROR")

    if [[ "$result" == *"$expected"* ]] || [[ "$expected" == "EXISTS" && -n "$result" && "$result" != "ERROR" ]]; then
        echo "  Result: PASS"
        return 0
    else
        echo "  Result: FAIL"
        OVERALL_STATUS="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

echo "Running security configuration checks..."
echo ""

# macOS specific checks
if [[ "$(uname)" == "Darwin" ]]; then
    # Check if SIP is enabled
    run_check "System Integrity Protection (SIP)" \
        "csrutil status" \
        "enabled" || true

    # Check FileVault status
    run_check "FileVault Disk Encryption" \
        "fdesetup status" \
        "On" || true

    # Check Firewall status
    run_check "macOS Application Firewall" \
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate" \
        "enabled" || true

    # Check Gatekeeper status
    run_check "Gatekeeper" \
        "spctl --status" \
        "enabled" || true

    # Check XProtect
    run_check "XProtect Malware Definitions" \
        "test -f /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist && echo EXISTS" \
        "EXISTS" || true

    # Check for pending security updates
    echo "Checking: Pending Security Updates"
    UPDATE_OUTPUT=$(softwareupdate -l 2>&1 || true)
    UPDATE_COUNT=$(echo "$UPDATE_OUTPUT" | grep -ci "security" || true)
    if [ -z "$UPDATE_COUNT" ] || [ "$UPDATE_COUNT" -eq 0 ]; then
        echo "  Result: PASS (no security updates pending)"
    else
        echo "  Result: FAIL (security updates available)"
        OVERALL_STATUS="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

# Linux specific checks
elif [[ "$(uname)" == "Linux" ]]; then
    # Check if firewall is active
    run_check "Firewall (ufw/iptables)" \
        "command -v ufw >/dev/null && ufw status | grep -q 'Status: active' && echo 'active' || iptables -L -n | head -1" \
        "active" || true

    # Check for unattended upgrades
    run_check "Automatic Security Updates" \
        "test -f /etc/apt/apt.conf.d/20auto-upgrades && echo EXISTS" \
        "EXISTS" || true

    # Check SELinux/AppArmor
    run_check "Mandatory Access Control" \
        "command -v getenforce >/dev/null && getenforce || command -v aa-status >/dev/null && aa-status --enabled && echo enabled" \
        "Enforcing\|enabled" || true
fi

# Cross-platform checks
run_check "SSH Agent" \
    "ssh-add -l 2>/dev/null || echo 'no keys'" \
    "" || true

echo ""
echo "=============================="
echo ""

# Reference to host inventory (collected separately for security reasons)
echo "Host Inventory Reference:"
echo "-------------------------"
echo "  Host inventory is collected separately by collect-host-inventory.sh"
echo "  This keeps sensitive data (MAC addresses, serial numbers) in a dedicated file."
echo "  Run: $SCRIPT_DIR/collect-host-inventory.sh [output_file]"
echo ""
echo "=============================="
echo ""

if [ "$OVERALL_STATUS" = "PASS" ]; then
    echo "OVERALL RESULT: PASS"
    echo "All security checks passed."
    exit 0
else
    echo "OVERALL RESULT: FAIL ($FAIL_COUNT check(s) failed)"
    echo "Remediate issues and re-run verification."
    exit 1
fi
