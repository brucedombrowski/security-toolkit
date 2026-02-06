#!/bin/bash
#
# Power Settings Verification Script
#
# Purpose: Check power/sleep settings to verify system availability configuration
# NIST Controls:
#   - CM-6 (Configuration Settings) - Verify power configuration
#   - AC-11 (Device Lock) - Screen lock after inactivity
#   - SC-24 (Fail in Known State) - Predictable power behavior
#
# Exit codes:
#   0 = Pass (system configured for availability)
#   1-99 = Warning count (settings may cause unexpected sleep/downtime)
#   100+ = Error (could not determine settings)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source shared libraries if available
if [ -f "$SCRIPT_DIR/lib/timestamps.sh" ]; then
    source "$SCRIPT_DIR/lib/timestamps.sh"
fi

# ============================================================================
# Configuration
# ============================================================================

TIMESTAMP=$(date -u "+%Y-%m-%dT%H%M%SZ")
REMOTE_HOST=""
REMOTE_USER=""
OUTPUT_DIR=""
VERBOSE=false
CHECK_ONLY=true  # Safety: read-only by default

# Thresholds (in seconds)
MAX_IDLE_LOCK_TIME=900      # 15 minutes - warn if longer
MAX_SYSTEM_SLEEP_TIME=0     # 0 = never (for always-on systems)

# ============================================================================
# Usage
# ============================================================================

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Check power and sleep settings for system availability verification.

Options:
  -r, --remote HOST      Check remote host via SSH (user@hostname)
  -o, --output DIR       Output directory (default: .scans/)
  -v, --verbose          Show detailed output
  -h, --help             Show this help message

Examples:
  $(basename "$0")                    # Check local machine
  $(basename "$0") -r admin@server    # Check remote Linux server
  $(basename "$0") -o /tmp/scans      # Save output to specific directory

NIST Controls: CM-6, AC-11, SC-24
EOF
    exit 0
}

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--remote)
            REMOTE_HOST="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# ============================================================================
# Output Setup
# ============================================================================

# Determine output directory
if [ -z "$OUTPUT_DIR" ]; then
    if [ -n "$REMOTE_HOST" ]; then
        OUTPUT_DIR="$(pwd)/.scans"
    else
        OUTPUT_DIR="$(pwd)/.scans"
    fi
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/power-settings-$TIMESTAMP.txt"

# ============================================================================
# Helper Functions
# ============================================================================

log() {
    echo "$1" | tee -a "$OUTPUT_FILE"
}

log_header() {
    log ""
    log "=== $1 ==="
}

log_item() {
    local label="$1"
    local value="$2"
    printf "  %-25s %s\n" "$label:" "$value" | tee -a "$OUTPUT_FILE"
}

log_status() {
    local status="$1"
    local message="$2"
    if [ "$status" = "pass" ]; then
        echo -e "  \033[0;32m[PASS]\033[0m $message" | tee -a "$OUTPUT_FILE"
    elif [ "$status" = "warn" ]; then
        echo -e "  \033[1;33m[WARN]\033[0m $message" | tee -a "$OUTPUT_FILE"
    elif [ "$status" = "fail" ]; then
        echo -e "  \033[0;31m[FAIL]\033[0m $message" | tee -a "$OUTPUT_FILE"
    else
        echo "  [INFO] $message" | tee -a "$OUTPUT_FILE"
    fi
}

# Run command locally or remotely
run_cmd() {
    if [ -n "$REMOTE_HOST" ]; then
        ssh -o ConnectTimeout=10 -o BatchMode=yes "$REMOTE_HOST" "$@" 2>/dev/null
    else
        eval "$@" 2>/dev/null
    fi
}

# Check if command exists (local or remote)
cmd_exists() {
    run_cmd "command -v $1" &>/dev/null
}

# ============================================================================
# Platform Detection
# ============================================================================

detect_platform() {
    local os_type
    os_type=$(run_cmd "uname -s" 2>/dev/null || echo "Unknown")

    case "$os_type" in
        Darwin)
            echo "macos"
            ;;
        Linux)
            # Check for systemd
            if run_cmd "systemctl --version" &>/dev/null; then
                echo "linux-systemd"
            else
                echo "linux-generic"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "windows"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# ============================================================================
# macOS Power Settings
# ============================================================================

check_macos_power() {
    log_header "macOS Power Settings (pmset)"

    if ! cmd_exists pmset; then
        log_status "fail" "pmset not found"
        return 100
    fi

    local pmset_output
    pmset_output=$(run_cmd "pmset -g")

    # Parse key settings
    local system_sleep display_sleep disk_sleep hibernate_mode wake_on_lan

    system_sleep=$(echo "$pmset_output" | grep -E "^\s*sleep\s+" | awk '{print $2}')
    display_sleep=$(echo "$pmset_output" | grep -E "^\s*displaysleep\s+" | awk '{print $2}')
    disk_sleep=$(echo "$pmset_output" | grep -E "^\s*disksleep\s+" | awk '{print $2}')
    hibernate_mode=$(echo "$pmset_output" | grep -E "^\s*hibernatemode\s+" | awk '{print $2}')
    wake_on_lan=$(echo "$pmset_output" | grep -E "^\s*womp\s+" | awk '{print $2}')

    # Also check for power nap and other settings
    local powernap standby autopoweroff
    powernap=$(echo "$pmset_output" | grep -E "^\s*powernap\s+" | awk '{print $2}')
    standby=$(echo "$pmset_output" | grep -E "^\s*standby\s+" | awk '{print $2}')
    autopoweroff=$(echo "$pmset_output" | grep -E "^\s*autopoweroff\s+" | awk '{print $2}')

    # Display values
    log_item "System sleep" "${system_sleep:-N/A} minutes"
    log_item "Display sleep" "${display_sleep:-N/A} minutes"
    log_item "Disk sleep" "${disk_sleep:-N/A} minutes"
    log_item "Hibernate mode" "${hibernate_mode:-N/A}"
    log_item "Wake on LAN" "${wake_on_lan:-N/A}"
    log_item "Power Nap" "${powernap:-N/A}"
    log_item "Standby" "${standby:-N/A}"
    log_item "Auto power off" "${autopoweroff:-N/A}"

    # Evaluate settings
    local issues=0
    log ""
    log "--- Assessment ---"

    if [ "$system_sleep" = "0" ]; then
        log_status "pass" "System sleep disabled (always on)"
    elif [ -n "$system_sleep" ]; then
        log_status "warn" "System will sleep after $system_sleep minutes"
        issues=$((issues + 1))
    fi

    if [ "$hibernate_mode" = "0" ]; then
        log_status "pass" "Hibernate disabled"
    elif [ -n "$hibernate_mode" ]; then
        log_status "warn" "Hibernate mode: $hibernate_mode (may cause downtime)"
        issues=$((issues + 1))
    fi

    if [ "$wake_on_lan" = "1" ]; then
        log_status "pass" "Wake on LAN enabled"
    elif [ "$wake_on_lan" = "0" ]; then
        log_status "info" "Wake on LAN disabled"
    fi

    if [ "$standby" = "1" ]; then
        log_status "warn" "Standby enabled (deep sleep after extended idle)"
        issues=$((issues + 1))
    fi

    if [ "$autopoweroff" = "1" ]; then
        log_status "warn" "Auto power off enabled"
        issues=$((issues + 1))
    fi

    # Check screen lock (via security settings)
    log ""
    log_header "Screen Lock Settings"

    local screen_lock_delay
    screen_lock_delay=$(run_cmd "defaults -currentHost read com.apple.screensaver idleTime" 2>/dev/null || echo "")

    if [ -n "$screen_lock_delay" ] && [ "$screen_lock_delay" != "0" ]; then
        local lock_minutes=$((screen_lock_delay / 60))
        log_item "Screen saver delay" "$lock_minutes minutes"

        if [ "$screen_lock_delay" -gt "$MAX_IDLE_LOCK_TIME" ]; then
            log_status "warn" "Screen lock delay exceeds 15 minutes (security risk)"
            issues=$((issues + 1))
        else
            log_status "pass" "Screen lock within recommended timeframe"
        fi
    else
        log_item "Screen saver delay" "Disabled or not set"
    fi

    return $issues
}

# ============================================================================
# Linux Power Settings (systemd)
# ============================================================================

check_linux_systemd_power() {
    log_header "Linux Power Settings (systemd)"

    # Check sleep/suspend/hibernate targets
    local sleep_status suspend_status hibernate_status

    sleep_status=$(run_cmd "systemctl is-enabled sleep.target" 2>/dev/null || echo "unknown")
    suspend_status=$(run_cmd "systemctl is-enabled suspend.target" 2>/dev/null || echo "unknown")
    hibernate_status=$(run_cmd "systemctl is-enabled hibernate.target" 2>/dev/null || echo "unknown")

    log_item "sleep.target" "$sleep_status"
    log_item "suspend.target" "$suspend_status"
    log_item "hibernate.target" "$hibernate_status"

    # Check logind.conf settings
    log ""
    log "--- logind.conf Settings ---"

    local logind_settings
    logind_settings=$(run_cmd "cat /etc/systemd/logind.conf" 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "")

    if [ -n "$logind_settings" ]; then
        echo "$logind_settings" | while read -r line; do
            log "  $line"
        done
    else
        log "  (using defaults)"
    fi

    # Check specific settings
    local idle_action handle_lid handle_suspend
    idle_action=$(run_cmd "grep -E '^IdleAction=' /etc/systemd/logind.conf" 2>/dev/null | cut -d= -f2 || echo "ignore")
    handle_lid=$(run_cmd "grep -E '^HandleLidSwitch=' /etc/systemd/logind.conf" 2>/dev/null | cut -d= -f2 || echo "suspend")
    handle_suspend=$(run_cmd "grep -E '^HandleSuspendKey=' /etc/systemd/logind.conf" 2>/dev/null | cut -d= -f2 || echo "suspend")

    log ""
    log "--- Effective Settings ---"
    log_item "Idle action" "${idle_action:-ignore (default)}"
    log_item "Lid switch action" "${handle_lid:-suspend (default)}"
    log_item "Suspend key action" "${handle_suspend:-suspend (default)}"

    # Check GNOME/KDE screen lock if available
    log ""
    log_header "Desktop Screen Lock"

    local gnome_idle kde_idle
    gnome_idle=$(run_cmd "gsettings get org.gnome.desktop.session idle-delay" 2>/dev/null || echo "")

    if [ -n "$gnome_idle" ]; then
        local idle_seconds
        idle_seconds=$(echo "$gnome_idle" | grep -oE "[0-9]+")
        if [ -n "$idle_seconds" ] && [ "$idle_seconds" -gt 0 ]; then
            log_item "GNOME idle delay" "$((idle_seconds / 60)) minutes"
        else
            log_item "GNOME idle delay" "Disabled"
        fi
    fi

    # Evaluate
    local issues=0
    log ""
    log "--- Assessment ---"

    if [ "$sleep_status" = "masked" ]; then
        log_status "pass" "Sleep target masked (disabled)"
    elif [ "$sleep_status" = "enabled" ] || [ "$sleep_status" = "static" ]; then
        log_status "warn" "Sleep target enabled"
        issues=$((issues + 1))
    fi

    if [ "$suspend_status" = "masked" ]; then
        log_status "pass" "Suspend target masked (disabled)"
    elif [ "$suspend_status" = "enabled" ] || [ "$suspend_status" = "static" ]; then
        log_status "warn" "Suspend target enabled"
        issues=$((issues + 1))
    fi

    if [ "$hibernate_status" = "masked" ]; then
        log_status "pass" "Hibernate target masked (disabled)"
    elif [ "$hibernate_status" = "enabled" ] || [ "$hibernate_status" = "static" ]; then
        log_status "warn" "Hibernate target enabled"
        issues=$((issues + 1))
    fi

    # Check for laptop (lid switch matters)
    if run_cmd "test -d /sys/class/power_supply/BAT0" 2>/dev/null; then
        log_status "info" "Laptop detected - lid switch settings may apply"
        if [ "$handle_lid" != "ignore" ] && [ "$handle_lid" != "lock" ]; then
            log_status "warn" "Lid close will: $handle_lid"
            issues=$((issues + 1))
        fi
    fi

    return $issues
}

# ============================================================================
# Linux Power Settings (Generic)
# ============================================================================

check_linux_generic_power() {
    log_header "Linux Power Settings (Generic)"

    # Check /sys/power settings
    log "--- /sys/power Settings ---"

    local mem_sleep disk_state
    mem_sleep=$(run_cmd "cat /sys/power/mem_sleep" 2>/dev/null || echo "N/A")
    disk_state=$(run_cmd "cat /sys/power/disk" 2>/dev/null || echo "N/A")

    log_item "Memory sleep" "$mem_sleep"
    log_item "Disk state" "$disk_state"

    # Check ACPI
    if cmd_exists acpi; then
        log ""
        log "--- ACPI Status ---"
        local acpi_output
        acpi_output=$(run_cmd "acpi -a" 2>/dev/null || echo "")
        if [ -n "$acpi_output" ]; then
            log "  $acpi_output"
        fi
    fi

    log ""
    log "--- Assessment ---"
    log_status "info" "Generic Linux - manual verification recommended"

    return 0
}

# ============================================================================
# Windows Power Settings (via SSH/PowerShell)
# ============================================================================

check_windows_power() {
    log_header "Windows Power Settings"

    # This would be called via SSH to a Windows host with OpenSSH
    # or could be a separate PowerShell script

    local powercfg_output
    powercfg_output=$(run_cmd "powercfg /query SCHEME_CURRENT" 2>/dev/null || echo "")

    if [ -z "$powercfg_output" ]; then
        log_status "fail" "Could not retrieve power settings (powercfg not available or SSH failed)"
        log "  For Windows targets, ensure OpenSSH is installed or run Check-PowerSettings.ps1 locally"
        return 100
    fi

    log "$powercfg_output"

    # Parse key settings
    local active_scheme
    active_scheme=$(run_cmd "powercfg /getactivescheme" 2>/dev/null || echo "Unknown")
    log ""
    log_item "Active power scheme" "$active_scheme"

    log ""
    log "--- Assessment ---"

    if echo "$active_scheme" | grep -qi "high performance"; then
        log_status "pass" "High Performance power plan active"
        return 0
    elif echo "$active_scheme" | grep -qi "balanced"; then
        log_status "warn" "Balanced power plan (may sleep)"
        return 1
    else
        log_status "info" "Custom power plan - verify settings manually"
        return 0
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Header
    {
        echo "POWER SETTINGS VERIFICATION"
        echo "==========================="
        echo "Timestamp: $TIMESTAMP"
        if [ -n "$REMOTE_HOST" ]; then
            echo "Target: $REMOTE_HOST (remote)"
        else
            echo "Target: localhost"
        fi
        echo ""
        echo "NIST Controls: CM-6, AC-11, SC-24"
        echo ""
    } > "$OUTPUT_FILE"

    # Detect platform
    local platform
    platform=$(detect_platform)

    log_item "Platform detected" "$platform"
    log ""

    # Run appropriate checks
    local exit_code=0

    case "$platform" in
        macos)
            check_macos_power || exit_code=$?
            ;;
        linux-systemd)
            check_linux_systemd_power || exit_code=$?
            ;;
        linux-generic)
            check_linux_generic_power || exit_code=$?
            ;;
        windows)
            check_windows_power || exit_code=$?
            ;;
        *)
            log_status "fail" "Unsupported platform: $platform"
            exit_code=100
            ;;
    esac

    # Summary
    log ""
    log "==========================="
    log "SUMMARY"
    log "==========================="

    if [ $exit_code -eq 0 ]; then
        log_status "pass" "System configured for availability"
    elif [ $exit_code -ge 100 ]; then
        log_status "fail" "Could not determine power settings"
    else
        log_status "warn" "Found $exit_code potential availability issue(s)"
        log ""
        log "To configure for always-on operation:"
        case "$platform" in
            macos)
                log "  sudo pmset -a sleep 0 hibernatemode 0 standby 0"
                ;;
            linux-systemd)
                log "  sudo systemctl mask sleep.target suspend.target hibernate.target"
                ;;
            windows)
                log "  powercfg /setactive SCHEME_MIN  # High Performance"
                ;;
        esac
    fi

    log ""
    log "Results saved to: $OUTPUT_FILE"

    return $exit_code
}

# Run main
main "$@"
