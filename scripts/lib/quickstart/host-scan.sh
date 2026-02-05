#!/bin/bash
#
# QuickStart Host/Machine Scanning Module
#
# Purpose: Vulnerability assessment of systems via network or SSH
# Used by: QuickStart.sh
#
# Scan types:
#   - Nmap (ports, services, OS, vuln scripts)
#   - OpenVAS (CVE vulnerability scanning)
#   - Lynis (security auditing)
#   - Host inventory (system info, packages)
#   - Security configuration checks
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# Host Scan Variables
# ============================================================================

RUN_NMAP_PORTS="${RUN_NMAP_PORTS:-false}"
RUN_NMAP_SERVICES="${RUN_NMAP_SERVICES:-false}"
RUN_NMAP_OS="${RUN_NMAP_OS:-false}"
RUN_NMAP_VULN="${RUN_NMAP_VULN:-false}"
RUN_HOST_INVENTORY="${RUN_HOST_INVENTORY:-false}"
RUN_HOST_SECURITY="${RUN_HOST_SECURITY:-false}"
RUN_HOST_POWER="${RUN_HOST_POWER:-false}"
RUN_HOST_LYNIS="${RUN_HOST_LYNIS:-false}"
RUN_OPENVAS="${RUN_OPENVAS:-false}"
LYNIS_MODE="${LYNIS_MODE:-quick}"
OPENVAS_SCAN_TYPE="${OPENVAS_SCAN_TYPE:-quick}"

# ============================================================================
# Host Scan Selection
# ============================================================================

select_host_scans_cli() {
    echo -e "${BOLD}Select Host Scans${NC}"
    echo ""

    if [ "$AUTH_MODE" = "credentialed" ]; then
        # SSH-based scans available
        echo "Authenticated scans (via SSH):"
        echo -n "  Host inventory (system info, packages)? [y/N]: "
        read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_HOST_INVENTORY=true
        echo -n "  Security configuration check? [y/N]: "
        read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_HOST_SECURITY=true
        echo -n "  Power settings check (sleep/hibernate)? [y/N]: "
        read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_HOST_POWER=true
        echo -n "  Lynis security audit? [y/N]: "
        read -r ans </dev/tty
        if [[ "$ans" =~ ^[Yy] ]]; then
            RUN_HOST_LYNIS=true
            echo -n "    Full scan (~10-15 min) or quick (~2 min)? [f/Q]: "
            read -r mode_ans </dev/tty
            [[ "$mode_ans" =~ ^[Ff] ]] && LYNIS_MODE="full" || LYNIS_MODE="quick"
        fi
        echo ""
    fi

    echo "Network scans:"
    echo -n "  Port scan (nmap)? [y/N]: "
    read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_PORTS=true
    echo -n "  Service version detection? [y/N]: "
    read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_SERVICES=true
    echo -n "  OS fingerprinting (requires root)? [y/N]: "
    read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_OS=true
    echo -n "  Vulnerability scripts (nmap --script vuln)? [y/N]: "
    read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_VULN=true

    # OpenVAS option
    if check_openvas_available; then
        echo -n "  OpenVAS deep vulnerability scan? [y/N]: "
        read -r ans </dev/tty
        if [[ "$ans" =~ ^[Yy] ]]; then
            RUN_OPENVAS=true
            echo -n "    Full scan (30-60 min) or quick (5-15 min)? [f/Q]: "
            read -r mode_ans </dev/tty
            [[ "$mode_ans" =~ ^[Ff] ]] && OPENVAS_SCAN_TYPE="full" || OPENVAS_SCAN_TYPE="quick"
        fi
    else
        echo -e "  ${GRAY}OpenVAS (not available - skipping)${NC}"
    fi

    echo ""

    # Log selections
    log_transcript "HOST SCANS: nmap_ports=$RUN_NMAP_PORTS nmap_svc=$RUN_NMAP_SERVICES nmap_os=$RUN_NMAP_OS nmap_vuln=$RUN_NMAP_VULN"
    log_transcript "HOST SCANS: inventory=$RUN_HOST_INVENTORY security=$RUN_HOST_SECURITY power=$RUN_HOST_POWER lynis=$RUN_HOST_LYNIS openvas=$RUN_OPENVAS"
}

select_host_scans() {
    # Skip if configured from file
    if [ "$SKIP_SCAN_SELECTION" = "true" ]; then
        echo "Scan selection from config file"
        return
    fi
    select_host_scans_cli
}

# ============================================================================
# Host Scan Execution
# ============================================================================

run_host_scans() {
    local output_dir="$SCAN_OUTPUT_DIR"
    local timestamp=$(date -u '+%Y-%m-%dT%H%M%SZ')
    local passed=0
    local failed=0
    local skipped=0

    echo ""
    echo -e "${BOLD}Running Host Scans on $TARGET_HOST${NC}"
    echo "================================================"
    echo ""

    # SSH-based scans (credentialed only)
    local ssh_available=false
    if [ "$AUTH_MODE" = "credentialed" ] && [ "$TARGET_LOCATION" = "remote" ]; then
        # Set up SSH connection
        REMOTE_HOST="$TARGET_HOST"
        if test_ssh_connection; then
            ssh_available=true
            run_ssh_host_scans "$output_dir" "$timestamp" passed failed skipped
        else
            # SSH failed - warn but continue with network scans
            print_warning "SSH connection failed - skipping SSH-based scans"
            echo "  (Windows hosts often don't have SSH enabled)"
            echo "  Continuing with network-based scans (nmap, OpenVAS)..."
            echo ""

            # Mark SSH scans as skipped
            [ "$RUN_HOST_INVENTORY" = true ] && ((skipped++))
            [ "$RUN_HOST_SECURITY" = true ] && ((skipped++))
            [ "$RUN_HOST_POWER" = true ] && ((skipped++))
            [ "$RUN_HOST_LYNIS" = true ] && ((skipped++))
        fi
    fi

    # Network-based scans (always run - don't require SSH)
    run_network_host_scans "$output_dir" "$timestamp" passed failed skipped

    # Update global counters
    SCANS_PASSED=$((SCANS_PASSED + passed))
    SCANS_FAILED=$((SCANS_FAILED + failed))
    SCANS_SKIPPED=$((SCANS_SKIPPED + skipped))

    # Cleanup SSH if it was established
    if [ "$ssh_available" = true ]; then
        stop_ssh_control_master
    fi
}

# SSH-based host scans
run_ssh_host_scans() {
    local output_dir="$1"
    local timestamp="$2"
    local -n _passed=$3
    local -n _failed=$4
    local -n _skipped=$5

    # Host Inventory
    if [ "$RUN_HOST_INVENTORY" = true ]; then
        print_step "Running remote host inventory..."
        local inv_file="$output_dir/host-inventory-$timestamp.txt"

        if ssh_cmd "command -v hostnamectl" &>/dev/null; then
            {
                echo "Remote Host Inventory"
                echo "====================="
                echo "Host: $TARGET_HOST"
                echo "Collected: $timestamp"
                echo ""
                echo "--- System Information ---"
                ssh_cmd "hostnamectl 2>/dev/null || hostname"
                echo ""
                echo "--- OS Release ---"
                ssh_cmd "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null"
                echo ""
                echo "--- CPU ---"
                ssh_cmd "lscpu 2>/dev/null | head -20"
                echo ""
                echo "--- Memory ---"
                ssh_cmd "free -h 2>/dev/null"
                echo ""
                echo "--- Disk ---"
                ssh_cmd "df -h 2>/dev/null"
                echo ""
                echo "--- Network Interfaces ---"
                ssh_cmd "ip addr 2>/dev/null || ifconfig"
                echo ""
                echo "--- Installed Packages (sample) ---"
                ssh_cmd "dpkg -l 2>/dev/null | head -50 || rpm -qa 2>/dev/null | head -50"
            } > "$inv_file" 2>&1

            print_success "Host inventory saved"
            ((_passed++))
        else
            print_warning "Could not collect inventory"
            ((_skipped++))
        fi
    fi

    # Security Configuration
    if [ "$RUN_HOST_SECURITY" = true ]; then
        print_step "Running remote security check..."
        local sec_file="$output_dir/host-security-$timestamp.txt"

        {
            echo "Remote Security Configuration"
            echo "=============================="
            echo "Host: $TARGET_HOST"
            echo "Checked: $timestamp"
            echo ""
            echo "--- Listening Services ---"
            ssh_cmd "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
            echo ""
            echo "--- Firewall Status ---"
            ssh_cmd "sudo iptables -L -n 2>/dev/null || echo 'iptables not accessible'"
            ssh_cmd "sudo ufw status 2>/dev/null || echo 'ufw not installed'"
            echo ""
            echo "--- SSH Configuration ---"
            ssh_cmd "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null"
            echo ""
            echo "--- Users with Login Shell ---"
            ssh_cmd "grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1,7"
            echo ""
            echo "--- Sudo Users ---"
            ssh_cmd "getent group sudo wheel 2>/dev/null"
        } > "$sec_file" 2>&1

        print_success "Security check saved"
        ((_passed++))
    fi

    # Power Settings Check
    if [ "$RUN_HOST_POWER" = true ]; then
        print_step "Checking remote power settings..."
        local power_file="$output_dir/host-power-$timestamp.txt"

        {
            echo "Remote Power Settings"
            echo "====================="
            echo "Host: $TARGET_HOST"
            echo "Checked: $timestamp"
            echo ""

            # Detect OS type
            local remote_os
            remote_os=$(ssh_cmd "uname -s" 2>/dev/null || echo "Unknown")
            echo "OS: $remote_os"
            echo ""

            if [ "$remote_os" = "Linux" ]; then
                echo "--- systemd Sleep Targets ---"
                ssh_cmd "systemctl is-enabled sleep.target suspend.target hibernate.target 2>/dev/null || echo 'systemctl not available'"
                echo ""
                echo "--- logind.conf Settings ---"
                ssh_cmd "grep -v '^#' /etc/systemd/logind.conf 2>/dev/null | grep -v '^$' || echo 'No custom settings'"
                echo ""
                echo "--- Active Power Profile ---"
                ssh_cmd "cat /sys/firmware/acpi/platform_profile 2>/dev/null || echo 'N/A'"
                echo ""
                echo "--- Screen Lock (GNOME) ---"
                ssh_cmd "gsettings get org.gnome.desktop.session idle-delay 2>/dev/null || echo 'GNOME not available'"
            elif [ "$remote_os" = "Darwin" ]; then
                echo "--- pmset Settings ---"
                ssh_cmd "pmset -g"
                echo ""
                echo "--- Screen Saver ---"
                ssh_cmd "defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null || echo 'Not set'"
            else
                echo "Unsupported OS for power settings check"
            fi
        } > "$power_file" 2>&1

        # Check for sleep-related issues
        if grep -qE "(sleep|suspend|hibernate).*(enabled|active)" "$power_file" 2>/dev/null; then
            print_warning "Power settings may cause downtime - review $power_file"
            ((_failed++))
        else
            print_success "Power settings check saved"
            ((_passed++))
        fi
    fi

    # Lynis Audit
    if [ "$RUN_HOST_LYNIS" = true ]; then
        print_step "Running remote Lynis audit ($LYNIS_MODE mode)..."
        local lynis_file="$output_dir/host-lynis-$timestamp.txt"

        if ssh_cmd "command -v lynis" &>/dev/null; then
            local lynis_opts="--quick"
            [ "$LYNIS_MODE" = "full" ] && lynis_opts=""

            {
                echo "Remote Lynis Security Audit"
                echo "==========================="
                echo "Host: $TARGET_HOST"
                echo "Mode: $LYNIS_MODE"
                echo "Started: $timestamp"
                echo ""
                ssh_cmd "sudo lynis audit system $lynis_opts --no-colors 2>&1"
            } > "$lynis_file" 2>&1

            # Check for warnings/suggestions
            local warnings=$(grep -c "Warning:" "$lynis_file" 2>/dev/null || echo "0")
            if [ "$warnings" -gt 0 ]; then
                print_warning "Lynis found $warnings warnings"
                ((_failed++))
            else
                print_success "Lynis audit complete"
                ((_passed++))
            fi
        else
            {
                echo "Lynis not installed on remote host"
                echo ""
                echo "To install:"
                echo "  Debian/Ubuntu: sudo apt install lynis"
                echo "  RHEL/CentOS:   sudo yum install lynis"
                echo "  Arch:          sudo pacman -S lynis"
            } > "$lynis_file"

            print_warning "Lynis not installed on remote (skipped)"
            ((_skipped++))
        fi
    fi
}

# Network-based host scans
run_network_host_scans() {
    local output_dir="$1"
    local timestamp="$2"
    local -n _passed=$3
    local -n _failed=$4
    local -n _skipped=$5

    # Nmap Port Scan
    if [ "$RUN_NMAP_PORTS" = true ]; then
        print_step "Running Nmap port scan..."
        local nmap_file="$output_dir/nmap-ports-$timestamp.txt"

        local nmap_args="-Pn"
        [ "$RUN_NMAP_SERVICES" = true ] && nmap_args="$nmap_args -sV"
        [ "$RUN_NMAP_OS" = true ] && nmap_args="$nmap_args -O"
        [ "$RUN_NMAP_VULN" = true ] && nmap_args="$nmap_args --script vuln"

        {
            echo "Nmap Scan Results"
            echo "================="
            echo "Target: $TARGET_HOST"
            echo "Options: $nmap_args"
            echo "Started: $timestamp"
            echo ""
            nmap $nmap_args "$TARGET_HOST" 2>&1
        } > "$nmap_file"

        # Check for open ports
        local open_ports=$(grep -c "open" "$nmap_file" 2>/dev/null || echo "0")
        print_success "Nmap found $open_ports open ports"
        ((_passed++))
    fi

    # OpenVAS Scan
    if [ "$RUN_OPENVAS" = true ]; then
        print_step "Running OpenVAS vulnerability scan..."

        if check_openvas_available; then
            run_openvas_scan "$TARGET_HOST" "$output_dir" "$timestamp" "$OPENVAS_SCAN_TYPE"
            local openvas_result=$?
            if [ $openvas_result -eq 0 ]; then
                print_success "OpenVAS scan complete"
                ((_passed++))
            else
                print_warning "OpenVAS scan completed with findings"
                ((_failed++))
            fi
        else
            print_warning "OpenVAS not available (skipped)"
            ((_skipped++))
        fi
    fi
}
