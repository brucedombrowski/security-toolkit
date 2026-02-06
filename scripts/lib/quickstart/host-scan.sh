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
RUN_HOST_MALWARE="${RUN_HOST_MALWARE:-false}"
RUN_HOST_KEV="${RUN_HOST_KEV:-false}"
LYNIS_MODE="${LYNIS_MODE:-quick}"

# Track installed packages (for cleanup)
INSTALLED_LYNIS="${INSTALLED_LYNIS:-false}"
INSTALLED_CLAMAV="${INSTALLED_CLAMAV:-false}"

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
            while true; do
                echo -n "    Full scan (~10-15 min) or quick (~2 min)? [f/Q]: "
                read -r mode_ans </dev/tty
                case "$mode_ans" in
                    [Ff]) LYNIS_MODE="full"; break ;;
                    [Qq]|"") LYNIS_MODE="quick"; break ;;
                    *) echo "    Invalid option. Enter 'f' for full or 'q' for quick." ;;
                esac
            done
        fi
        echo -n "  Malware scan (ClamAV)? [y/N]: "
        read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_HOST_MALWARE=true
        echo -n "  KEV check (CISA Known Exploited Vulnerabilities)? [y/N]: "
        read -r ans </dev/tty && [[ "$ans" =~ ^[Yy] ]] && RUN_HOST_KEV=true
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

    echo ""

    # Log selections
    log_transcript "HOST SCANS: nmap_ports=$RUN_NMAP_PORTS nmap_svc=$RUN_NMAP_SERVICES nmap_os=$RUN_NMAP_OS nmap_vuln=$RUN_NMAP_VULN"
    log_transcript "HOST SCANS: inventory=$RUN_HOST_INVENTORY security=$RUN_HOST_SECURITY power=$RUN_HOST_POWER lynis=$RUN_HOST_LYNIS malware=$RUN_HOST_MALWARE kev=$RUN_HOST_KEV"
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

    # Use global counters (Bash 3.2 compatible - avoids namerefs)
    _HOST_PASSED=0
    _HOST_FAILED=0
    _HOST_SKIPPED=0

    echo ""
    echo -e "${BOLD}Running Host Scans on $TARGET_HOST${NC}"
    echo "================================================"
    echo ""

    # SSH-based scans (credentialed only)
    local ssh_available=false
    local ssh_scans_requested=false

    # Check if any SSH-based scans were selected
    if [ "$RUN_HOST_INVENTORY" = true ] || [ "$RUN_HOST_SECURITY" = true ] || \
       [ "$RUN_HOST_POWER" = true ] || [ "$RUN_HOST_LYNIS" = true ]; then
        ssh_scans_requested=true
    fi

    if [ "$AUTH_MODE" = "credentialed" ] && [ "$TARGET_LOCATION" = "remote" ] && [ "$ssh_scans_requested" = true ]; then
        # Set up SSH connection (only if SSH-based scans were selected)
        REMOTE_HOST="$TARGET_HOST"
        if test_ssh_connection; then
            ssh_available=true
            run_ssh_host_scans "$output_dir" "$timestamp"
        else
            # SSH failed - warn but continue with network scans
            print_warning "SSH connection failed - skipping SSH-based scans"
            echo "  (Windows hosts often don't have SSH enabled)"
            echo "  Continuing with network-based scans (nmap)..."
            echo ""

            # Mark SSH scans as skipped
            [ "$RUN_HOST_INVENTORY" = true ] && ((_HOST_SKIPPED++)) || true
            [ "$RUN_HOST_SECURITY" = true ] && ((_HOST_SKIPPED++)) || true
            [ "$RUN_HOST_POWER" = true ] && ((_HOST_SKIPPED++)) || true
            [ "$RUN_HOST_LYNIS" = true ] && ((_HOST_SKIPPED++)) || true
        fi
    fi

    # Network-based scans (always run - don't require SSH)
    run_network_host_scans "$output_dir" "$timestamp"

    # Update global counters
    SCANS_PASSED=$((SCANS_PASSED + _HOST_PASSED))
    SCANS_FAILED=$((SCANS_FAILED + _HOST_FAILED))
    SCANS_SKIPPED=$((SCANS_SKIPPED + _HOST_SKIPPED))

    # Cleanup SSH if it was established
    if [ "$ssh_available" = true ]; then
        stop_ssh_control_master
    fi
}

# SSH-based host scans
# Updates global counters: _HOST_PASSED, _HOST_FAILED, _HOST_SKIPPED
run_ssh_host_scans() {
    local output_dir="$1"
    local timestamp="$2"

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
                ssh_cmd "hostnamectl 2>/dev/null || hostname" || true
                echo ""
                echo "--- OS Release ---"
                ssh_cmd "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo 'Unknown'" || true
                echo ""
                echo "--- CPU ---"
                ssh_cmd "lscpu 2>/dev/null | head -20 || echo 'Unknown'" || true
                echo ""
                echo "--- Memory ---"
                ssh_cmd "free -h 2>/dev/null || echo 'Unknown'" || true
                echo ""
                echo "--- Disk ---"
                ssh_cmd "df -h 2>/dev/null || echo 'Unknown'" || true
                echo ""
                echo "--- Network Interfaces ---"
                ssh_cmd "ip addr 2>/dev/null || ifconfig || echo 'Unknown'" || true
                echo ""
                echo "--- Installed Packages (sample) ---"
                ssh_cmd "dpkg -l 2>/dev/null | head -50 || rpm -qa 2>/dev/null | head -50 || echo 'Package manager not found'" || true
            } > "$inv_file" 2>&1

            print_success "Host inventory saved"
            ((_HOST_PASSED++)) || true
        else
            print_warning "Could not collect inventory"
            ((_HOST_SKIPPED++)) || true
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
            ssh_cmd "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'Cannot list ports'" || true
            echo ""
            echo "--- Firewall Status ---"
            ssh_cmd "sudo iptables -L -n 2>/dev/null || echo 'iptables not accessible'" || true
            ssh_cmd "sudo ufw status 2>/dev/null || echo 'ufw not installed'" || true
            echo ""
            echo "--- SSH Configuration ---"
            ssh_cmd "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null || echo 'Cannot read sshd_config'" || true
            echo ""
            echo "--- Users with Login Shell ---"
            ssh_cmd "grep -v '/nologin\|/false' /etc/passwd 2>/dev/null | cut -d: -f1,7 || echo 'Cannot read passwd'" || true
            echo ""
            echo "--- Sudo/Wheel Group Members ---"
            local sudo_group
            sudo_group=$(ssh_cmd "getent group sudo 2>/dev/null" 2>/dev/null) || true
            local wheel_group
            wheel_group=$(ssh_cmd "getent group wheel 2>/dev/null" 2>/dev/null) || true
            if [ -n "$sudo_group" ]; then
                echo "sudo group: $sudo_group"
            fi
            if [ -n "$wheel_group" ]; then
                echo "wheel group: $wheel_group"
            fi
            if [ -z "$sudo_group" ] && [ -z "$wheel_group" ]; then
                echo "No sudo or wheel group found on this system"
            fi
        } > "$sec_file" 2>&1

        print_success "Security check saved"
        ((_HOST_PASSED++)) || true
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
                local target
                for target in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
                    local status
                    status=$(ssh_cmd "systemctl is-enabled $target 2>/dev/null" 2>/dev/null) || status="not found"
                    echo "  $target: $status"
                done
                echo ""
                echo "--- logind.conf Settings ---"
                local logind_settings
                logind_settings=$(ssh_cmd "grep -v '^#' /etc/systemd/logind.conf 2>/dev/null | grep -v '^\$' | grep -v '^\['" 2>/dev/null) || true
                if [ -n "$logind_settings" ]; then
                    echo "$logind_settings"
                else
                    echo "  (using defaults - no custom settings)"
                fi
                echo ""
                echo "--- Active Power Profile ---"
                local profile
                profile=$(ssh_cmd "cat /sys/firmware/acpi/platform_profile 2>/dev/null" 2>/dev/null) || true
                if [ -n "$profile" ]; then
                    echo "  Profile: $profile"
                else
                    echo "  N/A (power-profiles-daemon not installed or not supported)"
                fi
                echo ""
                echo "--- Screen Lock (GNOME) ---"
                local idle_delay
                idle_delay=$(ssh_cmd "gsettings get org.gnome.desktop.session idle-delay 2>/dev/null" 2>/dev/null) || true
                if [ -n "$idle_delay" ]; then
                    # Parse "uint32 300" format
                    local seconds
                    seconds=$(echo "$idle_delay" | grep -oE '[0-9]+' || echo "0")
                    if [ "$seconds" -gt 0 ]; then
                        local minutes=$((seconds / 60))
                        echo "  Lock after idle: $minutes minutes ($seconds seconds)"
                    else
                        echo "  Lock after idle: Never (disabled)"
                    fi
                else
                    echo "  GNOME not available or not configured"
                fi
            elif [ "$remote_os" = "Darwin" ]; then
                echo "--- pmset Settings ---"
                ssh_cmd "pmset -g || echo 'pmset not available'" || true
                echo ""
                echo "--- Screen Saver ---"
                ssh_cmd "defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null || echo 'Not set'" || true
            else
                echo "Unsupported OS for power settings check"
            fi
        } > "$power_file" 2>&1

        # Check for sleep-related issues
        if grep -qE "(sleep|suspend|hibernate).*(enabled|active)" "$power_file" 2>/dev/null; then
            print_warning "Power settings may cause downtime - review $power_file"
            ((_HOST_FAILED++)) || true
        else
            print_success "Power settings check saved"
            ((_HOST_PASSED++)) || true
        fi
    fi

    # Lynis Audit
    if [ "$RUN_HOST_LYNIS" = true ]; then
        print_step "Running remote Lynis audit ($LYNIS_MODE mode)..."
        local lynis_file="$output_dir/host-lynis-$timestamp.txt"

        if ssh_cmd "command -v lynis" &>/dev/null; then
            local lynis_opts="--quick"
            [ "$LYNIS_MODE" = "full" ] && lynis_opts="" || true

            {
                echo "Remote Lynis Security Audit"
                echo "==========================="
                echo "Host: $TARGET_HOST"
                echo "Mode: $LYNIS_MODE"
                echo "Started: $timestamp"
                echo ""
                ssh_cmd "sudo lynis audit system $lynis_opts --no-colors 2>&1" || true
            } > "$lynis_file" 2>&1

            # Check for warnings/suggestions
            local warnings=$(grep -c "Warning:" "$lynis_file" 2>/dev/null || echo "0")
            if [ "$warnings" -gt 0 ]; then
                print_warning "Lynis found $warnings warnings"
                ((_HOST_FAILED++)) || true
            else
                print_success "Lynis audit complete"
                ((_HOST_PASSED++)) || true
            fi
        else
            # Offer to install Lynis
            print_warning "Lynis not installed on remote host"
            echo -n "  Install Lynis now? [y/N]: "
            read -r install_ans </dev/tty
            if [[ "$install_ans" =~ ^[Yy] ]]; then
                echo "  Updating package list and installing Lynis..."
                # Use ssh_cmd_sudo for TTY allocation (sudo password prompt)
                if ssh_cmd_sudo "sudo apt update && sudo apt install -y lynis" 2>&1; then
                    print_success "Lynis installed"
                    INSTALLED_LYNIS=true
                    # Run the audit now
                    local lynis_opts="--quick"
                    [ "$LYNIS_MODE" = "full" ] && lynis_opts="" || true
                    {
                        echo "Remote Lynis Security Audit"
                        echo "==========================="
                        echo "Host: $TARGET_HOST"
                        echo "Mode: $LYNIS_MODE"
                        echo "Started: $timestamp"
                        echo ""
                        ssh_cmd_sudo "sudo lynis audit system $lynis_opts --no-colors 2>&1" || true
                    } > "$lynis_file" 2>&1
                    print_success "Lynis audit complete"
                    ((_HOST_PASSED++)) || true
                else
                    print_error "Lynis installation failed (check sudo access and network)"
                    ((_HOST_SKIPPED++)) || true
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
                print_warning "Lynis not installed (skipped)"
                ((_HOST_SKIPPED++)) || true
            fi
        fi
    fi

    # Malware Scan (ClamAV)
    if [ "$RUN_HOST_MALWARE" = true ]; then
        print_step "Running remote malware scan..."
        local malware_file="$output_dir/host-malware-$timestamp.txt"

        if ssh_cmd "command -v clamscan" &>/dev/null; then
            {
                echo "Remote Malware Scan (ClamAV)"
                echo "============================"
                echo "Host: $TARGET_HOST"
                echo "Started: $timestamp"
                echo ""
                echo "--- ClamAV Version ---"
                ssh_cmd "clamscan --version" 2>/dev/null || echo "(version unavailable)"
                echo ""
                echo "--- Scan Results ---"
                ssh_cmd "clamscan --recursive --infected \
                    --exclude-dir='.git' \
                    --exclude-dir='node_modules' \
                    --exclude-dir='.cache' \
                    ~/ 2>&1" 2>/dev/null || echo "(scan completed)"
            } > "$malware_file" 2>&1

            # Check for errors first (no database, etc.)
            if grep -q "No supported database files found\|cli_loaddbdir" "$malware_file" 2>/dev/null; then
                print_warning "ClamAV has no virus database - scan invalid"
                echo "  Run 'sudo freshclam' on remote host to download definitions"
                ((_HOST_SKIPPED++)) || true
            elif grep -q "FOUND" "$malware_file" 2>/dev/null; then
                print_fail "Malware detected! Check $malware_file"
                ((_HOST_FAILED++)) || true
            elif grep -q "Infected files: 0" "$malware_file" 2>/dev/null; then
                print_success "No malware detected"
                ((_HOST_PASSED++)) || true
            else
                print_success "Malware scan completed"
                ((_HOST_PASSED++)) || true
            fi
        else
            # Offer to install ClamAV
            print_warning "ClamAV not installed on remote host"
            echo -n "  Install ClamAV now? [y/N]: "
            read -r install_ans </dev/tty
            if [[ "$install_ans" =~ ^[Yy] ]]; then
                echo "  Installing ClamAV on remote host..."
                # Use ssh_cmd_sudo for TTY allocation (sudo password prompt)
                if ssh_cmd_sudo "sudo apt update && sudo apt install -y clamav" 2>&1; then
                    print_success "ClamAV installed"
                    INSTALLED_CLAMAV=true
                    # Update virus database
                    echo "  Updating virus database (this may take a minute)..."
                    ssh_cmd_sudo "sudo freshclam" 2>&1 || echo "  (freshclam update skipped - may be locked by daemon)"
                    # Run the scan
                    {
                        echo "Remote Malware Scan (ClamAV)"
                        echo "============================"
                        echo "Host: $TARGET_HOST"
                        echo "Started: $timestamp"
                        echo ""
                        echo "--- ClamAV Version ---"
                        ssh_cmd "clamscan --version" 2>/dev/null || echo "(version unavailable)"
                        echo ""
                        echo "--- Scan Results ---"
                        ssh_cmd "clamscan --recursive --infected \
                            --exclude-dir='.git' \
                            --exclude-dir='node_modules' \
                            --exclude-dir='.cache' \
                            ~/ 2>&1" 2>/dev/null || echo "(scan completed)"
                    } > "$malware_file" 2>&1

                    # Check for errors first (no database, etc.)
                    if grep -q "No supported database files found\|cli_loaddbdir" "$malware_file" 2>/dev/null; then
                        print_warning "ClamAV has no virus database - scan invalid"
                        echo "  Run 'sudo freshclam' on remote host to download definitions"
                        ((_HOST_SKIPPED++)) || true
                    elif grep -q "FOUND" "$malware_file" 2>/dev/null; then
                        print_fail "Malware detected! Check $malware_file"
                        ((_HOST_FAILED++)) || true
                    elif grep -q "Infected files: 0" "$malware_file" 2>/dev/null; then
                        print_success "No malware detected"
                        ((_HOST_PASSED++)) || true
                    else
                        print_success "Malware scan completed"
                        ((_HOST_PASSED++)) || true
                    fi
                else
                    print_error "ClamAV installation failed"
                    ((_HOST_SKIPPED++)) || true
                fi
            else
                {
                    echo "ClamAV not installed on remote host"
                    echo ""
                    echo "To install:"
                    echo "  Debian/Ubuntu: sudo apt install clamav"
                    echo "  RHEL/CentOS:   sudo yum install clamav"
                    echo "  Arch:          sudo pacman -S clamav"
                } > "$malware_file"
                print_warning "ClamAV not installed (skipped)"
                ((_HOST_SKIPPED++)) || true
            fi
        fi
    fi

    # KEV Check (CISA Known Exploited Vulnerabilities)
    if [ "$RUN_HOST_KEV" = true ]; then
        print_step "Running KEV check..."
        local kev_file="$output_dir/host-kev-$timestamp.txt"

        # KEV check requires a vulnerability scan with CVEs
        # Check if nmap vuln scan was run, otherwise explain
        local vuln_scan_file=""
        if [ "$RUN_NMAP_VULN" = true ]; then
            vuln_scan_file="$output_dir/nmap-ports-$timestamp.txt"
            [ ! -f "$vuln_scan_file" ] && vuln_scan_file=""
        fi

        {
            echo "CISA KEV Check (Known Exploited Vulnerabilities)"
            echo "================================================"
            echo "Host: $TARGET_HOST"
            echo "Checked: $timestamp"
            echo ""

            if [ -n "$vuln_scan_file" ] && [ -f "$vuln_scan_file" ]; then
                echo "Checking vulnerability scan against KEV catalog..."
                echo "Source: $vuln_scan_file"
                echo ""
                # Run KEV check with nmap output (strip ANSI codes)
                "$SCRIPTS_DIR/check-kev.sh" "$vuln_scan_file" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' || true
            else
                echo "Note: KEV cross-reference requires vulnerability scan data."
                echo ""
                echo "To enable KEV checking:"
                echo "  1. Enable 'Vulnerability scripts (nmap --script vuln)' scan"
                echo "  2. Re-run scans to generate CVE data"
                echo ""
                echo "The KEV catalog tracks actively exploited CVEs per BOD 22-01."
            fi
        } > "$kev_file" 2>&1

        # Check results
        if grep -q "No known exploited vulnerabilities\|No KEV matches" "$kev_file" 2>/dev/null; then
            print_success "No known exploited vulnerabilities found"
            ((_HOST_PASSED++)) || true
        elif grep -q "KEV cross-reference requires" "$kev_file" 2>/dev/null; then
            print_warning "KEV check skipped (requires vulnerability scan)"
            ((_HOST_SKIPPED++)) || true
        elif grep -q "CVE-" "$kev_file" 2>/dev/null; then
            print_warning "Potential KEV matches found - review $kev_file"
            ((_HOST_FAILED++)) || true
        else
            print_success "KEV check completed"
            ((_HOST_PASSED++)) || true
        fi
    fi
}

# Network-based host scans
# Updates global counters: _HOST_PASSED, _HOST_FAILED, _HOST_SKIPPED
run_network_host_scans() {
    local output_dir="$1"
    local timestamp="$2"

    # Nmap Port Scan
    if [ "$RUN_NMAP_PORTS" = true ]; then
        print_step "Running Nmap port scan..."
        local nmap_file="$output_dir/nmap-ports-$timestamp.txt"

        local nmap_args="-Pn"
        local needs_sudo=false
        [ "$RUN_NMAP_SERVICES" = true ] && nmap_args="$nmap_args -sV" || true
        if [ "$RUN_NMAP_OS" = true ]; then
            nmap_args="$nmap_args -O"
            needs_sudo=true
        fi
        [ "$RUN_NMAP_VULN" = true ] && nmap_args="$nmap_args --script vuln" || true

        # OS fingerprinting requires root - use sudo if needed
        local nmap_cmd="nmap"
        if [ "$needs_sudo" = true ]; then
            echo "  (OS fingerprinting requires elevated privileges)"
            nmap_cmd="sudo nmap"
        fi

        {
            echo "Nmap Scan Results"
            echo "================="
            echo "Target: $TARGET_HOST"
            echo "Options: $nmap_args"
            echo "Started: $timestamp"
            echo ""
            $nmap_cmd $nmap_args "$TARGET_HOST" 2>&1 || echo "Nmap scan completed with warnings"
        } > "$nmap_file"

        # Check if scan actually ran (look for nmap output markers)
        if grep -q "Nmap scan report\|PORT.*STATE" "$nmap_file" 2>/dev/null; then
            # Scan ran successfully - check for open ports
            local open_ports
            open_ports=$(grep -c "/.*open" "$nmap_file" 2>/dev/null | head -1 | tr -d '[:space:]') || true
            open_ports=${open_ports:-0}
            if [ "$open_ports" -gt 0 ] 2>/dev/null; then
                print_success "Nmap found $open_ports open port(s)"
            else
                print_warning "Nmap found no open ports (host may be filtered)"
            fi
            ((_HOST_PASSED++)) || true
        elif grep -q "incorrect password\|sudo.*denied\|Permission denied" "$nmap_file" 2>/dev/null; then
            # Sudo failed - offer to retry without OS fingerprinting
            print_error "Nmap scan failed (sudo authentication failed)"
            echo "  OS fingerprinting (-O) requires root privileges"
            echo "  Re-run without OS fingerprinting, or use 'sudo ./QuickStart.sh'"
            ((_HOST_FAILED++)) || true
        else
            print_warning "Nmap scan may have failed - check $nmap_file"
            ((_HOST_FAILED++)) || true
        fi
    fi
}
