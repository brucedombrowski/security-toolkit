#!/bin/bash
#
# QuickStart Remote Scanning Library
#
# Purpose: SSH multiplexing, remote scan selection and execution
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# SSH Control Master (Connection Multiplexing)
# ============================================================================

SSH_CONTROL_PATH=""
SSH_OPTS=""

# Start SSH control master for connection multiplexing (single password prompt)
start_ssh_control_master() {
    # Create control socket path
    SSH_CONTROL_PATH="/tmp/ssh-quickstart-$$-$(date +%s)"
    SSH_OPTS="-o ControlPath=$SSH_CONTROL_PATH -o ControlMaster=auto -o ControlPersist=300"

    print_step "Establishing SSH connection to $REMOTE_USER@$REMOTE_HOST..."
    echo "  (You will only need to enter your password once)"
    echo ""

    # Start the control master connection
    if ssh -o ConnectTimeout=10 -o ControlMaster=yes -o ControlPath="$SSH_CONTROL_PATH" -o ControlPersist=300 -N -f "$REMOTE_USER@$REMOTE_HOST" 2>/dev/null; then
        print_success "SSH connection established (will be reused for all scans)"
        return 0
    else
        print_error "Failed to establish SSH connection"
        SSH_CONTROL_PATH=""
        SSH_OPTS=""
        return 1
    fi
}

# Stop SSH control master (cleanup)
stop_ssh_control_master() {
    if [ -n "$SSH_CONTROL_PATH" ] && [ -S "$SSH_CONTROL_PATH" ]; then
        ssh -o ControlPath="$SSH_CONTROL_PATH" -O exit "$REMOTE_USER@$REMOTE_HOST" 2>/dev/null || true
        rm -f "$SSH_CONTROL_PATH" 2>/dev/null || true
    fi
}

# Run SSH command using control master
ssh_cmd() {
    if [ -n "$SSH_OPTS" ]; then
        ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" "$@"
    else
        ssh "$REMOTE_USER@$REMOTE_HOST" "$@"
    fi
}

# Run SSH command with TTY allocation (needed for sudo password prompts)
ssh_cmd_sudo() {
    if [ -n "$SSH_OPTS" ]; then
        ssh -t $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" "$@"
    else
        ssh -t "$REMOTE_USER@$REMOTE_HOST" "$@"
    fi
}

# Test SSH connectivity and detect remote OS
test_ssh_connection() {
    # Set up SSH multiplexing first
    if ! start_ssh_control_master; then
        return 1
    fi

    # Detect remote OS using the multiplexed connection
    REMOTE_OS=$(ssh_cmd "uname -s" 2>/dev/null || echo "Unknown")
    print_success "Remote OS: $REMOTE_OS"
    echo ""

    # Register cleanup on exit
    trap stop_ssh_control_master EXIT

    return 0
}

# ============================================================================
# Remote Configuration Selection
# ============================================================================

select_remote_config_tui() {
    # Project name first (used in filenames instead of IP for security)
    PROJECT_NAME=$(tui_input "Project Name" "Enter a name for this scan (used in filenames):" "")
    if [ -z "$PROJECT_NAME" ]; then
        print_error "Project name required"
        exit 1
    fi
    # Sanitize project name for filenames
    PROJECT_NAME=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9_-]/_/g')

    REMOTE_HOST=$(tui_input "Remote Host" "Enter hostname or IP address:" "")
    if [ -z "$REMOTE_HOST" ]; then
        print_error "Cancelled"
        exit 1
    fi

    if [ "$AUTH_MODE" = "credentialed" ]; then
        REMOTE_USER=$(tui_input "SSH Username" "Enter username for $REMOTE_HOST:" "")
        if [ -z "$REMOTE_USER" ]; then
            print_error "Username required"
            exit 1
        fi
        tui_msgbox "SSH Authentication" "You will be prompted for SSH credentials when connecting.\n\nEnsure you have SSH access to $REMOTE_USER@$REMOTE_HOST"
    fi

    TARGET_DIR="$REMOTE_HOST"
}

select_remote_config_cli() {
    # Project name first (used in filenames instead of IP for security)
    echo ""
    echo -e "${BOLD}Remote Host Configuration${NC}"
    echo ""
    echo -n "Enter project name (used in filenames): "
    read -r PROJECT_NAME </dev/tty
    if [ -z "$PROJECT_NAME" ]; then
        print_error "Project name required"
        exit 1
    fi
    # Sanitize project name for filenames
    PROJECT_NAME=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9_-]/_/g')

    echo -n "Enter remote hostname or IP: "
    read -r REMOTE_HOST </dev/tty

    if [ -z "$REMOTE_HOST" ]; then
        print_error "Hostname required"
        exit 1
    fi

    if [ "$AUTH_MODE" = "credentialed" ]; then
        echo -n "Enter SSH username: "
        read -r REMOTE_USER </dev/tty
        if [ -z "$REMOTE_USER" ]; then
            print_error "Username required"
            exit 1
        fi
        echo ""
        echo "Note: You will be prompted for SSH credentials when connecting."
    fi

    TARGET_DIR="$REMOTE_HOST"
}

select_remote_config() {
    # Skip prompts if all values set from config
    if [ -n "$REMOTE_HOST" ] && [ -n "$REMOTE_USER" ] && [ -n "$PROJECT_NAME" ]; then
        echo "Remote config from file:"
    elif use_tui; then
        select_remote_config_tui
    else
        select_remote_config_cli
    fi
    echo ""
    print_success "Target: $REMOTE_HOST"
    [ -n "$REMOTE_USER" ] && print_success "User: $REMOTE_USER"
    [ -n "$PROJECT_NAME" ] && print_success "Project: $PROJECT_NAME"
    echo ""
}

# ============================================================================
# Remote Scan Selection
# ============================================================================

# Scan selection for remote credentialed (SSH) scans
select_remote_scans_ssh_tui() {
    # Check if OpenVAS is available
    local openvas_label="OpenVAS vulnerability scan"
    if ! check_openvas_available; then
        openvas_label="OpenVAS (not installed)"
    fi

    local selections
    selections=$(tui_checklist "Remote Scan Selection (SSH)" "Select scans to run on $REMOTE_HOST:" 20 70 8 \
        "inventory" "Host inventory (system info, packages)" "on" \
        "security" "Security configuration check" "on" \
        "malware" "Malware scan (ClamAV, if installed)" "on" \
        "lynis-quick" "Lynis audit - quick (~2 min)" "off" \
        "lynis-full" "Lynis audit - full (~10-15 min)" "off" \
        "openvas" "$openvas_label" "off" \
        "ports" "Port scan (nmap from local)" "off" \
        "services" "Service version detection (nmap)" "off")

    if [ -z "$selections" ]; then
        print_error "No scans selected"
        exit 1
    fi

    # Parse selections
    [[ "$selections" =~ inventory ]] && RUN_REMOTE_INVENTORY=true
    [[ "$selections" =~ security ]] && RUN_REMOTE_SECURITY=true
    [[ "$selections" =~ malware ]] && RUN_REMOTE_MALWARE=true
    [[ "$selections" =~ lynis-quick ]] && RUN_REMOTE_LYNIS=true && LYNIS_MODE="quick"
    [[ "$selections" =~ lynis-full ]] && RUN_REMOTE_LYNIS=true && LYNIS_MODE="full"
    [[ "$selections" =~ openvas ]] && RUN_REMOTE_OPENVAS=true
    [[ "$selections" =~ ports ]] && RUN_NMAP_PORTS=true
    [[ "$selections" =~ services ]] && RUN_NMAP_SERVICES=true

    # If OpenVAS selected, ask about scan type
    if [ "$RUN_REMOTE_OPENVAS" = true ]; then
        if ! check_openvas_available; then
            tui_msgbox "OpenVAS Not Available" "OpenVAS/GVM is not running.\n\nStart with:\ndocker compose -f ~/greenbone-community-container/docker-compose.yml up -d"
            RUN_REMOTE_OPENVAS=false
        else
            if tui_yesno "OpenVAS Scan Type" "Run full vulnerability scan?\n\n'Yes' = Full scan (30-60 min)\n'No' = Quick scan (5-15 min)"; then
                OPENVAS_SCAN_TYPE="full"
            else
                OPENVAS_SCAN_TYPE="quick"
            fi
        fi
    fi
}

select_remote_scans_ssh_cli() {
    echo -e "${BOLD}Select Remote Scans (SSH)${NC}"
    echo ""
    echo "Select scans (y/n for each):"
    echo -n "  Host inventory (system info, packages)? [Y/n]: "
    read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_REMOTE_INVENTORY=true
    echo -n "  Security configuration check? [Y/n]: "
    read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_REMOTE_SECURITY=true
    echo -n "  Malware scan (ClamAV, if installed)? [Y/n]: "
    read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_REMOTE_MALWARE=true
    echo -n "  Lynis security audit (if installed)? [y/N]: "
    read -r ans
    if [[ "$ans" =~ ^[Yy] ]]; then
        RUN_REMOTE_LYNIS=true
        echo -n "    Full scan (~10-15 min) or quick (~2 min)? [f/Q]: "
        read -r mode_ans
        [[ "$mode_ans" =~ ^[Ff] ]] && LYNIS_MODE="full" || LYNIS_MODE="quick"
    fi

    # OpenVAS option
    if check_openvas_available; then
        echo -n "  OpenVAS vulnerability scan? [y/N]: "
        read -r ans
        if [[ "$ans" =~ ^[Yy] ]]; then
            RUN_REMOTE_OPENVAS=true
            echo -n "    Full scan or quick? [f/Q]: "
            read -r mode_ans
            [[ "$mode_ans" =~ ^[Ff] ]] && OPENVAS_SCAN_TYPE="full" || OPENVAS_SCAN_TYPE="quick"
        fi
    else
        echo -e "  ${GRAY}OpenVAS (not installed - skipping)${NC}"
    fi

    echo -n "  Port scan (nmap from local)? [y/N]: "
    read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_PORTS=true
    echo -n "  Service version detection (nmap)? [y/N]: "
    read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_SERVICES=true
    echo ""
}

# Scan selection for remote uncredentialed (Nmap) scans
select_remote_scans_nmap_tui() {
    local choice
    choice=$(tui_menu "Network Scan Type" "Select scan type for $REMOTE_HOST:" 18 70 5 \
        "quick" "Quick scan - Top 100 ports only" \
        "standard" "Standard scan - Top 1000 ports + services" \
        "full" "Full scan - All ports + OS detection + vuln scripts" \
        "openvas" "OpenVAS - Deep CVE vulnerability scan" \
        "custom" "Custom - Select individual options")

    if [ -z "$choice" ]; then
        print_error "Cancelled"
        exit 1
    fi

    case "$choice" in
        quick)
            RUN_NMAP_PORTS=true
            ;;
        standard)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            ;;
        full)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            RUN_NMAP_OS=true
            RUN_NMAP_VULN=true
            ;;
        openvas)
            if check_openvas_available; then
                RUN_REMOTE_OPENVAS=true
                if tui_yesno "OpenVAS Scan Type" "Run full vulnerability scan?\n\n'Yes' = Full scan (30-60 min)\n'No' = Quick scan (5-15 min)"; then
                    OPENVAS_SCAN_TYPE="full"
                else
                    OPENVAS_SCAN_TYPE="quick"
                fi
            else
                tui_msgbox "OpenVAS Not Available" "OpenVAS/GVM is not running.\n\nStart with:\ndocker compose -f ~/greenbone-community-container/docker-compose.yml up -d"
                # Fall back to nmap full scan
                RUN_NMAP_PORTS=true
                RUN_NMAP_SERVICES=true
                RUN_NMAP_VULN=true
            fi
            ;;
        custom)
            local selections
            selections=$(tui_checklist "Custom Network Scan" "Select scan options:" 18 70 5 \
                "ports" "Port scan (TCP)" "on" \
                "services" "Service version detection (-sV)" "on" \
                "os" "OS fingerprinting (-O, requires root)" "off" \
                "vuln" "Vulnerability scripts (--script vuln)" "off" \
                "openvas" "OpenVAS deep vulnerability scan" "off")

            [[ "$selections" =~ ports ]] && RUN_NMAP_PORTS=true
            [[ "$selections" =~ services ]] && RUN_NMAP_SERVICES=true
            [[ "$selections" =~ os ]] && RUN_NMAP_OS=true
            [[ "$selections" =~ vuln ]] && RUN_NMAP_VULN=true
            if [[ "$selections" =~ openvas ]] && check_openvas_available; then
                RUN_REMOTE_OPENVAS=true
                OPENVAS_SCAN_TYPE="quick"
            fi
            ;;
    esac
}

select_remote_scans_nmap_cli() {
    echo -e "${BOLD}Select Network Scan Type${NC}"
    echo ""
    echo "  1) Quick scan    - Top 100 ports only (fast)"
    echo "  2) Standard scan - Top 1000 ports + service detection"
    echo "  3) Full scan     - All ports + OS + vulnerability scripts"
    echo "  4) Custom        - Select individual options"
    echo ""
    echo -n "Select [1-4]: "
    read -r choice

    case "$choice" in
        1)
            RUN_NMAP_PORTS=true
            ;;
        2)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            ;;
        3)
            RUN_NMAP_PORTS=true
            RUN_NMAP_SERVICES=true
            RUN_NMAP_OS=true
            RUN_NMAP_VULN=true
            ;;
        4)
            echo ""
            echo "Select options (y/n for each):"
            echo -n "  Port scan (TCP)? [Y/n]: "
            read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_NMAP_PORTS=true
            echo -n "  Service version detection? [Y/n]: "
            read -r ans && [[ ! "$ans" =~ ^[Nn] ]] && RUN_NMAP_SERVICES=true
            echo -n "  OS fingerprinting (requires sudo)? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_OS=true
            echo -n "  Vulnerability scripts? [y/N]: "
            read -r ans && [[ "$ans" =~ ^[Yy] ]] && RUN_NMAP_VULN=true
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
    echo ""
}

select_remote_scans() {
    if [ "$AUTH_MODE" = "credentialed" ]; then
        # Test SSH connection first
        if ! test_ssh_connection; then
            exit 1
        fi

        if [ "$SKIP_SCAN_SELECTION" = "true" ]; then
            echo "Using scan selections from config file"
        elif use_tui; then
            select_remote_scans_ssh_tui
        else
            select_remote_scans_ssh_cli
        fi
    else
        # Uncredentialed = Nmap only
        if [ "$SKIP_SCAN_SELECTION" = "true" ]; then
            echo "Using scan selections from config file"
        elif use_tui; then
            select_remote_scans_nmap_tui
        else
            select_remote_scans_nmap_cli
        fi
    fi
}

# ============================================================================
# Remote Scan Execution
# ============================================================================

# Run Nmap network scan
run_nmap_scan() {
    local output_dir="$1"
    local timestamp="$2"
    local nmap_file="$output_dir/nmap-$timestamp.txt"

    print_step "Running Nmap scan against $REMOTE_HOST..."

    if ! command -v nmap &>/dev/null; then
        print_error "Nmap not installed"
        return 1
    fi

    # Build nmap command
    # -Pn skips host discovery (ping) - many hosts block ICMP
    local nmap_args=("-v" "-Pn")

    if [ "$RUN_NMAP_PORTS" = true ]; then
        # Default is top 1000, use -F for fast (top 100)
        if [ "$RUN_NMAP_SERVICES" != true ] && [ "$RUN_NMAP_OS" != true ]; then
            nmap_args+=("-F")  # Fast scan for quick mode
        fi
    fi

    if [ "$RUN_NMAP_SERVICES" = true ]; then
        nmap_args+=("-sV")  # Service version detection
    fi

    if [ "$RUN_NMAP_OS" = true ]; then
        nmap_args+=("-O")  # OS detection (requires root)
        echo "  Note: OS detection requires sudo"
    fi

    if [ "$RUN_NMAP_VULN" = true ]; then
        nmap_args+=("--script=vuln")  # Vulnerability scripts
    fi

    nmap_args+=("$REMOTE_HOST")

    echo "  Running: nmap ${nmap_args[*]}"
    echo ""

    {
        echo "Nmap Scan Results"
        echo "================="
        echo "Target: $REMOTE_HOST"
        echo "Scanned: $timestamp"
        echo "Command: nmap ${nmap_args[*]}"
        echo ""
    } > "$nmap_file"

    # Run nmap (with sudo if OS detection requested)
    if [ "$RUN_NMAP_OS" = true ]; then
        sudo nmap "${nmap_args[@]}" >> "$nmap_file" 2>&1
    else
        nmap "${nmap_args[@]}" >> "$nmap_file" 2>&1
    fi

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        print_success "Nmap scan saved: $nmap_file"

        # Show quick summary
        echo ""
        echo "  Open ports found:"
        grep -E "^[0-9]+/(tcp|udp)" "$nmap_file" | head -10 | while read -r line; do
            echo "    $line"
        done
        local port_count
        port_count=$(grep -cE "^[0-9]+/(tcp|udp).*open" "$nmap_file" 2>/dev/null || echo "0")
        echo "  Total: $port_count open ports"
        return 0
    else
        print_error "Nmap scan failed (exit code: $exit_code)"
        return 1
    fi
}

# Run SSH-based remote scans
run_remote_ssh_scans() {
    local passed=0
    local failed=0
    local skipped=0

    # Use the session output directory
    local output_dir="$SCAN_OUTPUT_DIR"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H%M%SZ")

    echo -e "${BOLD}Running remote scans via SSH...${NC}"
    echo ""

    # Remote Host Inventory
    if [ "$RUN_REMOTE_INVENTORY" = true ]; then
        print_step "Collecting remote host inventory..."
        local inv_file="$output_dir/remote-inventory-$timestamp.txt"

        {
            echo "Remote Host Inventory"
            echo "====================="
            echo "Host: $REMOTE_HOST"
            echo "User: $REMOTE_USER"
            echo "Collected: $timestamp"
            echo "Remote OS: $REMOTE_OS"
            echo ""

            echo "--- System Information ---"
            ssh_cmd "uname -a" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- Hostname ---"
            ssh_cmd "hostname -f 2>/dev/null || hostname" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- OS Release ---"
            ssh_cmd "cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || echo 'Unknown'" 2>/dev/null
            echo ""

            echo "--- CPU Information ---"
            ssh_cmd "lscpu 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'Unknown'" 2>/dev/null
            echo ""

            echo "--- Memory ---"
            ssh_cmd "free -h 2>/dev/null || vm_stat 2>/dev/null || echo 'Unknown'" 2>/dev/null
            echo ""

            echo "--- Disk Usage ---"
            ssh_cmd "df -h" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- Network Interfaces ---"
            ssh_cmd "ip addr 2>/dev/null || ifconfig 2>/dev/null" 2>/dev/null || echo "(failed)"
            echo ""

            echo "--- Installed Packages (sample) ---"
            ssh_cmd "dpkg -l 2>/dev/null | head -50 || rpm -qa 2>/dev/null | head -50 || brew list 2>/dev/null | head -50 || echo 'Unknown package manager'" 2>/dev/null
            echo ""

            echo "--- Running Services ---"
            ssh_cmd "systemctl list-units --type=service --state=running 2>/dev/null | head -30 || launchctl list 2>/dev/null | head -30 || echo 'Unknown'" 2>/dev/null

        } > "$inv_file" 2>&1

        if [ -s "$inv_file" ]; then
            print_success "Remote inventory saved: $inv_file"
            ((passed++))
        else
            print_warning "Remote inventory collection had issues"
            ((failed++))
        fi
    fi

    # Remote Security Check
    if [ "$RUN_REMOTE_SECURITY" = true ]; then
        print_step "Checking remote security configuration..."
        local sec_file="$output_dir/remote-security-$timestamp.txt"

        {
            echo "Remote Security Configuration Check"
            echo "===================================="
            echo "Host: $REMOTE_HOST"
            echo "Checked: $timestamp"
            echo ""

            echo "--- SSH Configuration ---"
            ssh_cmd "grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null || echo 'Cannot read sshd_config'" 2>/dev/null
            echo ""

            echo "--- Firewall Status ---"
            ssh_cmd "sudo ufw status 2>/dev/null || sudo iptables -L -n 2>/dev/null | head -20 || sudo firewall-cmd --state 2>/dev/null || echo 'Firewall status unknown'" 2>/dev/null
            echo ""

            echo "--- Users with Shell Access ---"
            ssh_cmd "grep -E '/bin/(bash|sh|zsh)$' /etc/passwd 2>/dev/null || dscl . -list /Users 2>/dev/null || echo 'Cannot enumerate users'" 2>/dev/null
            echo ""

            echo "--- Sudo Configuration ---"
            ssh_cmd "sudo cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'Cannot read sudoers'" 2>/dev/null
            echo ""

            echo "--- Listening Ports ---"
            ssh_cmd "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || lsof -i -P -n | grep LISTEN 2>/dev/null || echo 'Cannot list ports'" 2>/dev/null
            echo ""

            echo "--- Failed Login Attempts (last 10) ---"
            ssh_cmd "sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10 || sudo grep 'Failed password' /var/log/secure 2>/dev/null | tail -10 || echo 'Cannot read auth logs'" 2>/dev/null
            echo ""

            echo "--- Kernel Security Parameters ---"
            ssh_cmd "sysctl -a 2>/dev/null | grep -E '(randomize|protect|secure)' | head -20 || echo 'Cannot read sysctl'" 2>/dev/null

        } > "$sec_file" 2>&1

        if [ -s "$sec_file" ]; then
            print_success "Remote security check saved: $sec_file"
            ((passed++))
        else
            print_warning "Remote security check had issues"
            ((failed++))
        fi
    fi

    # Remote Lynis Audit
    if [ "$RUN_REMOTE_LYNIS" = true ]; then
        print_step "Running Lynis audit on remote host..."

        # Check if Lynis is installed remotely
        if ssh_cmd "command -v lynis" &>/dev/null; then
            local lynis_file="$output_dir/remote-lynis-$timestamp.txt"
            local lynis_opts=""
            [[ "$LYNIS_MODE" == "quick" ]] && lynis_opts="--quick"

            if [[ "$LYNIS_MODE" == "quick" ]]; then
                echo "  Lynis quick audit running (~2-5 minutes)..."
            else
                echo "  Lynis full audit running (~10-15 minutes)..."
            fi

            # Run with TTY for sudo prompt, use tee to show AND save output
            if ssh_cmd_sudo "sudo lynis audit system $lynis_opts" 2>&1 | tee "$lynis_file.raw"; then
                # Strip terminal escape codes
                if command -v col &>/dev/null; then
                    col -b < "$lynis_file.raw" > "$lynis_file"
                    rm -f "$lynis_file.raw"
                else
                    mv "$lynis_file.raw" "$lynis_file"
                fi
                print_success "Remote Lynis audit saved: $lynis_file"
                ((passed++))
            else
                if [ -f "$lynis_file.raw" ]; then
                    mv "$lynis_file.raw" "$lynis_file"
                fi
                print_warning "Remote Lynis audit had issues (check $lynis_file)"
                ((failed++))
            fi
        else
            print_warning "Lynis not installed on remote host"
            echo -n "  Install Lynis now? [y/N]: "
            read -r install_ans
            if [[ "$install_ans" =~ ^[Yy] ]]; then
                echo "  Installing Lynis on remote host..."
                if ssh_cmd_sudo "sudo apt install -y lynis" 2>&1; then
                    print_success "Lynis installed"
                    # Now run the audit
                    local lynis_file="$output_dir/remote-lynis-$timestamp.txt"
                    local lynis_opts=""
                    [[ "$LYNIS_MODE" == "quick" ]] && lynis_opts="--quick"

                    if [[ "$LYNIS_MODE" == "quick" ]]; then
                        echo "  Lynis quick audit running (~2-5 minutes)..."
                    else
                        echo "  Lynis full audit running (~10-15 minutes)..."
                    fi
                    # Run with TTY for sudo, use tee to show AND save output
                    if ssh_cmd_sudo "sudo lynis audit system $lynis_opts" 2>&1 | tee "$lynis_file.raw"; then
                        if command -v col &>/dev/null; then
                            col -b < "$lynis_file.raw" > "$lynis_file"
                            rm -f "$lynis_file.raw"
                        else
                            mv "$lynis_file.raw" "$lynis_file"
                        fi
                        print_success "Remote Lynis audit saved: $lynis_file"
                        ((passed++))
                    else
                        [ -f "$lynis_file.raw" ] && mv "$lynis_file.raw" "$lynis_file"
                        print_warning "Remote Lynis audit had issues"
                        ((failed++))
                    fi
                else
                    print_error "Lynis installation failed"
                    ((skipped++))
                fi
            else
                ((skipped++))
            fi
        fi
    fi

    # Remote Malware Scan (ClamAV)
    if [ "$RUN_REMOTE_MALWARE" = true ]; then
        print_step "Running malware scan on remote host..."
        local malware_file="$output_dir/remote-malware-$timestamp.txt"

        # Check if clamscan is available on remote
        if ssh_cmd "command -v clamscan" &>/dev/null; then
            {
                echo "Remote Malware Scan (ClamAV)"
                echo "============================="
                echo "Host: $REMOTE_HOST"
                echo "Scanned: $timestamp"
                echo ""

                echo "--- ClamAV Version ---"
                ssh_cmd "clamscan --version" 2>/dev/null || echo "(failed to get version)"
                echo ""

                echo "--- Scan Results ---"
                echo "Scanning home directory with common exclusions..."
                echo ""
                # Scan home directory, show only infected files, limit output
                ssh_cmd "clamscan --recursive --infected \
                    --exclude-dir='.git' \
                    --exclude-dir='node_modules' \
                    --exclude-dir='.cache' \
                    --exclude-dir='.local/share/Trash' \
                    ~/ 2>&1" 2>/dev/null || echo "(scan completed with warnings)"

            } > "$malware_file" 2>&1

            # Check for infections in the output
            if grep -q "Infected files: 0" "$malware_file" 2>/dev/null; then
                print_success "No malware detected"
                REMOTE_MALWARE_RESULT="PASS"
                ((passed++))
            elif grep -q "FOUND" "$malware_file" 2>/dev/null; then
                print_fail "Malware detected! Check $malware_file"
                REMOTE_MALWARE_RESULT="FAIL"
                ((failed++))
            else
                print_success "Malware scan completed: $malware_file"
                REMOTE_MALWARE_RESULT="PASS"
                ((passed++))
            fi
        else
            print_warning "ClamAV not installed on remote host"
            echo -n "  Install ClamAV now? [y/N]: "
            read -r install_ans
            if [[ "$install_ans" =~ ^[Yy] ]]; then
                echo "  Installing ClamAV on remote host..."
                if ssh_cmd_sudo "sudo apt install -y clamav" 2>&1; then
                    print_success "ClamAV installed"
                    # Check if freshclam service is running (it auto-starts on install)
                    if ssh_cmd "systemctl is-active clamav-freshclam" &>/dev/null; then
                        echo "  Virus database update service running (clamav-freshclam)"
                    else
                        echo "  Updating virus database (this may take a minute)..."
                        ssh_cmd_sudo "sudo freshclam" 2>&1 || echo "  (freshclam update skipped)"
                    fi
                    # Now run the scan
                    {
                        echo "Remote Malware Scan (ClamAV)"
                        echo "============================="
                        echo "Host: $REMOTE_HOST"
                        echo "Scanned: $timestamp"
                        echo ""
                        echo "--- ClamAV Version ---"
                        ssh_cmd "clamscan --version" 2>/dev/null || echo "(version check failed)"
                        echo ""
                        echo "--- Scan Results ---"
                        ssh_cmd "clamscan --recursive --infected \
                            --exclude-dir='.git' \
                            --exclude-dir='node_modules' \
                            --exclude-dir='.cache' \
                            ~/ 2>&1" 2>/dev/null || echo "(scan completed)"
                    } > "$malware_file" 2>&1

                    if grep -q "Infected files: 0" "$malware_file" 2>/dev/null; then
                        print_success "No malware detected"
                        REMOTE_MALWARE_RESULT="PASS"
                        ((passed++))
                    elif grep -q "FOUND" "$malware_file" 2>/dev/null; then
                        print_fail "Malware detected! Check $malware_file"
                        REMOTE_MALWARE_RESULT="FAIL"
                        ((failed++))
                    else
                        print_success "Malware scan completed: $malware_file"
                        REMOTE_MALWARE_RESULT="PASS"
                        ((passed++))
                    fi
                else
                    print_error "ClamAV installation failed"
                    REMOTE_MALWARE_RESULT="SKIP"
                    ((skipped++))
                fi
            else
                {
                    echo "Remote Malware Scan (ClamAV)"
                    echo "============================="
                    echo "Host: $REMOTE_HOST"
                    echo "Checked: $timestamp"
                    echo ""
                    echo "ClamAV not installed - user declined installation."
                } > "$malware_file" 2>&1
                REMOTE_MALWARE_RESULT="SKIP"
                ((skipped++))
            fi
        fi
    fi

    # Also run local nmap if selected
    if [ "$RUN_NMAP_PORTS" = true ] || [ "$RUN_NMAP_SERVICES" = true ]; then
        run_nmap_scan "$output_dir" "$timestamp"
        if [ $? -eq 0 ]; then
            ((passed++))
        else
            ((failed++))
        fi
    fi

    # OpenVAS Network Vulnerability Scan (runs locally against remote target)
    if [ "$RUN_REMOTE_OPENVAS" = true ]; then
        if check_openvas_available; then
            print_step "OpenVAS Vulnerability Scan [$OPENVAS_SCAN_TYPE]..."
            echo "  Target: $REMOTE_HOST"
            echo "  Note: This scan may take 5-60 minutes"
            echo ""

            # Ensure OpenVAS containers are running
            if ! is_openvas_running; then
                echo "  Starting OpenVAS containers..."
                start_openvas
            fi

            local openvas_exit=0
            run_openvas_scan "$REMOTE_HOST" "$output_dir" "$timestamp" "$OPENVAS_SCAN_TYPE" || openvas_exit=$?

            if [ "$openvas_exit" -eq 0 ]; then
                print_success "OpenVAS scan completed (no high-severity findings)"
                ((passed++))
            else
                print_warning "OpenVAS scan found vulnerabilities"
                ((failed++))
            fi
        else
            print_warning "OpenVAS not available - skipping"
            ((skipped++))
        fi
    fi

    echo ""

    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}

# Run uncredentialed (Nmap only) scans
run_remote_nmap_scans() {
    local passed=0
    local failed=0
    local skipped=0

    # Use the session output directory
    local output_dir="$SCAN_OUTPUT_DIR"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H%M%SZ")

    echo -e "${BOLD}Running network scan (uncredentialed)...${NC}"
    echo ""

    # Run Nmap if any nmap options selected
    if [ "$RUN_NMAP_PORTS" = true ] || [ "$RUN_NMAP_SERVICES" = true ] || [ "$RUN_NMAP_OS" = true ] || [ "$RUN_NMAP_VULN" = true ]; then
        if run_nmap_scan "$output_dir" "$timestamp"; then
            ((passed++))
        else
            ((failed++))
        fi
    fi

    # OpenVAS Network Vulnerability Scan
    if [ "$RUN_REMOTE_OPENVAS" = true ]; then
        if check_openvas_available; then
            print_step "OpenVAS Vulnerability Scan [$OPENVAS_SCAN_TYPE]..."
            echo "  Target: $REMOTE_HOST"
            echo "  Note: This scan may take 5-60 minutes"
            echo ""

            # Ensure OpenVAS containers are running
            if ! is_openvas_running; then
                echo "  Starting OpenVAS containers..."
                start_openvas
            fi

            local openvas_exit=0
            run_openvas_scan "$REMOTE_HOST" "$output_dir" "$timestamp" "$OPENVAS_SCAN_TYPE" || openvas_exit=$?

            if [ "$openvas_exit" -eq 0 ]; then
                print_success "OpenVAS scan completed (no high-severity findings)"
                ((passed++))
            else
                print_warning "OpenVAS scan found vulnerabilities"
                ((failed++))
            fi
        else
            print_warning "OpenVAS not available - skipping"
            ((skipped++))
        fi
    fi

    echo ""

    SCANS_PASSED=$passed
    SCANS_FAILED=$failed
    SCANS_SKIPPED=$skipped
}
