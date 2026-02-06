#!/bin/bash
#
# Demo Target Preparation Script
#
# Purpose: Configure a fresh Ubuntu live boot as a scan target
#          Installs dependencies, starts SSH, opens ports, plants findings
#
# Usage:
#   sudo ./prepare-demo-target.sh            # Set up target
#   sudo ./prepare-demo-target.sh --cleanup   # Tear down
#
# Designed for live boot environments - reboot to fully reset
#
# Exit codes:
#   0 = Success
#   1 = Failure (not root, missing package manager)

set -eu

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Config
DEMO_DIR="/tmp/demo-target-data"
LISTENER_PIDFILE="/tmp/demo-target-listeners.pids"
DEMO_HTTP_PORT=8080
DEMO_PORTS=(4444 6667 9090 31337)

# ============================================================================
# Helpers
# ============================================================================

log_step()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

get_ip() {
    # Get the primary non-loopback IP
    ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "unknown"
}

# ============================================================================
# Cleanup Mode
# ============================================================================

cleanup() {
    log_step "Cleaning up demo target..."

    # Kill listeners
    if [ -f "$LISTENER_PIDFILE" ]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$LISTENER_PIDFILE"
        rm -f "$LISTENER_PIDFILE"
        log_success "Killed port listeners"
    fi

    # Remove planted files
    if [ -d "$DEMO_DIR" ]; then
        rm -rf "$DEMO_DIR"
        log_success "Removed planted demo data"
    fi

    # Restore SSH config
    rm -f /etc/ssh/sshd_config.d/demo-target.conf 2>/dev/null || true
    if [ -f /etc/ssh/sshd_config.demo-backup ]; then
        mv /etc/ssh/sshd_config.demo-backup /etc/ssh/sshd_config
    fi
    systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
    log_success "Restored SSH configuration"

    log_success "Cleanup complete. Reboot to fully reset live environment."
    exit 0
}

# ============================================================================
# 1. SSH Setup
# ============================================================================

setup_ssh() {
    log_step "Setting up SSH server..."

    # Install openssh-server
    if ! command -v sshd &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq openssh-server
    fi

    # Backup original config
    if [ -f /etc/ssh/sshd_config ] && [ ! -f /etc/ssh/sshd_config.demo-backup ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.demo-backup
    fi

    # Configure for demo (intentionally weak for scan findings)
    if [ -d /etc/ssh/sshd_config.d ]; then
        cat > /etc/ssh/sshd_config.d/demo-target.conf <<'SSHCONF'
# Demo target - intentionally weak for security scan findings
PasswordAuthentication yes
PermitRootLogin yes
SSHCONF
    else
        # Fallback: modify main config if .d directory not supported
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    fi

    # Start SSH
    systemctl enable ssh 2>/dev/null || true
    systemctl start ssh 2>/dev/null || service ssh start 2>/dev/null || true

    log_success "SSH server running (PasswordAuthentication=yes, PermitRootLogin=yes)"
}

# ============================================================================
# 2. Scan Dependencies
# ============================================================================

install_scan_deps() {
    log_step "Installing scan dependencies..."

    apt-get update -qq

    # ClamAV
    if ! command -v clamscan &>/dev/null; then
        apt-get install -y -qq clamav clamav-daemon
        log_success "ClamAV installed"
    else
        log_success "ClamAV already installed"
    fi

    # Update virus definitions
    log_step "Updating ClamAV virus definitions (this may take a minute)..."
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam --quiet 2>/dev/null || log_warn "freshclam update had warnings (may still work)"
    systemctl start clamav-freshclam 2>/dev/null || true
    log_success "Virus definitions updated"

    # Lynis
    if ! command -v lynis &>/dev/null; then
        apt-get install -y -qq lynis
        log_success "Lynis installed"
    else
        log_success "Lynis already installed"
    fi

    # nmap (useful for local scan too)
    if ! command -v nmap &>/dev/null; then
        apt-get install -y -qq nmap
        log_success "Nmap installed"
    else
        log_success "Nmap already installed"
    fi
}

# ============================================================================
# 3. Open Interesting Ports
# ============================================================================

open_demo_ports() {
    log_step "Opening demo ports for nmap findings..."

    # Ensure we have netcat or socat
    if ! command -v nc &>/dev/null && ! command -v ncat &>/dev/null; then
        apt-get install -y -qq ncat 2>/dev/null || apt-get install -y -qq netcat-openbsd 2>/dev/null || true
    fi

    local nc_cmd="nc"
    command -v ncat &>/dev/null && nc_cmd="ncat"

    : > "$LISTENER_PIDFILE"

    # Simple HTTP server
    if command -v python3 &>/dev/null; then
        mkdir -p "$DEMO_DIR/www"
        echo "<html><body><h1>Demo Target</h1><p>This is a demo web server for security scanning.</p></body></html>" > "$DEMO_DIR/www/index.html"
        (cd "$DEMO_DIR/www" && python3 -m http.server "$DEMO_HTTP_PORT" &>/dev/null &)
        echo $! >> "$LISTENER_PIDFILE"
        log_success "HTTP server on port $DEMO_HTTP_PORT"
    fi

    # Open suspicious-looking ports with banners
    for port in "${DEMO_PORTS[@]}"; do
        if [ "$nc_cmd" = "ncat" ]; then
            ncat -lk "$port" --exec "/bin/echo Demo service on port $port" &>/dev/null &
        else
            # Loop nc listener in background
            (while true; do echo "Demo service on port $port" | $nc_cmd -l -p "$port" -q 1 2>/dev/null || break; done) &
        fi
        echo $! >> "$LISTENER_PIDFILE"
        log_success "Listener on port $port"
    done
}

# ============================================================================
# 4. Plant Demo Findings
# ============================================================================

plant_findings() {
    log_step "Planting demo scan findings..."

    mkdir -p "$DEMO_DIR"

    # --- PII findings (fake data, obviously not real) ---
    cat > "$DEMO_DIR/customer-records.csv" <<'PII'
# DEMO DATA - NOT REAL
name,ssn,phone,email,credit_card
John Smith,078-05-1120,555-867-5309,john@example.com,4532015112830366
Jane Doe,219-09-9999,(555) 234-5678,jane@example.com,6011514433546201
Bob Johnson,123-45-6789,555.345.6789,bob@example.com,5425233430109903
Alice Williams,321-54-9876,1-555-456-7890,alice@example.com,4916338506082832
PII
    log_success "Planted PII data: $DEMO_DIR/customer-records.csv"

    # --- Secrets findings ---
    cat > "$DEMO_DIR/config.env" <<'SECRETS'
# DEMO SECRETS - NOT REAL CREDENTIALS
DATABASE_URL=postgres://admin:SuperSecret123!@db.example.com:5432/production
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12
STRIPE_SECRET_KEY=sk_test_EXAMPLE_NOT_REAL_51hdkeyT1zdp
password=Admin@2024!
SECRETS
    log_success "Planted secrets: $DEMO_DIR/config.env"

    # --- Private key finding ---
    cat > "$DEMO_DIR/deploy-key.pem" <<'PRIVKEY'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNlRtQ2mKQKmFADpB8EXAMPLE_NOT_A_REAL_KEY_JUST_DEMO_DATA_FOR_SCAN
PzgKhsMIVbEBOxDzF4EXAMPLE_NOT_A_REAL_KEY_JUST_DEMO_DATA_FOR_SCAN
-----END RSA PRIVATE KEY-----
PRIVKEY
    log_success "Planted private key: $DEMO_DIR/deploy-key.pem"

    # --- MAC address findings ---
    cat > "$DEMO_DIR/network-inventory.txt" <<'MACS'
# Network Device Inventory - DEMO DATA
Switch-01   Port 1    00:1A:2B:3C:4D:5E   Server Room A
Switch-01   Port 2    AA:BB:CC:DD:EE:FF   Server Room A
Router-01   WAN       DE:AD:BE:EF:CA:FE   Network Closet
AP-Floor2   Wifi      02:42:AC:11:00:02   Floor 2
MACS
    log_success "Planted MAC addresses: $DEMO_DIR/network-inventory.txt"

    # --- EICAR malware test file ---
    # Standard EICAR test string - every AV recognizes this as a test signature
    # This is NOT malware - it's an industry-standard test file
    printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$DEMO_DIR/suspicious-file.exe"
    log_success "Planted EICAR test file: $DEMO_DIR/suspicious-file.exe"

    # --- A "forgotten" database dump ---
    cat > "$DEMO_DIR/users-backup.sql" <<'SQL'
-- DEMO DATA - NOT REAL
INSERT INTO users (id, email, password_hash, ssn) VALUES
(1, 'admin@example.com', '$2b$12$EXAMPLEHASHnotreal', '078-05-1120'),
(2, 'user@example.com', '$2b$12$ANOTHEREXAMPLEhash', '219-09-9999');
INSERT INTO api_keys (user_id, key) VALUES
(1, 'sk-live-EXAMPLE-KEY-NOT-REAL-12345');
SQL
    log_success "Planted database dump: $DEMO_DIR/users-backup.sql"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║       Demo Target Preparation Script         ║${NC}"
    echo -e "${BOLD}║       Security Toolkit - Target Setup         ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    # Handle cleanup mode
    if [ "${1:-}" = "--cleanup" ]; then
        cleanup
    fi

    local start_time
    start_time=$(date +%s)

    echo -e "${BOLD}Phase 1: SSH Server${NC}"
    echo "-------------------"
    setup_ssh
    echo ""

    echo -e "${BOLD}Phase 2: Scan Dependencies${NC}"
    echo "-------------------------"
    install_scan_deps
    echo ""

    echo -e "${BOLD}Phase 3: Attack Surface${NC}"
    echo "-----------------------"
    open_demo_ports
    echo ""

    echo -e "${BOLD}Phase 4: Planted Findings${NC}"
    echo "-------------------------"
    plant_findings
    echo ""

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    local ip
    ip=$(get_ip)

    # Summary
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  TARGET READY${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Target IP:${NC}        $ip"
    echo -e "  ${BOLD}SSH:${NC}              Port 22 (password auth enabled)"
    echo -e "  ${BOLD}HTTP:${NC}             Port $DEMO_HTTP_PORT"
    echo -e "  ${BOLD}Open ports:${NC}       ${DEMO_PORTS[*]}"
    echo -e "  ${BOLD}Planted files:${NC}    $DEMO_DIR/"
    echo -e "  ${BOLD}Setup time:${NC}       ${elapsed}s"
    echo ""
    echo -e "  ${BOLD}Expected scan findings:${NC}"
    echo -e "    ${RED}■${NC} PII:         SSNs, phone numbers, credit cards"
    echo -e "    ${RED}■${NC} Secrets:     API keys, passwords, private key"
    echo -e "    ${RED}■${NC} Malware:     EICAR test signature"
    echo -e "    ${RED}■${NC} MAC addrs:   4 planted addresses"
    echo -e "    ${RED}■${NC} Ports:       $(( ${#DEMO_PORTS[@]} + 2 )) open (SSH + HTTP + ${#DEMO_PORTS[@]} listeners)"
    echo -e "    ${YELLOW}■${NC} Host:        Weak SSH config, running services"
    echo -e "    ${YELLOW}■${NC} Lynis:       Multiple findings on stock Ubuntu"
    echo ""
    echo -e "  ${BOLD}From Kali scanner:${NC}"
    echo -e "    ./scripts/run-all-scans.sh $DEMO_DIR"
    echo -e "    ${BOLD}OR${NC}"
    echo -e "    ./QuickStart.sh → Remote → $ip"
    echo ""
    echo -e "  ${BOLD}Cleanup:${NC}"
    echo -e "    sudo $0 --cleanup"
    echo -e "    ${BOLD}OR${NC} just reboot (live boot = nothing persists)"
    echo ""
}

main "$@"
