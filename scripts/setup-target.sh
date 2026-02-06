#!/bin/bash
#
# One-Command Target Setup Bootstrap
#
# Purpose: Download latest toolkit release and configure Ubuntu target for demo
# Usage:   wget -qO- https://raw.githubusercontent.com/brucedombrowski/security-toolkit/main/scripts/setup-target.sh | sudo bash
#
# What this does:
#   1. Downloads the latest release tarball from GitHub
#   2. Extracts to /opt/security-toolkit
#   3. Runs prepare-payload.sh (JSON-driven, 8 phases)
#      Falls back to prepare-demo-target.sh if payload script not found
#   4. Displays target IP in large banner
#
# All commands are logged to /tmp/demo-target-bootstrap.log
#
# Exit codes:
#   0 = Success
#   1 = Failure

set -eu

# ============================================================================
# Config
# ============================================================================

REPO="brucedombrowski/security-toolkit"
INSTALL_DIR="/opt/security-toolkit"
BOOTSTRAP_LOG="/tmp/demo-target-bootstrap.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Logging — every command logged with timestamp
# ============================================================================

log() {
    local msg="[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $1"
    echo "$msg" >> "$BOOTSTRAP_LOG"
    echo -e "${BLUE}[*]${NC} $1"
}

log_cmd() {
    local cmd="$1"
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [CMD] $cmd" >> "$BOOTSTRAP_LOG"
    eval "$cmd" >> "$BOOTSTRAP_LOG" 2>&1
}

log_ok() {
    local msg="[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [OK] $1"
    echo "$msg" >> "$BOOTSTRAP_LOG"
    echo -e "${GREEN}[+]${NC} $1"
}

log_err() {
    local msg="[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [ERR] $1"
    echo "$msg" >> "$BOOTSTRAP_LOG"
    echo -e "${RED}[-]${NC} $1"
}

# ============================================================================
# ASCII Art IP Display
# ============================================================================

# Print a digit in large 5-line ASCII block font
print_large_char() {
    local ch="$1"
    local line="$2"
    case "$ch" in
        0) local -a d=(" ██████ " "██    ██" "██    ██" "██    ██" " ██████ ") ;;
        1) local -a d=("   ██   " "  ███   " "   ██   " "   ██   " "  ████  ") ;;
        2) local -a d=(" ██████ " "      ██" " ██████ " "██      " " ██████ ") ;;
        3) local -a d=(" ██████ " "      ██" "  █████ " "      ██" " ██████ ") ;;
        4) local -a d=("██    ██" "██    ██" " ██████ " "      ██" "      ██") ;;
        5) local -a d=(" ██████ " "██      " " ██████ " "      ██" " ██████ ") ;;
        6) local -a d=(" ██████ " "██      " " ██████ " "██    ██" " ██████ ") ;;
        7) local -a d=(" ██████ " "      ██" "    ██  " "   ██   " "   ██   ") ;;
        8) local -a d=(" ██████ " "██    ██" " ██████ " "██    ██" " ██████ ") ;;
        9) local -a d=(" ██████ " "██    ██" " ██████ " "      ██" " ██████ ") ;;
        .) local -a d=("        " "        " "        " "        " "   ██   ") ;;
        *) local -a d=("        " "        " "        " "        " "        ") ;;
    esac
    printf '%s' "${d[$line]}"
}

display_large_ip() {
    local ip="$1"
    echo ""
    echo -e "${GREEN}${BOLD}"
    local line
    for line in 0 1 2 3 4; do
        printf '    '
        local i
        for (( i=0; i<${#ip}; i++ )); do
            print_large_char "${ip:$i:1}" "$line"
            printf ' '
        done
        echo ""
    done
    echo -e "${NC}"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║     Security Toolkit — Target Bootstrap          ║${NC}"
    echo -e "${BOLD}║     One-command demo target setup                 ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    # Initialize log
    : > "$BOOTSTRAP_LOG"
    echo "# Security Toolkit Target Bootstrap Log" >> "$BOOTSTRAP_LOG"
    echo "# Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$BOOTSTRAP_LOG"
    echo "# Hostname: $(hostname)" >> "$BOOTSTRAP_LOG"
    echo "" >> "$BOOTSTRAP_LOG"

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        log_err "Must run as root. Use: wget -qO- <url> | sudo bash"
        exit 1
    fi

    # Check internet connectivity
    log "Checking internet connectivity..."
    if ! ping -c 1 -W 3 github.com > /dev/null 2>&1; then
        log_err "Cannot reach github.com — check internet connection"
        exit 1
    fi
    log_ok "Internet: OK"

    # Install git if missing (needed for clone)
    if ! command -v git &>/dev/null; then
        log "Installing git..."
        log_cmd "apt-get update -qq"
        log_cmd "apt-get install -y -qq git"
        log_ok "git installed"
    fi

    # Clone latest release
    log "Downloading latest toolkit release..."

    # Get latest release tag (wget is available on stock Ubuntu, curl may not be)
    local tag=""
    if command -v wget &>/dev/null; then
        tag=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
    elif command -v curl &>/dev/null; then
        tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
    fi

    # Fallback to main if no release found
    if [ -z "${tag:-}" ]; then
        log "No release tag found, using main branch"
        tag="main"
    fi

    log "Release: $tag"

    # Remove old install if exists
    if [ -d "$INSTALL_DIR" ]; then
        log "Removing previous installation..."
        rm -rf "$INSTALL_DIR"
    fi

    # Clone at the specific tag
    log_cmd "git clone --depth 1 --branch '$tag' 'https://github.com/$REPO.git' '$INSTALL_DIR'"
    log_ok "Downloaded toolkit ($tag) to $INSTALL_DIR"

    # Prefer JSON-driven prepare-payload.sh, fall back to prepare-demo-target.sh
    local prep_script=""
    if [ -f "$INSTALL_DIR/scripts/prepare-payload.sh" ]; then
        prep_script="$INSTALL_DIR/scripts/prepare-payload.sh"
        log "Found JSON-driven payload script"
    elif [ -f "$INSTALL_DIR/scripts/prepare-demo-target.sh" ]; then
        prep_script="$INSTALL_DIR/scripts/prepare-demo-target.sh"
        log "Using legacy preparation script"
    else
        log_err "No preparation script found in release — aborting"
        exit 1
    fi

    # Make executable
    chmod +x "$prep_script"

    # Run the preparation script
    log "Running target preparation (8 phases)..."
    echo "" >> "$BOOTSTRAP_LOG"
    echo "# === $(basename "$prep_script") output ===" >> "$BOOTSTRAP_LOG"

    # Run and tee output to both terminal and log
    "$prep_script" 2>&1 | tee -a "$BOOTSTRAP_LOG"
    local prep_exit=${PIPESTATUS[0]}

    if [ "$prep_exit" -ne 0 ]; then
        log_err "Target preparation failed (exit code: $prep_exit)"
        log_err "Check log: $BOOTSTRAP_LOG"
        exit 1
    fi

    # Get IP address
    local ip
    ip=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1 || \
         hostname -I 2>/dev/null | awk '{print $1}' || \
         echo "unknown")

    # Display IP in giant banner
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  SCAN THIS TARGET FROM KALI:${NC}"
    display_large_ip "$ip"
    echo -e "  ${BOLD}SSH:${NC}  ssh $(whoami)@${ip}"
    echo ""
    echo -e "  ${BOLD}Logs:${NC}"
    echo -e "    Bootstrap: $BOOTSTRAP_LOG"
    echo -e "    Setup:     /tmp/demo-payload-setup.log"
    echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""

    # Final log
    echo "" >> "$BOOTSTRAP_LOG"
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DONE] Bootstrap complete" >> "$BOOTSTRAP_LOG"
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DONE] Target IP: $ip" >> "$BOOTSTRAP_LOG"
}

main "$@"
