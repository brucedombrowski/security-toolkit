#!/bin/bash
#
# Join Live Demo — Automated Demo Launcher
#
# Purpose: Go from cold start to live demo in one shot.
#          Installs screen2cam, starts virtual camera, opens meeting,
#          and launches QuickStart with a pre-built config.
#
# Usage:
#   ./scripts/join-live-demo.sh                    # Uses demo_scanner.conf
#   ./scripts/join-live-demo.sh my-meeting.conf    # Custom config
#
# Requires: Linux with X11, internet access (for screen2cam clone)
#
# NIST Controls: N/A (demo orchestration, not a scan)
#
# Exit codes:
#   0 = Success
#   1 = Failure

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="/tmp/join-live-demo.log"

# screen2cam defaults
SCREEN2CAM_DIR="/opt/screen2cam"
SCREEN2CAM_REPO="https://github.com/brucedombrowski/screen2cam.git"
PID_FILE="/tmp/screen2cam-demo.pid"

# Colors (same pattern as prepare-demo-target.sh)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Helpers
# ============================================================================

log_step()    { echo -e "${BLUE}[*]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [STEP] $1" >> "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [OK]   $1" >> "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [WARN] $1" >> "$LOG_FILE"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; echo "[$(date -u +%H:%M:%S)] [ERR]  $1" >> "$LOG_FILE"; }

die() {
    log_error "$1"
    exit 1
}

# ============================================================================
# Cleanup (runs on EXIT / Ctrl+C)
# ============================================================================

cleanup() {
    echo ""
    log_step "Cleaning up..."

    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            log_success "Stopped screen2cam (PID $pid)"
        fi
        rm -f "$PID_FILE"
    fi

    echo ""
    echo -e "${BOLD}Demo session ended.${NC}"
    echo "  Session log: $LOG_FILE"
}

trap cleanup EXIT

# ============================================================================
# Phase 1: Pre-flight Checks
# ============================================================================

preflight() {
    echo ""
    echo -e "${BOLD}Phase 1: Pre-flight Checks${NC}"
    echo "--------------------------"

    # Must be Linux
    if [ "$(uname -s)" != "Linux" ]; then
        die "This script requires Linux (detected: $(uname -s))"
    fi
    log_success "Platform: Linux"

    # Must have X11 display
    if [ -z "${DISPLAY:-}" ]; then
        die "No X11 display detected (DISPLAY not set). Run from a graphical session."
    fi
    log_success "X11 display: $DISPLAY"

    # Check for existing screen2cam process
    if [ -f "$PID_FILE" ]; then
        local old_pid
        old_pid=$(cat "$PID_FILE")
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            log_warn "screen2cam already running (PID $old_pid)"
            echo ""
            echo -n "  Restart screen2cam? [Y/n] "
            read -r restart_answer </dev/tty || restart_answer="y"
            case "$restart_answer" in
                [nN]*)
                    log_step "Keeping existing screen2cam process"
                    SKIP_SCREEN2CAM_START=true
                    ;;
                *)
                    kill "$old_pid" 2>/dev/null || true
                    rm -f "$PID_FILE"
                    log_success "Stopped previous screen2cam (PID $old_pid)"
                    SKIP_SCREEN2CAM_START=false
                    ;;
            esac
        else
            # Stale PID file
            rm -f "$PID_FILE"
            SKIP_SCREEN2CAM_START=false
        fi
    else
        SKIP_SCREEN2CAM_START=false
    fi

    # Check git (needed for screen2cam clone)
    if ! command -v git &>/dev/null; then
        die "git is required but not installed"
    fi
    log_success "git: found"

    # Check xdg-open (for meeting URL)
    if ! command -v xdg-open &>/dev/null; then
        log_warn "xdg-open not found — meeting URL will not auto-open"
    fi
}

# ============================================================================
# Phase 2: Install/Build screen2cam
# ============================================================================

install_screen2cam() {
    echo ""
    echo -e "${BOLD}Phase 2: Install/Build screen2cam${NC}"
    echo "----------------------------------"

    # Clone or update
    if [ ! -d "$SCREEN2CAM_DIR/.git" ]; then
        log_step "Cloning screen2cam to $SCREEN2CAM_DIR..."
        sudo git clone "$SCREEN2CAM_REPO" "$SCREEN2CAM_DIR"
        sudo chown -R "$USER:$USER" "$SCREEN2CAM_DIR"
        log_success "Cloned screen2cam"
    else
        log_step "Updating existing screen2cam install..."
        git -C "$SCREEN2CAM_DIR" pull --ff-only 2>/dev/null || log_warn "Could not update (offline or dirty tree — using existing)"
        log_success "screen2cam: $SCREEN2CAM_DIR"
    fi

    # Build + load kernel module
    if [ ! -f "$SCREEN2CAM_DIR/deploy_linux.sh" ]; then
        die "deploy_linux.sh not found in $SCREEN2CAM_DIR"
    fi

    log_step "Running deploy_linux.sh --setup (deps + kernel module + build)..."
    if "$SCREEN2CAM_DIR/deploy_linux.sh" --setup; then
        log_success "screen2cam build/setup complete"
    else
        die "screen2cam setup failed — check $LOG_FILE"
    fi

    # Verify video device
    local device="${SCREEN2CAM_DEVICE:-/dev/video10}"
    if [ -e "$device" ]; then
        log_success "Virtual camera device: $device"
    else
        log_warn "$device not found — kernel module may need a moment to load"
        sleep 2
        if [ -e "$device" ]; then
            log_success "Virtual camera device: $device (appeared after delay)"
        else
            die "$device still not found. Check: sudo modprobe v4l2loopback"
        fi
    fi
}

# ============================================================================
# Phase 3: Start Virtual Camera
# ============================================================================

start_screen2cam() {
    echo ""
    echo -e "${BOLD}Phase 3: Start Virtual Camera${NC}"
    echo "------------------------------"

    if [ "$SKIP_SCREEN2CAM_START" = true ]; then
        log_step "Using existing screen2cam process"
        return
    fi

    local device="${SCREEN2CAM_DEVICE:-/dev/video10}"
    local fps="${SCREEN2CAM_FPS:-15}"

    log_step "Starting screen2cam (device=$device, fps=$fps)..."

    "$SCREEN2CAM_DIR/screen2cam" --device "$device" --fps "$fps" &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    # Give it a moment to initialize
    sleep 2

    if kill -0 "$pid" 2>/dev/null; then
        log_success "screen2cam running (PID $pid)"
    else
        rm -f "$PID_FILE"
        die "screen2cam exited immediately — check display and device"
    fi

    echo ""
    echo -e "  ${BOLD}${YELLOW}WARNING: Your entire desktop is now being streamed${NC}"
    echo -e "  ${BOLD}${YELLOW}to the virtual camera. Meeting participants will${NC}"
    echo -e "  ${BOLD}${YELLOW}see everything on your screen.${NC}"
    echo ""
    echo -e "  ${BOLD}In your video app, select 'screen2cam' as the camera.${NC}"
}

# ============================================================================
# Phase 4: Open Meeting
# ============================================================================

open_meeting() {
    echo ""
    echo -e "${BOLD}Phase 4: Open Meeting${NC}"
    echo "---------------------"

    if [ -z "${MEETING_URL:-}" ]; then
        log_step "No MEETING_URL configured — skipping"
        return
    fi

    if command -v xdg-open &>/dev/null; then
        log_step "Opening meeting in browser..."
        xdg-open "$MEETING_URL" 2>/dev/null &
    else
        log_warn "Cannot auto-open — open this URL manually:"
        echo "  $MEETING_URL"
    fi

    echo ""
    echo -n "  Press ENTER when you've joined the meeting and selected 'screen2cam' as camera..."
    read -r </dev/tty
    log_success "Presenter confirmed — ready to demo"
}

# ============================================================================
# Phase 5: Launch QuickStart
# ============================================================================

launch_quickstart() {
    echo ""
    echo -e "${BOLD}Phase 5: Launch QuickStart${NC}"
    echo "--------------------------"

    local quickstart="$TOOLKIT_DIR/QuickStart.sh"

    if [ ! -f "$quickstart" ]; then
        die "QuickStart.sh not found at $quickstart"
    fi

    log_step "Launching QuickStart scan..."
    echo ""

    # Pass the config file so QuickStart sources the same target vars
    "$quickstart" "$CONFIG_FILE"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║         Join Live Demo — Auto Launcher       ║${NC}"
    echo -e "${BOLD}║         Security Toolkit + screen2cam         ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    # Initialize log
    : > "$LOG_FILE"
    echo "# Join Live Demo Log" >> "$LOG_FILE"
    echo "# Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    # Resolve config file
    CONFIG_FILE="${1:-}"

    if [ -z "$CONFIG_FILE" ]; then
        # Default: look for demo_scanner.conf in toolkit root
        if [ -f "$TOOLKIT_DIR/demo_scanner.conf" ]; then
            CONFIG_FILE="$TOOLKIT_DIR/demo_scanner.conf"
        elif [ -f "$TOOLKIT_DIR/demo_target.conf" ]; then
            CONFIG_FILE="$TOOLKIT_DIR/demo_target.conf"
            log_warn "demo_scanner.conf not found — falling back to demo_target.conf"
        else
            die "No config file specified and no demo_scanner.conf found in $TOOLKIT_DIR"
        fi
    fi

    # Resolve relative paths
    if [ ! -f "$CONFIG_FILE" ]; then
        # Check toolkit root
        if [ -f "$TOOLKIT_DIR/$CONFIG_FILE" ]; then
            CONFIG_FILE="$TOOLKIT_DIR/$CONFIG_FILE"
        fi
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        die "Config file not found: $CONFIG_FILE"
    fi

    log_step "Loading config: $CONFIG_FILE"
    source "$CONFIG_FILE"
    log_success "Config loaded"

    # Override screen2cam defaults from config
    SCREEN2CAM_DEVICE="${SCREEN2CAM_DEVICE:-/dev/video10}"
    SCREEN2CAM_FPS="${SCREEN2CAM_FPS:-15}"

    local start_time
    start_time=$(date +%s)

    preflight
    install_screen2cam
    start_screen2cam
    open_meeting
    launch_quickstart

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))

    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Demo Complete${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Duration:${NC}    ${elapsed}s"
    echo -e "  ${BOLD}Config:${NC}      $CONFIG_FILE"
    echo -e "  ${BOLD}Session log:${NC} $LOG_FILE"
    echo ""
}

main "$@"
