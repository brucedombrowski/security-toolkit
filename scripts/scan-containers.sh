#!/bin/bash
#
# Vulnerable Lab Container Scanner
#
# Wrapper script that starts the vulnerable lab and runs the container scanner.
# Uses the main check-containers.sh script for actual scanning.
#
# Usage:
#   ./scan-containers.sh              # Start lab and scan
#   ./scan-containers.sh --no-start   # Scan without starting lab
#   ./scan-containers.sh --runtime podman  # Use specific runtime
#
# Exit codes:
#   0 = Pass (no KEV matches)
#   1 = Fail (KEV matches found or error)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LAB_DIR="$REPO_DIR/demo/vulnerable-lab"

# Colors
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
START_LAB=true
RUNTIME_ARGS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-start)
            START_LAB=false
            shift
            ;;
        --runtime|-r)
            RUNTIME_ARGS="--runtime $2"
            shift 2
            ;;
        -h|--help)
            echo "Vulnerable Lab Container Scanner"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-start         Don't start lab containers (scan existing)"
            echo "  --runtime NAME     Use specific container runtime"
            echo "  -h, --help         Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Detect runtime for compose
detect_runtime() {
    for runtime in docker podman nerdctl; do
        if command -v "$runtime" &>/dev/null && "$runtime" info &>/dev/null; then
            echo "$runtime"
            return 0
        fi
    done
    echo ""
}

get_compose_cmd() {
    local runtime="$1"
    case "$runtime" in
        docker)
            command -v docker-compose &>/dev/null && echo "docker-compose" || echo "docker compose"
            ;;
        podman) echo "podman-compose" ;;
        nerdctl) echo "nerdctl compose" ;;
        *) echo "docker-compose" ;;
    esac
}

# Start vulnerable lab if requested
if [ "$START_LAB" = true ]; then
    RUNTIME=$(detect_runtime)
    if [ -z "$RUNTIME" ]; then
        echo -e "${YELLOW}No container runtime found${NC}"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd "$RUNTIME")

    echo -e "${CYAN}Starting vulnerable lab containers...${NC}"
    if [ -f "$LAB_DIR/docker-compose.yml" ]; then
        $COMPOSE_CMD -f "$LAB_DIR/docker-compose.yml" up -d
        echo "Waiting for containers to initialize..."
        sleep 10
    else
        echo -e "${YELLOW}Warning: docker-compose.yml not found at $LAB_DIR${NC}"
        exit 1
    fi
    echo ""
fi

# Run the main container scanner
exec "$SCRIPT_DIR/check-containers.sh" $RUNTIME_ARGS -o "$LAB_DIR"
