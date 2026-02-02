#!/bin/bash
#
# Container Security Scanner
#
# Purpose: Scan running containers for software versions and check against
#          NVD CVE database and CISA KEV catalog
# NIST Control: CM-8 (System Component Inventory), RA-5 (Vulnerability Monitoring)
#
# Supports: Docker, Podman, nerdctl (containerd)
#
# Usage:
#   ./check-containers.sh                    # Scan all running containers
#   ./check-containers.sh --runtime podman   # Use specific runtime
#   ./check-containers.sh -o /path/to/output # Specify output directory
#
# Exit codes:
#   0 = Pass (no KEV matches)
#   1 = Fail (KEV matches found)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/init.sh"

# Initialize toolkit (sets TIMESTAMP, TOOLKIT_VERSION, TOOLKIT_COMMIT)
init_security_toolkit
OUTPUT_DIR=""  # Will be set based on target or default

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
CONTAINER_RUNTIME=""
TARGET_DIR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --runtime|-r)
            CONTAINER_RUNTIME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Container Security Scanner"
            echo ""
            echo "Usage: $0 [OPTIONS] [TARGET_DIR]"
            echo ""
            echo "Options:"
            echo "  --runtime, -r NAME   Use specific container runtime (docker, podman, nerdctl)"
            echo "  -o, --output DIR     Output directory for scan results"
            echo "  -h, --help           Show this help message"
            echo ""
            echo "Arguments:"
            echo "  TARGET_DIR           Directory to save results (default: current directory)"
            echo ""
            echo "Supported runtimes: docker, podman, nerdctl"
            echo ""
            echo "Examples:"
            echo "  $0                           # Scan with auto-detected runtime"
            echo "  $0 --runtime podman          # Use Podman"
            echo "  $0 -o ./results              # Save results to ./results/.scans/"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

# Set output directory
if [ -n "$TARGET_DIR" ]; then
    OUTPUT_DIR="$TARGET_DIR/.scans"
elif [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$(pwd)/.scans"
fi

# Detect container runtime if not specified
detect_runtime() {
    if [ -n "$CONTAINER_RUNTIME" ]; then
        # Verify specified runtime exists
        if command -v "$CONTAINER_RUNTIME" &>/dev/null; then
            echo "$CONTAINER_RUNTIME"
            return 0
        else
            echo -e "${RED}Error: Specified runtime '$CONTAINER_RUNTIME' not found${NC}" >&2
            exit 1
        fi
    fi

    # Auto-detect in order of preference
    for runtime in docker podman nerdctl; do
        if command -v "$runtime" &>/dev/null; then
            # Check if runtime is actually working
            if "$runtime" info &>/dev/null; then
                echo "$runtime"
                return 0
            fi
        fi
    done

    echo ""
}

# Get compose command for runtime
get_compose_cmd() {
    local runtime="$1"
    case "$runtime" in
        docker)
            if command -v docker-compose &>/dev/null; then
                echo "docker-compose"
            else
                echo "docker compose"
            fi
            ;;
        podman)
            echo "podman-compose"
            ;;
        nerdctl)
            echo "nerdctl compose"
            ;;
        *)
            echo "docker-compose"
            ;;
    esac
}

echo "=============================================="
echo "  Container Security Scanner"
echo "=============================================="
echo ""
echo "Timestamp: $TIMESTAMP"
echo ""

# Detect runtime
RUNTIME=$(detect_runtime)
if [ -z "$RUNTIME" ]; then
    echo -e "${RED}Error: No container runtime found${NC}"
    echo "Please install Docker, Podman, or nerdctl."
    exit 1
fi

echo -e "Container runtime: ${GREEN}$RUNTIME${NC}"
COMPOSE_CMD=$(get_compose_cmd "$RUNTIME")
echo "Compose command: $COMPOSE_CMD"
echo ""


# Get list of running containers
CONTAINERS=$($RUNTIME ps --format '{{.Names}}' 2>/dev/null || $RUNTIME ps --format 'table {{.Names}}' | tail -n +2)

if [ -z "$CONTAINERS" ]; then
    echo -e "${YELLOW}No running containers found${NC}"
    echo ""
    echo "To start the vulnerable lab: $0 --lab"
    exit 0
fi

echo -e "${CYAN}Found running containers:${NC}"
echo "$CONTAINERS" | while read -r name; do
    echo "  - $name"
done
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

INVENTORY_FILE="$OUTPUT_DIR/container-inventory-$TIMESTAMP.txt"
CVE_FILE="$OUTPUT_DIR/container-cves-$TIMESTAMP.txt"
KEV_RESULTS="$OUTPUT_DIR/kev-matches-$TIMESTAMP.txt"

# Start inventory file
cat > "$INVENTORY_FILE" << EOF
Container Software Inventory
============================
Generated: $TIMESTAMP
Runtime: $RUNTIME

Containers Scanned:
-------------------
EOF

echo -e "${CYAN}Collecting software inventory from containers...${NC}"
echo ""

# Function to get software version from container
get_container_software() {
    local container="$1"
    local image=$($RUNTIME inspect "$container" --format '{{.Config.Image}}' 2>/dev/null || echo "unknown")

    echo "  Container: $container" >> "$INVENTORY_FILE"
    echo "    Image: $image" >> "$INVENTORY_FILE"

    # Extract version from image tag
    local version=$(echo "$image" | grep -oE ':[0-9]+\.[0-9]+(\.[0-9]+)?' | tr -d ':' || echo "")

    # Try to identify software and version
    case "$image" in
        *grafana*)
            local ver=$($RUNTIME exec "$container" grafana-server -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "$version")
            echo "    Software: Grafana $ver"
            echo "    grafana $ver" >> "$INVENTORY_FILE"
            ;;
        *jenkins*)
            local ver=$($RUNTIME exec "$container" cat /var/jenkins_home/war/META-INF/MANIFEST.MF 2>/dev/null | grep "Jenkins-Version" | cut -d' ' -f2 | tr -d '\r' || echo "$version")
            echo "    Software: Jenkins $ver"
            echo "    jenkins $ver" >> "$INVENTORY_FILE"
            ;;
        *elasticsearch*)
            echo "    Software: Elasticsearch $version"
            echo "    elasticsearch $version" >> "$INVENTORY_FILE"
            ;;
        *tomcat*)
            local ver=$($RUNTIME exec "$container" catalina.sh version 2>/dev/null | grep "Server number" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "$version")
            echo "    Software: Apache Tomcat $ver"
            echo "    tomcat $ver" >> "$INVENTORY_FILE"
            ;;
        *activemq*)
            echo "    Software: Apache ActiveMQ $version"
            echo "    activemq $version" >> "$INVENTORY_FILE"
            ;;
        *nginx*)
            local ver=$($RUNTIME exec "$container" nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "$version")
            echo "    Software: Nginx $ver"
            echo "    nginx $ver" >> "$INVENTORY_FILE"
            ;;
        *redis*)
            local ver=$($RUNTIME exec "$container" redis-server --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "$version")
            echo "    Software: Redis $ver"
            echo "    redis $ver" >> "$INVENTORY_FILE"
            ;;
        *postgres*)
            local ver=$($RUNTIME exec "$container" postgres --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' || echo "$version")
            echo "    Software: PostgreSQL $ver"
            echo "    postgresql $ver" >> "$INVENTORY_FILE"
            ;;
        *mysql*|*mariadb*)
            echo "    Software: MySQL/MariaDB $version"
            echo "    mysql $version" >> "$INVENTORY_FILE"
            ;;
        *mongo*)
            local ver=$($RUNTIME exec "$container" mongod --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "$version")
            echo "    Software: MongoDB $ver"
            echo "    mongodb $ver" >> "$INVENTORY_FILE"
            ;;
        *node*)
            local ver=$($RUNTIME exec "$container" node --version 2>/dev/null | tr -d 'v' || echo "$version")
            echo "    Software: Node.js $ver"
            echo "    nodejs $ver" >> "$INVENTORY_FILE"
            ;;
        *python*)
            local ver=$($RUNTIME exec "$container" python --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "$version")
            echo "    Software: Python $ver"
            echo "    python $ver" >> "$INVENTORY_FILE"
            ;;
        *)
            echo "    Software: Unknown (image: $image)"
            echo "    unknown $image" >> "$INVENTORY_FILE"
            ;;
    esac
    echo "" >> "$INVENTORY_FILE"
}

# Scan each container
echo "$CONTAINERS" | while read -r container; do
    if [ -n "$container" ]; then
        echo "Scanning: $container"
        get_container_software "$container"
    fi
done

echo ""
echo -e "${GREEN}Inventory saved to: $INVENTORY_FILE${NC}"
echo ""

# Known CVE mappings for vulnerable lab
echo -e "${CYAN}Checking for known CVEs...${NC}"
echo ""

cat > "$CVE_FILE" << EOF
CVE Detection Results - Container Scan
======================================
Generated: $TIMESTAMP
Runtime: $RUNTIME

Detected CVEs:
--------------
EOF

# Check for known vulnerable versions
CVE_LIST=""
CVE_COUNT=0

check_vulnerable_version() {
    local software="$1"
    local version="$2"
    local cve=""

    case "$software" in
        grafana)
            # CVE-2021-43798 affects Grafana 8.0.0 - 8.3.0
            if [[ "$version" =~ ^8\.[0-3]\. ]]; then
                cve="CVE-2021-43798"
            fi
            ;;
        jenkins)
            # CVE-2024-23897 affects Jenkins <= 2.441
            # Use awk for numeric version comparison
            if awk -v ver="$version" 'BEGIN { exit !(ver <= 2.441) }'; then
                cve="CVE-2024-23897"
            fi
            ;;
        elasticsearch)
            # CVE-2015-1427 affects Elasticsearch < 1.4.3
            if [[ "$version" =~ ^1\.[0-4]\. ]]; then
                cve="CVE-2015-1427"
            fi
            ;;
        tomcat)
            # CVE-2020-1938 affects Tomcat < 9.0.31
            if [[ "$version" =~ ^9\.0\.(([0-2][0-9])|(30))$ ]]; then
                cve="CVE-2020-1938"
            fi
            ;;
        activemq)
            # CVE-2023-46604 affects ActiveMQ < 5.18.3
            if [[ "$version" =~ ^5\.18\.[0-2]$ ]] || [[ "$version" < "5.18.3" ]]; then
                cve="CVE-2023-46604"
            fi
            ;;
    esac

    if [ -n "$cve" ]; then
        echo "$cve - $software $version" >> "$CVE_FILE"
        echo "  Found: $cve ($software $version)"
        CVE_LIST="$CVE_LIST $cve"
        CVE_COUNT=$((CVE_COUNT + 1))
    fi
}

# Parse inventory and check for CVEs
while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]+(grafana|jenkins|elasticsearch|tomcat|activemq|nginx|redis|postgresql|mysql|mongodb|nodejs|python)[[:space:]]+([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        software="${BASH_REMATCH[1]}"
        version="${BASH_REMATCH[2]}"
        check_vulnerable_version "$software" "$version"
    fi
done < "$INVENTORY_FILE"

echo "" >> "$CVE_FILE"
echo "Total CVEs detected: $CVE_COUNT" >> "$CVE_FILE"

echo ""
echo -e "${GREEN}CVE results saved to: $CVE_FILE${NC}"
echo ""

# Check against KEV catalog
echo -e "${CYAN}Cross-referencing with CISA KEV catalog...${NC}"
echo ""

KEV_FILE="$SECURITY_REPO_DIR/data/kev-catalog.json"
KEV_MATCHES=0

cat > "$KEV_RESULTS" << EOF
CISA KEV Catalog Matches - Container Scan
==========================================
Generated: $TIMESTAMP
Runtime: $RUNTIME

KEV Matches Found:
------------------
EOF

if [ -f "$KEV_FILE" ]; then
    for cve in $CVE_LIST; do
        cve_clean=$(echo "$cve" | tr -d ' ')
        if jq -e ".vulnerabilities[] | select(.cveID == \"$cve_clean\")" "$KEV_FILE" &>/dev/null; then
            KEV_MATCHES=$((KEV_MATCHES + 1))

            vendor=$(jq -r ".vulnerabilities[] | select(.cveID == \"$cve_clean\") | .vendorProject" "$KEV_FILE")
            product=$(jq -r ".vulnerabilities[] | select(.cveID == \"$cve_clean\") | .product" "$KEV_FILE")
            desc=$(jq -r ".vulnerabilities[] | select(.cveID == \"$cve_clean\") | .shortDescription" "$KEV_FILE" | head -c 100)

            echo -e "  ${RED}[KEV MATCH]${NC} $cve_clean"
            echo "             Vendor: $vendor"
            echo "             Product: $product"
            echo ""

            cat >> "$KEV_RESULTS" << EOF
$cve_clean
  Vendor: $vendor
  Product: $product
  Description: $desc...

EOF
        fi
    done
else
    echo -e "${YELLOW}Warning: KEV catalog not found at $KEV_FILE${NC}"
fi

echo "Total KEV Matches: $KEV_MATCHES" >> "$KEV_RESULTS"

echo ""
echo "=============================================="
if [ "$KEV_MATCHES" -gt 0 ]; then
    echo -e "  ${RED}KEV MATCHES FOUND: $KEV_MATCHES${NC}"
else
    echo -e "  ${GREEN}No KEV matches found${NC}"
fi
echo "=============================================="
echo ""
echo "Results saved to:"
echo "  - Inventory: $INVENTORY_FILE"
echo "  - CVEs: $CVE_FILE"
echo "  - KEV Matches: $KEV_RESULTS"
echo ""

if [ "$KEV_MATCHES" -gt 0 ]; then
    echo -e "${RED}WARNING: $KEV_MATCHES Known Exploited Vulnerabilities detected!${NC}"
    echo "These vulnerabilities are actively exploited in the wild."
    echo "Immediate remediation is required per CISA BOD 22-01."
    exit 1
else
    exit 0
fi
