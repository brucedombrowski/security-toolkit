#!/bin/bash
#
# QuickStart OpenVAS/GVM Integration
#
# Purpose: Run OpenVAS vulnerability scans via CLI
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# OpenVAS Configuration
# ============================================================================

OPENVAS_COMPOSE_FILE="$HOME/greenbone-community-container/docker-compose.yml"
OPENVAS_AVAILABLE=false

# Check if OpenVAS/GVM is available
check_openvas_available() {
    # Check for Docker-based GVM
    if [ -f "$OPENVAS_COMPOSE_FILE" ]; then
        if docker compose -f "$OPENVAS_COMPOSE_FILE" ps 2>/dev/null | grep -q "gvmd.*Up"; then
            OPENVAS_AVAILABLE=true
            return 0
        fi
    fi

    # Check for native gvm-cli
    if command -v gvm-cli &>/dev/null; then
        OPENVAS_AVAILABLE=true
        return 0
    fi

    # Check Python framework path
    if [ -x "/Library/Frameworks/Python.framework/Versions/3.14/bin/gvm-cli" ]; then
        OPENVAS_AVAILABLE=true
        return 0
    fi

    return 1
}

# Run GVM command via Docker
gvm_docker_cmd() {
    local cmd="$1"
    docker compose -f "$OPENVAS_COMPOSE_FILE" exec -T gvm-tools \
        gvm-cli --gmp-username admin --gmp-password admin123 \
        socket --socketpath /run/gvmd/gvmd.sock \
        --xml "$cmd" 2>/dev/null
}

# Extract ID from XML response (macOS compatible)
# Usage: extract_id "xml_string"
extract_id() {
    echo "$1" | grep -o 'id="[^"]*"' | head -1 | sed 's/id="//;s/"//'
}

# Get or create a target for scanning
# Usage: get_or_create_target "target_ip" "target_name"
# Returns: target_id
get_or_create_target() {
    local target_ip="$1"
    local target_name="${2:-QuickStart-$target_ip}"

    # Check if target already exists
    local response
    response=$(gvm_docker_cmd "<get_targets filter=\"name=$target_name\"/>")
    local existing
    existing=$(extract_id "$response")

    if [ -n "$existing" ]; then
        echo "$existing"
        return 0
    fi

    # Create new target
    response=$(gvm_docker_cmd "<create_target><name>$target_name</name><hosts>$target_ip</hosts></create_target>")
    extract_id "$response"
}

# Get the default scanner ID (OpenVAS Default)
get_scanner_id() {
    local response
    response=$(gvm_docker_cmd "<get_scanners/>")
    # Find the scanner with "OpenVAS Default" name
    echo "$response" | grep -B1 "OpenVAS Default" | grep -o 'id="[^"]*"' | head -1 | sed 's/id="//;s/"//'
}

# Get scan config ID
# Usage: get_config_id "config_name"
# Common configs: "Full and fast", "Base", "Discovery"
get_config_id() {
    local config_name="${1:-Full and fast}"
    local response
    response=$(gvm_docker_cmd "<get_configs/>")
    echo "$response" | grep -B1 "$config_name" | grep -o 'id="[^"]*"' | head -1 | sed 's/id="//;s/"//'
}

# Create and start a scan task
# Usage: run_openvas_scan "target_ip" "output_dir" "timestamp" ["scan_type"]
# scan_type: "quick" (Discovery), "full" (Full and fast)
run_openvas_scan() {
    local target_ip="$1"
    local output_dir="$2"
    local timestamp="$3"
    local scan_type="${4:-quick}"

    local output_file="$output_dir/openvas-$timestamp.txt"
    local task_name="QuickStart-$timestamp"

    echo "Starting OpenVAS vulnerability scan..."
    echo "  Target: $target_ip"
    echo "  Type: $scan_type"
    echo ""

    # Get IDs
    echo "  Configuring scan..."
    local scanner_id
    scanner_id=$(get_scanner_id)
    if [ -z "$scanner_id" ]; then
        echo "  Error: Could not find OpenVAS scanner"
        return 1
    fi

    local config_name
    if [ "$scan_type" = "quick" ]; then
        config_name="Base"
    else
        config_name="Full and fast"
    fi

    local config_id
    config_id=$(get_config_id "$config_name")
    if [ -z "$config_id" ]; then
        echo "  Error: Could not find scan config '$config_name'"
        return 1
    fi

    local target_id
    target_id=$(get_or_create_target "$target_ip" "QuickStart-$target_ip")
    if [ -z "$target_id" ]; then
        echo "  Error: Could not create target"
        return 1
    fi

    # Create task
    echo "  Creating scan task..."
    local task_response
    task_response=$(gvm_docker_cmd "<create_task><name>$task_name</name><config id=\"$config_id\"/><target id=\"$target_id\"/><scanner id=\"$scanner_id\"/></create_task>")

    local task_id
    task_id=$(extract_id "$task_response")

    if [ -z "$task_id" ]; then
        echo "  Error: Could not create task"
        echo "$task_response" >> "$output_file"
        return 1
    fi

    # Start task
    echo "  Starting scan (this may take 5-30 minutes)..."
    gvm_docker_cmd "<start_task task_id=\"$task_id\"/>" > /dev/null

    # Write header to output file
    {
        echo "OpenVAS Vulnerability Scan"
        echo "=========================="
        echo "Target: $target_ip"
        echo "Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "Scan Type: $scan_type ($config_name)"
        echo "Task ID: $task_id"
        echo ""
    } > "$output_file"

    # Poll for completion
    local status="Running"
    local progress=0
    local last_progress=-1
    local start_time=$(date +%s)
    local timeout=1800  # 30 minute timeout

    while [ "$status" = "Running" ] || [ "$status" = "Requested" ]; do
        sleep 10

        local task_info
        task_info=$(gvm_docker_cmd "<get_tasks task_id=\"$task_id\"/>")
        status=$(echo "$task_info" | grep -o '<status>[^<]*' | head -1 | sed 's/<status>//')
        progress=$(echo "$task_info" | grep -o '<progress>[^<]*' | head -1 | sed 's/<progress>//' | cut -d'.' -f1)

        # Show progress if changed
        if [ "$progress" != "$last_progress" ] && [ -n "$progress" ]; then
            echo -ne "\r  Progress: ${progress}%   "
            last_progress="$progress"
        fi

        # Check timeout
        local elapsed=$(($(date +%s) - start_time))
        if [ $elapsed -gt $timeout ]; then
            echo ""
            echo "  Warning: Scan timeout reached (30 min)"
            break
        fi
    done

    echo ""
    echo "  Scan completed with status: $status"

    # Get report
    local report_id
    report_id=$(gvm_docker_cmd "<get_tasks task_id=\"$task_id\"/>" | grep -o '<report id="[^"]*"' | head -1 | sed 's/<report id="//;s/"//')

    if [ -n "$report_id" ]; then
        echo "  Fetching report..."

        # Get report in TXT format
        local report
        report=$(gvm_docker_cmd "<get_reports report_id=\"$report_id\" format_id=\"a994b278-1f62-11e1-96ac-406186ea4fc5\"/>")

        # Append results to output file
        {
            echo "--- Scan Results ---"
            echo ""
            # Extract and decode the report content
            echo "$report" | grep -o '<report_format[^>]*>.*</report_format>' | head -1 || echo "$report"
            echo ""
            echo "--- End of Report ---"
            echo ""
            echo "Completed: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        } >> "$output_file"

        # Parse summary
        local high_count medium_count low_count
        high_count=$(echo "$report" | grep -c "High" 2>/dev/null || echo "0")
        medium_count=$(echo "$report" | grep -c "Medium" 2>/dev/null || echo "0")
        low_count=$(echo "$report" | grep -c "Low" 2>/dev/null || echo "0")

        echo ""
        echo "  Results: High=$high_count, Medium=$medium_count, Low=$low_count"
        echo "  Report saved: $(basename "$output_file")"

        # Return success/fail based on high findings
        if [ "$high_count" -gt 0 ]; then
            return 1
        fi
    else
        echo "  Warning: Could not retrieve report"
        echo "  Check web UI at http://127.0.0.1:9392 for results"
        {
            echo "--- Report Not Available ---"
            echo "Check OpenVAS web UI for detailed results"
            echo "URL: http://127.0.0.1:9392"
            echo "Task ID: $task_id"
        } >> "$output_file"
    fi

    return 0
}

# Quick check if OpenVAS containers are running
is_openvas_running() {
    if [ -f "$OPENVAS_COMPOSE_FILE" ]; then
        docker compose -f "$OPENVAS_COMPOSE_FILE" ps 2>/dev/null | grep -q "Up"
        return $?
    fi
    return 1
}

# Start OpenVAS containers if not running
start_openvas() {
    if [ -f "$OPENVAS_COMPOSE_FILE" ]; then
        echo "Starting OpenVAS containers..."
        docker compose -f "$OPENVAS_COMPOSE_FILE" up -d
        echo "Waiting for services to initialize (30 seconds)..."
        sleep 30
    else
        echo "OpenVAS not installed. Run setup first."
        return 1
    fi
}
