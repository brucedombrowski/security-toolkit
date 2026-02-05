#!/bin/bash
#
# AI Software Collector
#
# Purpose: Collect AI/ML software, frameworks, and tools for inventory
# NIST Controls: CM-8 (System Component Inventory), PM-7 (Enterprise Architecture)
#
# Functions:
#   collect_ai_software() - Collect AI frameworks, APIs, runtimes, and dev tools
#
# Dependencies: output.sh (for output function), detect.sh (for detect_tool)
#
# Data source: data/ai-software-catalog.json
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Path to AI software catalog
AI_CATALOG="${SECURITY_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}/data/ai-software-catalog.json"

# Check if a pip package is installed and get version
# Usage: detect_pip_package "package_name"
# Returns: version string or empty
detect_pip_package() {
    local package="$1"
    local version=""

    # Try pip3 first, then pip
    if command -v pip3 >/dev/null 2>&1; then
        version=$(pip3 show "$package" 2>/dev/null | grep "^Version:" | cut -d' ' -f2)
    elif command -v pip >/dev/null 2>&1; then
        version=$(pip show "$package" 2>/dev/null | grep "^Version:" | cut -d' ' -f2)
    fi

    echo "$version"
}

# Check if an npm package is globally installed
# Usage: detect_npm_package "package_name"
# Returns: version string or empty
detect_npm_package() {
    local package="$1"
    local version=""

    if command -v npm >/dev/null 2>&1; then
        version=$(npm list -g "$package" 2>/dev/null | grep "$package@" | head -1 | sed 's/.*@//')
    fi

    echo "$version"
}

# Check if environment variable is set (without revealing value)
# Usage: detect_env_var "VAR_NAME"
# Returns: "configured" or empty
detect_env_var() {
    local var_name="$1"
    if [ -n "${!var_name:-}" ]; then
        echo "configured"
    fi
}

# Check if config path exists
# Usage: detect_config_path "path"
# Returns: "found" or empty
detect_config_path() {
    local path="$1"
    # Expand tilde
    path="${path/#\~/$HOME}"
    if [ -e "$path" ]; then
        echo "found"
    fi
}

# Check if a process is running
# Usage: detect_process "process_name"
# Returns: "running" or empty
detect_process() {
    local process="$1"
    if pgrep -f "$process" >/dev/null 2>&1; then
        echo "running"
    fi
}

# Check brew package
# Usage: detect_brew_package "package"
# Returns: version or empty
detect_brew_package() {
    local package="$1"
    local version=""

    if command -v brew >/dev/null 2>&1; then
        version=$(brew list --versions "$package" 2>/dev/null | awk '{print $2}')
    fi

    echo "$version"
}

# Detect AI tool using multiple methods from catalog
# Usage: detect_ai_tool "name" "detectMethods_json"
# Outputs detection result
detect_ai_tool() {
    local name="$1"
    local methods="$2"
    local detected=""
    local version=""
    local source=""

    # Try command detection first (most reliable for version)
    local cmd
    cmd=$(echo "$methods" | jq -r '.command // empty' 2>/dev/null)
    if [ -n "$cmd" ]; then
        version=$(eval "$cmd" 2>/dev/null)
        if [ -n "$version" ]; then
            detected="yes"
            source="command"
        fi
    fi

    # Try pip package
    if [ -z "$detected" ]; then
        local pip_pkg
        pip_pkg=$(echo "$methods" | jq -r '.pip // empty' 2>/dev/null)
        if [ -n "$pip_pkg" ]; then
            version=$(detect_pip_package "$pip_pkg")
            if [ -n "$version" ]; then
                detected="yes"
                source="pip"
            fi
        fi
    fi

    # Try npm package
    if [ -z "$detected" ]; then
        local npm_pkg
        npm_pkg=$(echo "$methods" | jq -r '.npm // empty' 2>/dev/null)
        if [ -n "$npm_pkg" ]; then
            version=$(detect_npm_package "$npm_pkg")
            if [ -n "$version" ]; then
                detected="yes"
                source="npm"
            fi
        fi
    fi

    # Try brew package
    if [ -z "$detected" ]; then
        local brew_pkg
        brew_pkg=$(echo "$methods" | jq -r '.brew // empty' 2>/dev/null)
        if [ -n "$brew_pkg" ]; then
            version=$(detect_brew_package "$brew_pkg")
            if [ -n "$version" ]; then
                detected="yes"
                source="brew"
            fi
        fi
    fi

    # Try macOS app detection
    if [ -z "$detected" ]; then
        local mac_app
        mac_app=$(echo "$methods" | jq -r '.macApp // empty' 2>/dev/null)
        if [ -n "$mac_app" ] && [ -d "$mac_app" ]; then
            version=$(defaults read "$mac_app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "installed")
            detected="yes"
            source="macOS app"
        fi
    fi

    # Try config path detection
    if [ -z "$detected" ]; then
        local config_paths
        config_paths=$(echo "$methods" | jq -r '.configPaths[]? // empty' 2>/dev/null)
        if [ -n "$config_paths" ]; then
            while IFS= read -r path; do
                path="${path/#\~/$HOME}"
                if [ -e "$path" ]; then
                    detected="yes"
                    version="configured"
                    source="config"
                    break
                fi
            done <<< "$config_paths"
        fi
    fi

    # Try process detection
    if [ -z "$detected" ]; then
        local process
        process=$(echo "$methods" | jq -r '.process // empty' 2>/dev/null)
        if [ -n "$process" ]; then
            if pgrep -f "$process" >/dev/null 2>&1; then
                detected="yes"
                version="running"
                source="process"
            fi
        fi
    fi

    # Check for environment variables (API keys - don't show values)
    local env_vars
    env_vars=$(echo "$methods" | jq -r '.envVars[]? // empty' 2>/dev/null)
    local env_configured=""
    if [ -n "$env_vars" ]; then
        while IFS= read -r var; do
            if [ -n "${!var:-}" ]; then
                env_configured="yes"
                break
            fi
        done <<< "$env_vars"
    fi

    # Output result
    if [ -n "$detected" ]; then
        if [ -n "$env_configured" ]; then
            output "  $name: $version ($source) [API key configured]"
        else
            output "  $name: $version ($source)"
        fi
        return 0
    elif [ -n "$env_configured" ]; then
        output "  $name: API key configured (SDK not installed)"
        return 0
    fi

    return 1
}

# Collect AI software from a category
# Usage: collect_ai_category "category_name" "display_name"
collect_ai_category() {
    local category="$1"
    local display_name="$2"
    local found=0

    if [ ! -f "$AI_CATALOG" ]; then
        return 1
    fi

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        output "  (jq required for AI software detection)"
        return 1
    fi

    local items
    items=$(jq -r ".categories.$category[]? | @base64" "$AI_CATALOG" 2>/dev/null)

    if [ -z "$items" ]; then
        return 1
    fi

    while IFS= read -r item; do
        if [ -z "$item" ]; then
            continue
        fi

        local decoded
        decoded=$(echo "$item" | base64 -d 2>/dev/null)

        local name
        name=$(echo "$decoded" | jq -r '.name // empty')

        local methods
        methods=$(echo "$decoded" | jq -c '.detectMethods // {}')

        if [ -n "$name" ]; then
            if detect_ai_tool "$name" "$methods"; then
                found=$((found + 1))
            fi
        fi
    done <<< "$items"

    return $((found == 0))
}

# Main collection function
# Usage: collect_ai_software
collect_ai_software() {
    output "AI/ML Software:"
    output "---------------"

    # Check for jq dependency
    if ! command -v jq >/dev/null 2>&1; then
        output "  Note: Install jq for full AI software detection"
        output "  Basic detection only..."
        output ""

        # Fallback: basic detection without JSON catalog
        detect_tool "Python" "python3" "--version" "head -1"

        # Check common AI frameworks via pip
        local torch_ver
        torch_ver=$(detect_pip_package "torch")
        if [ -n "$torch_ver" ]; then
            output "  PyTorch: $torch_ver (pip)"
        fi

        local tf_ver
        tf_ver=$(detect_pip_package "tensorflow")
        if [ -n "$tf_ver" ]; then
            output "  TensorFlow: $tf_ver (pip)"
        fi

        # Check for Ollama
        if command -v ollama >/dev/null 2>&1; then
            local ollama_ver
            ollama_ver=$(ollama --version 2>/dev/null | head -1)
            output "  Ollama: $ollama_ver"
        fi

        # Check for Claude Code
        if command -v claude >/dev/null 2>&1; then
            local claude_ver
            claude_ver=$(claude --version 2>/dev/null | head -1)
            output "  Claude Code: $claude_ver"
        fi

        output ""
        return 0
    fi

    # Check catalog exists
    if [ ! -f "$AI_CATALOG" ]; then
        output "  Warning: AI software catalog not found at $AI_CATALOG"
        output ""
        return 1
    fi

    local total_found=0

    # Frameworks
    output ""
    output "  [Frameworks]"
    if collect_ai_category "frameworks" "Frameworks"; then
        total_found=$((total_found + 1))
    fi

    # API Services
    output ""
    output "  [API Services]"
    if collect_ai_category "apiServices" "API Services"; then
        total_found=$((total_found + 1))
    fi

    # Local Runtimes
    output ""
    output "  [Local Runtimes]"
    if collect_ai_category "localRuntimes" "Local Runtimes"; then
        total_found=$((total_found + 1))
    fi

    # Dev Tools
    output ""
    output "  [Dev Tools]"
    if collect_ai_category "devTools" "Dev Tools"; then
        total_found=$((total_found + 1))
    fi

    # MLOps Tools
    output ""
    output "  [MLOps Tools]"
    if collect_ai_category "mlopsTools" "MLOps Tools"; then
        total_found=$((total_found + 1))
    fi

    # Compute Libraries (GPU/accelerators)
    output ""
    output "  [Compute Libraries]"
    if collect_ai_category "computeLibraries" "Compute Libraries"; then
        total_found=$((total_found + 1))
    fi

    output ""
}
