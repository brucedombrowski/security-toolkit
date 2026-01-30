#!/bin/bash
#
# NVD Package Matcher Library
#
# Purpose: Match installed software packages to CVEs in NVD
# Maps package names to CPE (Common Platform Enumeration) format
#
# Compatible with Bash 3.2+ (macOS default)

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Get CPE vendor and product for known packages
# Returns "vendor:product" or empty if unknown
# Usage: get_cpe_mapping "openssl"
get_cpe_mapping() {
    local package="$1"
    local normalized
    normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]' | sed 's/-bin$//; s/-dev$//; s/-libs$//')

    case "$normalized" in
        # Security tools
        openssl)          echo "openssl:openssl" ;;
        openssh|ssh)      echo "openbsd:openssh" ;;
        gnupg|gpg)        echo "gnupg:gnupg" ;;
        clamav)           echo "clamav:clamav" ;;

        # Programming languages
        python|python3)   echo "python:python" ;;
        node|nodejs)      echo "nodejs:node.js" ;;
        ruby)             echo "ruby-lang:ruby" ;;
        perl)             echo "perl:perl" ;;
        php)              echo "php:php" ;;
        go|golang)        echo "golang:go" ;;
        rust|rustc)       echo "rust-lang:rust" ;;
        java|openjdk)     echo "oracle:openjdk" ;;

        # Web servers
        nginx)            echo "nginx:nginx" ;;
        apache|httpd|apache2) echo "apache:http_server" ;;
        caddy)            echo "caddyserver:caddy" ;;

        # Databases
        postgresql|postgres) echo "postgresql:postgresql" ;;
        mysql)            echo "oracle:mysql" ;;
        mariadb)          echo "mariadb:mariadb" ;;
        mongodb)          echo "mongodb:mongodb" ;;
        redis)            echo "redis:redis" ;;
        sqlite|sqlite3)   echo "sqlite:sqlite" ;;

        # Container tools
        docker)           echo "docker:docker" ;;
        podman)           echo "redhat:podman" ;;
        kubectl)          echo "kubernetes:kubectl" ;;
        helm)             echo "helm:helm" ;;

        # Package managers
        npm)              echo "npmjs:npm" ;;
        pip|pip3)         echo "pypa:pip" ;;
        gem)              echo "rubygems:rubygems" ;;
        cargo)            echo "rust-lang:cargo" ;;

        # Common utilities
        curl)             echo "curl:curl" ;;
        wget)             echo "gnu:wget" ;;
        git)              echo "git-scm:git" ;;
        vim)              echo "vim:vim" ;;
        tmux)             echo "tmux:tmux" ;;
        zsh)              echo "zsh:zsh" ;;
        bash)             echo "gnu:bash" ;;

        # Browsers
        chrome)           echo "google:chrome" ;;
        firefox)          echo "mozilla:firefox" ;;
        safari)           echo "apple:safari" ;;

        # Compression
        gzip)             echo "gnu:gzip" ;;
        bzip2)            echo "bzip:bzip2" ;;
        xz)               echo "tukaani:xz" ;;
        zstd)             echo "facebook:zstandard" ;;

        # Unknown package
        *)                echo "" ;;
    esac
}

# Convert package name and version to CPE 2.3 format
# Usage: package_to_cpe "openssl" "3.0.10"
package_to_cpe() {
    local package="$1"
    local version="$2"

    # Look up in CPE map
    local cpe_info
    cpe_info=$(get_cpe_mapping "$package")

    if [ -z "$cpe_info" ]; then
        # Unknown package - use generic format
        local normalized
        normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]' | sed 's/-bin$//; s/-dev$//; s/-libs$//')
        echo "cpe:2.3:a:*:${normalized}:${version}:*:*:*:*:*:*:*"
    else
        local vendor product
        vendor=$(echo "$cpe_info" | cut -d: -f1)
        product=$(echo "$cpe_info" | cut -d: -f2)
        echo "cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*"
    fi
}

# Parse version string to extract major.minor.patch
# Usage: parse_version "3.0.10-1ubuntu1"
parse_version() {
    local version="$1"

    # Extract version numbers (handles formats like 3.0.10, 3.0.10-1, 3.0.10_1)
    echo "$version" | grep -oE '^[0-9]+(\.[0-9]+)*' | head -1
}

# Compare versions (returns 0 if v1 >= v2, 1 otherwise)
# Usage: version_gte "3.0.10" "3.0.5"
version_gte() {
    local v1="$1"
    local v2="$2"

    # Use sort -V for version comparison
    local higher
    higher=$(printf '%s\n%s' "$v1" "$v2" | sort -V | tail -1)

    if [ "$higher" = "$v1" ]; then
        return 0
    else
        return 1
    fi
}

# Parse host inventory file and extract packages with versions
# Usage: parse_inventory_packages "/path/to/host-inventory.txt"
parse_inventory_packages() {
    local inventory_file="$1"

    if [ ! -f "$inventory_file" ]; then
        echo "Error: Inventory file not found: $inventory_file" >&2
        return 1
    fi

    # Parse Homebrew packages section
    local in_homebrew=0
    local in_applications=0
    local in_security=0
    local in_languages=0

    while IFS= read -r line; do
        # Detect section headers
        if echo "$line" | grep -q "Homebrew Packages:"; then
            in_homebrew=1
            in_applications=0
            in_security=0
            in_languages=0
            continue
        elif echo "$line" | grep -q "Applications.*:"; then
            in_homebrew=0
            in_applications=1
            in_security=0
            in_languages=0
            continue
        elif echo "$line" | grep -q "Security Tools:"; then
            in_homebrew=0
            in_applications=0
            in_security=1
            in_languages=0
            continue
        elif echo "$line" | grep -q "Programming Languages:"; then
            in_homebrew=0
            in_applications=0
            in_security=0
            in_languages=1
            continue
        elif echo "$line" | grep -qE "^[A-Z].*:$"; then
            # New section - reset all flags
            in_homebrew=0
            in_applications=0
            in_security=0
            in_languages=0
            continue
        fi

        # Parse package lines based on section
        if [ "$in_homebrew" -eq 1 ]; then
            # Format: "    package version" or "    package version1 version2"
            local pkg_line
            pkg_line=$(echo "$line" | sed 's/^[[:space:]]*//')
            if [ -n "$pkg_line" ] && [ "$pkg_line" != "..." ]; then
                local pkg_name pkg_version
                pkg_name=$(echo "$pkg_line" | awk '{print $1}')
                pkg_version=$(echo "$pkg_line" | awk '{print $2}')
                if [ -n "$pkg_name" ] && [ -n "$pkg_version" ] && [ "$pkg_version" != "not" ]; then
                    echo "${pkg_name}:${pkg_version}"
                fi
            fi
        elif [ "$in_security" -eq 1 ] || [ "$in_languages" -eq 1 ]; then
            # Format: "  Tool: version"
            if echo "$line" | grep -q ":"; then
                local tool_name tool_version
                tool_name=$(echo "$line" | sed 's/^[[:space:]]*//' | cut -d: -f1 | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
                tool_version=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//' | awk '{print $1}')
                if [ -n "$tool_name" ] && [ -n "$tool_version" ] && [ "$tool_version" != "not" ]; then
                    # Clean up version string
                    tool_version=$(parse_version "$tool_version")
                    if [ -n "$tool_version" ]; then
                        echo "${tool_name}:${tool_version}"
                    fi
                fi
            fi
        fi
    done < "$inventory_file"
}

# Get high-priority packages for CVE scanning
# Returns commonly exploited software that should be checked
get_priority_packages() {
    echo "openssl"
    echo "openssh"
    echo "curl"
    echo "git"
    echo "nginx"
    echo "apache"
    echo "postgresql"
    echo "mysql"
    echo "python"
    echo "node"
    echo "php"
    echo "ruby"
    echo "docker"
}

# Check if package is in priority list
is_priority_package() {
    local package="$1"
    local normalized
    normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]')

    get_priority_packages | grep -qx "$normalized"
}

# Filter packages to only those with known CPE mappings
filter_known_packages() {
    while IFS=: read -r package version; do
        local cpe_info
        cpe_info=$(get_cpe_mapping "$package")

        if [ -n "$cpe_info" ]; then
            echo "${package}:${version}"
        fi
    done
}

# Get CPE vendor for a package
get_cpe_vendor() {
    local package="$1"
    local cpe_info
    cpe_info=$(get_cpe_mapping "$package")

    if [ -n "$cpe_info" ]; then
        echo "$cpe_info" | cut -d: -f1
    else
        echo "*"
    fi
}

# Get CPE product for a package
get_cpe_product() {
    local package="$1"
    local cpe_info
    cpe_info=$(get_cpe_mapping "$package")

    if [ -n "$cpe_info" ]; then
        echo "$cpe_info" | cut -d: -f2
    else
        local normalized
        normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]' | sed 's/-bin$//; s/-dev$//; s/-libs$//')
        echo "$normalized"
    fi
}
