#!/bin/bash
#
# NVD API Integration Library
#
# Purpose: Query National Vulnerability Database for CVE information
# API: NVD API 2.0 (https://nvd.nist.gov/developers/vulnerabilities)
#
# Rate Limits:
#   - Without API key: 5 requests per 30 seconds
#   - With API key: 50 requests per 30 seconds
#
# Environment Variables:
#   NVD_API_KEY - Optional API key for higher rate limits

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# NVD API configuration
NVD_API_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_BASE="https://services.nvd.nist.gov/rest/json/cpes/2.0"

# Cache configuration
NVD_CACHE_DIR="${NVD_CACHE_DIR:-${SECURITY_REPO_DIR:-.}/.cache/nvd}"
NVD_CACHE_MAX_AGE="${NVD_CACHE_MAX_AGE:-86400}"  # 24 hours default

# Rate limiting
NVD_RATE_LIMIT_DELAY=6  # 6 seconds between requests (5 per 30s)
NVD_LAST_REQUEST_TIME=0

# Initialize NVD cache directory
init_nvd_cache() {
    if [ ! -d "$NVD_CACHE_DIR" ]; then
        mkdir -p "$NVD_CACHE_DIR"
        chmod 700 "$NVD_CACHE_DIR"
    fi
}

# Rate limit handler - ensures we don't exceed API limits
nvd_rate_limit() {
    local current_time
    current_time=$(date +%s)
    local elapsed=$((current_time - NVD_LAST_REQUEST_TIME))

    if [ "$elapsed" -lt "$NVD_RATE_LIMIT_DELAY" ]; then
        local sleep_time=$((NVD_RATE_LIMIT_DELAY - elapsed))
        sleep "$sleep_time"
    fi

    NVD_LAST_REQUEST_TIME=$(date +%s)
}

# Build API headers (includes API key if available)
nvd_api_headers() {
    local headers=""
    if [ -n "${NVD_API_KEY:-}" ]; then
        headers="-H 'apiKey: $NVD_API_KEY'"
        NVD_RATE_LIMIT_DELAY=1  # With API key, can go faster
    fi
    echo "$headers"
}

# Query NVD for CVEs affecting a specific CPE (Common Platform Enumeration)
# Usage: query_nvd_by_cpe "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"
query_nvd_by_cpe() {
    local cpe="$1"
    local cache_file="$NVD_CACHE_DIR/cpe-$(echo "$cpe" | md5 -q 2>/dev/null || echo "$cpe" | md5sum | cut -d' ' -f1).json"

    init_nvd_cache

    # Check cache
    if [ -f "$cache_file" ]; then
        local cache_age=$(($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ "$cache_age" -lt "$NVD_CACHE_MAX_AGE" ]; then
            cat "$cache_file"
            return 0
        fi
    fi

    # Rate limit
    nvd_rate_limit

    # Query API
    local encoded_cpe
    encoded_cpe=$(printf '%s' "$cpe" | sed 's/:/%3A/g; s/\*/%2A/g')

    local response
    if [ -n "${NVD_API_KEY:-}" ]; then
        response=$(curl -s --connect-timeout 10 --max-time 30 \
            -H "apiKey: $NVD_API_KEY" \
            "${NVD_API_BASE}?cpeName=${encoded_cpe}" 2>/dev/null)
    else
        response=$(curl -s --connect-timeout 10 --max-time 30 \
            "${NVD_API_BASE}?cpeName=${encoded_cpe}" 2>/dev/null)
    fi

    # Validate and cache response
    if echo "$response" | jq -e '.vulnerabilities' >/dev/null 2>&1; then
        echo "$response" > "$cache_file"
        echo "$response"
        return 0
    else
        echo '{"vulnerabilities":[],"error":"API request failed"}'
        return 1
    fi
}

# Query NVD for a specific CVE ID
# Usage: query_nvd_by_cve "CVE-2024-1234"
query_nvd_by_cve() {
    local cve_id="$1"
    local cache_file="$NVD_CACHE_DIR/cve-${cve_id}.json"

    init_nvd_cache

    # Check cache
    if [ -f "$cache_file" ]; then
        local cache_age=$(($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ "$cache_age" -lt "$NVD_CACHE_MAX_AGE" ]; then
            cat "$cache_file"
            return 0
        fi
    fi

    # Rate limit
    nvd_rate_limit

    # Query API
    local response
    if [ -n "${NVD_API_KEY:-}" ]; then
        response=$(curl -s --connect-timeout 10 --max-time 30 \
            -H "apiKey: $NVD_API_KEY" \
            "${NVD_API_BASE}?cveId=${cve_id}" 2>/dev/null)
    else
        response=$(curl -s --connect-timeout 10 --max-time 30 \
            "${NVD_API_BASE}?cveId=${cve_id}" 2>/dev/null)
    fi

    # Validate and cache response
    if echo "$response" | jq -e '.vulnerabilities' >/dev/null 2>&1; then
        echo "$response" > "$cache_file"
        echo "$response"
        return 0
    else
        echo '{"vulnerabilities":[],"error":"API request failed"}'
        return 1
    fi
}

# Search NVD by keyword (product name)
# Usage: query_nvd_by_keyword "openssl" "3.0.0"
query_nvd_by_keyword() {
    local keyword="$1"
    local version="${2:-}"
    local cache_key="${keyword}-${version:-all}"
    local cache_file="$NVD_CACHE_DIR/keyword-$(echo "$cache_key" | md5 -q 2>/dev/null || echo "$cache_key" | md5sum | cut -d' ' -f1).json"

    init_nvd_cache

    # Check cache
    if [ -f "$cache_file" ]; then
        local cache_age=$(($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ "$cache_age" -lt "$NVD_CACHE_MAX_AGE" ]; then
            cat "$cache_file"
            return 0
        fi
    fi

    # Rate limit
    nvd_rate_limit

    # Build query
    local query="${NVD_API_BASE}?keywordSearch=${keyword}"
    if [ -n "$version" ]; then
        query="${query}%20${version}"
    fi

    # Query API
    local response
    if [ -n "${NVD_API_KEY:-}" ]; then
        response=$(curl -s --connect-timeout 10 --max-time 30 \
            -H "apiKey: $NVD_API_KEY" \
            "$query" 2>/dev/null)
    else
        response=$(curl -s --connect-timeout 10 --max-time 30 \
            "$query" 2>/dev/null)
    fi

    # Validate and cache response
    if echo "$response" | jq -e '.vulnerabilities' >/dev/null 2>&1; then
        echo "$response" > "$cache_file"
        echo "$response"
        return 0
    else
        echo '{"vulnerabilities":[],"error":"API request failed"}'
        return 1
    fi
}

# Extract CVSS score from NVD response
# Usage: extract_cvss_score "$nvd_json"
extract_cvss_score() {
    local nvd_json="$1"

    # Try CVSS 3.1 first, then 3.0, then 2.0
    local score
    score=$(echo "$nvd_json" | jq -r '
        .vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore //
        .vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseScore //
        .vulnerabilities[0].cve.metrics.cvssMetricV2[0].cvssData.baseScore //
        "N/A"
    ' 2>/dev/null)

    echo "$score"
}

# Extract severity from NVD response
# Usage: extract_severity "$nvd_json"
extract_severity() {
    local nvd_json="$1"

    local severity
    severity=$(echo "$nvd_json" | jq -r '
        .vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity //
        .vulnerabilities[0].cve.metrics.cvssMetricV30[0].cvssData.baseSeverity //
        .vulnerabilities[0].cve.metrics.cvssMetricV2[0].baseSeverity //
        "UNKNOWN"
    ' 2>/dev/null)

    echo "$severity"
}

# Extract CVE description
# Usage: extract_cve_description "$nvd_json"
extract_cve_description() {
    local nvd_json="$1"

    local desc
    desc=$(echo "$nvd_json" | jq -r '
        .vulnerabilities[0].cve.descriptions[] |
        select(.lang == "en") | .value
    ' 2>/dev/null | head -1)

    echo "$desc"
}

# Check if NVD API is accessible
check_nvd_api() {
    local response
    response=$(curl -s --connect-timeout 5 --max-time 10 \
        "${NVD_API_BASE}?resultsPerPage=1" 2>/dev/null)

    if echo "$response" | jq -e '.resultsPerPage' >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Clear NVD cache
clear_nvd_cache() {
    if [ -d "$NVD_CACHE_DIR" ]; then
        rm -rf "${NVD_CACHE_DIR:?}"/*
        echo "NVD cache cleared"
    fi
}

# Get cache statistics
nvd_cache_stats() {
    if [ ! -d "$NVD_CACHE_DIR" ]; then
        echo "Cache directory not initialized"
        return
    fi

    local file_count
    file_count=$(find "$NVD_CACHE_DIR" -type f -name "*.json" 2>/dev/null | wc -l | tr -d ' ')

    local cache_size
    cache_size=$(du -sh "$NVD_CACHE_DIR" 2>/dev/null | cut -f1)

    echo "NVD Cache Statistics:"
    echo "  Location: $NVD_CACHE_DIR"
    echo "  Files: $file_count"
    echo "  Size: $cache_size"
    echo "  Max Age: ${NVD_CACHE_MAX_AGE}s"
}
