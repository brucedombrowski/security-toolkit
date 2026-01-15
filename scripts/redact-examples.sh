#!/bin/bash
#
# Redaction Script for Example Files
#
# Purpose: Strip sensitive data from scan outputs for public example distribution
# Usage: ./scripts/redact-examples.sh <source_dir> <output_dir>
#
# This script is run during release builds to generate sanitized example files
# showing the structure and format of toolkit outputs without exposing real data.

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <source_scan_dir> <output_example_dir>"
    echo ""
    echo "Example:"
    echo "  $0 /tmp/project/.scans examples/"
    exit 1
fi

SOURCE_DIR="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"

# Clean up old example files (but preserve README.md)
echo "Cleaning old example files..."
find "$OUTPUT_DIR" -name "*-EXAMPLE.txt" -type f -delete 2>/dev/null || true
find "$OUTPUT_DIR" -name "*-EXAMPLE.pdf" -type f -delete 2>/dev/null || true

# Redaction patterns - AGGRESSIVE redaction for public examples
redact_file() {
    local input="$1"
    local output="$2"

    # Redact MAC addresses (case insensitive for uppercase MAC)
    sed -E 's/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/[REDACTED]/gi' "$input" | \
    # Redact IPv6 addresses (full and compressed formats)
    sed -E 's/[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}/[REDACTED]/g' | \
    sed -E 's/[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,7}/[REDACTED]/g' | \
    # Redact IPv4 addresses (space or colon before, preserves OIDs like 1.3.6.1)
    sed -E 's/(^|[[:space:]:])([0-9]{1,3}\.){3}[0-9]{1,3}/\1[REDACTED]/g' | \
    # Redact serial numbers (common patterns)
    sed -E 's/[A-Z][0-9]{2}[A-Z0-9]{6,8}/[REDACTED]/g' | \
    # Redact hostnames in URLs
    sed -E 's|https://[a-zA-Z0-9.-]+/|https://[REDACTED]/|g' | \
    # Redact hostnames with domains
    sed -E 's/[a-zA-Z0-9_-]+\.(local|com|org|net)/[REDACTED]/g' | \
    # Redact ALL user paths completely
    sed -E 's|/Users/[^[:space:]]+|/Users/[REDACTED]|g' | \
    sed -E 's|/home/[^[:space:]]+|/home/[REDACTED]|g' | \
    # Redact ALL labeled system info fields
    sed -E 's/(Hostname):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(Serial Number):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(OS Version):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(Build):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(Kernel):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(Hardware Model):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(Architecture):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    sed -E 's/(Platform):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    # Redact timestamps (entire line after Generated:)
    sed -E 's/(Generated):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    # Redact ClamAV version strings with dates
    sed -E 's/(ClamAV):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    # Redact version strings for security software
    sed -E 's/(OpenSSL|SSH|GPG|Git|Python|Node\.js|Java|\.NET):[[:space:]]*.*$/\1: [REDACTED]/g' | \
    # Redact application version numbers
    sed -E 's/:[[:space:]]*[0-9]+\.[0-9]+(\.[0-9]+)*([._-][0-9]+)?$/: [REDACTED]/g' | \
    # Redact Git commit hashes
    sed -E 's/Commit:[^)]*\)/Commit: [REDACTED])/g' | \
    # Redact SHA256 checksums
    sed -E 's/SHA256:[[:space:]]*[a-f0-9]{64}/SHA256: [REDACTED]/g' | \
    sed -E 's/[a-f0-9]{64}/[CHECKSUM_REDACTED]/g' > "$output"

    # For host inventory files, truncate software package lists
    if echo "$output" | grep -q "host-inventory"; then
        truncate_package_lists "$output"
    fi
}

# Truncate long lists in host inventory (keep headers + 3 examples)
truncate_package_lists() {
    local file="$1"
    local temp_file="${file}.tmp"

    awk '
    BEGIN { in_list = 0; list_count = 0; printed_truncate = 0; list_indent = "    " }

    # Start of a new package/app list section (2-space indent headers)
    /^  Homebrew Packages:/ || /^  Homebrew Casks:/ || /^  Applications \(/ {
        # End previous list if needed
        if (in_list && list_count > 3 && !printed_truncate) {
            print list_indent "... (list truncated for example)"
        }
        in_list = 1
        list_count = 0
        printed_truncate = 0
        list_indent = "    "
        print
        next
    }

    # Start of network interfaces section (no indent)
    /^Network Interfaces:/ {
        if (in_list && list_count > 3 && !printed_truncate) {
            print list_indent "... (list truncated for example)"
        }
        in_list = 1
        list_count = 0
        printed_truncate = 0
        list_indent = "  "
        print
        next
    }

    # End of list (new top-level section)
    /^[A-Za-z]/ {
        if (in_list && list_count > 3 && !printed_truncate) {
            print list_indent "... (list truncated for example)"
            printed_truncate = 1
        }
        in_list = 0
        print
        next
    }

    # Network interface entry (2-space indent, interface name followed by colon)
    in_list && list_indent == "  " && /^  [a-z0-9]+:$/ {
        list_count++
        if (list_count <= 3) {
            print
        }
        next
    }

    # Network interface details (4-space indent under interface)
    in_list && list_indent == "  " && /^    / {
        if (list_count <= 3) {
            print
        }
        next
    }

    # Package entry (4 spaces indent)
    in_list && list_indent == "    " && /^    [a-zA-Z]/ {
        list_count++
        if (list_count <= 3) {
            print
        }
        next
    }

    # Everything else
    { print }

    END {
        if (in_list && list_count > 3 && !printed_truncate) {
            print list_indent "... (list truncated for example)"
        }
    }
    ' "$file" > "$temp_file"

    mv "$temp_file" "$file"
}

# Process scan files
for file in "$SOURCE_DIR"/*-scan-*.txt; do
    if [ -f "$file" ]; then
        # Strip full timestamp (e.g., 2026-01-15-T185310Z) from filename
        filename=$(basename "$file" | sed -E 's/-[0-9]{4}-[0-9]{2}-[0-9]{2}-T[0-9]{6}Z//' | sed 's/.txt/-EXAMPLE.txt/')
        redact_file "$file" "$OUTPUT_DIR/$filename"
        echo "Created: $OUTPUT_DIR/$filename"
    fi
done

# Process consolidated report
if [ -f "$SOURCE_DIR/security-scan-report-"*.txt ]; then
    redact_file "$SOURCE_DIR/security-scan-report-"*.txt "$OUTPUT_DIR/security-scan-report-EXAMPLE.txt"
    echo "Created: $OUTPUT_DIR/security-scan-report-EXAMPLE.txt"
fi

# Process host inventory if present
if [ -f "$SOURCE_DIR/host-inventory-"*.txt ]; then
    redact_file "$SOURCE_DIR/host-inventory-"*.txt "$OUTPUT_DIR/host-inventory-EXAMPLE.txt"
    echo "Created: $OUTPUT_DIR/host-inventory-EXAMPLE.txt"
fi

echo ""
echo "Redaction complete. Review files in $OUTPUT_DIR before committing."
