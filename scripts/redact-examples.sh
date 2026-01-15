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

# Redaction patterns
redact_file() {
    local input="$1"
    local output="$2"
    
    # Redact MAC addresses
    sed -E 's/([0-9a-f]{2}:){5}[0-9a-f]{2}/[REDACTED]/g' "$input" | \
    # Redact IPv4 addresses (but preserve patterns like 1.3.6.1 used in OIDs)
    sed -E 's/\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/[REDACTED]/g' | \
    # Redact serial numbers (common patterns)
    sed -E 's/[A-Z][0-9]{2}[A-Z0-9]{6,8}/[REDACTED]/g' | \
    # Redact hostnames with domains
    sed -E 's/[a-zA-Z0-9_-]+\.(local|com|org|net)/[REDACTED]/g' | \
    # Redact specific paths (but keep structure)
    sed -E 's|/Users/[^/]+/|/Users/[REDACTED]/|g' | \
    sed -E 's|/home/[^/]+/|/home/[REDACTED]/|g' | \
    # Preserve generic structure but redact specific content in certain lines
    sed -E 's/(Hostname|Serial Number|IP Address):[^$]*/\1: [REDACTED]/g' | \
    # Redact Git commit hashes (keep toolkit version visible)
    sed -E 's/Commit:[^)]*\)/Commit: [REDACTED])/g' > "$output"
}

# Process scan files
for file in "$SOURCE_DIR"/*-scan-*.txt; do
    if [ -f "$file" ]; then
        filename=$(basename "$file" | sed 's/-[0-9]*-[0-9]*//' | sed 's/.txt/-EXAMPLE.txt/')
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
