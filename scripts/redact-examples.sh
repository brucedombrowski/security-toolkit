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

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SCRIPT_CHECKSUM=$(shasum -a 256 "$SCRIPT_PATH" 2>/dev/null | awk '{print $1}')
REDACTION_TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

mkdir -p "$OUTPUT_DIR"

# Clean up old example files (but preserve README.md)
echo "Cleaning old example files..."
find "$OUTPUT_DIR" -name "*-EXAMPLE.txt" -type f -delete 2>/dev/null || true
find "$OUTPUT_DIR" -name "*-EXAMPLE.pdf" -type f -delete 2>/dev/null || true

# Generate redaction banner with source file checksum
generate_banner() {
    local source_checksum="$1"
    cat <<EOF
################################################################################
#                                                                              #
#                         REDACTED EXAMPLE FILE                                #
#                                                                              #
#  This file has been automatically redacted for public distribution.          #
#  Sensitive data (IP addresses, MAC addresses, hostnames, versions, etc.)     #
#  has been replaced with [REDACTED] placeholders.                             #
#                                                                              #
#  Source SHA256:    ${source_checksum:0:16}...                                       #
#  Redaction Script: scripts/redact-examples.sh                                #
#  Script SHA256:    ${SCRIPT_CHECKSUM:0:16}...                                       #
#  Redacted:         $REDACTION_TIMESTAMP                                       #
#                                                                              #
################################################################################

EOF
}

# Redaction patterns - AGGRESSIVE redaction for public examples
redact_file() {
    local input="$1"
    local output="$2"

    # Calculate source file checksum before redaction
    local source_checksum
    source_checksum=$(shasum -a 256 "$input" 2>/dev/null | awk '{print $1}')

    # Create temp file for redacted content
    local temp_redacted
    temp_redacted=$(mktemp)

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
    sed -E 's/[a-f0-9]{64}/[CHECKSUM_REDACTED]/g' | \
    # Redact Homebrew package versions (format: "    package-name version")
    sed -E 's/^(    [a-zA-Z0-9_@.-]+)[[:space:]]+[0-9]+(\.[0-9]+)*([._-][a-zA-Z0-9]+)?$/\1 [REDACTED]/g' > "$temp_redacted"

    # Combine banner and redacted content
    generate_banner "$source_checksum" > "$output"
    cat "$temp_redacted" >> "$output"
    rm -f "$temp_redacted"

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

# Copy scan attestation PDF if present
# Note: PDF attestation is UNCLASSIFIED - it contains:
# - Scan results (PASS/FAIL, no sensitive data)
# - Host inventory CHECKSUM (not the actual inventory)
# - Target path (repo directory - public for this toolkit)
# - NIST control mappings and verification chain
# No CUI markings, no MAC addresses, no hostnames, no serial numbers.
for pdf in "$SOURCE_DIR"/scan-attestation-*.pdf; do
    if [ -f "$pdf" ]; then
        cp "$pdf" "$OUTPUT_DIR/scan-attestation-EXAMPLE.pdf"
        echo "Created: $OUTPUT_DIR/scan-attestation-EXAMPLE.pdf"
        break  # Only copy the first/latest one
    fi
done

# Generate README.md automatically (self-documenting)
generate_readme() {
    local readme_file="$OUTPUT_DIR/README.md"

    cat > "$readme_file" <<'README_EOF'
# Examples

This directory contains redacted example outputs from the Security Verification Toolkit.
These examples show the structure and format of toolkit outputs without exposing real data.

**This file is auto-generated by `scripts/redact-examples.sh` - do not edit manually.**

## Contents

### Scan Output Examples

README_EOF

    # List generated example files dynamically
    for f in "$OUTPUT_DIR"/*-EXAMPLE.txt; do
        if [ -f "$f" ]; then
            local basename=$(basename "$f")
            local description=""
            case "$basename" in
                security-scan-report-EXAMPLE.txt) description="Consolidated scan report" ;;
                pii-scan-EXAMPLE.txt) description="PII pattern scan results" ;;
                malware-scan-EXAMPLE.txt) description="ClamAV malware scan results" ;;
                secrets-scan-EXAMPLE.txt) description="Secrets/credentials scan results" ;;
                mac-address-scan-EXAMPLE.txt) description="MAC address scan results" ;;
                host-security-scan-EXAMPLE.txt) description="Host security posture results" ;;
                host-inventory-EXAMPLE.txt) description="System component inventory" ;;
                *) description="Scan output" ;;
            esac
            echo "- \`$basename\` - $description" >> "$readme_file"
        fi
    done

    # Add PDF attestation section if present
    if [ -f "$OUTPUT_DIR/scan-attestation-EXAMPLE.pdf" ]; then
        cat >> "$readme_file" <<'PDF_EOF'

### PDF Attestation

- `scan-attestation-EXAMPLE.pdf` - Security scan attestation document (NIST control mapping, results summary, verification chain)

PDF_EOF
    fi

    cat >> "$readme_file" <<'README_EOF'

## Redaction Rules

All example files are processed with the following redaction patterns:

| Data Type | Replacement |
|-----------|-------------|
| MAC addresses | `[REDACTED]` |
| IPv4 addresses | `[REDACTED]` |
| IPv6 addresses | `[REDACTED]` |
| Serial numbers | `[REDACTED]` |
| Hostnames/domains | `[REDACTED]` |
| User paths (`/Users/*`, `/home/*`) | `[REDACTED]` |
| System info (OS, kernel, platform, etc.) | `[REDACTED]` |
| Timestamps | `[REDACTED]` |
| Software versions | `[REDACTED]` |
| SHA256 checksums | `[CHECKSUM_REDACTED]` |
| Package versions (Homebrew, etc.) | `[REDACTED]` |

**Preserved information:**
- Scan pass/fail status
- NIST control mappings
- Script names and descriptions
- General structure and format
- Toolkit version (non-sensitive)

## Regenerating Examples

During release builds, examples are regenerated automatically:

```bash
./scripts/redact-examples.sh <scan_output_dir> examples/
```

README_EOF

    echo "Generated: $readme_file"
}

generate_readme

echo ""
echo "Redaction complete. Review files in $OUTPUT_DIR before committing."
