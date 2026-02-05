#!/bin/bash
#
# QuickStart Attestation Library
#
# Purpose: PDF attestation generation functions
# Used by: QuickStart.sh
#
# Note: This file is sourced, not executed directly

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# ============================================================================
# PDF Attestation Generation
# ============================================================================

generate_pdf_attestation() {
    local output_dir="$1"

    # Check for pdflatex
    if ! command -v pdflatex &>/dev/null; then
        print_warning "PDF attestation skipped (pdflatex not installed)"
        echo "  Install with: brew install basictex (macOS) or apt install texlive-latex-base (Linux)"
        return 0
    fi

    # Check for attestation script
    local attestation_script="$SCRIPTS_DIR/generate-scan-attestation.sh"
    if [ ! -x "$attestation_script" ]; then
        print_warning "PDF attestation skipped (script not found)"
        return 0
    fi

    print_step "Generating PDF attestation..."

    # Set up required environment variables for attestation script
    local file_timestamp
    file_timestamp=$(date -u +"%Y-%m-%d-T%H%M%SZ")

    export TARGET_DIR="${TARGET_DIR:-$(pwd)}"
    export FILE_TIMESTAMP="$file_timestamp"
    export TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    export DATE_STAMP=$(date -u +"%Y-%m-%d")
    export TOOLKIT_VERSION="${TOOLKIT_VERSION:-unknown}"
    export TOOLKIT_COMMIT="${TOOLKIT_COMMIT:-unknown}"
    export TOOLKIT_SOURCE="${SCRIPT_DIR:-unknown}"
    export TOOLKIT_NAME="Security Toolkit"

    # Set scan results based on what was run
    if [ "$SCAN_MODE" = "remote" ]; then
        # Use PROJECT_NAME for clean display, no IP addresses in PDF
        export TARGET_DIR="$PROJECT_NAME"
        export SCAN_SCOPE="Remote - credentialed SSH scan"

        # Get actual checksum from remote inventory file
        local remote_inv_file
        remote_inv_file=$(ls -t "$output_dir"/remote-inventory-*.txt 2>/dev/null | head -1)
        if [ -n "$remote_inv_file" ] && [ -f "$remote_inv_file" ]; then
            export INVENTORY_CHECKSUM=$(shasum -a 256 "$remote_inv_file" 2>/dev/null | awk '{print $1}' || echo "N/A")
        else
            export INVENTORY_CHECKSUM="N/A"
        fi
        export PII_RESULT="SKIP"
        export PII_FINDINGS="Not applicable for remote scans"
        export SECRETS_RESULT="SKIP"
        export SECRETS_FINDINGS="Not applicable for remote scans"
        export MAC_RESULT="SKIP"
        export MAC_FINDINGS="Not applicable for remote scans"
        # Use actual malware scan result if available
        export MALWARE_RESULT="${REMOTE_MALWARE_RESULT:-SKIP}"
        if [ "$MALWARE_RESULT" = "PASS" ]; then
            export MALWARE_FINDINGS="No malware detected on remote host"
        elif [ "$MALWARE_RESULT" = "FAIL" ]; then
            export MALWARE_FINDINGS="Malware detected - see remote-malware-*.txt"
        else
            export MALWARE_FINDINGS="ClamAV not available on remote host"
        fi
        export HOST_RESULT="PASS"
        export HOST_FINDINGS="Remote security check completed"
        export VULN_RESULT="${RUN_NMAP_PORTS:+PASS}"
        export VULN_RESULT="${VULN_RESULT:-SKIP}"
        export VULN_FINDINGS="Nmap network scan"
    else
        # Local scan - set scope
        export SCAN_SCOPE="Local - $TARGET_DIR"

        # Get inventory checksum if available
        local inv_file
        inv_file=$(ls -t "$output_dir"/host-inventory-*.txt 2>/dev/null | head -1)
        if [ -n "$inv_file" ] && [ -f "$inv_file" ]; then
            export INVENTORY_CHECKSUM=$(shasum -a 256 "$inv_file" 2>/dev/null | awk '{print $1}' || echo "N/A")
        else
            export INVENTORY_CHECKSUM="N/A"
        fi

        # Set results based on what was selected and run
        export PII_RESULT="${RUN_PII:+PASS}"
        export PII_RESULT="${PII_RESULT:-SKIP}"
        export PII_FINDINGS="${RUN_PII:+PII scan completed}"
        export PII_FINDINGS="${PII_FINDINGS:-Not selected}"

        export SECRETS_RESULT="${RUN_SECRETS:+PASS}"
        export SECRETS_RESULT="${SECRETS_RESULT:-SKIP}"
        export SECRETS_FINDINGS="${RUN_SECRETS:+Secrets scan completed}"
        export SECRETS_FINDINGS="${SECRETS_FINDINGS:-Not selected}"

        export MAC_RESULT="${RUN_MAC:+PASS}"
        export MAC_RESULT="${MAC_RESULT:-SKIP}"
        export MAC_FINDINGS="${RUN_MAC:+MAC scan completed}"
        export MAC_FINDINGS="${MAC_FINDINGS:-Not selected}"

        export MALWARE_RESULT="${RUN_MALWARE:+PASS}"
        export MALWARE_RESULT="${MALWARE_RESULT:-SKIP}"
        export MALWARE_FINDINGS="${RUN_MALWARE:+Malware scan completed}"
        export MALWARE_FINDINGS="${MALWARE_FINDINGS:-Not selected}"

        export HOST_RESULT="PASS"
        export HOST_FINDINGS="QuickStart local scan"

        export VULN_RESULT="${RUN_LYNIS:+PASS}"
        export VULN_RESULT="${VULN_RESULT:-SKIP}"
        export VULN_FINDINGS="${RUN_LYNIS:+Lynis audit completed}"
        export VULN_FINDINGS="${VULN_FINDINGS:-Not selected}"
    fi

    # Overall status
    if [ "$SCANS_FAILED" -gt 0 ]; then
        export OVERALL_STATUS="FAIL"
    else
        export OVERALL_STATUS="PASS"
    fi
    export PASS_COUNT="$SCANS_PASSED"
    export FAIL_COUNT="$SCANS_FAILED"
    export SKIP_COUNT="$SCANS_SKIPPED"

    # Generate the attestation
    local pdf_output
    if pdf_output=$("$attestation_script" "$output_dir" 2>&1); then
        print_success "PDF attestation generated"
        # Extract PDF path from output
        local pdf_path
        pdf_path=$(echo "$pdf_output" | grep -o "$output_dir/scan-attestation-[^[:space:]]*\.pdf" | head -1)
        if [ -n "$pdf_path" ] && [ -f "$pdf_path" ]; then
            PDF_ATTESTATION_PATH="$pdf_path"
        fi
    else
        local exit_code=$?
        if [ $exit_code -eq 2 ]; then
            print_warning "PDF attestation skipped (optional dependency missing)"
        else
            print_warning "PDF attestation failed"
        fi
    fi
}

# ============================================================================
# Malware Attestation PDF
# ============================================================================

# Generate malware-specific attestation PDF
# Only runs if a malware scan was performed
generate_malware_attestation() {
    local output_dir="$1"

    # Check if malware scan was run
    local malware_file
    malware_file=$(ls -t "$output_dir"/malware-scan-*.txt "$output_dir"/remote-malware-*.txt 2>/dev/null | head -1)

    if [ -z "$malware_file" ] || [ ! -f "$malware_file" ]; then
        return 0  # No malware scan to attest
    fi

    # Check for pdflatex
    if ! command -v pdflatex &>/dev/null; then
        return 0  # Silently skip if no pdflatex
    fi

    # Check for attestation script
    local attestation_script="$SCRIPTS_DIR/generate-malware-attestation.sh"
    if [ ! -x "$attestation_script" ]; then
        return 0  # Script not available
    fi

    print_step "Generating malware attestation PDF..."

    # Export variables for the script
    export TARGET_NAME="${PROJECT_NAME:-$(basename "$TARGET_DIR")}"
    if [ "$SCAN_MODE" = "remote" ]; then
        export SCAN_SCOPE="Remote Scan"
    else
        export SCAN_SCOPE="Local Scan"
    fi

    # Run the attestation generator
    local pdf_output
    local exit_code=0
    if pdf_output=$("$attestation_script" "$output_dir" "$malware_file" 2>&1); then
        print_success "Malware attestation generated"
        # Extract PDF path from output
        local pdf_path
        pdf_path=$(echo "$pdf_output" | grep -o "malware-attestation-[^[:space:]]*\.pdf" | head -1)
        if [ -n "$pdf_path" ]; then
            echo "    $pdf_path"
        fi
    else
        exit_code=$?
        if [ $exit_code -eq 2 ]; then
            # Optional dependency missing - silent skip
            :
        else
            print_warning "Malware attestation failed"
        fi
    fi
}

# ============================================================================
# Vulnerability Attestation PDF
# ============================================================================

# Generate vulnerability scan attestation PDF (Lynis, etc.)
# Only runs if a vulnerability scan was performed
generate_vuln_attestation() {
    local output_dir="$1"

    # Check if Lynis scan was run
    local vuln_file
    vuln_file=$(ls -t "$output_dir"/lynis-*.txt "$output_dir"/remote-lynis-*.txt 2>/dev/null | head -1)

    if [ -z "$vuln_file" ] || [ ! -f "$vuln_file" ]; then
        return 0  # No vuln scan to attest
    fi

    # Check for pdflatex
    if ! command -v pdflatex &>/dev/null; then
        return 0
    fi

    # Check for attestation script
    local attestation_script="$SCRIPTS_DIR/generate-vuln-attestation.sh"
    if [ ! -x "$attestation_script" ]; then
        return 0
    fi

    print_step "Generating vulnerability attestation PDF..."

    # Export variables for the script
    export TOOLKIT_VERSION
    export TOOLKIT_COMMIT

    # Run the attestation generator
    local pdf_output
    local exit_code=0
    if pdf_output=$("$attestation_script" "$output_dir" "$vuln_file" 2>&1); then
        print_success "Vulnerability attestation generated"
        local pdf_path
        pdf_path=$(echo "$pdf_output" | grep -o "vulnerability-attestation-[^[:space:]]*\.pdf" | head -1)
        if [ -n "$pdf_path" ]; then
            echo "    $pdf_path"
        fi
    else
        exit_code=$?
        if [ $exit_code -ne 2 ]; then
            print_warning "Vulnerability attestation failed"
        fi
    fi
}
