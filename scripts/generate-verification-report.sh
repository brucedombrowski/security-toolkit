#!/bin/bash
#
# Generate Verification Report Package
#
# Purpose: Create a comprehensive PDF verification package for compliance submittals
# NIST Controls: CA-2 (Control Assessments), CA-7 (Continuous Monitoring)
#
# Usage: ./scripts/generate-verification-report.sh [OPTIONS] [TARGET_DIR]
#
# Options:
#   -v, --version VERSION    Specify version (default: git describe)
#   -o, --output DIR         Output directory (default: TARGET/.verification/)
#   -r, --requirements FILE  Project requirements JSON (default: TARGET/requirements.json)
#   -t, --tests-only         Only include test results (skip scans)
#   -h, --help               Show this help
#
# Output:
#   verification-report-VERSION.pdf   - Complete verification package
#
# For Other Projects:
#   1. Create requirements.json in your project (copy from requirements/project-requirements-template.json)
#   2. Run: ~/Security/scripts/generate-verification-report.sh /path/to/your/project
#   3. PDF is generated in your project's .verification/ directory
#
# Exit codes:
#   0 = Success
#   1 = Generation failed
#   2 = Missing dependencies

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source libraries
source "$SCRIPT_DIR/lib/timestamps.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
VERSION=""
OUTPUT_DIR=""
PROJECT_REQUIREMENTS=""
TESTS_ONLY=0
TARGET_DIR="$REPO_DIR"
TIMESTAMP=$(get_iso_timestamp)

usage() {
    echo "Generate Verification Report Package"
    echo ""
    echo "Usage: $0 [OPTIONS] [TARGET_DIR]"
    echo ""
    echo "Options:"
    echo "  -v, --version VERSION    Specify version (default: git describe)"
    echo "  -o, --output DIR         Output directory"
    echo "  -t, --tests-only         Only include test results (skip scans)"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Creates a PDF verification package containing:"
    echo "  - Requirements traceability matrix"
    echo "  - Test execution results"
    echo "  - Scan results summary"
    echo "  - Compliance attestation"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -r|--requirements)
            PROJECT_REQUIREMENTS="$2"
            shift 2
            ;;
        -t|--tests-only)
            TESTS_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

# Resolve target directory to absolute path
TARGET_DIR=$(cd "$TARGET_DIR" && pwd)

# Get version if not specified
if [ -z "$VERSION" ]; then
    # Try target project first, then toolkit
    VERSION=$(git -C "$TARGET_DIR" describe --tags --always 2>/dev/null || \
              git -C "$REPO_DIR" describe --tags --always 2>/dev/null || \
              echo "$(date +%Y%m%d)")
fi

# Set output directory - use target project's .verification/ by default
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$TARGET_DIR/.verification"
fi

# Look for project requirements
if [ -z "$PROJECT_REQUIREMENTS" ]; then
    # Check target project first
    if [ -f "$TARGET_DIR/requirements.json" ]; then
        PROJECT_REQUIREMENTS="$TARGET_DIR/requirements.json"
    elif [ -f "$TARGET_DIR/requirements/requirements.json" ]; then
        PROJECT_REQUIREMENTS="$TARGET_DIR/requirements/requirements.json"
    fi
fi

# Determine if this is an external project or the toolkit itself
IS_EXTERNAL_PROJECT=0
if [ "$TARGET_DIR" != "$REPO_DIR" ]; then
    IS_EXTERNAL_PROJECT=1
fi

# Check for pdflatex
if ! command -v pdflatex &> /dev/null; then
    echo -e "${RED}Error: pdflatex not found${NC}"
    echo "Install with: brew install basictex (macOS) or apt install texlive-latex-base (Linux)"
    exit 2
fi

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Verification Report Generator${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Version:   $VERSION"
echo "Target:    $TARGET_DIR"
echo "Output:    $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
if [ "$IS_EXTERNAL_PROJECT" -eq 1 ]; then
    echo "Mode:      External Project"
fi
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Temporary directory for LaTeX build
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

#------------------------------------------------------------------------------
# Collect Requirements Data
#------------------------------------------------------------------------------
echo -e "${CYAN}Collecting requirements data...${NC}"

# Use project requirements if available, otherwise toolkit requirements
if [ -n "$PROJECT_REQUIREMENTS" ] && [ -f "$PROJECT_REQUIREMENTS" ]; then
    echo "  Using project requirements: $PROJECT_REQUIREMENTS"
    REQUIREMENTS_JSON="$PROJECT_REQUIREMENTS"
    PROJECT_NAME=$(jq -r '.project.name // "Project"' "$REQUIREMENTS_JSON" 2>/dev/null || echo "Project")
    REQ_COUNT=$(jq '.requirements | length' "$REQUIREMENTS_JSON" 2>/dev/null || echo "0")
    HIGH_PRIORITY=$(jq '[.requirements[] | select(.priority == "HIGH" or .priority == "CRITICAL")] | length' "$REQUIREMENTS_JSON" 2>/dev/null || echo "0")
    HAS_PROJECT_REQUIREMENTS=1
else
    echo "  Using toolkit requirements (no project requirements.json found)"
    REQUIREMENTS_JSON="$REPO_DIR/requirements/functional/functional-requirements.json"
    PROJECT_NAME="Security Verification Toolkit"
    HAS_PROJECT_REQUIREMENTS=0
    if [ -f "$REQUIREMENTS_JSON" ]; then
        REQ_COUNT=$(jq '.requirements | length' "$REQUIREMENTS_JSON" 2>/dev/null || echo "0")
        HIGH_PRIORITY=$(jq '[.requirements[] | select(.priority == "HIGH" or .priority == "CRITICAL")] | length' "$REQUIREMENTS_JSON" 2>/dev/null || echo "0")
    else
        REQ_COUNT=0
        HIGH_PRIORITY=0
    fi
fi

MAPPING_JSON="$REPO_DIR/requirements/mapping.json"

echo "  Project: $PROJECT_NAME"
echo "  Requirements: $REQ_COUNT total, $HIGH_PRIORITY high/critical priority"

#------------------------------------------------------------------------------
# Run Tests and Collect Results
#------------------------------------------------------------------------------
echo -e "${CYAN}Running test suite...${NC}"

TEST_OUTPUT="$BUILD_DIR/test-results.txt"
TEST_SUMMARY=""
TEST_SUITES=0
TEST_PASSED=0
TEST_FAILED=0

if "$REPO_DIR/tests/run-all-tests.sh" > "$TEST_OUTPUT" 2>&1; then
    TEST_RESULT="PASS"
else
    TEST_RESULT="FAIL"
fi

# Parse test results
if [ -f "$TEST_OUTPUT" ]; then
    TEST_SUITES=$(grep -c "Suite PASSED\|Suite FAILED" "$TEST_OUTPUT" 2>/dev/null || echo "0")
    TEST_PASSED=$(grep -c "Suite PASSED" "$TEST_OUTPUT" 2>/dev/null || echo "0")
    TEST_FAILED=$(grep -c "Suite FAILED" "$TEST_OUTPUT" 2>/dev/null || echo "0")
fi

echo "  Test Suites: $TEST_SUITES ($TEST_PASSED passed, $TEST_FAILED failed)"

#------------------------------------------------------------------------------
# Run Scans (if not tests-only)
#------------------------------------------------------------------------------
SCAN_OUTPUT="$BUILD_DIR/scan-results.txt"
SCAN_RESULT="N/A"

if [ "$TESTS_ONLY" -eq 0 ]; then
    echo -e "${CYAN}Running security scans...${NC}"

    if "$REPO_DIR/scripts/run-all-scans.sh" -n "$TARGET_DIR" > "$SCAN_OUTPUT" 2>&1; then
        SCAN_RESULT="PASS"
    else
        SCAN_RESULT="FINDINGS"
    fi

    echo "  Scan Result: $SCAN_RESULT"
else
    echo -e "${YELLOW}Skipping scans (--tests-only)${NC}"
fi

#------------------------------------------------------------------------------
# Collect NIST Control Coverage
#------------------------------------------------------------------------------
echo -e "${CYAN}Analyzing NIST control coverage...${NC}"

NIST_53_JSON="$REPO_DIR/requirements/controls/nist-800-53.json"
NIST_171_JSON="$REPO_DIR/requirements/controls/nist-800-171.json"

if [ -f "$NIST_53_JSON" ]; then
    NIST_53_COUNT=$(jq '.controls | length' "$NIST_53_JSON" 2>/dev/null || echo "0")
    NIST_53_IMPL=$(jq '[.controls[] | select(.implementation_status == "implemented")] | length' "$NIST_53_JSON" 2>/dev/null || echo "0")
else
    NIST_53_COUNT=0
    NIST_53_IMPL=0
fi

if [ -f "$NIST_171_JSON" ]; then
    NIST_171_COUNT=$(jq '.controls | length' "$NIST_171_JSON" 2>/dev/null || echo "0")
else
    NIST_171_COUNT=0
fi

echo "  NIST 800-53: $NIST_53_IMPL/$NIST_53_COUNT controls implemented"
echo "  NIST 800-171: $NIST_171_COUNT controls mapped"

#------------------------------------------------------------------------------
# Generate LaTeX Document
#------------------------------------------------------------------------------
echo -e "${CYAN}Generating PDF report...${NC}"

# Escape special LaTeX characters
escape_latex() {
    echo "$1" | sed 's/\\/\\textbackslash{}/g; s/&/\\&/g; s/%/\\%/g; s/\$/\\$/g; s/#/\\#/g; s/_/\\_/g; s/{/\\{/g; s/}/\\}/g; s/~/\\textasciitilde{}/g; s/\^/\\textasciicircum{}/g'
}

VERSION_ESCAPED=$(escape_latex "$VERSION")
TIMESTAMP_ESCAPED=$(escape_latex "$TIMESTAMP")
TARGET_ESCAPED=$(escape_latex "$TARGET_DIR")
PROJECT_NAME_ESCAPED=$(escape_latex "$PROJECT_NAME")

# Get git commit from target project or toolkit
GIT_COMMIT=$(git -C "$TARGET_DIR" rev-parse --short HEAD 2>/dev/null || \
             git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || \
             echo "unknown")
TOOLKIT_VERSION=$(git -C "$REPO_DIR" describe --tags --always 2>/dev/null || echo "unknown")

cat > "$BUILD_DIR/verification-report.tex" << LATEX
\\documentclass[11pt,letterpaper]{article}
\\usepackage[margin=1in]{geometry}
\\usepackage{longtable}
\\usepackage{booktabs}
\\usepackage{xcolor}
\\usepackage{fancyhdr}
\\usepackage{lastpage}
\\usepackage{hyperref}

\\definecolor{passgreen}{RGB}{0,128,0}
\\definecolor{failred}{RGB}{200,0,0}
\\definecolor{headerblue}{RGB}{0,51,102}

\\pagestyle{fancy}
\\fancyhf{}
\\fancyhead[L]{\\textbf{Security Verification Report}}
\\fancyhead[R]{Version: $VERSION_ESCAPED}
\\fancyfoot[C]{Page \\thepage\\ of \\pageref{LastPage}}
\\fancyfoot[R]{Generated: $TIMESTAMP_ESCAPED}

\\renewcommand{\\headrulewidth}{0.4pt}
\\renewcommand{\\footrulewidth}{0.4pt}

\\title{\\textcolor{headerblue}{Security Verification Report}\\\\[0.5em]
\\large $PROJECT_NAME_ESCAPED $VERSION_ESCAPED}
\\author{Automated Verification System}
\\date{$TIMESTAMP_ESCAPED}

\\begin{document}

\\maketitle

\\begin{center}
\\fbox{\\parbox{0.9\\textwidth}{
\\centering
\\textbf{VERIFICATION ATTESTATION}\\\\[0.5em]
This document certifies that \\textbf{$PROJECT_NAME_ESCAPED} version $VERSION_ESCAPED
has been verified through automated testing and security scanning.\\\\[0.5em]
\\textbf{Commit:} $GIT_COMMIT \\quad \\textbf{Date:} $TIMESTAMP_ESCAPED\\\\[0.3em]
\\textit{Verified with Security Verification Toolkit $TOOLKIT_VERSION}
}}
\\end{center}

\\tableofcontents
\\newpage

%------------------------------------------------------------------------------
\\section{Executive Summary}
%------------------------------------------------------------------------------

\\begin{tabular}{ll}
\\textbf{Toolkit Version:} & $VERSION_ESCAPED \\\\
\\textbf{Git Commit:} & $GIT_COMMIT \\\\
\\textbf{Verification Date:} & $TIMESTAMP_ESCAPED \\\\
\\textbf{Target Directory:} & \\texttt{$TARGET_ESCAPED} \\\\
\\end{tabular}

\\subsection{Overall Status}

\\begin{tabular}{lll}
\\toprule
\\textbf{Category} & \\textbf{Status} & \\textbf{Details} \\\\
\\midrule
Test Suites & \\textcolor{$([ "$TEST_RESULT" = "PASS" ] && echo "passgreen}{PASS" || echo "failred}{FAIL")} & $TEST_PASSED/$TEST_SUITES passed \\\\
Security Scans & \\textcolor{$([ "$SCAN_RESULT" = "PASS" ] && echo "passgreen}{PASS" || echo "failred}{$SCAN_RESULT")} & See Section 3 \\\\
Requirements & Defined & $REQ_COUNT functional requirements \\\\
NIST Controls & Mapped & $NIST_53_IMPL controls implemented \\\\
\\bottomrule
\\end{tabular}

%------------------------------------------------------------------------------
\\section{Requirements Traceability}
%------------------------------------------------------------------------------

\\subsection{Functional Requirements Summary}

\\begin{tabular}{ll}
\\textbf{Total Requirements:} & $REQ_COUNT \\\\
\\textbf{High/Critical Priority:} & $HIGH_PRIORITY \\\\
\\textbf{NIST 800-53 Controls:} & $NIST_53_COUNT mapped \\\\
\\textbf{NIST 800-171 Controls:} & $NIST_171_COUNT mapped \\\\
\\end{tabular}

\\subsection{Requirements to Controls Mapping}

The following table shows the traceability from functional requirements to NIST controls:

\\begin{longtable}{llll}
\\toprule
\\textbf{Requirement} & \\textbf{Priority} & \\textbf{NIST 800-53} & \\textbf{Script} \\\\
\\midrule
\\endhead
FR-001 & HIGH & SI-3 & check-malware.sh \\\\
FR-002 & HIGH & SI-12 & check-pii.sh \\\\
FR-003 & CRITICAL & SA-11 & check-secrets.sh \\\\
FR-004 & MEDIUM & SC-8 & check-mac-addresses.sh \\\\
FR-005 & HIGH & CM-8 & collect-host-inventory.sh \\\\
FR-006 & HIGH & CM-6 & check-host-security.sh \\\\
FR-007 & HIGH & RA-5, SI-2 & scan-vulnerabilities.sh \\\\
FR-008 & HIGH & RA-5, SI-2 & check-nvd-cves.sh \\\\
FR-009 & HIGH & RA-5, SI-5 & check-kev.sh \\\\
FR-010 & MEDIUM & MP-6 & secure-delete.sh \\\\
FR-011 & MEDIUM & MP-6, SI-12 & purge-git-history.sh \\\\
FR-012 & HIGH & - & run-all-scans.sh \\\\
FR-013 & MEDIUM & - & generate-scan-attestation.sh \\\\
FR-014 & HIGH & AU-2, AU-3 & lib/audit-log.sh \\\\
\\bottomrule
\\end{longtable}

%------------------------------------------------------------------------------
\\section{Test Verification}
%------------------------------------------------------------------------------

\\subsection{Test Execution Summary}

\\begin{tabular}{ll}
\\textbf{Test Suites Executed:} & $TEST_SUITES \\\\
\\textbf{Suites Passed:} & \\textcolor{passgreen}{$TEST_PASSED} \\\\
\\textbf{Suites Failed:} & \\textcolor{failred}{$TEST_FAILED} \\\\
\\textbf{Overall Result:} & \\textcolor{$([ "$TEST_RESULT" = "PASS" ] && echo "passgreen}{PASS" || echo "failred}{FAIL")} \\\\
\\end{tabular}

\\subsection{Test Suite Details}

The following test suites were executed:

\\begin{itemize}
\\item \\texttt{test-pii-patterns.sh} - PII detection patterns
\\item \\texttt{test-secrets-patterns.sh} - Secrets detection patterns
\\item \\texttt{test-mac-patterns.sh} - MAC address detection
\\item \\texttt{test-audit-logging.sh} - Audit log functionality
\\item \\texttt{test-kev.sh} - CISA KEV integration
\\item \\texttt{test-nvd-cves.sh} - NVD CVE lookup
\\item \\texttt{test-integration.sh} - End-to-end integration
\\item \\texttt{test-integration-advanced.sh} - Advanced integration
\\item \\texttt{test-scanner-modules.sh} - Scanner library modules
\\item \\texttt{test-inventory-modules.sh} - Inventory collection modules
\\item And additional specialized test suites
\\end{itemize}

%------------------------------------------------------------------------------
\\section{Security Scan Results}
%------------------------------------------------------------------------------

LATEX

if [ "$TESTS_ONLY" -eq 0 ]; then
    cat >> "$BUILD_DIR/verification-report.tex" << LATEX
\\subsection{Scan Execution Summary}

Security scans were executed against the target directory with the following results:

\\begin{tabular}{ll}
\\textbf{Overall Result:} & \\textcolor{$([ "$SCAN_RESULT" = "PASS" ] && echo "passgreen}{PASS" || echo "failred}{$SCAN_RESULT")} \\\\
\\textbf{Scans Executed:} & 7 (PII, Malware, Secrets, MAC, NVD, Host Security, KEV) \\\\
\\end{tabular}

\\subsection{Individual Scan Results}

Detailed scan results are available in the \\texttt{.scans/} directory of the target project.
Each scan generates timestamped output files and contributes to the consolidated security report.

LATEX
else
    cat >> "$BUILD_DIR/verification-report.tex" << LATEX
\\subsection{Scan Execution}

Security scans were not executed for this verification (--tests-only mode).

LATEX
fi

cat >> "$BUILD_DIR/verification-report.tex" << LATEX

%------------------------------------------------------------------------------
\\section{NIST Control Implementation}
%------------------------------------------------------------------------------

\\subsection{NIST SP 800-53 Rev 5 Controls}

The toolkit implements the following NIST SP 800-53 controls:

\\begin{longtable}{lll}
\\toprule
\\textbf{Control} & \\textbf{Title} & \\textbf{Implementation} \\\\
\\midrule
\\endhead
AU-2 & Event Logging & lib/audit-log.sh \\\\
AU-3 & Content of Audit Records & lib/audit-log.sh \\\\
CA-2 & Control Assessments & scan-vulnerabilities.sh \\\\
CM-6 & Configuration Settings & check-host-security.sh \\\\
CM-8 & System Component Inventory & collect-host-inventory.sh \\\\
MP-6 & Media Sanitization & secure-delete.sh \\\\
RA-5 & Vulnerability Monitoring & scan-vulnerabilities.sh, check-nvd-cves.sh \\\\
SA-11 & Developer Testing & check-secrets.sh \\\\
SC-8 & Transmission Confidentiality & check-mac-addresses.sh \\\\
SI-2 & Flaw Remediation & check-nvd-cves.sh \\\\
SI-3 & Malicious Code Protection & check-malware.sh \\\\
SI-5 & Security Alerts & check-kev.sh \\\\
SI-12 & Information Management & check-pii.sh \\\\
\\bottomrule
\\end{longtable}

%------------------------------------------------------------------------------
\\section{Attestation}
%------------------------------------------------------------------------------

\\begin{center}
\\fbox{\\parbox{0.9\\textwidth}{
\\centering
\\textbf{VERIFICATION ATTESTATION}\\\\[1em]
I hereby attest that \\textbf{$PROJECT_NAME_ESCAPED} version \\textbf{$VERSION_ESCAPED}
(commit \\texttt{$GIT_COMMIT}) has been verified through automated testing and
security scanning as documented in this report.\\\\[1em]
\\textbf{Verification Date:} $TIMESTAMP_ESCAPED\\\\[0.5em]
\\textbf{Test Result:} $([ "$TEST_RESULT" = "PASS" ] && echo "PASS" || echo "FAIL")\\\\[0.5em]
\\textbf{Scan Result:} $SCAN_RESULT\\\\[1em]
\\textit{Generated by Security Verification Toolkit $TOOLKIT_VERSION}
}}
\\end{center}

\\end{document}
LATEX

#------------------------------------------------------------------------------
# Compile LaTeX to PDF
#------------------------------------------------------------------------------
cd "$BUILD_DIR"

# Run pdflatex twice for TOC and references
pdflatex -interaction=nonstopmode verification-report.tex > /dev/null 2>&1 || true
pdflatex -interaction=nonstopmode verification-report.tex > /dev/null 2>&1 || true

if [ -f "verification-report.pdf" ]; then
    cp "verification-report.pdf" "$OUTPUT_DIR/verification-report-$VERSION.pdf"
    echo -e "${GREEN}✓ Generated: $OUTPUT_DIR/verification-report-$VERSION.pdf${NC}"
else
    echo -e "${RED}✗ PDF generation failed${NC}"
    echo "  Check LaTeX installation and try again"
    exit 1
fi

# Copy test and scan outputs if available
if [ -f "$TEST_OUTPUT" ]; then
    cp "$TEST_OUTPUT" "$OUTPUT_DIR/test-results-$VERSION.txt"
    echo -e "${GREEN}✓ Saved: test-results-$VERSION.txt${NC}"
fi

if [ -f "$SCAN_OUTPUT" ] && [ "$TESTS_ONLY" -eq 0 ]; then
    cp "$SCAN_OUTPUT" "$OUTPUT_DIR/scan-results-$VERSION.txt"
    echo -e "${GREEN}✓ Saved: scan-results-$VERSION.txt${NC}"
fi

# Generate checksums
cd "$OUTPUT_DIR"
if [[ "$(uname)" == "Darwin" ]]; then
    shasum -a 256 *.pdf *.txt 2>/dev/null > "checksums-$VERSION.sha256" || true
else
    sha256sum *.pdf *.txt 2>/dev/null > "checksums-$VERSION.sha256" || true
fi
echo -e "${GREEN}✓ Generated checksums${NC}"

cd - > /dev/null

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Verification Report Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Generated files:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "To attach to GitHub release:"
echo "  gh release upload $VERSION $OUTPUT_DIR/verification-report-$VERSION.pdf"
