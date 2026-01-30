# Verification Documentation

This directory contains templates and tooling for generating verification evidence.

## Purpose

Generate PDF verification packages for compliance submittals that demonstrate:
- Requirements have been defined
- Tests validate requirements
- Scans execute successfully
- Evidence is traceable and timestamped

## Quick Start

```bash
# Generate verification report for this toolkit
./scripts/generate-verification-report.sh

# Generate for an external project
./scripts/generate-verification-report.sh /path/to/your/project

# Tests only (skip scans for faster generation)
./scripts/generate-verification-report.sh --tests-only /path/to/project
```

## Structure

```
verification/
├── README.md                    # This file
└── templates/                   # LaTeX templates (if needed)

# Output goes to:
.verification/                   # Generated PDFs (gitignored)
├── verification-report-VERSION.pdf
├── test-results-VERSION.txt
├── scan-results-VERSION.txt
└── checksums-VERSION.sha256
```

## Verification Package Contents

Each verification report PDF includes:

1. **Executive Summary**
   - Project version and commit hash
   - Overall test/scan status
   - Requirements count

2. **Requirements Traceability Matrix**
   - FR-XXX → NIST Control → Script → Test

3. **Test Execution Report**
   - All test suites with pass/fail counts
   - Execution timestamps

4. **Scan Results Summary**
   - Each scan type with findings
   - NIST control mapping

5. **NIST Control Implementation**
   - 800-53 controls mapped to scripts
   - Implementation status

6. **Attestation**
   - Formal verification statement
   - Checksums for reproducibility

## For External Projects

If your project needs verification reports:

1. **Create requirements.json** in your project root:
   ```bash
   cp ~/Security/requirements/project-requirements-template.json \
      /path/to/your/project/requirements.json
   ```

2. **Edit requirements.json** with your project's requirements

3. **Generate verification report**:
   ```bash
   ~/Security/scripts/generate-verification-report.sh /path/to/your/project
   ```

4. **Find output** in your project's `.verification/` directory

Your requirements will be linked to NIST controls and verified by toolkit scans.

## Usage Options

```bash
# Basic usage (runs tests + scans)
./scripts/generate-verification-report.sh [TARGET_DIR]

# Specify version
./scripts/generate-verification-report.sh -v 1.0.0 /path/to/project

# Custom output directory
./scripts/generate-verification-report.sh -o /path/to/output /path/to/project

# Use specific requirements file
./scripts/generate-verification-report.sh -r /path/to/reqs.json /path/to/project

# Tests only (faster, no scans)
./scripts/generate-verification-report.sh --tests-only /path/to/project
```

## Workflow Integration

### With release.sh

```bash
# Verification reports are generated during release
./scripts/release.sh 1.18.0

# Or generate separately
./scripts/generate-verification-report.sh -v 1.18.0
```

### Attach to GitHub Release

```bash
VERSION="v1.18.0"
gh release upload $VERSION .verification/verification-report-$VERSION.pdf
```

## Requirements

- **pdflatex** - For PDF generation (TeX Live or MiKTeX)
- **jq** - For JSON parsing

Install on macOS:
```bash
brew install basictex jq
```

Install on Linux:
```bash
apt install texlive-latex-base jq
```

## Notes

- Generated PDFs are not committed (add `.verification/` to `.gitignore`)
- PDFs are attached to GitHub releases for distribution
- Templates and requirements JSON are version controlled
- Each PDF includes SHA256 checksums for verification
- Toolkit version is included for traceability
