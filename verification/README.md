# Verification Documentation

This directory contains templates and tooling for generating verification evidence.

## Purpose

Generate PDF verification packages for compliance submittals that demonstrate:
- Requirements have been defined
- Tests validate requirements
- Scans execute successfully
- Evidence is traceable and timestamped

## Structure

```
verification/
├── README.md                    # This file
├── templates/
│   └── verification-report.tex  # LaTeX template (future)
└── releases/                    # Generated PDFs (gitignored, attached to GitHub releases)
```

## Verification Package Contents

Each release verification package includes:

1. **Requirements Traceability Matrix**
   - FR-XXX → NIST Control → Script → Test → Status

2. **Test Execution Report**
   - All test suites with pass/fail counts
   - Individual test results
   - Execution timestamps

3. **Scan Results Summary**
   - Each scan type with findings
   - NIST control mapping
   - Overall compliance status

4. **Attestation**
   - Toolkit version and commit hash
   - Timestamp
   - Checksums for reproducibility

## Workflow

```
release.sh →
  1. Run tests/run-all-tests.sh
  2. Run scripts/run-all-scans.sh
  3. Generate verification PDFs (future)
  4. Attach to GitHub release
```

## Current Status

**Implemented:**
- `scripts/generate-scan-attestation.sh` - Basic PDF attestation
- `templates/scan_attestation_template.tex` - LaTeX template

**Planned:**
- `scripts/generate-verification-report.sh` - Full verification package
- `templates/verification-report.tex` - Comprehensive template
- Requirements-to-test mapping in PDF
- Automated attachment to releases

## Future Integration

```bash
# Generate verification package
./scripts/generate-verification-report.sh --release v1.17.14

# Output:
#   verification/releases/v1.17.14/
#     ├── requirements-traceability.pdf
#     ├── test-verification.pdf
#     └── compliance-attestation.pdf
```

## Notes

- Generated PDFs are not committed to the repository (binary files)
- PDFs are attached to GitHub releases for distribution
- Templates and requirements JSON are version controlled
- Each PDF includes SHA256 checksums for verification
