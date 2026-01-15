# Security Compliance Statement Generation

This document describes how to generate security compliance statement PDFs for software projects using the Security Verification Toolkit.

## Overview

The compliance statement is a formal PDF document that:
- Certifies a project has been scanned against federal security standards
- Maps NIST SP 800-53 controls to specific verification methods
- Documents cryptographic implementation details
- Provides a timestamped attestation with toolkit version traceability

## Prerequisites

### Required
- **Bash** - Required to execute security scripts (included by default on macOS/Linux; Windows users need WSL or Git Bash)
- **pdflatex** - TeX Live or MiKTeX for PDF generation

### Optional
- **ClamAV** - For malware scanning (scan will be skipped if not installed)

### Bundled
- **LaTeX template** - Included in `templates/` directory (no external dependencies)

## Quick Start

```bash
# Generate compliance statement for a project
./scripts/generate-compliance.sh /path/to/your/project

# Specify custom output directory
./scripts/generate-compliance.sh /path/to/your/project /path/to/output
```

## Manual Workflow

If you need more control over the process:

### 1. Run Security Scans

```bash
./scripts/run-all-scans.sh /path/to/your/project
```

Review the output. All scans should pass or have documented exceptions.

### 2. Update LaTeX Template Variables

Edit `templates/security_compliance_statement.tex`:

```latex
\newcommand{\SoftwareName}{YourProject}
\newcommand{\SoftwareVersion}{1.0.0}
\newcommand{\GitHubURL}{https://github.com/org/project}
\newcommand{\ScanDate}{January 14, 2026}
\newcommand{\SecurityToolkitCommit}{abc1234}
```

### 3. Update Scan Results Table

If any scans flagged items for review, update the results table:

```latex
\begin{tabular}{@{}llll@{}}
\toprule
\textbf{Scan} & \textbf{NIST Control} & \textbf{Result} & \textbf{Findings} \\
\midrule
Malware Scan & SI-3 & PASS & No malware detected (ClamAV) \\
PII Scan & SI-12 & PASS* & Reviewed, no actual PII \\
...
\bottomrule
\end{tabular}
```

Add notes for any items requiring explanation.

### 4. Compile PDF

```bash
cd templates
pdflatex security_compliance_statement.tex
pdflatex security_compliance_statement.tex  # Second pass for references
```

### 5. Copy to Project

```bash
cp security_compliance_statement.pdf /path/to/your/project/
```

## LaTeX Template Location

The compliance statement LaTeX template is bundled in this repository:

```
templates/
├── security_compliance_statement.tex
└── logo.png
```

To use a custom template location, set the `LATEX_TEMPLATE_DIR` environment variable:

```bash
export LATEX_TEMPLATE_DIR=/custom/path/to/templates
./scripts/generate-compliance.sh /path/to/project
```

## Customizing the Template

The template uses LaTeX variables for easy customization:

| Variable | Description |
|----------|-------------|
| `\UniqueID` | Document identifier (e.g., SCS-2026-001) |
| `\DocumentDate` | Date of document generation |
| `\AuthorName` | Name of person certifying compliance |
| `\AuthorTitle` | Title of certifying person |
| `\SoftwareName` | Name of the scanned project |
| `\SoftwareVersion` | Version of the scanned project |
| `\GitHubURL` | Repository URL for the scanned project |
| `\SecurityToolkitURL` | URL of this Security toolkit |
| `\SecurityToolkitCommit` | Short commit hash of toolkit version used |
| `\SecurityToolkitCommitFull` | Full commit hash for traceability |
| `\ScanDate` | Date when scans were executed |

## NIST Control Mapping

The compliance statement maps to the following NIST SP 800-53 controls:

| Control | Family | Script | Description |
|---------|--------|--------|-------------|
| SI-3 | System Integrity | `check-malware.sh` | Malicious Code Protection |
| SI-12 | System Integrity | `check-pii.sh` | Information Management |
| SA-11 | Services Acquisition | `check-secrets.sh` | Developer Testing |
| SC-8 | Communications Protection | `check-mac-addresses.sh` | Transmission Confidentiality |
| CM-6 | Configuration Management | `check-host-security.sh` | Configuration Settings |

## Handling Scan Findings

When a scan flags potential issues:

1. **Review each finding** - Determine if it's a true positive or false positive
2. **Document exceptions** - Add notes explaining why flagged items are acceptable
3. **Update the template** - Mark items as "PASS*" with explanatory footnotes
4. **Re-scan if needed** - After fixing true positives, re-run scans

### Common False Positives

| Pattern | Cause | Resolution |
|---------|-------|------------|
| X.509 OIDs (e.g., 1.3.6.1.5.5.7.3.4) | Certificate EKU constants | Document as reviewed |
| Version strings (e.g., 6.0.0.0) | Assembly versions | Exclude build directories |
| Test data | Sample files for testing | Exclude test directories |

## Exit Codes

The `generate-compliance.sh` script returns:

| Code | Meaning |
|------|---------|
| 0 | Success - all scans passed |
| 1 | PDF generated but scans have findings requiring review |
| 2 | Fatal error - missing dependencies or template |

## Signing the Compliance Statement

For formal compliance submissions, it is recommended to digitally sign the generated PDF to ensure authenticity and non-repudiation:

```bash
# Sign the compliance statement with your signing certificate
# macOS/Linux with iText or similar
pdfsigner -input security_compliance_statement.pdf \
          -output security_compliance_statement-signed.pdf \
          -certificate /path/to/your/cert.p12

# Or using PDFSigner on Windows
PDFSigner.exe security_compliance_statement.pdf your-certificate-name
```

The signed PDF provides cryptographic proof that:
- The document has not been modified since signing
- The signatory identity is verified
- The signature includes a timestamp for non-repudiation

This is especially important for compliance documentation submitted to federal agencies or contractors.

**Recommended Tool:** [PDFSigner](https://github.com/brucedombrowski/PDFSigner) - A cross-platform utility for digitally signing PDF documents with X.509 certificates.

> **Future:** PDFSigner will be integrated as an optional component of the Security toolkit to enable one-command signing and submission workflows.


## Integration with CI/CD

```yaml
# GitHub Actions example
- name: Generate Security Compliance Statement
  run: |
    ./scripts/generate-compliance.sh ${{ github.workspace }} ./artifacts

- name: Upload Compliance PDF
  uses: actions/upload-artifact@v3
  with:
    name: security-compliance
    path: ./artifacts/security_compliance_statement.pdf
```


## U.S. Export Control (EAR 740.13(e)) Statement

The Security Verification Toolkit does not implement or distribute cryptographic functionality for data confidentiality (encryption). All cryptographic operations are limited to digital signature generation, verification, and hashing for integrity and authentication purposes only.

As such, this toolkit is **not subject to U.S. Export Administration Regulations (EAR) encryption controls** under 15 CFR 740.13(e) (encryption commodities, software, and technology). No encryption for the purpose of data confidentiality is present, and the toolkit is not classified under ECCN 5D002.

This statement is provided for compliance and export review purposes. For further details, see [15 CFR 740.13(e)](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-740/section-740.13).

## Related Documents

- [README.md](README.md) - Security toolkit overview
- [AGENTS.md](AGENTS.md) - AI agent development guide
