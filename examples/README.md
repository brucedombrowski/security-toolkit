# Examples

This directory contains redacted example outputs from the Security Verification Toolkit. These examples show what successful scan results look like and are automatically generated during release builds.

## Contents

### Scan Output Examples

- `security-scan-report-EXAMPLE.txt` - Consolidated scan report with all checks passing
- `pii-scan-EXAMPLE.txt` - PII pattern scan results
- `malware-scan-EXAMPLE.txt` - ClamAV malware scan results
- `secrets-scan-EXAMPLE.txt` - Secrets/credentials scan results
- `mac-address-scan-EXAMPLE.txt` - MAC address scan results
- `host-security-scan-EXAMPLE.txt` - Host security posture scan results

### Compliance Documentation

- `security_compliance_statement-EXAMPLE.pdf` - Example compliance statement PDF (generated from LaTeX template)

### Redaction Guidelines

All example files are redacted according to these rules:

| Data Type | Handling |
|-----------|----------|
| MAC addresses | `[REDACTED]` |
| Serial numbers | `[REDACTED]` |
| IP addresses | `[REDACTED]` |
| Hostnames | `[REDACTED]` |
| Usernames | `[REDACTED]` |
| Timestamps (specific) | `[REDACTED]` |
| Paths with home directories | `/path/to/[REDACTED]/...` |
| Sensitive software names | `[REDACTED-APP]` |
| Security product versions | `[VERSION]` |
| Hardware model details | `[MODEL]` |

**Preserved information:**
- Scan pass/fail status
- Control mapping (NIST)
- Script names and descriptions
- Pattern categories
- General structure and format
- Toolkit version and commit hash
- Generic timestamps (dates, not specific times)

## Release Build Instructions

During release preparation:

1. Run security scans on a clean system
2. Generate compliance statements
3. Apply redaction script to all outputs:
   ```bash
   ./scripts/redact-examples.sh <scan_output_dir> examples/
   ```
4. Review redacted examples for accuracy
5. Commit examples/ directory with release tag
6. Push with `git push --tags`

## Using These Examples

To understand what the toolkit produces:

1. Review the scan report structure
2. Check the NIST control mappings
3. Review compliance statement format
4. Use as templates for your own compliance documentation

## Note on Confidentiality

Example files contain no actual sensitive data—they are purely illustrative of the toolkit's output format and capabilities.
