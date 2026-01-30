# Requirements Documentation

This directory contains machine-readable requirements documentation for the Security Verification Toolkit.

## Purpose

These JSON files enable:
- **Traceability** - Link functional requirements → NIST controls → scripts → tests
- **Verification** - Generate compliance evidence showing requirements are met
- **Automation** - Produce PDF attestations on each release
- **Project Integration** - Other projects can define their requirements and link to NIST controls

## How Requirements Linkage Works

Many compliance requirements ultimately reference NIST controls. The chain looks like:

```
Your Requirement          →  NIST Control  →  Toolkit Script  →  Evidence
─────────────────────────────────────────────────────────────────────────
"Scan for credentials"    →  SA-11         →  check-secrets.sh →  secrets-scan.txt
"Monitor vulnerabilities" →  RA-5, SI-2    →  check-nvd-cves.sh → nvd-cve-scan.txt
"Protect against malware" →  SI-3          →  check-malware.sh →  malware-scan.txt
```

This toolkit provides the **verification evidence** that your requirements are satisfied.

## For Other Projects

If you're using this toolkit to verify your project's compliance:

1. **Copy the template**: `project-requirements-template.json`
2. **Define your requirements** with their source documents
3. **Link to NIST controls** that your requirement satisfies
4. **Run the toolkit** to generate evidence
5. **Use the PDF attestation** for your compliance submittal

Example requirement from your project:

```json
{
  "REQ-001": {
    "title": "No Hardcoded Credentials",
    "source_document": "Contract DAAB07-XX-XXXX Section H.4",
    "source_reference": "DFARS 252.204-7012",
    "nist_controls": {
      "800-53": ["SA-11"],
      "800-171": ["3.5.10"]
    },
    "verification": {
      "toolkit_script": "check-secrets.sh",
      "acceptance": "Exit code 0 (PASS)"
    }
  }
}
```

The verification chain:
- **Your requirement**: "No hardcoded credentials" (from contract/policy)
- **Maps to**: NIST SA-11 (Developer Testing)
- **Verified by**: `check-secrets.sh` scan
- **Evidence**: `secrets-scan-TIMESTAMP.txt` + `scan-attestation-TIMESTAMP.pdf`

## Structure

```
requirements/
├── README.md                           # This file
├── schema.json                         # JSON Schema for validation
├── mapping.json                        # Traceability matrix
├── controls/
│   ├── nist-800-53.json               # NIST SP 800-53 Rev 5 controls
│   └── nist-800-171.json              # NIST SP 800-171 Rev 2 controls
└── functional/
    └── functional-requirements.json    # Functional requirements (FR-001, etc.)
```

## Files

### controls/nist-800-53.json

NIST SP 800-53 Rev 5 security controls implemented by this toolkit:

| Control | Title | Implementation |
|---------|-------|----------------|
| AU-2 | Event Logging | lib/audit-log.sh |
| AU-3 | Content of Audit Records | lib/audit-log.sh |
| CA-2 | Control Assessments | scan-vulnerabilities.sh |
| CM-6 | Configuration Settings | check-host-security.sh |
| CM-8 | System Component Inventory | collect-host-inventory.sh |
| MP-6 | Media Sanitization | secure-delete.sh |
| RA-5 | Vulnerability Monitoring | scan-vulnerabilities.sh, check-nvd-cves.sh |
| SA-11 | Developer Testing | check-secrets.sh |
| SC-8 | Transmission Confidentiality | check-mac-addresses.sh |
| SI-2 | Flaw Remediation | scan-vulnerabilities.sh, check-nvd-cves.sh |
| SI-3 | Malicious Code Protection | check-malware.sh |
| SI-4 | System Monitoring | scan-vulnerabilities.sh |
| SI-5 | Security Alerts | check-kev.sh |
| SI-12 | Information Management | check-pii.sh |

### controls/nist-800-171.json

NIST SP 800-171 Rev 2 controls for protecting CUI:

| Control | Title | Derived From |
|---------|-------|--------------|
| 3.4.1 | System Component Inventory | CM-8 |
| 3.4.2 | Security Configuration | CM-6 |
| 3.8.9 | Media Sanitization | MP-6 |
| 3.11.2 | Vulnerability Scanning | RA-5 |
| 3.14.1 | Flaw Remediation | SI-2 |
| 3.14.2 | Malicious Code Protection | SI-3 |
| 3.14.3 | Security Alerts | SI-5 |

### functional/functional-requirements.json

Functional requirements with acceptance criteria:

| ID | Title | Priority | NIST Controls |
|----|-------|----------|---------------|
| FR-001 | Malware Detection | HIGH | SI-3 |
| FR-002 | PII Pattern Detection | HIGH | SI-12 |
| FR-003 | Secrets Detection | CRITICAL | SA-11 |
| FR-004 | MAC Address Detection | MEDIUM | SC-8 |
| FR-005 | Host System Inventory | HIGH | CM-8 |
| FR-006 | Host Security Check | HIGH | CM-6 |
| FR-007 | Vulnerability Scanning | HIGH | RA-5, SI-2, SI-4 |
| FR-008 | NVD CVE Lookup | HIGH | RA-5, SI-2 |
| FR-009 | CISA KEV Cross-Reference | HIGH | RA-5, SI-5 |
| FR-010 | Secure File Deletion | MEDIUM | MP-6 |
| FR-011 | Git History Purging | MEDIUM | MP-6, SI-12 |
| FR-012 | Consolidated Scan Report | HIGH | - |
| FR-013 | PDF Attestation | MEDIUM | - |
| FR-014 | Audit Logging | HIGH | AU-2, AU-3 |

### mapping.json

Traceability matrix enabling navigation:
- **by_script** - Find requirements and controls for each script
- **by_nist_800_53** - Find scripts implementing each control
- **by_nist_800_171** - Find scripts implementing 800-171 controls

## Usage

### Validate JSON

```bash
# Using jq to validate against schema
jq --jsonargs -n -f schema.json < controls/nist-800-53.json

# Or simply check JSON validity
jq . requirements/functional/functional-requirements.json > /dev/null && echo "Valid"
```

### Query Requirements

```bash
# List all HIGH priority requirements
jq '.requirements | to_entries[] | select(.value.priority == "HIGH") | .key' \
    functional/functional-requirements.json

# Find scripts implementing RA-5
jq '.traceability.by_nist_800_53["RA-5"].scripts' mapping.json

# Get all NIST 800-53 controls
jq '.controls | keys' controls/nist-800-53.json
```

### Generate Reports

```bash
# Future: Generate verification PDF
./scripts/generate-verification-report.sh
```

## Adding New Requirements

1. Add functional requirement to `functional/functional-requirements.json`
2. Map to NIST controls in the requirement's `nist_800_53` field
3. Update `mapping.json` traceability entries
4. Ensure corresponding test exists

## Verification Workflow

On each release:
1. Run all tests → collect results
2. Run all scans → collect outputs
3. Match results to requirements
4. Generate PDF verification report
5. Attach to GitHub release

## References

- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-171 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
- [NIST SP 800-88 Rev 1](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
