# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security verification toolkit for scanning software projects against federal security standards (NIST 800-53, NIST 800-171, FIPS 199/200). Pure Bash implementation with no build system.

## Core Values (TIA Principles)

All changes must maintain:
- **Transparency** - Document all findings, exceptions, and decisions clearly
- **Inspectability** - Output includes file:line references for verification
- **Accountability** - Allowlist entries require SHA256 integrity hash + justification
- **Traceability** - Checksums, toolkit version, and commit hashes link attestations to sources

## Commands

```bash
# Run all tests
./tests/run-all-tests.sh

# Run specific test suite
./tests/test-pii-patterns.sh
./tests/test-secrets-patterns.sh
./tests/test-mac-patterns.sh
./tests/test-audit-logging.sh

# Run all scans on a target project
./scripts/run-all-scans.sh /path/to/project

# Non-interactive mode (CI/CD)
./scripts/run-all-scans.sh -n /path/to/project

# Release workflow
./scripts/release.sh              # Test release
./scripts/release.sh 1.16.0       # Specific version
```

## Architecture

### Script Design Pattern

All scripts in `scripts/` follow this interface:
- First argument (optional): target directory (defaults to parent of script)
- Exit codes: 0 = Pass, 1 = Fail
- Output saved to `<target>/.scans/` with timestamps

### Shared Libraries (`scripts/lib/`)

| Library | Purpose |
|---------|---------|
| `audit-log.sh` | JSON Lines audit logging (NIST AU-2/AU-3) |
| `progress.sh` | Spinners, progress bars, ETA, TTY detection |
| `timestamps.sh` | ISO 8601 UTC timestamp utilities |

Source libraries with: `source "$SCRIPT_DIR/lib/audit-log.sh"`

### Output Directories

| Directory | Contents | Sensitivity |
|-----------|----------|-------------|
| `.scans/` | Raw scan results, checksums, PDFs | Shareable (references inventory checksum) |
| `.assessments/` | Analysis reports, recommendations | Private (never commit) |
| `.allowlists/` | Reviewed exceptions with SHA256 hashes | Project-specific |
| `.cache/` | Threat intelligence (KEV catalog) | Auto-managed |

### NIST Control Mapping

Each script maps to specific controls documented in headers and AGENTS.md:
- `check-pii.sh` → SI-12
- `check-secrets.sh` → SA-11
- `check-malware.sh` → SI-3
- `check-mac-addresses.sh` → SC-8
- `collect-host-inventory.sh` → CM-8
- `scan-vulnerabilities.sh` → RA-5, SI-2, SI-4, CA-2

## Adding New Scans

1. Create `scripts/check-<category>.sh` following template in AGENTS.md
2. Map to appropriate NIST 800-53 control
3. Add to `run-all-scans.sh` orchestrator
4. Create test file `tests/test-<category>-patterns.sh`
5. Update AGENTS.md and README.md

## Key Considerations

### Pattern Changes
Regex pattern modifications affect detection accuracy across all scanned projects. Test thoroughly with `./tests/run-all-tests.sh`.

### Allowlist System
Allowlist entries use SHA256 hash of `file:line:content` for integrity verification. Never modify allowlist format without updating verification logic.

### CUI Sensitivity
Host inventory contains Controlled Unclassified Information (MAC addresses, serial numbers, software versions). Never expose in logs, tests, or examples.

### Audit Logging
JSON Lines format with ISO 8601 UTC timestamps. Maintain schema compatibility for compliance tooling.

## Key Documentation

- [AGENTS.md](AGENTS.md) - Full architecture, templates, security model
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) - NIST control mapping details
- [INSTALLATION.md](INSTALLATION.md) - Platform-specific setup
- [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md) - CISA KEV integration
