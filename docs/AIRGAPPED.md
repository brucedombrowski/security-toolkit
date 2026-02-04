# Airgapped Systems Guide

This guide explains how to use the Security Toolkit on systems without network access (airgapped environments).

## Overview

Airgapped systems require special handling because they cannot download dependencies or update virus definitions over the network. The Security Toolkit provides platform-specific releases that bundle everything needed for offline operation.

## Release Types

| Release | Size | ClamAV Included | Use Case |
|---------|------|-----------------|----------|
| `security-toolkit-vX.Y.Z.tar.gz` | < 1 MB | No | Connected systems |
| `security-toolkit-vX.Y.Z-macos-arm64.tar.gz` | ~150 MB | Yes | macOS Apple Silicon (M1/M2/M3) |
| `security-toolkit-vX.Y.Z-macos-x64.tar.gz` | ~150 MB | Yes | macOS Intel |
| `security-toolkit-vX.Y.Z-linux-x64.tar.gz` | ~150 MB | Yes | Linux x64 |
| `security-toolkit-vX.Y.Z-windows-x64.zip` | ~140 MB | Yes | Windows x64 |

## Quick Start

### 1. Download the Appropriate Release

On a connected machine, download the platform-specific release for your airgapped system:

```bash
# Example for Linux x64
curl -LO https://github.com/brucedombrowski/security-toolkit/releases/latest/download/security-toolkit-vX.Y.Z-linux-x64.tar.gz
```

### 2. Transfer to Airgapped System

Copy the release archive to a USB drive or other approved transfer medium.

### 3. Install on Airgapped System

```bash
# Extract the toolkit
tar -xzf security-toolkit-vX.Y.Z-linux-x64.tar.gz
cd security-toolkit-vX.Y.Z-linux-x64

# Verify the bundled ClamAV
./clamav/clamscan --version

# Run a scan
./scripts/check-malware.sh /path/to/project
```

## Bundled Components

Each platform-specific release includes:

```
security-toolkit-vX.Y.Z-<platform>/
├── scripts/                    # All toolkit scripts
├── docs/                       # Documentation
├── data/                       # KEV catalog and other data
├── clamav/
│   ├── clamscan               # ClamAV scanner binary
│   ├── freshclam              # Database updater (for online use)
│   ├── sigtool                # Signature tool
│   ├── db/
│   │   ├── main.cvd           # Main virus database (~89 MB)
│   │   ├── daily.cvd          # Daily updates (~23 MB)
│   │   ├── bytecode.cvd       # Bytecode signatures
│   │   └── downloaded.txt     # Database timestamp
│   ├── LICENSE-CLAMAV.txt     # ClamAV license (GPLv2)
│   └── PLATFORM-INFO.txt      # Build information
└── README.md
```

## Updating Virus Definitions

Virus definitions become stale over time. For airgapped systems, use the sneakernet update process.

### Creating an Update Package (On Connected Machine)

```bash
# On a machine with internet access
./scripts/update-clamav-offline.sh --download

# Output: clamav-db-update-YYYY-MM-DD.tar.gz (~112 MB)
```

### Applying the Update (On Airgapped Machine)

```bash
# Copy the update package via USB, then:
./scripts/update-clamav-offline.sh --apply clamav-db-update-YYYY-MM-DD.tar.gz
```

### Checking Database Status

```bash
./scripts/update-clamav-offline.sh --status
```

## System Requirements

### Minimum Requirements

| Resource | Requirement |
|----------|-------------|
| Disk Space | 200 MB (toolkit + ClamAV + databases) |
| RAM | 1.6 GB minimum for scanning |
| RAM (DB update) | 3.2 GB during definition updates |

### Supported Platforms

| Platform | Architecture | Tested On |
|----------|--------------|-----------|
| macOS | ARM64 (Apple Silicon) | macOS 14 (Sonoma) |
| macOS | x86_64 (Intel) | macOS 13 (Ventura) |
| Linux | x86_64 | Ubuntu 22.04, RHEL 9 |
| Windows | x64 | Windows 10/11, Server 2022 |

## Workflow Examples

### Initial Deployment

```
Connected Machine                    Airgapped System
─────────────────                    ────────────────
1. Download platform release
2. Verify SHA256 checksum
3. Copy to USB drive
                                     4. Copy from USB
                                     5. Extract archive
                                     6. Run scans
```

### Periodic Updates

```
Connected Machine                    Airgapped System
─────────────────                    ────────────────
1. Run update-clamav-offline.sh
   --download
2. Copy .tar.gz to USB
                                     3. Copy from USB
                                     4. Run update-clamav-offline.sh
                                        --apply <file>
                                     5. Verify with --status
```

## Security Considerations

### Chain of Custody

1. **Verify downloads**: Always check SHA256 checksums before transferring to airgapped systems
2. **Dedicated transfer media**: Use dedicated USB drives for airgapped transfers
3. **Scan transfer media**: Scan USB drives for malware before connecting to airgapped systems
4. **Document transfers**: Log all data transfers to/from airgapped systems

### Database Freshness

Virus definitions are only as current as when they were downloaded. For high-security environments:

- Update definitions at least **weekly**
- Update immediately after security advisories
- Document the last update date in your security logs

### Verification

After transferring to an airgapped system, verify integrity:

```bash
# Check the toolkit version
./scripts/lib/toolkit-info.sh

# Check ClamAV version
./clamav/clamscan --version

# Check database date
cat ./clamav/db/downloaded.txt

# Run a test scan
./scripts/check-malware.sh .
```

## Troubleshooting

### ClamAV Not Found

If the bundled ClamAV isn't detected:

```bash
# Check if binaries exist
ls -la ./clamav/

# Check if executable
file ./clamav/clamscan

# On Linux, check library dependencies
ldd ./clamav/clamscan
```

### Permission Denied

```bash
# Make binaries executable
chmod +x ./clamav/clamscan ./clamav/freshclam ./clamav/sigtool
chmod +x ./scripts/*.sh
```

### Database Errors

If ClamAV reports database errors:

```bash
# Check database integrity
./clamav/sigtool --info ./clamav/db/main.cvd

# Re-apply update package if corrupted
./scripts/update-clamav-offline.sh --apply <update-file>
```

### Insufficient Memory

ClamAV requires at least 1.6 GB of RAM. If you see out-of-memory errors:

- Close other applications
- Scan smaller directories at a time
- Consider increasing system swap space

## NIST Control Mapping

| Control | Requirement | How This Addresses It |
|---------|-------------|----------------------|
| SI-3 | Malicious Code Protection | ClamAV bundled for offline scanning |
| SI-3(1) | Central Management | Update packages distributed centrally |
| SI-3(2) | Automatic Updates | Manual but documented update process |
| CM-8 | Component Inventory | `collect-host-inventory.sh` works offline |
| RA-5 | Vulnerability Scanning | All scans work with bundled data |

## See Also

- [INSTALLATION.md](../INSTALLATION.md) - Installation instructions
- [README.md](../README.md) - General usage
- [COMPLIANCE.md](COMPLIANCE.md) - NIST control mapping
- [MAINTENANCE.md](MAINTENANCE.md) - Maintenance schedules
