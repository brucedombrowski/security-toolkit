# Demo Cheat Sheet: Remote SSH Scan

Quick reference for demonstrating the Security Verification Toolkit scanning a live Ubuntu target from a Kali Linux machine over SSH.

## Topology

```
┌──────────────────────┐         SSH          ┌──────────────────────┐
│    Kali (Scanner)     │ ──────────────────►  │   Ubuntu (Target)    │
│                       │                      │                      │
│  ~/Security/          │                      │  Live boot           │
│  QuickStart.sh        │                      │  Internet access     │
│  .scans/ (output)     │                      │  Fresh install       │
└──────────────────────┘                       └──────────────────────┘
```

## Prerequisites

| Item | Requirement |
|------|-------------|
| Kali | Toolkit cloned to `~/Security` |
| Kali | `nmap` installed (standard on Kali) |
| Kali | `pdflatex` installed (for attestation PDF) |
| Ubuntu | SSH server running (`sudo apt install openssh-server`) |
| Ubuntu | User account with sudo access |
| Network | Kali can reach Ubuntu over SSH (port 22) |

## Pre-Demo Checklist

```bash
# On Kali — verify toolkit
cd ~/Security
git status                    # Clean working tree
./scripts/lib/toolkit-info.sh # Confirm version

# On Kali — verify connectivity
ssh user@<ubuntu-ip> "hostname && uname -a"

# On Kali — verify nmap
nmap --version
```

## Demo Flow

### Step 1: Launch QuickStart

```bash
cd ~/Security
./QuickStart.sh
```

### Step 2: Select Remote Scan

```
Main Menu → Remote Scan → Credentialed (SSH)
```

Enter when prompted:
- **Target IP/hostname**: `<ubuntu-ip>`
- **SSH username**: `<user>`
- **SSH password or key**: (authenticate)

### Step 3: Select Scan Types

Select all of the following:
- Host Inventory (CM-8)
- Host Security Check (CM-6)
- Malware Scan (SI-3)
- Lynis Quick Audit (CA-2)
- Port Scan (RA-5)

### Step 4: Install Dependencies on Target

The toolkit will detect that the fresh Ubuntu target is missing ClamAV and Lynis:

```
ClamAV not found on target. Install? [y/N]  → y
Lynis not found on target. Install? [y/N]   → y
```

**Demo talking point:** The toolkit handles dependency installation on remote targets over SSH, including preserving the sudo password prompt while filtering apt output.

### Step 5: Scans Execute

The following scans run in sequence:

| Scan | What Happens | Duration |
|------|-------------|----------|
| Host Inventory | Collects OS, packages, network info from Ubuntu | ~10s |
| Host Security | Checks SSH config, firewall, permissions | ~15s |
| Malware Scan | ClamAV scans the target filesystem | 1-5 min |
| Lynis Audit | Security hardening audit on Ubuntu | 2-5 min |
| Nmap Port Scan | Network scan from Kali → Ubuntu | 1-3 min |

### Step 6: Review Output

```bash
ls -la .scans/
```

Output includes:
- `host-inventory-<timestamp>.txt` — System inventory (CUI)
- `host-security-<timestamp>.txt` — Security posture findings
- `malware-scan-<timestamp>.txt` — ClamAV results
- `lynis-audit-<timestamp>.txt` — Hardening score and findings
- `nmap-<timestamp>.txt` — Open ports and services
- `audit-log-<timestamp>.jsonl` — Machine-readable audit trail

### Step 7: Generate Attestation PDF

```
Generate attestation? [Y/n] → y
```

**Demo talking point:** The PDF includes SHA256 checksums, toolkit version, scan timestamps, and NIST control mappings — everything needed for an audit package.

### Step 8: Cleanup Prompt

```
Remove packages installed during scan (ClamAV, Lynis)? [y/N] → y
```

**Demo talking point:** "Leave no trace" — the toolkit offers to uninstall any packages it installed on the target, returning the system to its pre-scan state. This is critical for production systems where you don't want scanner artifacts left behind.

## Key Demo Talking Points

| Moment | Point |
|--------|-------|
| Dependency install prompt | Toolkit handles remote dependency management |
| Scan execution | One command, multiple NIST controls assessed |
| Attestation PDF | Audit-ready output, checksummed and traceable |
| Cleanup prompt | Leave no trace on production targets |
| Audit log | Machine-readable JSON Lines for SIEM integration |
| CUI handling | Host inventory marked CUI with mode 600 permissions |

## Troubleshooting During Demo

| Problem | Quick Fix |
|---------|-----------|
| SSH connection refused | `sudo systemctl start ssh` on Ubuntu |
| Permission denied | Verify username/password, check `sudo` access |
| Nmap scan slow | Use quick mode if time-constrained |
| ClamAV database missing | `sudo freshclam` on target (requires internet) |
| pdflatex not found | `sudo apt install texlive-latex-base` on Kali |
| Script hangs on input | Ensure `/dev/tty` fixes are applied (#134) |

## Cleanup After Demo

```bash
# On Kali — review/archive scan output
ls .scans/

# On Ubuntu — verify packages were removed (if cleanup was selected)
ssh user@<ubuntu-ip> "dpkg -l | grep -E 'clamav|lynis'"
```

## NIST Controls Demonstrated

| Control | ID | Demonstrated By |
|---------|----|----|
| System Component Inventory | CM-8 | Host inventory collection |
| Configuration Settings | CM-6 | Host security check |
| Malicious Code Protection | SI-3 | ClamAV malware scan |
| Security Assessment | CA-2 | Lynis audit |
| Vulnerability Scanning | RA-5 | Nmap port scan |
| Audit Record Content | AU-3 | JSON Lines audit log |
| Information Management | SI-12 | CUI handling on inventory |
