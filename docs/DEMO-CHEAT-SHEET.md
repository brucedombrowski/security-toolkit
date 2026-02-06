# Demo Cheat Sheet: Remote SSH Scan

Quick reference for demonstrating the Security Verification Toolkit scanning a live Ubuntu target from a Kali Linux machine over SSH.

## Topology

### Same Network (LAN)

```
┌──────────────────────┐         SSH          ┌──────────────────────┐
│    Kali (Scanner)     │ ──────────────────►  │   Ubuntu (Target)    │
│                       │                      │                      │
│  ~/Security/          │                      │  Live boot           │
│  QuickStart.sh        │                      │  Internet access     │
│  .scans/ (output)     │                      │  Fresh install       │
└──────────────────────┘                       └──────────────────────┘
```

### Different Networks (VPN)

```
┌──────────────────────┐    Tailscale or      ┌──────────────────────┐
│    Kali (Scanner)     │    WireGuard VPN     │   Ubuntu (Target)    │
│                       │ ◄═══════════════════►│                      │
│  ~/Security/          │    NAT traversal     │  Live boot           │
│  vpn-connect.sh       │    (encrypted)       │  Internet access     │
│  .scans/ (output)     │                      │  Auto VPN setup      │
└──────────────────────┘                       └──────────────────────┘
```

## Prerequisites

| Item | Requirement |
|------|-------------|
| Kali | Toolkit cloned to `~/Security` |
| Kali | `nmap` installed (standard on Kali) |
| Kali | `pdflatex` installed (for attestation PDF) |
| Ubuntu | SSH server running (setup script handles this) |
| Ubuntu | `payload` user with sudo access (setup script creates this) |
| Network | Kali can reach Ubuntu over SSH (port 22) — LAN or VPN |
| VPN (optional) | Tailscale account with auth key, or a reachable IP for WireGuard |

## Pre-Demo Checklist

```bash
# On Kali — verify toolkit
cd ~/Security
git status                    # Clean working tree
./scripts/lib/toolkit-info.sh # Confirm version

# On Kali — verify connectivity
ssh payload@<ubuntu-ip> "hostname && uname -a"
# Password: 11111111

# On Kali — verify nmap
nmap --version
```

## Target Setup (On Ubuntu)

Connect the Ubuntu target to the internet (WiFi or Ethernet), open a terminal, and run **one command**:

```bash
wget -qO- https://raw.githubusercontent.com/brucedombrowski/security-toolkit/main/scripts/setup-target.sh | sudo bash
```

This single command does **everything** on the target:
1. Downloads the latest toolkit release to `/opt/security-toolkit`
2. Creates `payload` user (password: `11111111`) with sudo access
3. Creates `ubuntu` user (password: `11111111`) with sudo access
4. Enables SSH with password authentication
5. Installs ClamAV, Lynis, and scan dependencies
6. Opens random ports, plants findings (PII, secrets, malware, MAC addresses)
7. Installs KEV-trigger packages (Apache, Log4j, ImageMagick)
8. Displays target IP in a **large banner**

See [DEMO-PLANTED-FINDINGS.md](DEMO-PLANTED-FINDINGS.md) for details on what gets planted.

**Scanner credentials** (created automatically):
| Username | Password | Sudo |
|----------|----------|------|
| `payload` | `11111111` | Yes |
| `ubuntu` | `11111111` | Yes |

All commands are logged to:
- `/tmp/demo-target-bootstrap.log` — bootstrap/download log
- `/tmp/demo-payload-setup.log` — phase-by-phase setup log

## VPN Setup (When Scanner and Target Are on Different Networks)

Use VPN when the scanner (Kali) and target (Ubuntu) are behind different NATs / on different networks.

### Option A: Tailscale (Recommended for NAT)

Tailscale handles NAT traversal automatically. Free tier supports up to 100 devices.

**One-time setup (instructor):**
1. Create a Tailscale account at https://login.tailscale.com
2. Generate an ephemeral, single-use auth key at **Settings > Keys > Generate auth key**
   - Check: **Ephemeral** (auto-expires)
   - Check: **Single use** (can't be reused)

**On Kali (scanner):**
```bash
# Install Tailscale (if not already installed)
curl -fsSL https://tailscale.com/install.sh | sh

# Connect to Tailnet
sudo tailscale up

# Or use the helper script
./scripts/vpn-connect.sh tailscale
```

**On Ubuntu (target) — one-liner with auth key:**
```bash
TS_AUTHKEY=tskey-auth-XXXX wget -qO- https://raw.githubusercontent.com/<repo>/main/scripts/setup-target.sh | sudo bash
```

The target setup script installs Tailscale, connects with the auth key, and displays the Tailscale IP on the TARGET READY screen.

**Enable VPN in config** (if using a custom JSON config):
```json
{
  "vpn": {
    "enabled": true,
    "mode": "tailscale"
  }
}
```

### Option B: Raw WireGuard (When One Side Has a Reachable IP)

Use when at least one side has a public IP or port-forwarded port (lab, VPS).

**On Ubuntu (target):**

Set `vpn.enabled: true` and `vpn.mode: "wireguard"` in the payload config, with `peer_endpoint` pointing to the scanner's reachable IP. Run the one-liner. The TARGET READY screen shows the target's public key.

**On Kali (scanner):**
```bash
./scripts/vpn-connect.sh wireguard
```

The script prompts for the target's public key and endpoint, generates a local keypair, creates the tunnel, and displays the scanner's public key.

**Key exchange (2-step):**
1. Target generates keys, displays public key + endpoint on TARGET READY screen
2. Scanner operator runs `vpn-connect.sh wireguard`, enters target info, gets own public key
3. Target operator adds scanner's public key: `sudo wg set wg0 peer <key> allowed-ips 10.200.200.1/32`
4. Tunnel is up — verify with `ping 10.200.200.2`

### Auth Key Security

- The `auth_key` field in the default JSON is always empty — never commit real keys
- Use the `TS_AUTHKEY` environment variable (never written to disk)
- Use **ephemeral + single-use** auth keys (auto-expire, can't be reused)
- Live boot destroys everything on reboot

## Config-Driven Scanning

The toolkit supports config files that define the complete scan profile — target, credentials, which scans to run, and how aggressive each scan should be. This eliminates interactive prompts and ensures repeatable, consistent scans.

### Using a Config File

```bash
cd ~/Security
./QuickStart.sh demo_target.conf
```

The config file replaces all interactive prompts. QuickStart prints `(from config)` next to each setting so the audience sees exactly where the values come from.

### Config File Reference

```bash
# ── Target ──────────────────────────────────────────────
SCAN_TYPE=host                    # "host" or "repo"
TARGET_HOST=10.0.0.244            # IP or hostname
TARGET_LOCATION=remote            # "remote" or "local"
AUTH_MODE=credentialed             # "credentialed" or "uncredentialed"
REMOTE_USER=payload               # SSH username
PROJECT_NAME="My Project"         # Label for reports

# ── Scan Selection ──────────────────────────────────────
SKIP_SCAN_SELECTION=true           # Skip interactive menu

# SSH/credentialed scans
RUN_HOST_INVENTORY=true            # System info, packages (CM-8)
RUN_HOST_SECURITY=true             # SSH config, firewall (CM-6)
RUN_HOST_POWER=true                # Sleep/hibernate settings
RUN_HOST_LYNIS=true                # Lynis security audit (CA-2)
RUN_HOST_MALWARE=true              # ClamAV malware scan (SI-3)
RUN_HOST_KEV=true                  # CISA KEV cross-reference (RA-5)

# Network scans
RUN_NMAP_PORTS=true                # Port scan
RUN_NMAP_SERVICES=true             # Service version detection (-sV)
RUN_NMAP_OS=true                   # OS fingerprinting (-O, needs root)
RUN_NMAP_VULN=true                 # Vulnerability scripts (--script vuln)

# ── Scan Options ────────────────────────────────────────
LYNIS_MODE=full                    # "full" (~10 min) or "quick" (~2 min)
```

### Customizing for Your Project

Other teams can copy `demo_target.conf` and modify it for their environment:

```bash
cp demo_target.conf my_project.conf
# Edit: set your target IP, username, and which scans matter
./QuickStart.sh my_project.conf
```

**Demo talking point:** "This config file is how you adapt the toolkit to your project. Point it at your server, choose which NIST controls to verify, and run. Every scan is repeatable and auditable."

## Demo Flow (On Kali)

### Step 1: Launch QuickStart with Config

```bash
cd ~/Security
./QuickStart.sh demo_target.conf
```

**Demo talking point:** "The config defines our target, credentials, and scan profile. No manual menu navigation — it's repeatable and scriptable for CI/CD."

### Step 2: Enter SSH Password

The only interactive prompt is the SSH password:

```
payload@10.0.0.244's password: 11111111
```

**Demo talking point:** "We authenticate once. The toolkit multiplexes the SSH connection so every subsequent scan reuses it — no repeated password prompts."

### Step 3: Scans Execute

The following scans run in sequence:

| Scan | What Happens | Duration | Audience Value |
|------|-------------|----------|----------------|
| Host Inventory | Collects OS, packages, network info | ~10s | Quick, shows CUI handling |
| Host Security | Checks SSH config, firewall, permissions | ~15s | Finds planted weaknesses |
| Power Settings | Sleep/hibernate check | ~5s | Quick |
| Lynis Audit | Full security hardening audit | ~2-5 min | Excellent — fills screen with findings |
| Malware Scan | ClamAV scans target | 1-15 min | Finds EICAR test samples |
| Nmap Port Scan | Network scan from Kali to target | 1-5 min | Finds open ports and services |
| KEV Check | Cross-reference nmap CVEs against CISA KEV | ~5s | Shows threat intelligence integration |

### Step 4: Review Output

```bash
ls -la .scans/Scan*/
```

Output includes:
- `host-inventory-<timestamp>.txt` — System inventory (CUI-marked, mode 600)
- `host-security-<timestamp>.txt` — Security posture findings
- `host-lynis-<timestamp>.txt` — Hardening score and suggestions
- `host-malware-<timestamp>.txt` — ClamAV results with EICAR detections
- `nmap-ports-<timestamp>.txt` — Open ports, services, vulnerabilities
- `host-kev-<timestamp>.txt` — CISA KEV cross-reference results
- `scan-attestation-<timestamp>.pdf` — Signed attestation with checksums

### Step 5: Attestation PDF

**Demo talking point:** "The PDF includes SHA256 checksums, toolkit version, scan timestamps, and NIST control mappings — everything needed for an audit package."

### Step 6: Cleanup Prompt

```
Remove packages installed during scan (ClamAV, Lynis)? [y/N] → y
```

**Demo talking point:** "Leave no trace — the toolkit offers to uninstall any packages it installed on the target, returning the system to its pre-scan state."

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
| SSH host key changed | Fixed automatically — `~/.ssh/config` skips strict checking for `10.0.0.*` |
| SSH connection refused | Re-run the one-liner on target |
| Permission denied | Username: `payload`, Password: `11111111` |
| Multiple password prompts for Lynis | Known issue (#155) — `sudo -v` opens separate SSH connection |
| Nmap hangs on sudo prompt | Fixed in v2.5.3+ — auto-skips `-O` when not root |
| ClamAV scan appears frozen | Expected — `--infected` flag only shows hits, scan is running (#156) |
| ClamAV scan takes too long | Full disk scan can take 5-15 min; consider scoping to target dirs (#157) |
| Lynis "can't find include dir" | Install from CISOfy repo, not apt default (fixed in v2.5.1+ bootstrap) |
| KEV check skipped | Fixed in v2.5.2+ — KEV now runs after nmap instead of before |
| ClamAV database missing | `sudo freshclam` on target (requires internet) |
| pdflatex not found | `sudo apt install texlive-latex-base` on Kali |
| Tailscale auth key rejected | Generate a new key — single-use keys expire after one use |
| WireGuard tunnel no traffic | Ensure peer public keys are exchanged on both sides |
| Can't reach target over VPN | Verify both sides show tunnel IP: `tailscale ip` or `wg show` |

## Cleanup After Demo

```bash
# On Kali — review/archive scan output
ls .scans/

# On Ubuntu — run cleanup to revert planted findings
ssh payload@<ubuntu-ip> "sudo /opt/security-toolkit/scripts/prepare-payload.sh --cleanup"
# Password: 11111111

# Or just reboot the live boot — nothing persists
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
