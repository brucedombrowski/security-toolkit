# Demo Planted Findings — Security Disclosure

## Purpose

The Security Verification Toolkit includes a demo preparation script (`scripts/prepare-demo-target.sh`) that intentionally places **synthetic security findings** on a target system. This document explains what is planted, why, and confirms that none of this data is real or poses a security risk.

## Why Planted Findings Exist

Security scanning tools are difficult to demonstrate on clean systems — a scan with zero findings doesn't show the tool's capabilities. The `prepare-demo-target.sh` script creates a controlled set of realistic-looking (but entirely fake) findings so that every scan type produces meaningful output during demonstrations.

**This is standard practice** in security tooling. Products like Nessus, Qualys, and OpenSCAP all ship with similar test fixtures and demo environments.

## What Is Planted

### PII Test Data (`customer-records.csv`)

| Data Type | Example | Real? |
|-----------|---------|-------|
| SSNs | `078-05-1120`, `219-09-9999` | **No** — These are well-known invalid SSNs. `078-05-1120` is the Woolworth wallet SSN (invalidated by SSA in 1938). `219-09-9999` is in a range never issued. |
| Phone numbers | `555-867-5309` | **No** — 555 prefix is reserved for fictional use by NANPA. |
| Credit cards | `4532015112830366` | **No** — Generated test numbers that pass Luhn checksum but are not issued by any bank. |
| Email addresses | `john@example.com` | **No** — `example.com` is an IANA-reserved domain (RFC 2606). |
| Names | `John Smith`, `Jane Doe` | **No** — Standard placeholder names. |

### Secrets Test Data (`config.env`)

| Secret Type | Example | Real? |
|-------------|---------|-------|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | **No** — This is AWS's official example key from their documentation. It has never been and will never be a valid key. |
| AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | **No** — AWS's official example secret key. |
| GitHub Token | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12` | **No** — Alphabetical sequence, not a valid token. |
| Database URL | `postgres://admin:SuperSecret123!@db.example.com` | **No** — Points to `example.com` (reserved domain). |
| API Key | `sk-proj-abc123def456...` | **No** — Sequential placeholder. |
| Password | `Admin@2024!` | **No** — Generic demo string, not used anywhere. |

### Private Key (`deploy-key.pem`)

The planted RSA private key contains the string `EXAMPLE_NOT_A_REAL_KEY_JUST_DEMO_DATA_FOR_SCAN` in its body. It is **structurally invalid** — it cannot be used for any cryptographic operation. It exists solely to trigger the toolkit's private key detection pattern.

### EICAR Test File (`suspicious-file.exe`)

The [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is an **industry-standard antivirus test string** developed by the European Institute for Computer Antivirus Research. It is:

- **Not malware** — it contains no executable code and cannot harm any system
- **Recognized by every antivirus product** as a test signature
- **Designed specifically** for testing AV detection capabilities
- **68 bytes of ASCII text** — literally just a string

The EICAR standard explicitly states: *"Any anti-virus product that detects the EICAR test file must treat it exactly as if it found a real virus."*

### MAC Addresses (`network-inventory.txt`)

| Address | Real? |
|---------|-------|
| `00:1A:2B:3C:4D:5E` | **No** — Sequential hex placeholder |
| `AA:BB:CC:DD:EE:FF` | **No** — Obviously patterned |
| `DE:AD:BE:EF:CA:FE` | **No** — Classic hex wordplay (`DEADBEEFCAFE`) |
| `02:42:AC:11:00:02` | **No** — Docker default bridge range |

### Database Dump (`users-backup.sql`)

Contains the same fake SSNs and a fake API key (`sk-live-EXAMPLE-KEY-NOT-REAL-12345`). The password hashes are truncated bcrypt strings that cannot be reversed to any real password.

### Weak SSH Configuration

The script sets `PermitRootLogin yes` and `PasswordAuthentication yes` on the demo target. This is:

- **Intentional** — creates a finding for the host security check
- **Reverted on cleanup** — `--cleanup` flag restores the original config
- **Ephemeral** — designed for live boot environments that reset on reboot

### Open Ports

Ports 4444, 6667, 8080, 9090, and 31337 are opened with simple echo listeners. These are commonly flagged by port scanners as suspicious (Metasploit default, IRC, common backdoor ports). The listeners serve no function beyond producing nmap findings.

## Lifecycle

```
prepare-demo-target.sh              prepare-demo-target.sh --cleanup
        │                                       │
        ▼                                       ▼
  Plants files in /tmp/demo-target-data    Deletes all planted files
  Opens port listeners                     Kills all listeners
  Weakens SSH config                       Restores SSH config
        │                                       │
        ▼                                       ▼
  Demo scans run against planted data      System returns to pre-demo state
```

On a live boot system, rebooting also fully resets everything regardless of cleanup.

## How to Verify

To confirm that planted data is not real:

```bash
# SSNs: 078-05-1120 is the famous Woolworth invalid SSN
# https://www.ssa.gov/history/ssn/misused.html

# AWS keys: Official AWS example credentials
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html

# EICAR: Official test file documentation
# https://www.eicar.org/download-anti-malware-testfile/

# example.com: IANA reserved domain
# https://www.iana.org/domains/reserved
```

## For Auditors

If you are reviewing this toolkit as part of a security assessment:

1. **The planted findings are test fixtures**, equivalent to unit test data in any software project
2. **No real credentials exist** anywhere in this repository
3. **The EICAR file is not malware** — it is the industry-standard AV test string
4. **All planted data is marked** with comments like `# DEMO DATA - NOT REAL` and `EXAMPLE_NOT_A_REAL_KEY`
5. **The plant script is self-cleaning** via `--cleanup` flag or system reboot
6. **The repository passes its own scans** — running the toolkit against itself produces only the expected findings from these test fixtures and known allowlisted items

## Related Files

- `scripts/prepare-demo-target.sh` — The planting script
- `demo/vulnerable-lab/` — Docker Compose vulnerable lab (separate from planted findings)
- `.allowlists/` — Allowlist entries for known-good matches in the codebase
- `docs/DEMO-CHEAT-SHEET.md` — Demo walkthrough guide
