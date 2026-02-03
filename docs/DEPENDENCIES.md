# Dependencies

This document specifies version requirements for all toolkit dependencies.

## Core Requirements

These are required for basic functionality:

| Dependency | Minimum Version | Check Command | Notes |
|------------|-----------------|---------------|-------|
| Bash | 4.0+ | `bash --version` | macOS ships with 3.2; upgrade via Homebrew |
| Git | 2.0+ | `git --version` | For version tracking, commit hashes |
| grep | GNU 2.5+ or BSD | `grep --version` | Pattern matching |
| find | POSIX | `find --version` | File discovery |
| date | POSIX | `date --version` | Timestamps (GNU coreutils on Linux) |
| shasum | 5.0+ | `shasum --version` | SHA256 integrity hashes |

### Bash 4.0+ Requirement

The toolkit uses Bash 4.0+ features:
- Associative arrays (`declare -A`)
- `${var,,}` lowercase expansion
- `mapfile` / `readarray`

**macOS users:** The default `/bin/bash` is 3.2. Install modern Bash:

```bash
brew install bash
# Use /opt/homebrew/bin/bash (Apple Silicon) or /usr/local/bin/bash (Intel)
```

## Optional Dependencies

### Malware Scanning (check-malware.sh)

The toolkit requires a malware scanner for SI-3 (Malicious Code Protection) compliance. Currently supported:

| Scanner | Platform | Status | Check Command |
|---------|----------|--------|---------------|
| ClamAV | macOS, Linux, WSL | Supported | `clamscan --version` |
| Windows Defender | Windows | Planned | `Get-MpComputerStatus` |

**ClamAV** is the recommended scanner for macOS and Linux:

| Dependency | Minimum Version | Install |
|------------|-----------------|---------|
| ClamAV | 0.103+ | `brew install clamav` / `apt install clamav` |

ClamAV paths vary by platform:
- **macOS Homebrew:** `/opt/homebrew/bin/clamscan` or `/usr/local/bin/clamscan`
- **Linux:** `/usr/bin/clamscan`
- **Database update:** Run `freshclam` before first use

**Windows users:** Windows Defender is built-in and provides equivalent malware protection. Native PowerShell integration is in development (see [MALWARE-SCANNER-ABSTRACTION.md](MALWARE-SCANNER-ABSTRACTION.md) for roadmap).

### PDF Generation (generate-*.sh)

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| pdflatex | TeX Live 2020+ | `pdflatex --version` | `brew install basictex` / `apt install texlive` |

Required LaTeX packages: `geometry`, `fancyhdr`, `hyperref`, `xcolor`, `longtable`

### Vulnerability Scanning (scan-vulnerabilities.sh)

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| Nmap | 7.80+ | `nmap --version` | `brew install nmap` / `apt install nmap` |
| Lynis | 3.0+ | `lynis --version` | `brew install lynis` / `apt install lynis` |

### JSON Processing

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| jq | 1.6+ | `jq --version` | `brew install jq` / `apt install jq` |

Used by: `check-kev.sh`, `check-nvd-cves.sh`, scanner modules

### Network Operations

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| curl | 7.68+ | `curl --version` | Usually pre-installed |

Used by: KEV catalog download, NVD API queries

### Container Scanning

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| Docker | 20.10+ | `docker --version` | docker.com |
| docker-compose | 2.0+ | `docker-compose --version` | Included with Docker Desktop |

### Secure Deletion (secure-delete.sh)

| Dependency | Platform | Check Command | Notes |
|------------|----------|---------------|-------|
| shred | Linux | `shred --version` | GNU coreutils |
| gshred | macOS | `gshred --version` | `brew install coreutils` |

### Interactive TUI (tui.sh)

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| dialog | 1.3+ | `dialog --version` | `brew install dialog` / `apt install dialog` |
| whiptail | 0.52+ | `whiptail --version` | `apt install whiptail` (Linux only) |

### GitHub CLI (release.sh)

| Dependency | Minimum Version | Check Command | Install |
|------------|-----------------|---------------|---------|
| gh | 2.0+ | `gh --version` | `brew install gh` / `apt install gh` |

## Platform Compatibility Matrix

| Feature | macOS | Linux | Windows (WSL) |
|---------|-------|-------|---------------|
| Core scans (PII, secrets, MAC) | Yes | Yes | Yes |
| Malware scanning | Yes | Yes | Yes |
| PDF generation | Yes | Yes | Yes |
| Nmap scanning | Yes | Yes | Partial |
| Lynis auditing | Yes | Yes | No |
| Host inventory | Yes | Yes | PowerShell |
| Secure delete | Yes (gshred) | Yes (shred) | No |

## Version Check Script

Run this to check all dependencies:

```bash
echo "=== Core Requirements ==="
echo "Bash: $(bash --version | head -1)"
echo "Git: $(git --version)"
echo "grep: $(grep --version 2>&1 | head -1)"

echo ""
echo "=== Optional Tools ==="
command -v clamscan && echo "ClamAV: $(clamscan --version | head -1)" || echo "ClamAV: not installed"
command -v pdflatex && echo "pdflatex: $(pdflatex --version | head -1)" || echo "pdflatex: not installed"
command -v jq && echo "jq: $(jq --version)" || echo "jq: not installed"
command -v nmap && echo "Nmap: $(nmap --version | head -1)" || echo "Nmap: not installed"
command -v lynis && echo "Lynis: $(lynis --version 2>&1)" || echo "Lynis: not installed"
command -v docker && echo "Docker: $(docker --version)" || echo "Docker: not installed"
command -v gh && echo "GitHub CLI: $(gh --version | head -1)" || echo "GitHub CLI: not installed"
```

## Upgrading Dependencies

### macOS (Homebrew)

```bash
brew update
brew upgrade bash clamav jq nmap lynis
```

### Ubuntu/Debian

```bash
sudo apt update
sudo apt upgrade clamav jq nmap lynis
```

### CentOS/RHEL

```bash
sudo yum update clamav jq nmap lynis
# or with dnf:
sudo dnf upgrade clamav jq nmap lynis
```
