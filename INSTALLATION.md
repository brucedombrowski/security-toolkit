# Installation Guide

## System Requirements

### Minimum Requirements

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| Bash | 4.0+ | Most Linux/macOS systems |
| Git | 2.0+ | For version tracking |
| Grep | GNU or BSD | Most systems have this |
| Find | Standard | Most systems have this |

### Supported Platforms

- **macOS:** 10.15+ (Catalina or later)
  - Intel (x86_64) and Apple Silicon (ARM64) supported
- **Linux:** Ubuntu 18.04+, CentOS 7+, Debian 10+
- **Other:** Any POSIX-compatible system with bash 4.0+

### Optional Dependencies

| Tool | Purpose | Platform | Status |
|------|---------|----------|--------|
| ClamAV | Malware scanning | macOS, Linux | Optional but recommended |
| pdflatex | PDF attestation generation | macOS, Linux | Optional (reports work without) |
| Nmap | Network scanning | macOS, Linux | Optional |
| Lynis | System auditing | macOS, Linux | Optional |

## Installation Steps

### Option 1: Clone from GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/brucedombrowski/security-toolkit.git
cd security-toolkit

# Make scripts executable
chmod +x scripts/*.sh

# Verify installation
./scripts/run-all-scans.sh --help
```

### Option 2: Download Archive

```bash
# Download latest release
curl -L https://github.com/brucedombrowski/security-toolkit/archive/main.zip -o security-toolkit.zip
unzip security-toolkit.zip
cd security-toolkit-main

# Make scripts executable
chmod +x scripts/*.sh

# Verify installation
./scripts/run-all-scans.sh --help
```

## Platform-Specific Setup

### macOS Setup

#### 1. Install Required Tools

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install ClamAV (recommended for malware scanning)
brew install clamav

# Install pdflatex (optional, for PDF attestation)
brew install basictex

# Install Lynis (optional, for system auditing)
brew install lynis

# Install Nmap (optional, for network scanning)
brew install nmap

# Verify installations
which clamscan pdflatex lynis nmap
```

#### 2. Initial ClamAV Setup (first time only)

```bash
# Create config directory if needed
sudo mkdir -p /opt/homebrew/etc/clamav

# Copy sample config
sudo cp /opt/homebrew/etc/clamav/freshclam.conf.sample \
       /opt/homebrew/etc/clamav/freshclam.conf

# Edit config to remove "Example" line
sudo sed -i '' 's/^Example/#Example/' /opt/homebrew/etc/clamav/freshclam.conf

# Update virus database
sudo freshclam

# Verify databases exist
ls /opt/homebrew/var/lib/clamav/
```

#### 3. Verify Installation

```bash
# Test ClamAV
clamscan --version

# Test toolkit
./scripts/check-pii.sh ./README.md
```

### Linux Setup

#### 1. Install Required Tools

**Ubuntu/Debian:**
```bash
# Update package list
sudo apt update

# Install ClamAV
sudo apt install clamav clamav-daemon

# Install pdflatex (optional)
sudo apt install texlive-latex-base

# Install Lynis (optional)
sudo apt install lynis

# Install Nmap (optional)
sudo apt install nmap

# Verify installations
which clamscan pdflatex lynis nmap
```

**CentOS/RHEL:**
```bash
# Install ClamAV
sudo yum install clamav clamav-update

# Install pdflatex (optional)
sudo yum install texlive-latex

# Install Lynis (optional)
sudo yum install lynis

# Install Nmap (optional)
sudo yum install nmap

# Verify installations
which clamscan pdflatex lynis nmap
```

#### 2. Initial ClamAV Setup

```bash
# Update virus database
sudo freshclam

# Start ClamAV daemon (optional)
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon
```

#### 3. Verify Installation

```bash
# Test ClamAV
clamscan --version

# Test toolkit
./scripts/check-pii.sh ./README.md
```

## Verification Steps

After installation, verify everything works:

### 1. Check bash version

```bash
bash --version
# Should output 4.0 or higher
```

### 2. Test script execution

```bash
./scripts/run-all-scans.sh --help
# Should display help without errors
```

### 3. Run a test scan

```bash
# Scan this repository for PII
./scripts/check-pii.sh .

# Expected output:
# - Summary of files scanned
# - Any PII patterns found (should be none)
# - Exit code 0 (pass) or 1 (findings)
```

### 4. Verify optional tools (if installed)

```bash
# Test ClamAV
clamscan --version

# Test pdflatex
pdflatex --version

# Test Nmap
nmap --version

# Test Lynis
lynis --version
```

### 5. Full test suite (optional)

```bash
# Run all scans on the repository itself
./scripts/run-all-scans.sh .

# Review .scans/ directory for results
ls -la ./.scans/
```

## Troubleshooting

### Issue: "command not found: bash"

**Solution:** Ensure bash 4.0+ is installed
```bash
bash --version
# If old version on macOS, install newer bash via Homebrew
brew install bash
```

### Issue: "Permission denied" when running scripts

**Solution:** Make scripts executable
```bash
chmod +x scripts/*.sh
./scripts/run-all-scans.sh --help
```

### Issue: "clamscan: command not found"

**Solution:** Install ClamAV
```bash
# macOS
brew install clamav

# Linux (Ubuntu/Debian)
sudo apt install clamav

# Linux (CentOS/RHEL)
sudo yum install clamav
```

### Issue: "pdflatex: command not found"

**Solution:** Install TeX Live (optional but recommended)
```bash
# macOS
brew install basictex

# Linux (Ubuntu/Debian)
sudo apt install texlive-latex-base

# Linux (CentOS/RHEL)
sudo yum install texlive-latex
```

**Note:** PDF generation is optional. Scans work fine without it.

### Issue: "freshclam: error - Can't read config file"

**Solution:** Setup ClamAV configuration
```bash
# macOS
sudo mkdir -p /opt/homebrew/etc/clamav
sudo cp /opt/homebrew/etc/clamav/freshclam.conf.sample \
       /opt/homebrew/etc/clamav/freshclam.conf
sudo sed -i '' 's/^Example/#Example/' /opt/homebrew/etc/clamav/freshclam.conf
sudo freshclam

# Linux
sudo freshclam
```

### Issue: "too many open files" error

**Solution:** Increase file descriptor limit
```bash
# Temporarily
ulimit -n 4096

# Permanently (Linux)
echo "* soft nofile 4096" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 4096" | sudo tee -a /etc/security/limits.conf
```

### Issue: Scripts run very slowly

**Possible causes:**
- Large directory being scanned (try smaller target)
- Slow network access (timeout during scans)
- Antivirus software slowing file operations
- ClamAV updating databases (wait for freshclam to finish)

### Issue: "set -e: permission denied"

**Solution:** Check file permissions and shebang
```bash
# Verify shebang at top of script
head -1 scripts/run-all-scans.sh
# Should be: #!/bin/bash

# Make executable
chmod +x scripts/*.sh
```

## Upgrading

### Using the Upgrade Script

```bash
# Navigate to toolkit directory
cd ~/security-toolkit

# Run upgrade script
./scripts/upgrade.sh
```

The upgrade script will:
1. Show what commits are pending
2. Show if the KEV catalog will be updated
3. Confirm before applying changes

### Manual Upgrade

```bash
cd ~/security-toolkit
git fetch origin
git pull origin main
```

### What's Preserved During Upgrades

Your **project-specific data** is stored in your scanned projects, not in the toolkit:

| Location | Description | Preserved? |
|----------|-------------|------------|
| `<your-project>/.scans/` | Scan results | Yes (in your project) |
| `<your-project>/.allowlists/` | Reviewed exceptions | Yes (in your project) |
| `<your-project>/requirements.json` | Your requirements | Yes (copy from template) |
| `security-toolkit/.cache/` | Toolkit cache | Refreshed on upgrade |
| `security-toolkit/data/` | Bundled resources | Updated to latest |

### Using Your Own Requirements

If you use the `requirements/project-requirements-template.json`:

1. **Copy** the template to your own project:
   ```bash
   cp ~/security-toolkit/requirements/project-requirements-template.json \
      /path/to/your-project/requirements.json
   ```

2. **Customize** with your project's requirements

3. **Upgrade the toolkit** without affecting your project's requirements file

### Offline/Air-Gapped Systems

The toolkit bundles a KEV catalog snapshot (`data/kev-catalog.json`) for offline use. After upgrading:

- New bundled KEV catalog is available immediately
- Your project's cached KEV data (`.cache/`) is refreshed on next scan
- No network required to use the bundled catalog

## Getting Help

If you encounter issues not covered here:

1. **Check the README:** General usage and examples
2. **Check CLAUDE.md:** Toolkit architecture and design
3. **Review logs:** Check `.scans/` directory for detailed logs
4. **Check GitHub Issues:** Search for similar problems
5. **Security concerns:** See [SECURITY.md](./SECURITY.md) for responsible disclosure

## Next Steps

After successful installation:

1. **Read README.md** for usage examples
2. **Review CLAUDE.md** to understand toolkit design
3. **Run a test scan** on a safe target
4. **Set up CI/CD** integration (see README.md)
5. **Generate attestation** for compliance (optional)

---

**Last Updated:** January 30, 2026
**Tested On:** macOS 13+, Ubuntu 20.04+, CentOS 7+
