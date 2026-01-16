# Lynis macOS False Positives and Non-Applicable Findings

This document explains Lynis suggestions that are false positives or not applicable on macOS systems. These findings can be safely ignored or suppressed without impacting actual system security.

## Summary

| Check ID | Description | Status | Reason |
|----------|-------------|--------|--------|
| AUTH-9262 | PAM password strength module | Not Applicable | macOS uses OpenDirectory, not PAM |
| FILE-6310 | Symlinked mount points | False Positive | Standard macOS filesystem architecture |
| PKGS-7398 | Package audit tool | Not Applicable | No macOS equivalent exists |
| HTTP-6640 | Apache mod_evasive | Not Applicable | Apache not actively used on macOS |
| HTTP-6643 | Apache ModSecurity | Not Applicable | Apache not actively used on macOS |
| TOOL-5002 | Automation tools | Informational | Not a security issue |
| HRDN-7222 | Restrict compilers | Not Recommended | Would break Xcode/development |
| CONT-8104 | Docker daemon warnings | Informational | Check only if using Docker |

## Detailed Explanations

### AUTH-9262: PAM Password Strength Module

**Suggestion:** Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc

**Why it's not applicable:**
- macOS does not use PAM (Pluggable Authentication Modules) for password policy enforcement
- macOS uses OpenDirectory/DirectoryService for authentication
- Password policies on macOS are configured via:
  - System Preferences > Users & Groups
  - `pwpolicy` command-line tool
  - MDM (Mobile Device Management) profiles
  - Configuration profiles (.mobileconfig)

**macOS equivalent:**
```bash
# View current password policy
pwpolicy -getaccountpolicies

# Set minimum password length (example)
sudo pwpolicy -setglobalpolicy "minChars=12"
```

**NIST Control:** IA-5 (Authenticator Management) - Satisfied by macOS native controls

---

### FILE-6310: Symlinked Mount Points (/home, /tmp, /var)

**Suggestion:** Symlinked mount point needs to be checked manually

**Why it's a false positive:**
- macOS uses a **firmlinked** filesystem architecture since macOS Catalina (10.15)
- `/home`, `/tmp`, and `/var` are intentionally symlinks to locations on the Data volume
- This is Apple's design for separating the read-only System volume from user data
- The symlinks are:
  - `/home` → `/System/Volumes/Data/home`
  - `/tmp` → `/private/tmp`
  - `/var` → `/private/var`

**Security impact:** None. This is standard macOS architecture and cannot be changed.

**NIST Control:** N/A - Filesystem architecture, not a security control

---

### PKGS-7398: Package Audit Tool

**Suggestion:** Install a package audit tool to determine vulnerable packages

**Why it's not applicable:**
- Lynis looks for tools like `apt-check`, `yum-security`, or `pkg audit`
- macOS does not have a built-in package vulnerability scanner
- Homebrew does not provide an equivalent to `apt-check`

**Alternatives for macOS:**
- Use `brew outdated` to check for outdated packages
- Use `softwareupdate -l` for macOS system updates
- Third-party tools: Snyk, OSQuery, or commercial vulnerability scanners

**NIST Control:** RA-5 (Vulnerability Scanning) - Partially satisfied by other toolkit scans

---

### HTTP-6640 / HTTP-6643: Apache Modules

**Suggestion:** Install Apache mod_evasive / ModSecurity

**Why it's not applicable:**
- Apache httpd is pre-installed on macOS but typically **not used**
- macOS ships with Apache for legacy compatibility
- Most macOS users don't run Apache as a production webserver
- If you're actively using Apache, these modules would be relevant

**When to address:**
- Only if you're running Apache httpd as a webserver
- Check: `sudo apachectl status` - if "not running", ignore these suggestions

**NIST Control:** SC-5 (Denial of Service Protection) - Only relevant if running Apache

---

### TOOL-5002: Automation Tools

**Suggestion:** Determine if automation tools are present for system management

**Why it's informational only:**
- Lynis looks for Ansible, Puppet, Chef, SaltStack, etc.
- These are enterprise configuration management tools
- Not having them is not a security vulnerability
- They're useful for managing fleets of servers, not single workstations

**Security impact:** None. This is an operational suggestion, not a security finding.

**NIST Control:** CM-2 (Baseline Configuration) - Manual configuration is acceptable

---

### HRDN-7222: Harden Compilers

**Suggestion:** Harden compilers like restricting access to root user only

**Why it's not recommended on macOS:**
- macOS is primarily a **development platform**
- Xcode and command-line tools require compiler access
- Restricting compilers would break:
  - Xcode builds
  - Homebrew package installation
  - Any development workflow
- This suggestion is for production Linux servers, not development workstations

**When to address:**
- Only on dedicated, non-development macOS systems
- Never on developer workstations

**NIST Control:** CM-7 (Least Functionality) - Development requires compilers

---

### CONT-8104: Docker Daemon Warnings

**Suggestion:** Run 'docker info' to see warnings applicable to Docker daemon

**Why it's informational:**
- This only appears if Docker is installed
- It's asking you to check Docker's own configuration warnings
- Not a Lynis finding per se, just a reminder to check Docker

**How to address:**
```bash
docker info 2>&1 | grep -i warning
```

**NIST Control:** CM-6 (Configuration Settings) - Review Docker config if using containers

---

## Suppressing False Positives in Lynis

To suppress checks that don't apply to macOS, create a custom profile:

```bash
# Create custom profile for macOS
sudo tee /opt/homebrew/Cellar/lynis/3.1.6/custom.prf << 'EOF'
# macOS False Positives - See docs/lynis-macos-false-positives.md
skip-test=AUTH-9262
skip-test=FILE-6310
skip-test=PKGS-7398
skip-test=HTTP-6640
skip-test=HTTP-6643
skip-test=TOOL-5002
skip-test=HRDN-7222
EOF
```

**Note:** Suppressing checks will increase the hardening score but doesn't change actual security posture.

## Actionable Findings on macOS

These Lynis findings ARE actionable on macOS:

| Check ID | Description | Fix |
|----------|-------------|-----|
| NAME-4404 | Hostname in /etc/hosts | `sudo sh -c 'echo "127.0.0.1 $(hostname -s)" >> /etc/hosts'` |
| HOME-9304 | Home directory permissions | `chmod 750 ~` |
| FILE-7524 | sshd_config permissions | `sudo chmod 600 /etc/ssh/sshd_config` |
| LOGG-2190 | Deleted files in use | Restart apps holding deleted files |

Use `scripts/harden-system.sh` to check and fix these automatically.

## References

- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [macOS Security Compliance Project](https://github.com/usnistgov/macos_security)
