# SSH Troubleshooting Guide for Remote Scans

This guide helps troubleshoot SSH connection issues when running credentialed remote scans with QuickStart.

## Quick Diagnosis

From your scanning machine, test the connection:

```bash
# Test basic connectivity
ping -c 3 <target-ip>

# Test if SSH port is reachable
nc -zv <target-ip> 22

# Test SSH with verbose output
ssh -v user@<target-ip>
```

## Common Error Messages

### "Connection refused"

**Cause:** SSH server is not running on the target.

**Fix on target machine:**
```bash
# Check SSH status
sudo systemctl status ssh

# Start and enable SSH
sudo systemctl start ssh
sudo systemctl enable ssh
```

### "Connection timed out"

**Cause:** Firewall blocking the connection or incorrect IP address.

**Fix:**
```bash
# Verify target IP is correct
ping <target-ip>

# Check firewall on target (Ubuntu/Debian)
sudo ufw status
sudo ufw allow ssh

# Check firewall on target (RHEL/CentOS)
sudo firewall-cmd --list-all
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

### "Permission denied (publickey,password)"

**Cause:** Incorrect username or password, or password auth disabled.

**Fix:**
```bash
# On target: Check SSH config allows password auth
sudo grep -E "^PasswordAuthentication" /etc/ssh/sshd_config

# If it shows "no", enable password auth:
sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### "Host key verification failed"

**Cause:** Target's host key changed (reinstall, different machine on same IP).

**Fix:**
```bash
# Remove old key from known_hosts
ssh-keygen -R <target-ip>

# Try connecting again (will prompt to accept new key)
ssh user@<target-ip>
```

### "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"

**Cause:** Same as above - host key mismatch.

**Fix:**
```bash
ssh-keygen -R <target-ip>
```

## Platform-Specific Setup

### Kali Linux (Target)

SSH is installed but **disabled by default** on Kali:

```bash
# Start and enable SSH
sudo systemctl enable --now ssh

# Verify it's running
sudo systemctl status ssh
```

### Ubuntu/Debian (Target)

May need to install OpenSSH server:

```bash
# Install SSH server
sudo apt update
sudo apt install openssh-server

# Start and enable
sudo systemctl enable --now ssh
```

### RHEL/CentOS/Fedora (Target)

```bash
# Install SSH server
sudo dnf install openssh-server

# Start and enable
sudo systemctl enable --now sshd

# Open firewall
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

### macOS (Target)

Enable via System Settings:
1. Open **System Settings** (or System Preferences on older versions)
2. Go to **General** → **Sharing**
3. Enable **Remote Login**
4. Choose which users can access

Or via command line:
```bash
sudo systemsetup -setremotelogin on
```

### Windows (Target)

Windows requires OpenSSH Server to be installed:

1. **Settings** → **Apps** → **Optional Features**
2. Click **Add a feature**
3. Find and install **OpenSSH Server**
4. Start the service:
   ```powershell
   Start-Service sshd
   Set-Service -Name sshd -StartupType Automatic
   ```

See also: [docs/WINDOWS-TARGET-SETUP.md](WINDOWS-TARGET-SETUP.md)

## Verifying SSH Access

Once SSH is set up on the target, verify from your scanning machine:

```bash
# Basic connection test
ssh user@<target-ip> "echo 'SSH works!'"

# Test with the exact user you'll use for scanning
ssh scanuser@<target-ip> "hostname && uname -a"
```

## SSH Key-Based Authentication (Recommended)

For passwordless scanning, set up SSH keys:

```bash
# On scanning machine: Generate key (if you don't have one)
ssh-keygen -t ed25519

# Copy key to target
ssh-copy-id user@<target-ip>

# Test passwordless login
ssh user@<target-ip>
```

## Network Issues

### Testing Port Connectivity

```bash
# Using netcat
nc -zv <target-ip> 22

# Using telnet
telnet <target-ip> 22

# Using nmap
nmap -p 22 <target-ip>
```

### Behind NAT/Router

If the target is behind a router:
1. Ensure port 22 is forwarded to the target machine
2. Use the router's external IP (or hostname) from outside the network
3. Use the internal IP when on the same network

## QuickStart-Specific Tips

### Using Uncredentialed Mode for Windows

If SSH isn't available on a Windows target, use **uncredentialed mode** instead:
- Select option 2 (Uncredentialed) in the auth menu
- Nmap can still scan the target using network protocols

### SSH Multiplexing Issues

QuickStart uses SSH connection multiplexing. If you have issues:

```bash
# Clear any stale control sockets
rm -f /tmp/ssh-quickstart-*
```

### Verbose SSH Output

To debug QuickStart SSH connections, you can temporarily modify the SSH command:

```bash
# In scripts/lib/quickstart/remote.sh, find ssh_cmd() and add -v:
ssh -v $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" "$@"
```

## Getting Help

If you're still having issues:
1. Run `ssh -vvv user@target` for maximum verbosity
2. Check `/var/log/auth.log` on the target (Linux)
3. Check Event Viewer → Windows Logs → Security (Windows)
4. Open an issue at: https://github.com/brucedombrowski/security-toolkit/issues
