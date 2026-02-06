# Windows Target Setup Guide

This guide covers setting up Windows hosts as targets for remote vulnerability scanning.

## Quick Start

For most users, create a dedicated local scanning account:

```cmd
net user scanuser YourSecurePassword123! /add
net localgroup administrators scanuser /add
```

Then use `scanuser` as the username when running QuickStart scans.

## Understanding Windows Account Types

### Check Your Account Type

Open Command Prompt and run:
```cmd
whoami
```

- **Local account**: Shows `COMPUTERNAME\username`
- **Microsoft account**: Shows your email address or `AzureAD\username`

### Microsoft Account Limitations

If you're using a Microsoft account (common on Windows 10/11):

1. **Cannot change password locally** - `net user` commands will fail with "The system is not authoritative for the specified account"
2. **Windows Hello PIN won't work** - SSH and SMB require actual passwords, not PINs
3. **Password managed online** - Must change via account.microsoft.com

## Recommended: Create a Local Scanning Account

For security scanning, we recommend creating a dedicated local administrator account:

```cmd
:: Run as Administrator
net user scanuser YourSecurePassword123! /add
net localgroup administrators scanuser /add
```

**Benefits:**
- Dedicated credentials for scanning
- Won't affect your daily-use account
- Easy to disable/remove after scanning
- Works with SSH and remote scanning tools

## Enabling Remote Access

### For Network Scanning (Nmap)

Nmap performs host discovery, port scanning, and service detection. Ensure:

1. **Windows Firewall** allows incoming connections (or create exceptions for scanner IP)
2. **File and Printer Sharing** is enabled (for SMB service detection):
   - Settings → Network & Internet → Advanced sharing settings
   - Turn on file and printer sharing

### For SSH-Based Scanning (Optional)

If you want SSH access to Windows:

1. **Install OpenSSH Server:**
   ```powershell
   # Run PowerShell as Administrator
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Start-Service sshd
   Set-Service -Name sshd -StartupType Automatic
   ```

2. **Configure Windows Firewall:**
   ```powershell
   New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
   ```

## Windows Hello PIN Issues

If you only have a Windows Hello PIN configured:

1. Go to **Settings → Accounts → Sign-in options**
2. Under "Password", click "Add"
3. Set a password for your Microsoft account
4. Use this password for remote scanning

**Note:** For Microsoft accounts, you may still need to create a local account for scanning.

## Troubleshooting

### "Access Denied" during scan
- Ensure the scanning account is in the Administrators group
- Check Windows Firewall settings
- Try disabling Windows Firewall temporarily for testing

### SSH connection refused
- Verify OpenSSH Server is installed and running: `Get-Service sshd`
- Check firewall allows port 22
- Verify the account has a password (not just a PIN)

### Nmap scan shows filtered ports
- Ensure Windows Firewall allows connections from the scanner IP
- Check that target services are running
- Try running Nmap with `--unprivileged` if not scanning as root

## Security Considerations

After scanning:

1. **Disable or remove** the scanning account if no longer needed:
   ```cmd
   net user scanuser /active:no
   :: or delete entirely
   net user scanuser /delete
   ```

2. **Re-enable Windows Firewall** if you disabled it

3. **Review scan results** and remediate any vulnerabilities found

## Related Issues

- SSH failure on Windows targets will show a warning but allow network-based scans (Nmap) to proceed
- Windows Defender may flag scanning activity - consider adding exceptions for the scanner IP
