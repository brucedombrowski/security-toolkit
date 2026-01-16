<#
.SYNOPSIS
    Host Inventory Collection Script for Windows

.DESCRIPTION
    Collects detailed host system information for audit/compliance including:
    - OS version, build, architecture
    - Network interfaces with MAC addresses
    - Installed software packages
    - Security tools, programming languages, browsers
    - Productivity software, containers, web servers, databases

    SENSITIVE: This script collects MAC addresses and system inventory.
    Output is classified as CONTROLLED UNCLASSIFIED INFORMATION (CUI)
    and handled according to NIST SP 800-171 and 32 CFR Part 2002

.PARAMETER OutputFile
    Optional path to save inventory output. If not specified, saves to user's Desktop
    with filename: host-inventory-COMPUTERNAME-YYYY-MM-DD.txt

.PARAMETER NoFile
    If specified, outputs to console instead of saving to a file.

.EXAMPLE
    .\Collect-HostInventory.ps1
    Saves inventory to user's Desktop

.EXAMPLE
    .\Collect-HostInventory.ps1 -NoFile
    Outputs inventory to console only

.EXAMPLE
    .\Collect-HostInventory.ps1 -OutputFile "C:\Scans\inventory.txt"
    Saves inventory to specified file

.NOTES
    Standards:
      - NIST SP 800-53: CM-8 (System Component Inventory), AC-3 (Access Control)
      - NIST SP 800-171: CUI protection requirements
      - 32 CFR Part 2002: CUI handling standards
      - NIST SP 800-88: Secure deletion of digital media

    Exit codes:
      0 = Success
      1 = Error collecting inventory
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,

    [Parameter(Mandatory=$false)]
    [switch]$NoFile
)

# Use SilentlyContinue to prevent terminating errors
$ErrorActionPreference = "SilentlyContinue"

# Set default output file to user's Desktop if not specified and -NoFile not used
if (-not $OutputFile -and -not $NoFile) {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $datestamp = (Get-Date).ToString("yyyy-MM-dd")
    $hostname = $env:COMPUTERNAME
    $OutputFile = Join-Path $desktopPath "host-inventory-$hostname-$datestamp.txt"
}

# Check if running elevated
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Script metadata
$TIMESTAMP = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$TOOLKIT_VERSION = "1.15.0"
$TOOLKIT_SOURCE = "https://github.com/brucedombrowski/Security"

# Output buffer for file writing
$script:OutputBuffer = @()

function Write-Output-Line {
    param([string]$Line = "")
    if ($OutputFile) {
        $script:OutputBuffer += $Line
    } else {
        Write-Host $Line
    }
}

function Get-CommandVersion {
    param(
        [string]$Command,
        [string]$Arguments = "--version",
        [switch]$StdErr
    )
    try {
        $result = if ($StdErr) {
            & $Command $Arguments.Split(" ") 2>&1 | Select-Object -First 1
        } else {
            & $Command $Arguments.Split(" ") 2>$null | Select-Object -First 1
        }
        if ($result) { return $result.ToString().Trim() }
    } catch {}
    return $null
}

function Test-CommandExists {
    param([string]$Command)
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Get-InstalledApp {
    param([string]$Name)
    $app = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -like "*$Name*" } |
           Select-Object -First 1
    return $app
}

function Get-InstalledAppVersion {
    param([string]$Name)
    $app = Get-InstalledApp -Name $Name
    if ($app -and $app.DisplayVersion) {
        return $app.DisplayVersion
    }
    return $null
}

# Display CUI warning
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host "  SECURITY WARNING: CONTROLLED UNCLASSIFIED INFORMATION (CUI)" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Host inventory file contains CUI per NIST SP 800-171 and 32 CFR Part 2002:" -ForegroundColor Yellow
Write-Host ""
if ($OutputFile) {
    Write-Host "  Location: $OutputFile" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "This file includes sensitive system information:" -ForegroundColor Yellow
Write-Host "  - MAC addresses (network topology identification)"
Write-Host "  - Hardware serial numbers (device identity)"
Write-Host "  - Installed software versions (attack surface analysis)"
Write-Host "  - System configuration details (security control details)"
Write-Host ""
Write-Host "REQUIRED HANDLING:" -ForegroundColor Red
Write-Host "  1. Keep file permission-restricted - verify with: icacls"
Write-Host "  2. Never upload to public cloud storage or repositories"
Write-Host "  3. Never commit to version control (even private)"
Write-Host "  4. Store on encrypted media or encrypted filesystems"
Write-Host "  5. Delete securely when no longer needed (use cipher /w or SDelete)"
Write-Host ""

if (-not $isAdmin) {
    Write-Host "NOTE: Running without Administrator privileges." -ForegroundColor Cyan
    Write-Host "      Some features (Windows Defender, Hyper-V, IIS) will show 'requires elevation'." -ForegroundColor Cyan
    Write-Host "      Run as Administrator for complete inventory." -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# BEGIN INVENTORY OUTPUT
# ============================================================================

Write-Output-Line "////////////////////////////////////////////////////////////////////////////////"
Write-Output-Line "//                                                                            //"
Write-Output-Line "//                 CONTROLLED UNCLASSIFIED INFORMATION (CUI)                  //"
Write-Output-Line "//                                                                            //"
Write-Output-Line "//  CUI Category: CTI (Controlled Technical Information)                      //"
Write-Output-Line "//  Dissemination: FEDCON - Federal Contractors                               //"
Write-Output-Line "//  Safeguarding: Per NIST SP 800-171                                         //"
Write-Output-Line "//                                                                            //"
Write-Output-Line "////////////////////////////////////////////////////////////////////////////////"
Write-Output-Line ""
Write-Output-Line "Host System Inventory"
Write-Output-Line "====================="
Write-Output-Line "Generated: $TIMESTAMP"
Write-Output-Line "Hostname: $env:COMPUTERNAME"
Write-Output-Line "Toolkit: Security Verification Toolkit v$TOOLKIT_VERSION (PowerShell)"
Write-Output-Line "Source: $TOOLKIT_SOURCE"
Write-Output-Line "Elevated: $(if ($isAdmin) { 'Yes' } else { 'No (some features unavailable)' })"
Write-Output-Line ""
Write-Output-Line "HANDLING NOTICE:"
Write-Output-Line "  This document contains Controlled Unclassified Information (CUI)."
Write-Output-Line "  Contents include MAC addresses, serial numbers, and system inventory."
Write-Output-Line "  - Do not post to public repositories or websites"
Write-Output-Line "  - Limit distribution to authorized personnel"
Write-Output-Line "  - Store on encrypted media or systems"
Write-Output-Line "  - Destroy with: cipher /w or SDelete (NIST SP 800-88)"
Write-Output-Line ""

# ============================================================================
# OS AND SYSTEM INFORMATION
# ============================================================================

Write-Output-Line "Operating System Information:"
Write-Output-Line "-----------------------------"

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

Write-Output-Line "  Platform: Windows"
Write-Output-Line "  OS Version: $($os.Caption) $($os.Version)"
Write-Output-Line "  Build: $($os.BuildNumber)"
Write-Output-Line "  Architecture: $($os.OSArchitecture)"
Write-Output-Line "  Hardware Model: $($cs.Manufacturer) $($cs.Model)"
Write-Output-Line "  Serial Number: $($bios.SerialNumber)"
Write-Output-Line "  Domain: $($cs.Domain)"
Write-Output-Line "  Total Memory: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB"
Write-Output-Line ""

# ============================================================================
# NETWORK INTERFACES WITH MAC ADDRESSES
# ============================================================================

Write-Output-Line "Network Interfaces:"
Write-Output-Line "-------------------"

$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.MacAddress }

foreach ($adapter in $adapters) {
    Write-Output-Line "  $($adapter.Name):"
    Write-Output-Line "    MAC Address: $($adapter.MacAddress)"
    Write-Output-Line "    Status: $($adapter.Status)"
    Write-Output-Line "    Link Speed: $($adapter.LinkSpeed)"
    Write-Output-Line "    Interface Type: $($adapter.InterfaceDescription)"

    # Get IP addresses for this adapter
    $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
    $ipv4 = $ipConfig | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
    $ipv6 = $ipConfig | Where-Object { $_.AddressFamily -eq 'IPv6' -and $_.IPAddress -notlike 'fe80*' } | Select-Object -First 1

    if ($ipv4) { Write-Output-Line "    IPv4: $($ipv4.IPAddress)" }
    if ($ipv6) { Write-Output-Line "    IPv6: $($ipv6.IPAddress)" }
}
Write-Output-Line ""

# ============================================================================
# INSTALLED SOFTWARE PACKAGES
# ============================================================================

Write-Output-Line "Installed Software Packages:"
Write-Output-Line "----------------------------"

$installedSoftware = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                      "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName } |
                     Sort-Object DisplayName |
                     Select-Object -First 100

foreach ($software in $installedSoftware) {
    $version = if ($software.DisplayVersion) { $software.DisplayVersion } else { "unknown" }
    Write-Output-Line "    $($software.DisplayName): $version"
}

$totalCount = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName }).Count

if ($totalCount -gt 100) {
    Write-Output-Line "    ... and $($totalCount - 100) more packages (total: $totalCount)"
}
Write-Output-Line ""

# ============================================================================
# SECURITY TOOLS
# ============================================================================

Write-Output-Line "Security Tools:"
Write-Output-Line "---------------"

# Windows Defender (requires elevation)
if ($isAdmin) {
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        if ($defender) {
            Write-Output-Line "  Windows Defender: Enabled (Engine: $($defender.AMEngineVersion))"
            Write-Output-Line "    Antivirus Signature: $($defender.AntivirusSignatureVersion)"
            Write-Output-Line "    Real-time Protection: $($defender.RealTimeProtectionEnabled)"
        } else {
            Write-Output-Line "  Windows Defender: not available"
        }
    } catch {
        Write-Output-Line "  Windows Defender: unable to query"
    }
} else {
    Write-Output-Line "  Windows Defender: requires elevation"
}

# ClamAV
$clamVersion = Get-CommandVersion -Command "clamscan" -Arguments "--version"
if ($clamVersion) {
    Write-Output-Line "  ClamAV: $clamVersion"
} else {
    Write-Output-Line "  ClamAV: not installed"
}

# OpenSSL
$opensslVersion = Get-CommandVersion -Command "openssl" -Arguments "version"
if ($opensslVersion) {
    Write-Output-Line "  OpenSSL: $opensslVersion"
} else {
    Write-Output-Line "  OpenSSL: not installed"
}

# SSH
$sshVersion = Get-CommandVersion -Command "ssh" -Arguments "-V" -StdErr
if ($sshVersion) {
    Write-Output-Line "  SSH: $sshVersion"
} else {
    Write-Output-Line "  SSH: not installed"
}

# GPG
$gpgVersion = Get-CommandVersion -Command "gpg" -Arguments "--version"
if ($gpgVersion) {
    Write-Output-Line "  GPG: $gpgVersion"
} else {
    Write-Output-Line "  GPG: not installed"
}

# Git
$gitVersion = Get-CommandVersion -Command "git" -Arguments "--version"
if ($gitVersion) {
    Write-Output-Line "  Git: $gitVersion"
} else {
    Write-Output-Line "  Git: not installed"
}

Write-Output-Line ""

# ============================================================================
# PROGRAMMING LANGUAGES
# ============================================================================

Write-Output-Line "Programming Languages:"
Write-Output-Line "----------------------"

# Python
$pythonVersion = Get-CommandVersion -Command "python" -Arguments "--version"
if (-not $pythonVersion) { $pythonVersion = Get-CommandVersion -Command "python3" -Arguments "--version" }
if ($pythonVersion) { Write-Output-Line "  Python: $pythonVersion" } else { Write-Output-Line "  Python: not installed" }

# Node.js
$nodeVersion = Get-CommandVersion -Command "node" -Arguments "--version"
if ($nodeVersion) { Write-Output-Line "  Node.js: $nodeVersion" } else { Write-Output-Line "  Node.js: not installed" }

# Java
$javaVersion = Get-CommandVersion -Command "java" -Arguments "-version" -StdErr
if ($javaVersion) { Write-Output-Line "  Java: $javaVersion" } else { Write-Output-Line "  Java: not installed" }

# .NET
$dotnetVersion = Get-CommandVersion -Command "dotnet" -Arguments "--version"
if ($dotnetVersion) { Write-Output-Line "  .NET: $dotnetVersion" } else { Write-Output-Line "  .NET: not installed" }

# Ruby
$rubyVersion = Get-CommandVersion -Command "ruby" -Arguments "--version"
if ($rubyVersion) { Write-Output-Line "  Ruby: $rubyVersion" } else { Write-Output-Line "  Ruby: not installed" }

# Go
$goVersion = Get-CommandVersion -Command "go" -Arguments "version"
if ($goVersion) { Write-Output-Line "  Go: $goVersion" } else { Write-Output-Line "  Go: not installed" }

# Rust
$rustVersion = Get-CommandVersion -Command "rustc" -Arguments "--version"
if ($rustVersion) { Write-Output-Line "  Rust: $rustVersion" } else { Write-Output-Line "  Rust: not installed" }

# Perl
$perlVersion = Get-CommandVersion -Command "perl" -Arguments "--version"
if ($perlVersion) {
    $perlMatch = [regex]::Match($perlVersion, 'v[\d.]+')
    Write-Output-Line "  Perl: $($perlMatch.Value)"
} else {
    Write-Output-Line "  Perl: not installed"
}

# PHP
$phpVersion = Get-CommandVersion -Command "php" -Arguments "--version"
if ($phpVersion) { Write-Output-Line "  PHP: $phpVersion" } else { Write-Output-Line "  PHP: not installed" }

# PowerShell
Write-Output-Line "  PowerShell: $($PSVersionTable.PSVersion.ToString())"

# Lua
$luaVersion = Get-CommandVersion -Command "lua" -Arguments "-v" -StdErr
if ($luaVersion) { Write-Output-Line "  Lua: $luaVersion" } else { Write-Output-Line "  Lua: not installed" }

# R
$rVersion = Get-CommandVersion -Command "R" -Arguments "--version"
if ($rVersion) { Write-Output-Line "  R: $rVersion" } else { Write-Output-Line "  R: not installed" }

# Kotlin
$kotlinVersion = Get-CommandVersion -Command "kotlin" -Arguments "-version" -StdErr
if ($kotlinVersion) { Write-Output-Line "  Kotlin: $kotlinVersion" } else { Write-Output-Line "  Kotlin: not installed" }

# Scala
$scalaVersion = Get-CommandVersion -Command "scala" -Arguments "-version" -StdErr
if ($scalaVersion) { Write-Output-Line "  Scala: $scalaVersion" } else { Write-Output-Line "  Scala: not installed" }

# Groovy
$groovyVersion = Get-CommandVersion -Command "groovy" -Arguments "--version"
if ($groovyVersion) { Write-Output-Line "  Groovy: $groovyVersion" } else { Write-Output-Line "  Groovy: not installed" }

# TypeScript
$tscVersion = Get-CommandVersion -Command "tsc" -Arguments "--version"
if ($tscVersion) { Write-Output-Line "  TypeScript: $tscVersion" } else { Write-Output-Line "  TypeScript: not installed" }

# Elixir
$elixirVersion = Get-CommandVersion -Command "elixir" -Arguments "--version"
if ($elixirVersion) { Write-Output-Line "  Elixir: $elixirVersion" } else { Write-Output-Line "  Elixir: not installed" }

# Haskell (GHC)
$ghcVersion = Get-CommandVersion -Command "ghc" -Arguments "--version"
if ($ghcVersion) { Write-Output-Line "  Haskell (GHC): $ghcVersion" } else { Write-Output-Line "  Haskell (GHC): not installed" }

# Julia
$juliaVersion = Get-CommandVersion -Command "julia" -Arguments "--version"
if ($juliaVersion) { Write-Output-Line "  Julia: $juliaVersion" } else { Write-Output-Line "  Julia: not installed" }

Write-Output-Line ""

# ============================================================================
# WEB BROWSERS
# ============================================================================

Write-Output-Line "Web Browsers:"
Write-Output-Line "-------------"

# Chrome
$chromePath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
$chromePath86 = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
if (Test-Path $chromePath) {
    $chromeVersion = (Get-Item $chromePath).VersionInfo.ProductVersion
    Write-Output-Line "  Chrome: $chromeVersion"
} elseif (Test-Path $chromePath86) {
    $chromeVersion = (Get-Item $chromePath86).VersionInfo.ProductVersion
    Write-Output-Line "  Chrome: $chromeVersion"
} else {
    Write-Output-Line "  Chrome: not installed"
}

# Firefox
$firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
$firefoxPath86 = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
if (Test-Path $firefoxPath) {
    $firefoxVersion = (Get-Item $firefoxPath).VersionInfo.ProductVersion
    Write-Output-Line "  Firefox: $firefoxVersion"
} elseif (Test-Path $firefoxPath86) {
    $firefoxVersion = (Get-Item $firefoxPath86).VersionInfo.ProductVersion
    Write-Output-Line "  Firefox: $firefoxVersion"
} else {
    Write-Output-Line "  Firefox: not installed"
}

# Microsoft Edge
$edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if (Test-Path $edgePath) {
    $edgeVersion = (Get-Item $edgePath).VersionInfo.ProductVersion
    Write-Output-Line "  Edge: $edgeVersion"
} else {
    Write-Output-Line "  Edge: not installed"
}

# Brave
$bravePath = "${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe"
$bravePath86 = "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe"
if (Test-Path $bravePath) {
    $braveVersion = (Get-Item $bravePath).VersionInfo.ProductVersion
    Write-Output-Line "  Brave: $braveVersion"
} elseif (Test-Path $bravePath86) {
    $braveVersion = (Get-Item $bravePath86).VersionInfo.ProductVersion
    Write-Output-Line "  Brave: $braveVersion"
} else {
    Write-Output-Line "  Brave: not installed"
}

# Internet Explorer (legacy)
$iePath = "${env:ProgramFiles}\Internet Explorer\iexplore.exe"
if (Test-Path $iePath) {
    $ieVersion = (Get-Item $iePath).VersionInfo.ProductVersion
    Write-Output-Line "  Internet Explorer: $ieVersion (legacy)"
}

Write-Output-Line ""

# ============================================================================
# BACKUP AND RESTORE SOFTWARE
# ============================================================================

Write-Output-Line "Backup and Restore Software:"
Write-Output-Line "----------------------------"

# Windows Backup (requires elevation)
if ($isAdmin) {
    try {
        $windowsBackup = Get-WindowsOptionalFeature -Online -FeatureName "WindowsServerBackup" -ErrorAction Stop
        if ($windowsBackup -and $windowsBackup.State -eq "Enabled") {
            Write-Output-Line "  Windows Server Backup: enabled"
        } else {
            Write-Output-Line "  Windows Server Backup: not enabled"
        }
    } catch {
        Write-Output-Line "  Windows Server Backup: unable to query"
    }
} else {
    Write-Output-Line "  Windows Server Backup: requires elevation"
}

# File History
$fileHistory = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory" -ErrorAction SilentlyContinue
if ($fileHistory) {
    Write-Output-Line "  File History: configured"
} else {
    Write-Output-Line "  File History: not configured"
}

# Veeam
$veeamVersion = Get-InstalledAppVersion "Veeam"
if ($veeamVersion) { Write-Output-Line "  Veeam: $veeamVersion" } else { Write-Output-Line "  Veeam: not installed" }

# Acronis
$acronisVersion = Get-InstalledAppVersion "Acronis"
if ($acronisVersion) { Write-Output-Line "  Acronis: $acronisVersion" } else { Write-Output-Line "  Acronis: not installed" }

# Backblaze
$backblazeVersion = Get-InstalledAppVersion "Backblaze"
if ($backblazeVersion) { Write-Output-Line "  Backblaze: $backblazeVersion" } else { Write-Output-Line "  Backblaze: not installed" }

Write-Output-Line ""

# ============================================================================
# REMOTE DESKTOP / CONTROL SOFTWARE
# ============================================================================

Write-Output-Line "Remote Desktop / Control Software:"
Write-Output-Line "-----------------------------------"

# Remote Desktop
$rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
if ($rdp.fDenyTSConnections -eq 0) {
    Write-Output-Line "  Remote Desktop: enabled"
} else {
    Write-Output-Line "  Remote Desktop: disabled"
}

# TeamViewer
$teamviewerVersion = Get-InstalledAppVersion "TeamViewer"
if ($teamviewerVersion) { Write-Output-Line "  TeamViewer: $teamviewerVersion" } else { Write-Output-Line "  TeamViewer: not installed" }

# AnyDesk
$anydeskVersion = Get-InstalledAppVersion "AnyDesk"
if ($anydeskVersion) { Write-Output-Line "  AnyDesk: $anydeskVersion" } else { Write-Output-Line "  AnyDesk: not installed" }

# Zoom
$zoomVersion = Get-InstalledAppVersion "Zoom"
if ($zoomVersion) { Write-Output-Line "  Zoom: $zoomVersion" } else { Write-Output-Line "  Zoom: not installed" }

# VNC
$vncVersion = Get-InstalledAppVersion "VNC"
if ($vncVersion) { Write-Output-Line "  VNC: $vncVersion" } else { Write-Output-Line "  VNC: not installed" }

# LogMeIn
$logmeinVersion = Get-InstalledAppVersion "LogMeIn"
if ($logmeinVersion) { Write-Output-Line "  LogMeIn: $logmeinVersion" } else { Write-Output-Line "  LogMeIn: not installed" }

Write-Output-Line ""

# ============================================================================
# PRODUCTIVITY SOFTWARE
# ============================================================================

Write-Output-Line "Productivity Software:"
Write-Output-Line "----------------------"

# Microsoft Word
$wordPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\WINWORD.EXE"
$wordPath86 = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINWORD.EXE"
if (Test-Path $wordPath) {
    $wordVersion = (Get-Item $wordPath).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft Word: $wordVersion"
} elseif (Test-Path $wordPath86) {
    $wordVersion = (Get-Item $wordPath86).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft Word: $wordVersion"
} else {
    $wordVersion = Get-InstalledAppVersion "Microsoft Word"
    if ($wordVersion) { Write-Output-Line "  Microsoft Word: $wordVersion" } else { Write-Output-Line "  Microsoft Word: not installed" }
}

# Microsoft Excel
$excelPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\EXCEL.EXE"
$excelPath86 = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\EXCEL.EXE"
if (Test-Path $excelPath) {
    $excelVersion = (Get-Item $excelPath).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft Excel: $excelVersion"
} elseif (Test-Path $excelPath86) {
    $excelVersion = (Get-Item $excelPath86).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft Excel: $excelVersion"
} else {
    $excelVersion = Get-InstalledAppVersion "Microsoft Excel"
    if ($excelVersion) { Write-Output-Line "  Microsoft Excel: $excelVersion" } else { Write-Output-Line "  Microsoft Excel: not installed" }
}

# Microsoft PowerPoint
$pptPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\POWERPNT.EXE"
$pptPath86 = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\POWERPNT.EXE"
if (Test-Path $pptPath) {
    $pptVersion = (Get-Item $pptPath).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft PowerPoint: $pptVersion"
} elseif (Test-Path $pptPath86) {
    $pptVersion = (Get-Item $pptPath86).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft PowerPoint: $pptVersion"
} else {
    $pptVersion = Get-InstalledAppVersion "Microsoft PowerPoint"
    if ($pptVersion) { Write-Output-Line "  Microsoft PowerPoint: $pptVersion" } else { Write-Output-Line "  Microsoft PowerPoint: not installed" }
}

# Microsoft Outlook
$outlookPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\OUTLOOK.EXE"
$outlookPath86 = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"
if (Test-Path $outlookPath) {
    $outlookVersion = (Get-Item $outlookPath).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft Outlook: $outlookVersion"
} elseif (Test-Path $outlookPath86) {
    $outlookVersion = (Get-Item $outlookPath86).VersionInfo.ProductVersion
    Write-Output-Line "  Microsoft Outlook: $outlookVersion"
} else {
    $outlookVersion = Get-InstalledAppVersion "Microsoft Outlook"
    if ($outlookVersion) { Write-Output-Line "  Microsoft Outlook: $outlookVersion" } else { Write-Output-Line "  Microsoft Outlook: not installed" }
}

# Microsoft Teams
$teamsVersion = Get-InstalledAppVersion "Microsoft Teams"
if ($teamsVersion) { Write-Output-Line "  Microsoft Teams: $teamsVersion" } else { Write-Output-Line "  Microsoft Teams: not installed" }

# LibreOffice
$libreVersion = Get-InstalledAppVersion "LibreOffice"
if ($libreVersion) { Write-Output-Line "  LibreOffice: $libreVersion" } else { Write-Output-Line "  LibreOffice: not installed" }

# Slack
$slackVersion = Get-InstalledAppVersion "Slack"
if ($slackVersion) { Write-Output-Line "  Slack: $slackVersion" } else { Write-Output-Line "  Slack: not installed" }

# Cisco Webex
$webexVersion = Get-InstalledAppVersion "Webex"
if ($webexVersion) { Write-Output-Line "  Cisco Webex: $webexVersion" } else { Write-Output-Line "  Cisco Webex: not installed" }

# Discord
$discordVersion = Get-InstalledAppVersion "Discord"
if ($discordVersion) { Write-Output-Line "  Discord: $discordVersion" } else { Write-Output-Line "  Discord: not installed" }

# Skype
$skypeVersion = Get-InstalledAppVersion "Skype"
if ($skypeVersion) { Write-Output-Line "  Skype: $skypeVersion" } else { Write-Output-Line "  Skype: not installed" }

Write-Output-Line ""

# ============================================================================
# CONTAINERS AND VIRTUALIZATION
# ============================================================================

Write-Output-Line "Containers and Virtualization:"
Write-Output-Line "------------------------------"

# Docker
$dockerVersion = Get-CommandVersion -Command "docker" -Arguments "--version"
if ($dockerVersion) { Write-Output-Line "  Docker: $dockerVersion" } else { Write-Output-Line "  Docker: not installed" }

# Podman
$podmanVersion = Get-CommandVersion -Command "podman" -Arguments "--version"
if ($podmanVersion) { Write-Output-Line "  Podman: $podmanVersion" } else { Write-Output-Line "  Podman: not installed" }

# kubectl
$kubectlVersion = Get-CommandVersion -Command "kubectl" -Arguments "version --client"
if ($kubectlVersion) { Write-Output-Line "  kubectl: $kubectlVersion" } else { Write-Output-Line "  kubectl: not installed" }

# Minikube
$minikubeVersion = Get-CommandVersion -Command "minikube" -Arguments "version"
if ($minikubeVersion) { Write-Output-Line "  Minikube: $minikubeVersion" } else { Write-Output-Line "  Minikube: not installed" }

# Helm
$helmVersion = Get-CommandVersion -Command "helm" -Arguments "version --short"
if ($helmVersion) { Write-Output-Line "  Helm: $helmVersion" } else { Write-Output-Line "  Helm: not installed" }

# Vagrant
$vagrantVersion = Get-CommandVersion -Command "vagrant" -Arguments "--version"
if ($vagrantVersion) { Write-Output-Line "  Vagrant: $vagrantVersion" } else { Write-Output-Line "  Vagrant: not installed" }

# VirtualBox
$vboxVersion = Get-InstalledAppVersion "VirtualBox"
if ($vboxVersion) { Write-Output-Line "  VirtualBox: $vboxVersion" } else { Write-Output-Line "  VirtualBox: not installed" }

# VMware Workstation
$vmwareVersion = Get-InstalledAppVersion "VMware Workstation"
if ($vmwareVersion) { Write-Output-Line "  VMware Workstation: $vmwareVersion" } else { Write-Output-Line "  VMware Workstation: not installed" }

# Hyper-V (requires elevation)
if ($isAdmin) {
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V" -ErrorAction Stop
        if ($hyperv -and $hyperv.State -eq "Enabled") {
            Write-Output-Line "  Hyper-V: enabled"
        } else {
            Write-Output-Line "  Hyper-V: not enabled"
        }
    } catch {
        Write-Output-Line "  Hyper-V: unable to query"
    }
} else {
    Write-Output-Line "  Hyper-V: requires elevation"
}

# WSL
$wslVersion = Get-CommandVersion -Command "wsl" -Arguments "--version"
if ($wslVersion) { Write-Output-Line "  WSL: $wslVersion" } else { Write-Output-Line "  WSL: not installed" }

Write-Output-Line ""

# ============================================================================
# WEB SERVERS
# ============================================================================

Write-Output-Line "Web Servers:"
Write-Output-Line "------------"

# IIS (requires elevation for full check)
if ($isAdmin) {
    try {
        $iis = Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -ErrorAction Stop
        if ($iis -and $iis.State -eq "Enabled") {
            $iisVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
            Write-Output-Line "  IIS: $iisVersion"
        } else {
            Write-Output-Line "  IIS: not installed"
        }
    } catch {
        Write-Output-Line "  IIS: unable to query"
    }
} else {
    # Can still check registry without elevation
    $iisVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if ($iisVersion) {
        Write-Output-Line "  IIS: $iisVersion"
    } else {
        Write-Output-Line "  IIS: not detected (run elevated for full check)"
    }
}

# Apache
$apacheVersion = Get-CommandVersion -Command "httpd" -Arguments "-v"
if ($apacheVersion) { Write-Output-Line "  Apache: $apacheVersion" } else { Write-Output-Line "  Apache: not installed" }

# Nginx
$nginxVersion = Get-CommandVersion -Command "nginx" -Arguments "-v" -StdErr
if ($nginxVersion) { Write-Output-Line "  Nginx: $nginxVersion" } else { Write-Output-Line "  Nginx: not installed" }

# Caddy
$caddyVersion = Get-CommandVersion -Command "caddy" -Arguments "version"
if ($caddyVersion) { Write-Output-Line "  Caddy: $caddyVersion" } else { Write-Output-Line "  Caddy: not installed" }

# Traefik
$traefikVersion = Get-CommandVersion -Command "traefik" -Arguments "version"
if ($traefikVersion) { Write-Output-Line "  Traefik: $traefikVersion" } else { Write-Output-Line "  Traefik: not installed" }

Write-Output-Line ""

# ============================================================================
# DATABASE SERVERS
# ============================================================================

Write-Output-Line "Database Servers:"
Write-Output-Line "-----------------"

# SQL Server
$sqlServerVersion = Get-InstalledAppVersion "SQL Server"
if ($sqlServerVersion) { Write-Output-Line "  SQL Server: $sqlServerVersion" } else { Write-Output-Line "  SQL Server: not installed" }

# PostgreSQL
$psqlVersion = Get-CommandVersion -Command "psql" -Arguments "--version"
if ($psqlVersion) { Write-Output-Line "  PostgreSQL: $psqlVersion" } else { Write-Output-Line "  PostgreSQL: not installed" }

# MySQL
$mysqlVersion = Get-CommandVersion -Command "mysql" -Arguments "--version"
if ($mysqlVersion) { Write-Output-Line "  MySQL: $mysqlVersion" } else { Write-Output-Line "  MySQL: not installed" }

# SQLite
$sqliteVersion = Get-CommandVersion -Command "sqlite3" -Arguments "--version"
if ($sqliteVersion) { Write-Output-Line "  SQLite: $sqliteVersion" } else { Write-Output-Line "  SQLite: not installed" }

# MongoDB
$mongoVersion = Get-CommandVersion -Command "mongod" -Arguments "--version"
if ($mongoVersion) { Write-Output-Line "  MongoDB: $mongoVersion" } else { Write-Output-Line "  MongoDB: not installed" }

# Redis
$redisVersion = Get-CommandVersion -Command "redis-server" -Arguments "--version"
if ($redisVersion) { Write-Output-Line "  Redis: $redisVersion" } else { Write-Output-Line "  Redis: not installed" }

Write-Output-Line ""

# ============================================================================
# FOOTER
# ============================================================================

Write-Output-Line "====================="
Write-Output-Line "Inventory collection complete."
Write-Output-Line ""
Write-Output-Line "////////////////////////////////////////////////////////////////////////////////"
Write-Output-Line "//                                                                            //"
Write-Output-Line "//                 CONTROLLED UNCLASSIFIED INFORMATION (CUI)                  //"
Write-Output-Line "//                                                                            //"
Write-Output-Line "//  Reference: 32 CFR Part 2002, NIST SP 800-171                              //"
Write-Output-Line "//  Unauthorized disclosure subject to administrative/civil penalties         //"
Write-Output-Line "//                                                                            //"
Write-Output-Line "////////////////////////////////////////////////////////////////////////////////"

# Write to file if specified
if ($OutputFile) {
    try {
        $script:OutputBuffer | Out-File -FilePath $OutputFile -Encoding UTF8 -Force

        # Set restrictive permissions (owner only)
        $acl = Get-Acl $OutputFile
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $OutputFile -AclObject $acl -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host "Inventory saved to: $OutputFile" -ForegroundColor Green
    } catch {
        Write-Error "Failed to write output file: $_"
        exit 1
    }
}

exit 0
