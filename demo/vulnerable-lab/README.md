# Vulnerable Lab - KEV Detection Demo

This demo environment provides intentionally vulnerable software for testing the Security Verification Toolkit's KEV (Known Exploited Vulnerabilities) detection capabilities.

**WARNING: These environments contain KNOWN VULNERABILITIES. Use only in isolated test environments.**

## Two Approaches

### 1. Docker Containers (Quick Demo)

Spins up containers with vulnerable software for container security scanning.

```bash
# From repository root:

# Start vulnerable lab and scan
./scripts/scan-containers.sh

# Scan without starting lab (if containers already running)
./scripts/scan-containers.sh --no-start

# Use specific runtime
./scripts/scan-containers.sh --runtime podman
```

**Supported Runtimes:** Docker, Podman, nerdctl

### 2. Vagrant VM (Full Host Simulation)

Creates a VM with vulnerable software installed - tests the real `collect-host-inventory.sh` workflow.

**Platform Requirements:**
- **Intel Mac/Linux/Windows**: VirtualBox (free)
- **Apple Silicon (M1/M2/M3)**: VMware Fusion or Parallels Desktop (paid)
  ```bash
  # Install VMware provider plugin first
  vagrant plugin install vagrant-vmware-desktop
  vagrant up --provider=vmware_desktop
  ```

```bash
# Start the VM
vagrant up

# SSH in and run the toolkit
vagrant ssh
cd /vagrant/toolkit
./scripts/collect-host-inventory.sh
./scripts/check-nvd-cves.sh
./scripts/check-kev.sh
```

## Vulnerable Software Included

| Software | Version | CVE | Description |
|----------|---------|-----|-------------|
| Grafana | 8.3.0 | CVE-2021-43798 | Path traversal / arbitrary file read |
| Jenkins | 2.441 | CVE-2024-23897 | Arbitrary file read via CLI |
| Elasticsearch | 1.4.2 | CVE-2015-1427 | Groovy sandbox bypass RCE |
| Apache Tomcat | 9.0.30 | CVE-2020-1938 | AJP Ghostcat file read |
| Apache ActiveMQ | 5.18.2 | CVE-2023-46604 | Deserialization RCE |

All of these CVEs are in the CISA KEV catalog - meaning they have been actively exploited in the wild.

## Expected Output

When scanning the vulnerable lab, you should see:

```
==============================================
  KEV MATCHES FOUND: 5
==============================================

  [KEV MATCH] CVE-2021-43798
             Vendor: Grafana Labs
             Product: Grafana

  [KEV MATCH] CVE-2024-23897
             Vendor: Jenkins
             Product: Jenkins Command Line Interface (CLI)
  ...

WARNING: 5 Known Exploited Vulnerabilities detected!
These vulnerabilities are actively exploited in the wild.
Immediate remediation is required per CISA BOD 22-01.
```

## Cleanup

### Docker
```bash
docker-compose down -v
```

### Vagrant
```bash
vagrant destroy -f
```

## Use Cases

1. **Demo/Training** - Show stakeholders what KEV detection looks like
2. **CI/CD Testing** - Verify the scanner correctly identifies vulnerabilities
3. **Tool Validation** - Confirm detection accuracy before production deployment
4. **Security Awareness** - Educate teams on the importance of KEV remediation

## NIST Control Mapping

- **CM-8**: System Component Inventory (container/host inventory)
- **RA-5**: Vulnerability Monitoring and Scanning
- **SI-2**: Flaw Remediation (KEV-driven prioritization)
