# Threat Intelligence Integration

## Overview

This document describes the threat intelligence sources, certification requirements, and federal reporting integrations for security assessment operations using the Security Verification Toolkit.

## Personnel Certification Requirements

### Required Certifications for Security Assessors

Personnel conducting security assessments with this toolkit should hold one or more of the following certifications:

| Certification | Issuing Body | Focus Area | Relevance |
|---------------|--------------|------------|-----------|
| **CISSP** | (ISC)² | Certified Information Systems Security Professional | Broad security management, risk assessment, security architecture |
| **CISM** | ISACA | Certified Information Security Manager | Security program management, incident response, governance |
| **CEH** | EC-Council | Certified Ethical Hacker | Penetration testing, vulnerability assessment, exploit analysis |

### Certification Alignment with Toolkit Functions

| Toolkit Function | CISSP Domain | CISM Domain | CEH Module |
|------------------|--------------|-------------|------------|
| Vulnerability Scanning | Domain 6: Security Assessment | Domain 3: Information Security Program | Module 5: Vulnerability Analysis |
| Malware Detection | Domain 7: Security Operations | Domain 4: Incident Management | Module 19: Malware Threats |
| PII/Secrets Detection | Domain 2: Asset Security | Domain 2: Information Risk Management | Module 13: Social Engineering |
| Host Security Assessment | Domain 3: Security Architecture | Domain 3: Information Security Program | Module 6: System Hacking |
| Compliance Reporting | Domain 1: Security & Risk Mgmt | Domain 1: Information Security Governance | Module 20: Cryptography |

---

## CISA Known Exploited Vulnerabilities (KEV) Catalog Integration

### About the KEV Catalog

The CISA Known Exploited Vulnerabilities Catalog is the authoritative source of vulnerabilities that have been exploited in the wild. Federal agencies are required to remediate KEV entries within specified timeframes per BOD 22-01.

**Catalog URL:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Data Feed:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

### Integration Points

#### 1. Vulnerability Scan Cross-Reference

When `scan-vulnerabilities.sh` identifies CVEs, assessors should cross-reference against the KEV catalog:

```bash
# Download current KEV catalog
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o /tmp/kev-catalog.json

# Extract CVE IDs from vulnerability scan
grep -oE 'CVE-[0-9]{4}-[0-9]+' .scans/vulnerability-scan-*.txt | sort -u > /tmp/scan-cves.txt

# Check for KEV matches
jq -r '.vulnerabilities[].cveID' /tmp/kev-catalog.json | sort -u > /tmp/kev-cves.txt
comm -12 /tmp/scan-cves.txt /tmp/kev-cves.txt
```

#### 2. Decision Matrix for KEV Findings

| KEV Status | Due Date | Required Action |
|------------|----------|-----------------|
| In KEV, past due date | Immediate | **CRITICAL**: Stop work, remediate immediately |
| In KEV, within due date | Per BOD 22-01 | **HIGH**: Prioritize remediation, document timeline |
| In KEV, future due date | Plan remediation | **MEDIUM**: Schedule remediation before due date |
| Not in KEV | Standard process | Follow normal vulnerability management |

#### 3. KEV Catalog Fields

| Field | Description | Use in Assessment |
|-------|-------------|-------------------|
| `cveID` | CVE identifier | Match against scan findings |
| `vendorProject` | Affected vendor | Filter relevant findings |
| `product` | Affected product | Scope assessment |
| `vulnerabilityName` | Common name | Report clarity |
| `dateAdded` | Date added to KEV | Track emerging threats |
| `dueDate` | Remediation deadline | Compliance timeline |
| `knownRansomwareCampaignUse` | Ransomware association | Risk prioritization |

### Automated KEV Check Script

The toolkit includes `scripts/check-kev.sh` for automated KEV cross-referencing:

```bash
# Cross-reference a vulnerability scan against CISA KEV
./scripts/check-kev.sh .scans/vulnerability-scan-2026-01-15.txt

# Force refresh of KEV catalog
./scripts/check-kev.sh --force .scans/vulnerability-scan-2026-01-15.txt

# Quiet mode (only output matches)
./scripts/check-kev.sh --quiet .scans/vulnerability-scan-2026-01-15.txt

# Uses most recent scan if no file specified
./scripts/check-kev.sh
```

### Offline Mode (Air-Gapped Systems)

For security scanning on offline or air-gapped systems, the toolkit bundles a KEV catalog snapshot with each release:

- **Bundled file:** `data/kev-catalog.json`
- **SHA256 hash:** `data/kev-catalog.json.sha256`
- **Updated:** With each release (check catalog date in output)

When network is unavailable:
1. Script attempts to download latest KEV from CISA
2. Falls back to `.cache/kev-catalog.json` (if recent)
3. Falls back to bundled `data/kev-catalog.json` (offline mode)

**Note:** For maximum security, ensure the bundled catalog is recent enough for your compliance requirements. The catalog date is displayed in script output.

---

## NASA Security Operations Center - Malware Analysis Reports (SOC-MARs)

### About NASA SOC-MARs

NASA SOC-MARs are malware analysis reports produced by NASA's Security Operations Center. These reports document malware samples, indicators of compromise (IOCs), and recommended mitigations for threats observed in the federal aerospace sector.

### Access and Distribution

- **Classification:** Most SOC-MARs are TLP:AMBER or TLP:RED
- **Distribution:** NASA contractors and federal partners
- **Request Access:** Contact NASA SOC via agency ISSO

### Integration with Toolkit

#### 1. IOC Integration

When SOC-MARs are received, extract and integrate IOCs:

```bash
# Example: Add file hashes from SOC-MAR to custom ClamAV signature
# Format: MalwareName:0:*:HexSignature

# SHA256 hashes can be converted to ClamAV .hsb format
echo "NASA-SOC-MAR-2026-001:0:*:$(cat soc-mar-hashes.txt | tr '\n' ':')" \
  >> /var/lib/clamav/nasa-custom.hsb

# Reload ClamAV
sudo freshclam
```

#### 2. SOC-MAR Reference in Reports

When documenting findings that match SOC-MAR indicators:

```
Finding: Suspicious file detected
  File: /path/to/suspicious.exe
  SHA256: abc123...
  Reference: NASA SOC-MAR-2026-001
  Classification: TLP:AMBER
  Recommended Action: [Per SOC-MAR guidance]
```

#### 3. SOC-MAR Tracking

Maintain a register of applicable SOC-MARs:

| SOC-MAR ID | Date | TLP | Applicable | Status |
|------------|------|-----|------------|--------|
| SOC-MAR-2026-001 | 2026-01-15 | AMBER | Yes | IOCs integrated |
| SOC-MAR-2026-002 | 2026-01-10 | RED | No | N/A - different platform |

---

## DHS Malware Analysis Reports (MARs)

### About DHS MARs

DHS Malware Analysis Reports are produced by CISA's malware analysis team and provide detailed technical analysis of malware samples, often associated with nation-state actors or significant cybercrime campaigns.

**Public MARs:** https://www.cisa.gov/news-events/analysis-reports

### MAR Identifier Format

- Format: `MAR-XXXXXXXX-X.vX`
- Example: `MAR-10135536-8.v4` (North Korean Remote Access Tool: BLINDINGCAN)

### Integration with Toolkit

#### 1. YARA Rule Integration

Many DHS MARs include YARA rules for detection:

```bash
# Download YARA rules from MAR
# Store in toolkit custom rules directory
mkdir -p /etc/clamav/yara-rules/dhs-mars

# Example: Add MAR YARA rule
cat > /etc/clamav/yara-rules/dhs-mars/mar-10135536.yara << 'EOF'
rule MAR_10135536_BLINDINGCAN {
    meta:
        description = "Detects BLINDINGCAN RAT"
        reference = "https://www.cisa.gov/news-events/analysis-reports/ar20-232a"
        date = "2020-08-19"
    strings:
        $s1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 }
        // Additional signatures from MAR
    condition:
        any of them
}
EOF

# Configure ClamAV to use YARA rules
echo "YaraRules /etc/clamav/yara-rules/" >> /etc/clamav/clamd.conf
```

#### 2. Network IOC Integration

For network-based IOCs from MARs:

```bash
# Extract IPs and domains from MAR
# Add to network monitoring/blocking

# Example blocklist format
cat >> /etc/security/mar-blocklist.txt << 'EOF'
# MAR-10135536-8 - BLINDINGCAN C2
192.168.1.100  # Example - replace with actual IOCs
malicious-domain.com
EOF
```

#### 3. MAR Cross-Reference in Assessments

When malware is detected matching a DHS MAR:

```
=== CRITICAL FINDING ===
Detection: ClamAV signature match
  File: /path/to/malware.dll
  Signature: Win.Trojan.BLINDINGCAN
  DHS MAR Reference: MAR-10135536-8.v4

Threat Actor: Hidden Cobra (North Korea)
MITRE ATT&CK:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1547.001 (Boot or Logon Autostart Execution)

Required Actions:
  1. Isolate affected system immediately
  2. Report to SOC per incident response plan
  3. Preserve forensic evidence
  4. Follow MAR remediation guidance
```

---

## Decision Framework for Certified Assessors

### Severity Assessment Matrix

Certified assessors (CISSP/CISM/CEH) should use this matrix when evaluating findings:

| Finding Type | KEV Status | MAR/SOC-MAR Match | Severity | Required Action |
|--------------|------------|-------------------|----------|-----------------|
| CVE detected | In KEV | Yes | **CRITICAL** | Immediate isolation, incident response |
| CVE detected | In KEV | No | **HIGH** | Remediate per BOD 22-01 timeline |
| CVE detected | Not in KEV | Yes | **HIGH** | Investigate, potential targeted attack |
| CVE detected | Not in KEV | No | **MEDIUM** | Standard remediation process |
| Malware detected | N/A | Yes | **CRITICAL** | Incident response, forensics |
| Malware detected | N/A | No | **HIGH** | Isolate, analyze, remediate |
| PII/Secrets exposed | N/A | N/A | **HIGH** | Contain, assess breach scope |
| Configuration issue | N/A | N/A | **MEDIUM/LOW** | Remediate per policy |

### Escalation Criteria

| Condition | Escalate To | Timeframe |
|-----------|-------------|-----------|
| KEV match past due date | CISO, Agency SOC | Immediate |
| DHS MAR match | CISO, CISA | Within 1 hour |
| NASA SOC-MAR match | NASA SOC, Project Security | Within 1 hour |
| Ransomware indicators | Incident Response Team | Immediate |
| Data breach indicators | Privacy Officer, Legal | Within 4 hours |

---

## Automated Threat Intelligence Workflow

### Recommended Integration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Verification Toolkit                 │
├─────────────────────────────────────────────────────────────────┤
│  Scan Outputs                                                    │
│  ├── vulnerability-scan-*.txt (CVEs)                            │
│  ├── malware-scan-*.txt (Hashes, signatures)                    │
│  └── host-security-*.txt (Configuration)                        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Threat Intelligence Enrichment                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  CISA KEV    │  │  DHS MARs    │  │  NASA SOC-MARs       │  │
│  │  Catalog     │  │  (Public)    │  │  (TLP:AMBER/RED)     │  │
│  │  (JSON feed) │  │  (YARA/IOCs) │  │  (IOCs per access)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └────────────────┼──────────────────────┘              │
│                          │                                      │
│                          ▼                                      │
│              ┌───────────────────────┐                         │
│              │   Correlation Engine   │                         │
│              │   (Cross-reference     │                         │
│              │    findings vs TI)     │                         │
│              └───────────┬───────────┘                         │
└──────────────────────────┼──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Enriched Assessment Report                    │
├─────────────────────────────────────────────────────────────────┤
│  • Findings with KEV status                                     │
│  • MAR/SOC-MAR cross-references                                 │
│  • Severity adjusted for threat intelligence                    │
│  • Recommended actions with federal compliance context          │
└─────────────────────────────────────────────────────────────────┘
```

---

## References

### CISA Resources
- KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- BOD 22-01: https://www.cisa.gov/binding-operational-directive-22-01
- Analysis Reports: https://www.cisa.gov/news-events/analysis-reports

### Certification Bodies
- (ISC)² CISSP: https://www.isc2.org/certifications/cissp
- ISACA CISM: https://www.isaca.org/credentialing/cism
- EC-Council CEH: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/

### Federal Guidance
- NIST SP 800-53: Security and Privacy Controls
- NIST SP 800-171: Protecting CUI
- BOD 22-01: Reducing Significant Risk of Known Exploited Vulnerabilities

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-16 | Security Team | Initial release |

**Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY
**Review Schedule:** Quarterly or upon new MAR/KEV guidance
