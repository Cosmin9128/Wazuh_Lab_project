# Wazuh Blue Team Lab – SSH Brute-Force Detection

This small project shows how I learned to detect and document a simulated SSH brute force attack using Wazuh SIEM.  
It's my first real blue team lab, so I focused on understanding how attacks look in logs and how Wazuh alerts work.

---

## Environment

| Component | Description |
|-----------|-------------|
| Attacker  | Kali Linux running Hydra and Nmap |
| Target    | Ubuntu Server with Wazuh agent installed |
| SIEM      | Wazuh Manager and Dashboard |
| Network   | VirtualBox, bridged mode |
| Timeframe | 20–21 October 2025 |

---

## Evidence

- Nmap Scan Results (sanitized): `evidence/sanitized/nmap_full_20251020T200827Z.xml.sanitized`  
- Hydra Attack Log (sanitized): `evidence/sanitized/hydra_*.log.sanitized`  
- Wazuh Alerts Summary: `evidence/events_summary_20251020T204012Z.sanitized.csv`  
- Threat Hunting PDF Report: `evidence/reports/wazuh-module-overview-general-1761008211.pdf`

---

## MITRE ATT&CK Mapping

| Technique ID | Name                                | Detected By                         |
|--------------|-------------------------------------|-------------------------------------|
| T1046        | Network Service Scanning            | Nmap                                |
| T1110.001    | Brute-Force: Password Guessing      | Wazuh SSH rules (5710, 5712, 5758)  |
| T1078        | Valid Accounts                      | Successful SSH login                |
| T1082        | System Information Discovery        | System configuration checks         |

---

## What I Learned

- How to simulate attacks with Nmap and Hydra  
- How Wazuh detects brute-force and failed login patterns
- How Wazuh detects successful login's
- How to read alert IDs and rule levels  
- How to collect and sanitize logs before publishing  
- How to write a short incident report with real evidence  

---

## Summary

Wazuh detected several SSH brute force attempts on port **2222/tcp**.  
The alerts (5710, 5712, 5758) matched the Hydra activity I ran from Kali.  
The lab also showed how Wazuh's compliance checks report basic system configuration issues.

---

## Nessus Vulnerability Scan

I ran a Nessus basic network scan against the lab host and converted the export to CSV for easier reading. Sensitive data (IP addresses) was redacted before publishing.

**Files**
- `evidence/sanitized/report_sanitized.csv` — full scan export (sanitized).
- `evidence/sanitized/nessus_triage_top5.csv` — short triage of the top 5 critical/high findings.
- `evidence/screenshot_nessus.png` — screenshot of the scan summary .

**Quick results**
- Total findings: 181  
- Critical: 9 — immediate attention, patch or mitigate.  
- High: 5 — prioritize after criticals.  
- Medium: 23 — plan remediation.  
- Info/Low: remaining items for hardening or contextual review.
  
---

## Top 5 Critical & High Vulnerabilities (Expanded Triage)

## Nessus Vulnerability Triage

After scanning the lab VM (`DMZ-MSEXCHANGE-2013`) with Nessus, I analyzed the top 5 critical/high findings.

| Vulnerability | Severity | CVE | Port | Remediation |
|---------------|-----------|-----|------|--------------|
| SMBv1 Remote Code Execution (EternalBlue) | Critical | CVE-2017-0144 | 445/tcp | Disable SMBv1, apply KB4013389 |
| Apache HTTPD Path Traversal | Critical | CVE-2021-41773 | 80/tcp | Update Apache ≥ 2.4.51 |
| Exchange Server SSRF (ProxyShell) | Critical | CVE-2021-34473, CVE-2021-34523, CVE-2021-31207 | 443/tcp | Apply latest CU patches |
| Outdated OpenSSL Version | High | CVE-2022-0778 | 443/tcp | Update OpenSSL |
| Weak TLS/SSL Cipher Suites | High | — | 443/tcp | Disable weak ciphers, enforce TLS 1.2+ |

The scan showed several exploitable services in default configurations.  

---

## Next Steps

I want to build more small labs like this to learn SIEM tuning and threat detection.  
Next time I'll try more attack surfaces and install a Metasploit VM to expand testing capabilities
