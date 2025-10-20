# Incident Report — Wazuh Lab: Nmap + Hydra Simulation
**Author:** Pavel Cosmin  
**Date:** 2025-10-21  
**Environment:** Home lab — Wazuh Manager + Dashboard, Ubuntu agent, Kali attacker VM  
**Classification:** Controlled lab test (non-production)

---

## 1. Executive Summary
On October 21, 2025, I performed several simulated attacks (Nmap port scan and Hydra SSH brute-force) from a Kali VM against an Ubuntu host monitored by Wazuh.  
The purpose was to validate Wazuh’s detection capability, rule correlation, and MITRE ATT&CK mapping.

Wazuh successfully generated alerts for SSH brute-force attempts, failed authentication, and network scanning.

---

## 2. Scope & Impact
- **Target:** Ubuntu Server with Wazuh agent  
- **Source:** Kali attacker (10.0.0.X – redacted)  
- **Impact:** Controlled lab only. No persistence, data exfiltration, or privilege escalation occurred.  
- **Objective:** Detection and documentation of alerts for SOC portfolio.

---

## 3. Timeline
| Time (UTC+3) | Actor | Action |
|--------------|--------|--------|
| 20:10 | Kali | Nmap -sS -Pn -p22,80,443 <REDACTED_IP> |
| 20:11 | Wazuh | Alert triggered: SSH scan detected (rule id: 5800) |
| 20:15 | Kali | Hydra brute-force attack on SSH service |
| 20:16 | Wazuh | Alert triggered: Multiple failed SSH logins (rule id: 5712) |

---

## 4. Detection Details
- Alerts exported via Wazuh API and sanitized (`evidence/alerts_sanitized.json`)  
- Alert levels: 7–10  
- MITRE ATT&CK mapping:
  - **T1110.001** — Brute Force (Password Guessing)  
  - **T1046** — Network Service Scanning  

---

## 5. Indicators of Compromise (IOCs)
- **Source IP:** `<REDACTED_IP>`  
- **Usernames:** `root`, `testuser`  
- **Modified file:** `/etc/test_wazuh_file`

---

## 6. Mitigation & Recommendations
- Disabled root login and enforced SSH key authentication  
- Configured `fail2ban` for repeated failed logins  
- Blocked attacker IP using `iptables`  
- Tuned brute-force detection rules for faster correlation  

---

## 7. SOC L1 Playbook (Response Steps)
1. **Triage** — Validate the alert and review raw event details in Wazuh Dashboard  
2. **Containment** — Block source IP temporarily via firewall  
3. **Eradication** — Verify no persistence or backdoor present  
4. **Recovery** — Restart affected service (SSH)  
5. **Lessons Learned** — Fine-tune detection rules, document incident response

---

## 8. Evidence
- `evidence/alerts_sanitized.json` — sanitized alert export  
- `evidence/commands.txt` — commands executed during simulation  
- `evidence/screenshots/alert_full.png` — visual proof from dashboard  

---

## 9. Conclusion
This lab demonstrates the ability of Wazuh to detect reconnaissance and brute-force activity.  
It serves as a realistic SOC analyst training scenario and a practical addition to my cybersecurity portfolio.
