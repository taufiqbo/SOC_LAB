# SOC_LAB

A hands-on home SOC (Security Operations Center) lab, built and documented as a phased project to develop practical blue-team / detection engineering skills.

**Author:** Taufiq Bo
**Environment:** Self-hosted on Proxmox VE, isolated lab network

---

## Overview

This project started from the MyDFIR "Build a SOC Lab" baseline and is being extended into a fuller SOC/blue-team training environment: a working SIEM (Wazuh), endpoint telemetry (Sysmon), a controlled attacker VM (Kali), and a series of phases covering network forensics, adversary emulation, phishing triage, threat hunting, and automation.

Each phase folder contains its own write-up, evidence (screenshots, logs, rule IDs), and findings — written the way a SOC analyst documents real investigation work, not as a tutorial walkthrough.

## Architecture

- **Proxmox VE host**, two internal bridges:
  - `vmbr0` — home network (management access only)
  - `vmbr1` — isolated lab network (NAT'd to the internet, firewalled off from the home LAN)
- **Wazuh** (SIEM, all-in-one) — dual-homed: one NIC on the lab network to receive telemetry, one on the home network for dashboard access
- **Windows 10 endpoint** — Sysmon (Olaf Hartong config) + Wazuh agent, lab network only
- **Kali attacker VM** — lab network only, powered on only when actively testing

Full network diagram and configuration notes: [`00-infrastructure/`](./00-infrastructure/)

## Project Phases

| Phase | Description | Status |
|---|---|---|
| [00 — Infrastructure](./00-infrastructure/) | Proxmox, networking, VM provisioning | ✅ Complete |
| [01 — Baseline SOC](./01-baseline/) | Wazuh + Sysmon detections: RDP brute force (T1110), LSASS credential dumping (T1003.001) | ✅ Complete |
| [02 — PCAP Analysis](./02-pcap-analysis/) | Wireshark/tshark investigation of real-world malware traffic captures | ⬜ Not started |
| [03 — Atomic Red Team](./03-atomic-red-team/) | ATT&CK-mapped adversary emulation and detection coverage testing | ⬜ Not started |
| [04 — Phishing Analysis](./04-phishing-analysis/) | Header/SPF/DKIM/DMARC analysis, IOC extraction | ⬜ Not started |
| [05 — Threat Hunting](./05-threat-hunting/) | Hypothesis-driven hunts, no starting alert | ⬜ Not started |
| [06 — Automation](./06-automation/) | Python alert enrichment pipeline (VirusTotal/AbuseIPDB) | ⬜ Not started |
| [07 — Capstone](./07-capstone/) | Full simulated incident, end-to-end investigation and report | ⬜ Not started |

## Highlights So Far

- Full detection chain validated end-to-end: endpoint → Sysmon → Wazuh agent → manager → alert
- Detected RDP brute-force (Hydra) and credential dumping (Mimikatz / LSASS access) with correct MITRE ATT&CK mapping
- Identified and documented a real gap in default detection coverage (no correlation between repeated auth failures and a subsequent success) — see [`01-baseline/detection-validation-report.md`](./01-baseline/detection-validation-report.md)

## Future Work

Beyond the phases above, planned follow-on projects include an Active Directory purple-team lab, a Sigma-rule detection engineering portfolio, public CTF write-ups (HTB/THM), and a cloud security lab (AWS/Azure misconfigurations).
