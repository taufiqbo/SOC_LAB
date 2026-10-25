# Network Architecture

The lab runs on a single Proxmox VE host, split across two internal bridges so the attack/telemetry traffic never touches the home network.

```mermaid
flowchart TB
    Internet((Internet))
    Analyst["Analyst workstation"]

    subgraph Proxmox["Proxmox VE Host"]
        direction TB

        subgraph vmbr0["vmbr0 — Home Network (management access only)"]
            direction TB
        end

        Wazuh["Wazuh SIEM\n10.10.10.10\nmanager + indexer + dashboard\n(dual-homed)"]

        subgraph vmbr1["vmbr1 — Isolated Lab Network (10.10.10.0/24)"]
            direction TB
            Win10["win-10-endpoint\n10.10.10.20\nSysmon + Wazuh agent"]
            Kali["kali-attacker\n10.10.10.30\npowered on only when testing"]
        end
    end

    Analyst -- "dashboard access" --> vmbr0
    vmbr0 === Wazuh
    Wazuh === vmbr1
    Win10 -- telemetry --> Wazuh
    Kali -. attacks .-> Win10
    vmbr1 -- "NAT'd, firewalled from home LAN" --> Internet
```

## Notes

- **vmbr0 (home network)** carries management/dashboard access only — the analyst reaches the Wazuh dashboard over this bridge from the home LAN.
- **vmbr1 (isolated lab network, `10.10.10.0/24`)** is NAT'd to the internet (for updates/tooling) but firewalled off from the home LAN in both directions. All attacker and endpoint traffic stays on this bridge.
- **Wazuh is dual-homed**: one NIC on each bridge. This is the only host with a presence on both networks — it receives Sysmon/agent telemetry from `win-10-endpoint` over vmbr1, and serves the dashboard to the analyst over vmbr0.
- **`kali-attacker`** is powered on only when actively running a test, rather than left running continuously.

| Role | Hostname | IP | Bridge |
|---|---|---|---|
| SIEM / Manager | wazuh | 10.10.10.10 (lab) + home-side NIC | vmbr0 + vmbr1 |
| Target endpoint | win-10-endpoint | 10.10.10.20 | vmbr1 |
| Attack host | kali-attacker | 10.10.10.30 | vmbr1 |
