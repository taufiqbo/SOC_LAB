# Phase 2: PCAP Analysis

Network traffic analysis using Wireshark/tshark against real-world malware capture datasets (malware-traffic-analysis.net and similar sources).

**Status:** Complete

## Contents

- [`pcap-analysis-report.md`](./pcap-analysis-report.md) — full write-up: host identification, payload delivery, and post-infection C2/DoH evasion activity, reconstructed entirely from a packet capture with no endpoint telemetry
- `phase2-screenshots/` — supporting evidence

**Summary:** worked the 2026-10-01 "Natureforce" exercise from malware-traffic-analysis.net. Identified the infected host, hostname, MAC, and logged-on user via DHCP/LLMNR/Kerberos; traced a malicious `curl`-delivered payload from a self-hosted MinIO server on a non-standard port; and found the infected host pivoting to DNS-over-HTTPS immediately afterward to resolve a likely C2 server over a non-standard pseudo-TLS channel — a real DNS-evasion technique, not something simulated.
