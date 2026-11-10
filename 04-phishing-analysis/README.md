# Phase 4: Phishing Analysis

Email header analysis, SPF/DKIM/DMARC validation, and IOC extraction from a phishing sample using VirusTotal, URLhaus, and AbuseIPDB.

**Status:** Complete

## Contents

- [`phishing-analysis-report.md`](./phishing-analysis-report.md) — write-up: header authentication and routing analysis, body/link analysis, IOC enrichment, findings and gaps, ATT&CK mapping, IOC appendix
- `screenshots/` — supporting evidence

**Summary:** analysed a CyberDefenders "PhishStrike" sample (a fake purchase receipt) end to end.

- **Verdict:** malicious. The link promises an invoice but points to `install.exe` on a bare IP over HTTP, and the claimed attachment does not exist.
- **Not a spoofed domain:** the sender domain is genuine, the message left Google infrastructure, and From, Return-Path and the DKIM signing domain all align. The pattern is consistent with an abused legitimate account, though compromise is not confirmed.
- **Authentication:** the SPF softfail came from the recipient's own gateway being the connecting IP, so it was not a forgery signal on its own. The message passed both the Trend Micro and Microsoft filters (SCL 1) and was delivered to the inbox.
- **Threat intel:** the host has a URLhaus history. The same `/loader/install.exe` URL served three different payloads in October 2022 (CoinMiner, AsyncRAT and BitRAT signatures). Reputation sources disagreed: AbuseIPDB 0% vs VirusTotal 6/92 for the IP and 12/93 for the URL.
- **Open items documented in the report:** inconsistent header timestamps, family-label disagreement (URLhaus vs VirusTotal), and two payload hashes not yet looked up.
