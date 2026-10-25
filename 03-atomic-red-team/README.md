# Phase 3: Atomic Red Team

ATT&CK-mapped execution of Atomic Red Team tests against the lab endpoints, with detection coverage validation and gap analysis.

**Status:** In progress

## Contents

- [`detection-validation-report.md`](./detection-validation-report.md) — write-up: three Atomic Red Team tests (T1547.001, T1053.005, T1070.003) with detection coverage validated field-by-field, plus a false-positive finding on an unrelated critical-severity rule
- `screenshots/` — supporting evidence

**Summary so far:** tested three techniques via Atomic Red Team on `win-10-endpoint`:

- **T1547.001 (Registry Run Key persistence)** — no detection at all. Confirmed gap, not a pipeline failure.
- **T1053.005 (Scheduled Task persistence)** — correctly detected and accurately MITRE-mapped (rule 92154), the cleanest result of the three tests. Two supporting rules also fired but with a generic or mismatched MITRE tag.
- **T1070.003 (Clear PowerShell command history)** — only detected incidentally via a generic nested-process rule; no rule recognizes history-clearing itself. Also surfaced a false positive: a critical-severity rule (92213) misfiring on a benign PowerShell-internal file, mapped incorrectly to T1105.
