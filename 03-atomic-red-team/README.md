# Phase 3: Atomic Red Team

ATT&CK-mapped execution of Atomic Red Team tests against the lab endpoints, with detection coverage validation and gap analysis.

**Status:** In progress

## Contents

- [`detection-validation-report.md`](./detection-validation-report.md) — write-up: T1070.003 (Indicator Removal: Clear Command History) detection test, plus a false-positive finding on an unrelated critical-severity rule
- `screenshots/` — supporting evidence

**Summary so far:** tested T1070.003 (clearing PowerShell command history) via Atomic Red Team. Found that detection only happened incidentally through a generic nested-PowerShell-process rule — no rule recognizes the history-clearing action itself as a defense-evasion indicator. Also caught and verified a false positive: a critical-severity rule (92213) misfiring on a benign PowerShell-internal file, mapped incorrectly to T1105.
