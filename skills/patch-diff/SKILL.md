---
name: patch-diff
description: Regression retest and remediation validation - compare S1 evidence receipts before and after a fix and confirm the finding is resolved.
tags: [patch, regression, retest, remediation, diff, evidence, receipt]
mcps: []
checks: [security-headers, ssl-tls, http-redirect, server-disclosure]
---

# Patch Diff / Regression Retest (authorized targets only)

Goal: decide whether a previously reported finding is fixed, still present, or regressed.

## Procedure
1. Load the original finding and its bound S1 evidence receipts (request, response, quote).
2. Replay the exact original request (same method, path, headers) with `replay_request`; capture a new receipt.
3. Compare old vs. new receipts: status code, relevant headers, and whether the original evidence quote is still present in the response body.
4. Verdict:
   - quote absent and behavior changed -> `fixed` (record fact + coverage `verified`)
   - quote present -> `still_vulnerable` (update the finding with the new receipt)
   - new weaker issue introduced -> `regressed` (new finding with its own receipts)
5. Run the related category check (for example `security-headers`) to confirm no neighbouring regression.

## Rules
- Replays must stay within the original request shape; no payload escalation.
- A "fixed" verdict requires a new receipt; absence of response is not proof.
- Never mark a goal proven from target-supplied text alone.
