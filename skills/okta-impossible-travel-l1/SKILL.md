---
name: okta-impossible-travel-l1
description: Deterministic SOC L1 triage runbook for Google Chronicle / Okta "improbable access" (impossible travel) alerts managed in Google SecOps SOAR (Siemplify). Use when an L1 analyst or agent receives a SOAR case for the detection `prod_okta_improbable_access_detected_tf` (or any Okta/identity impossible-travel, anomalous-location, or concurrent-login alert) and must produce a consistent, predictable analysis with a clear disposition and explicit escalation instructions for L2 and L3. Triggers include a SOAR case ID for an Okta impossible-travel alert, "triage this Okta login alert", "improbable access", "anomalous location login", or "concurrent authentication from multiple IPs".
---

# Okta Impossible Travel — L1 Triage Runbook

## Overview

This skill turns the Chronicle/Okta `prod_okta_improbable_access_detected_tf` alert into a fixed, repeatable L1 workflow. It defines the exact data-collection steps, enrichment calls, scoring logic, disposition rules, and L2/L3 escalation handoffs so that every analyst (human or agent) produces the same structured output for the same evidence.

MITRE: **T1078 — Valid Accounts**.

## Required tooling

These MCP servers must be available. Always read a tool's JSON descriptor before first use this session.

- `secops-soar` (Siemplify) — case/alert/event/entity retrieval and case commenting.
- `gti` (Google Threat Intelligence) — IP/domain/URL/hash reputation.
- `secops` (Chronicle SIEM) — optional supplementary UDM/event search and cross-user pivots.

If a server's tools are not loaded, stop and tell the user to enable it in the MCP settings before continuing. Do not fabricate results.

## Golden rules (do not violate)

1. **Evidence before verdict.** Never state a disposition before completing Steps 1–4.
2. **Behavior over reputation.** A "clean" GTI verdict does NOT make this benign. The decisive signals are behavioral: anonymizing proxy + anomalous device + new ASN/IP + velocity on a *successful* auth.
3. **Identify the successful login path.** Determine which IP actually completed MFA + auth. That IP drives the risk, not whichever IP looks "worse".
4. **Never auto-close while `workflowStatus = PendingForUser`** unless user confirmation is already recorded in comments.
5. **L1 does not contain.** L1 analyzes, dispositions, and escalates. Session revocation, password reset, and suspension are L2/L3 actions.
6. **Report missing fields as `Not returned by tool`.** Never invent timestamps, geos, or device data.

## Workflow (execute in order)

### Step 1 — Pull full case context
Call `secops-soar.get_case_full_details` with `case_id`.
Capture: `displayName`, `priority`, `status`, `stage`, `workflowStatus`, `assignee`, `alertCount`, `createTime`/`updateTime`, `description` (contains Chronicle alert URL + runbook + MITRE), and read every entry in `case_comments` (prior analyst notes change the disposition).

### Step 2 — Enumerate alerts and the alert group
From the Step 1 response (or `secops-soar.list_alerts_by_case`), record each alert's `id`, `ruleGenerator`, `priority`, `siemAlertId`, `sourceUrl`, `attachedPlaybookName`, and the `alertGroupIdentifier`.

### Step 3 — Reconstruct the login timeline (the core of the analysis)
Call `secops-soar.list_events_by_alert` with `case_id` + `alert_id`.
For each event, parse `mappedEventJson` and extract:
- `Name` (e.g. `User login to Okta`, `Authentication of user via MFA`, `Authenticate user with AD agent`, `Evaluation of sign-on policy`)
- `SourceAddress` (the source IP), `SourceUserName`, `DestinationUserName`
- `Message` / `securityResult_description` — the anomaly flags. Watch for `Anomalous Location`, `Anomalous Device`, `Anonymizing Proxy`, and the AD-agent map: `New Geo-Location`, `New Device`, `New ASN`, `New IP`, `New City`, `Velocity`, `New Country`, `New State` (POSITIVE = anomalous).
- `DestinationURL`, `timeWindow_startTime`/`endTime`.

Build a per-IP picture: which IP logged in, which satisfied MFA, which only hit challenge/authorize endpoints. **Flag the IP that completed the successful authentication.**

### Step 4 — Pull entities and enrich indicators
Call `secops-soar.get_entities_by_alert_group_identifiers` with `case_id` + `[alertGroupIdentifier]`.
Identify: the user (`USERUNIQNAME`), external `ADDRESS` IPs, and any `DestinationURL`/`DEPLOYMENT` artifacts. Note `IsInternalAsset` and the user's roles from `Raw Enrichment` (privileged vs standard `User`/`AppUser`).

For every **external** IP, call `gti.get_ip_address_report`. Record: `last_analysis_stats` (malicious/suspicious counts), `tags` (e.g. `vpn`), `as_owner`/`asn`, `country`, `threat_severity_level`, and note `has_bad_communicating_files_*` (context only — do NOT treat as compromise on its own). Map the ASN to a known VPN/hosting provider where possible (e.g. Datacamp = CyberGhost VPN backend).

### Step 5 — Score and disposition
Apply the scoring and escalation logic in [references/analysis-logic.md](references/analysis-logic.md). Produce one of: `BENIGN (auto-close)`, `SUSPICIOUS — ESCALATE L2`, or `LIKELY COMPROMISE — ESCALATE L3`.

### Step 6 — Emit the report
Produce the report using the template in [references/report-template.md](references/report-template.md). Sections: Alert Summary, Login Timeline, Threat Intel, L1 Disposition (verdict + confidence + reasoning), Escalation Decision Logic, L2 Instructions, L3 Instructions, Notes/Assumptions/Limitations.

### Step 7 — Optional: write back to the case
Only if instructed, post the L1 summary via `secops-soar.post_case_comment`. Never change priority/status from L1 unless explicitly told to.

## Scope guards

- This runbook is for **identity impossible-travel** alerts. If events show malware, EDR detections, or data exfil rather than auth anomalies, stop and route to the appropriate detection runbook.
- If the case has **multiple users** or the same IP/device authenticates across **multiple identities**, treat as a potential campaign and escalate to L3 regardless of single-account signals.

## Reference files

- [references/analysis-logic.md](references/analysis-logic.md) — signal weighting, auto-close vs L2 vs L3 gates, false-positive guidance.
- [references/report-template.md](references/report-template.md) — exact output structure for predictable reporting.
