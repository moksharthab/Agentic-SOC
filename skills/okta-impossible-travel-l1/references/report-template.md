# L1 Report Template

Emit exactly these sections, in this order, every time. Replace bracketed placeholders. Use `Not returned by tool` for any field the MCP responses did not provide. Keep it concise and evidence-anchored.

---

# L1 Analyst Report — Case [CASE_ID]
### `[rule_name]` — Okta Impossible Travel / Valid Accounts (MITRE T1078)

## 1. Alert Summary
| Attribute | Value |
|---|---|
| Case ID | [case_id] |
| Alert ID | [alert_id] ([siemAlertId]) |
| User | [user id] — [display name if known] ([emails]) |
| Role / Privilege | [User/AppUser/admin/etc.] |
| Detection window | [start]–[end] UTC |
| Risk score / Severity | [score] / [severity] |
| Event count | [n] |
| Playbook | [attachedPlaybookName] ([status]) |
| Workflow status | [workflowStatus] |
| Chronicle alert | [sourceUrl] |

## 2. Login Timeline (evidence)
One row per source IP. Mark which IP completed the successful authentication.

| IP | Geo / ASN (owner) | Role in chain | Anomaly signals | Outcome |
|---|---|---|---|---|
| [ip] | [city, country] — [asn] ([owner]) | [primary/secondary] | [Anomalous Location/Device/Anonymizing Proxy; New Geo/Device/ASN/IP/City/Velocity] | [login→MFA→auth success / challenged only] |

**Successful-auth IP:** [ip] — [one-line why it matters].

Event-by-event (optional, for clarity):
- [ip]: [event names in sequence and key flags]

## 3. Threat Intel (GTI)
| IP | GTI verdict | Detail |
|---|---|---|
| [ip] | [malicious/suspicious counts]; tags [..]; severity [..] | [ASN owner, VPN/hosting mapping, notable context] |

**Interpretation:** [1–2 sentences — emphasize behavioral risk vs reputation].

## 4. L1 Disposition
**Verdict:** [BENIGN (auto-close) | SUSPICIOUS — ESCALATE L2 | LIKELY COMPROMISE — ESCALATE L3]
**Confidence:** [High | Medium-High | Medium | Low]

Reasoning:
- [bullet — strongest corroborating signal]
- [bullet — mitigating factor and why it does/doesn't change verdict]
- [bullet — which disposition gate matched]

## 5. Escalation Decision Logic
- Auto-close conditions met? [yes/no — which]
- L2 trigger matched? [which]
- L3 trigger matched? [which / none currently]

## 6. Instructions for L2
1. [Resolve user-verification gap out-of-band — exact question with timeframe/geo.]
2. [Pull full Okta system log ±24h for the user; look for MFA type, factor/password changes, token reuse.]
3. [Determine what the successful session accessed.]
4. [Containment decision and authority — revoke sessions / reset / re-enroll MFA / suspend if confirmed.]
5. [Scope IP/device across tenant for other users.]
6. [Update case: priority, comment, close or hand to L3.]
- **L2→L3 triggers:** [user denial, post-auth manipulation, multi-user reuse, sensitive data access].

## 7. Instructions for L3 / IR (if escalated)
1. [Declare incident, preserve logs.]
2. [Full session-chain reconstruction + scope of access.]
3. [Hard containment & eradication: kill tokens, rotate creds, revoke OAuth, remove attacker MFA/persistence.]
4. [Campaign hunt on VPN ASN + device fingerprint across all identities.]
5. [Data-impact & notification assessment.]
6. [Root cause + detection-engineering feedback.]
7. [Close-out & lessons learned.]

## 8. Notes, Assumptions & Limitations
- [Time normalization, default windows.]
- [Privilege inferred vs confirmed.]
- [What L1 did NOT do and left to L2 — e.g., full Okta log pull, cross-user search.]
- [Any `Not returned by tool` fields.]
