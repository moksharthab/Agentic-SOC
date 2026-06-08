# Analysis Logic — Scoring, Disposition & Escalation Gates

Table of contents:
- Signal model
- Disposition gates (auto-close / L2 / L3)
- Confidence rubric
- False-positive guidance
- Common pitfalls

## Signal model

The detection fires on concurrent/geographically-impossible Okta authentication for a single identity. Reputation of the source IPs is usually clean; the risk lives in the **behavioral signals on the successful authentication**.

Weight signals as follows (evaluate against the IP that completed the successful login):

| Signal (from event `Message` / `securityResult_description`) | Weight |
|---|---|
| `Anonymizing Proxy` (VPN/Tor/proxy) on the successful auth | High |
| `Anomalous Device` + `New Device = POSITIVE` | High |
| `New ASN = POSITIVE` and `New IP = POSITIVE` together | Medium-High |
| `Velocity = POSITIVE` (impossible travel speed) | Medium-High |
| `New Geo-Location` / `New City` = POSITIVE | Medium |
| `New Country = POSITIVE` | Medium (lower if user has travel history to that country) |
| MFA satisfied from the anomalous source | High (means credentials + factor both worked from untrusted egress) |
| Post-auth sensitive action (see L3 gate) | Critical |

Mitigating signals (reduce severity, never zero it out alone):
- User has documented prior logins from the same country/ASN.
- The anomalous path was **challenged/blocked** and did NOT complete auth.
- User positively confirms the activity out-of-band.

GTI context (do not let it override behavior):
- `tags: ["vpn"]` / hosting ASN → expected for commercial VPN egress; explains "why VPN" but does not clear the case.
- `has_bad_communicating_files_*: true` on shared VPN infra is common and is **not**, by itself, evidence of compromise.
- A genuine malicious/suspicious GTI count (>0) escalates severity.

## Disposition gates

Evaluate top-down. First matching gate wins.

### Gate A — ESCALATE TO L3 (Likely compromise / incident) if ANY:
- A post-auth sensitive action is observed in events/comments: MFA factor added or reset, password change, OAuth app consent grant, mailbox forwarding rule, privileged role assignment, or access to crown-jewel/sensitive apps from the suspicious session.
- The affected account is **privileged** (admin, service account, finance/HR/security) AND the successful login carries High-weight anomalies.
- The same source IP or device fingerprint authenticated as **multiple distinct users** (campaign / credential stuffing).
- Lateral movement or data staging/exfil indicators present.

### Gate B — ESCALATE TO L2 (Suspicious) if ANY (and Gate A not met):
- Successful MFA login from an `Anonymizing Proxy` / VPN on a `New Device` + `New ASN`.
- Impossible travel confirmed AND `workflowStatus = PendingForUser` (user has not confirmed).
- Concurrent failed-then-success MFA pattern (possible MFA fatigue).
- Any High-weight signal present without out-of-band user confirmation.

### Gate C — BENIGN (auto-close) ONLY if ALL:
- User **positively confirms** (recorded out-of-band) they performed the login, AND
- No `Anonymizing Proxy` + `Anomalous Device` combination on the successful event, AND
- No post-auth sensitive actions, AND
- Activity is consistent with the user's documented history.

If none of A/B/C cleanly applies, default to **Gate B (escalate L2)**. Bias toward escalation for identity-compromise detections.

## Confidence rubric

- **High** — multiple corroborating High-weight signals (e.g. anonymizing proxy + new device + velocity + MFA success), or a confirmed post-auth action.
- **Medium-High** — impossible travel confirmed + one High-weight signal, user unconfirmed.
- **Medium** — impossible travel confirmed but signals are mostly geo-only and user has relevant travel history.
- **Low** — partial/ambiguous event data; note what is missing and still escalate per Gate B.

## False-positive guidance

Legitimate causes that L2 will validate (L1 should NOT close on these assumptions alone):
- Corporate or personal VPN/split-tunnel making the user appear in another geo.
- Mobile carrier-grade NAT placing the user in an unexpected city.
- Roaming/travel the user genuinely undertook.
- Two devices (e.g. phone on cellular + laptop on VPN) authenticating in parallel.

Even when an FP cause is plausible, a successful auth via **anonymizing proxy on a new device** must be confirmed with the user before closure — that is the exact pattern abused in account takeover.

## Common pitfalls

- **Down-ranking because GTI is clean.** The decisive evidence is behavioral, not reputational.
- **Blaming the "foreign" IP.** The user's home-geo IP is often benign; the *new VPN* IP that completed MFA is usually the real risk. Always anchor on the successful-auth IP.
- **Closing while PendingForUser.** Never disposition benign without recorded user confirmation.
- **Ignoring prior comments.** A previous analyst may have already contacted the user or found a post-auth action — read all comments in Step 1.
- **Missing multi-user reuse.** Always consider whether the source IP/device touched other accounts (campaign signal → L3).
