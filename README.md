# Agentic SOC

An autonomous, skill-driven Security Operations Center. Each **skill** is a deterministic runbook for a specific class of work (L1 triage, IOC analysis, threat hunting, detection engineering). A routing **agent** reads the incoming alert/request, selects the right skill, runs it against the live security stack (Google SecOps SOAR, Chronicle SIEM, GTI, SentinelOne), and produces a consistent, predictable analysis with clear escalation handoffs.

> Design goal: **same alert + same evidence → same analysis, every time.** Humans (L1/L2/L3) and agents read identical structured output.

---

## Table of contents
- [Architecture](#architecture)
- [Tooling (MCP servers)](#tooling-mcp-servers)
- [Skill catalog](#skill-catalog)
- [Alert → Skill routing](#alert--skill-routing)
- [Agent system prompt](#agent-system-prompt)
- [Tier model & escalation](#tier-model--escalation)
- [Operating principles](#operating-principles)
- [Adding a new skill](#adding-a-new-skill)

---

## Architecture

```
                         ┌─────────────────────────────┐
   Alert / Case / IOC ──▶│      SOC Routing Agent        │
   (SOAR case, IOC list, │  - classify the input         │
    threat report, rule) │  - select skill (router rules)│
                         │  - load SKILL.md + refs        │
                         └──────────────┬────────────────┘
                                        │ invokes
              ┌─────────────────────────┼─────────────────────────┐
                                        ▼                         
                             ┌──────────────────┐ 
                             │ L1 triage skills │    
                             │ (case runbooks)  │    
                             └────────┬─────────┘    
                                      │ uses                   
                                      ▼                         
   ┌───────────────────────────────────────────────────────────────────┐
   │  MCP layer: secops-soar · secops (Chronicle) · gti · sentinelone  │
   └───────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
   Structured report  ──▶  L1 disposition  ──▶  Escalate L2 / L3 with instructions
```

Three layers:
1. **Router agent** — one decision: which skill handles this input. It does not analyze; it dispatches.
2. **Skills** — self-contained runbooks (SKILL.md + `references/`) that do the actual work deterministically.
3. **MCP tools** — the live data plane the skills call.

---

## Tooling (MCP servers)

| Server | Purpose | Used by |
|---|---|---|
| `secops-soar` | Siemplify cases/alerts/events/entities, case comments | L1 triage skills |
| `secops` | Chronicle SIEM UDM search, alerts, rule detections | IOC analysis, hunting, L1 pivots |
| `gti` | Google Threat Intelligence (IP/domain/URL/hash, actors, campaigns) | IOC analysis, enrichment, hunting |

**Rule:** always read a tool's JSON descriptor before first use in a session. If a required server isn't loaded, stop and report it — never fabricate results.

---

## Skill catalog

| Skill | What it does | Trigger inputs |
|---|---|---|
| **`okta-impossible-travel-l1`** | L1 triage runbook for Okta/Chronicle impossible-travel ("improbable access") cases in SOAR. Produces disposition + L2/L3 instructions. | SOAR case for `prod_okta_improbable_access_detected_tf`; "impossible travel", "anomalous location login", "concurrent auth from multiple IPs" |

---

## Alert → Skill routing

The router selects **one primary skill** by matching the input. Evaluate top-down; first match wins. Chain skills only when a step's output feeds the next (noted below).

| If the input is… | Route to | Notes |
|---|---|---|
| A **SOAR case** whose rule is `prod_okta_improbable_access_detected_tf` or describes impossible travel / anomalous-location / concurrent Okta logins | `okta-impossible-travel-l1` | Primary L1 path today |
| A **SOAR case** for another detection type | Nearest L1 runbook; if none exists, run a generic L1 (gather case → events → entities → enrich → disposition) and flag that a dedicated runbook is missing | Build a new skill (see below) |

---

## Tier model & escalation

| Tier | Role | Authority | Output |
|---|---|---|---|
| **L1 (agent)** | Triage every alert via a runbook; collect evidence, enrich, disposition | Analyze only — no containment | Structured report: verdict + confidence + L2/L3 instructions |
| **L2** | Validate L1 disposition; user/account verification; scoping | Containment (revoke sessions, reset, re-enroll MFA, suspend) | Confirm/close or escalate to L3 |
| **L3 / IR** | Incident handling, eradication, campaign hunt, root cause | Full IR authority | Incident close-out + detection feedback |

Escalation gates are defined per-skill (e.g. `okta-impossible-travel-l1/references/analysis-logic.md`). General triggers to L3: post-auth account manipulation, privileged-account compromise, the same IP/device across multiple users, or confirmed lateral movement / data access.

---

## Operating principles

1. **Determinism** — skills encode fixed steps, scoring, and output templates so results are reproducible and auditable.
2. **Behavior over reputation** — a "clean" TI verdict never auto-clears an alert; weight behavioral signals.
3. **Evidence before verdict** — no disposition before data collection + enrichment is complete.
4. **No fabrication** — only report what the tools returned; mark gaps explicitly.
5. **L1 doesn't contain** — clean separation of analysis (L1) from action (L2/L3).
6. **Human-readable handoffs** — every report ends with explicit, role-specific next steps.

---

## Adding a new skill

Use the `skill-creator` skill. For a new L1 detection runbook, mirror `okta-impossible-travel-l1`:

1. `SKILL.md` — ordered workflow (case → alerts → events → entities → enrich → score → report), golden rules, and scope guards. Put precise trigger conditions in the `description` frontmatter.
2. `references/analysis-logic.md` — signal weighting + auto-close/L2/L3 gates + FP guidance.
3. `references/report-template.md` — the fixed output structure.
4. Validate with the skill-creator validator, then add the routing rule above and a line in the agent prompt.
5. Forward-test on a real case before trusting it in production.
```
```
