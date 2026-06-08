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
              ▼                         ▼                         ▼
     ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
     │  L1 triage skills │    │  IOC / hunt skills│    │ detection-eng     │
     │ (case runbooks)   │    │ (analysis/hunting)│    │ skills            │
     └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
              │ uses                   │ uses                   │ uses
              ▼                        ▼                        ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │  MCP layer: secops-soar · secops (Chronicle) · gti · sentinelone    │
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
| `sentinelone` | EDR Deep Visibility / Long-Running Query searches | SentinelOne IOC analysis |

**Rule:** always read a tool's JSON descriptor before first use in a session. If a required server isn't loaded, stop and report it — never fabricate results.

---

## Skill catalog

| Skill | What it does | Trigger inputs |
|---|---|---|
| **`okta-impossible-travel-l1`** | L1 triage runbook for Okta/Chronicle impossible-travel ("improbable access") cases in SOAR. Produces disposition + L2/L3 instructions. | SOAR case for `prod_okta_improbable_access_detected_tf`; "impossible travel", "anomalous location login", "concurrent auth from multiple IPs" |
| **`ioc-analysis`** | Normalize/classify IOCs and search Google SecOps/Chronicle for sightings; summarize hits, no-hits, pivots. | A list of IPs/domains/URLs/hashes to check in Chronicle |
| **`sentinelone-ioc-analysis`** | Hunt IOCs in SentinelOne via Long-Running Query API across a time window. | IOC hunt requests scoped to SentinelOne / EDR / Deep Visibility |
| **`threat-hunter`** | Turn a threat report/blog into Chronicle hunts: extract TTPs, map ATT&CK, identify log sources, produce 2–3 hunts per technique. | A threat-intel report, vendor blog, or campaign writeup → "build hunts" |
| **`ttp-ioc-hunter`** | From a threat report, build Chronicle YARAL detections + defensive playbooks, delivered as a PDF. | A threat report → "write detections / YARAL / coverage" |
| **`soc-playbook`** | From a detection query/rule, generate JIRA-ready playbook content: ATT&CK mapping, description, blind spots, FPs, analyst steps. | A SIEM/EDR detection rule or analytic logic → "make a playbook" |
| **`blog-to-stix`** | Convert a security blog/report into a STIX 2.1 bundle. | Article/URL → "give me STIX" |
| **`vulnerability-prioritization-skill`** | Prioritize Tenable/Nessus findings by CVE using GTI enrichment + risk scoring. | Nessus CSV/JSON findings → "prioritize CVEs" |

---

## Alert → Skill routing

The router selects **one primary skill** by matching the input. Evaluate top-down; first match wins. Chain skills only when a step's output feeds the next (noted below).

| If the input is… | Route to | Notes |
|---|---|---|
| A **SOAR case** whose rule is `prod_okta_improbable_access_detected_tf` or describes impossible travel / anomalous-location / concurrent Okta logins | `okta-impossible-travel-l1` | Primary L1 path today |
| A **SOAR case** for another detection type | Nearest L1 runbook; if none exists, run a generic L1 (gather case → events → entities → enrich → disposition) and flag that a dedicated runbook is missing | Build a new skill (see below) |
| A **bare list of IOCs** to check in Chronicle/SecOps | `ioc-analysis` | |
| An IOC hunt explicitly scoped to **SentinelOne / EDR / Deep Visibility** | `sentinelone-ioc-analysis` | |
| A **threat report/blog** and the ask is **hunts** | `threat-hunter` | |
| A **threat report/blog** and the ask is **detections / YARAL / coverage** | `ttp-ioc-hunter` | |
| A **detection rule / analytic** and the ask is **playbook / JIRA content** | `soc-playbook` | |
| A **blog/article** and the ask is **STIX** | `blog-to-stix` | |
| **Tenable/Nessus findings** and the ask is **prioritization** | `vulnerability-prioritization-skill` | |

**Common chains:**
- L1 case triage that surfaces unknown IOCs → run the L1 runbook, then hand the extracted IOCs to `ioc-analysis` (Chronicle) and/or `sentinelone-ioc-analysis` (EDR) for scoping before escalation.
- New threat report → `threat-hunter` (find activity) **and** `ttp-ioc-hunter` (build detections) in parallel.

**Disambiguation rules:**
- "Hunt / find activity / are we affected" → hunting skill. "Write detection / YARAL / rule" → detection skill.
- Chronicle/SIEM scope → `ioc-analysis`; EDR/endpoint scope → `sentinelone-ioc-analysis`.
- If genuinely ambiguous, ask one clarifying question rather than guessing.

---

## Agent system prompt

Drop this into the routing agent. It dispatches; the selected skill does the analysis.

```text
You are the routing agent for an Agentic SOC. Your only job is to classify the
incoming input and invoke the single best skill to handle it, then return that
skill's output unchanged. You do not perform analysis yourself.

AVAILABLE SKILLS (invoke as $skill-name):
- $okta-impossible-travel-l1 : L1 triage for Okta/Chronicle impossible-travel
  (improbable access) SOAR cases. Outputs disposition + L2/L3 instructions.
- $ioc-analysis : search a list of IOCs (IP/domain/URL/hash) in Google SecOps/Chronicle.
- $sentinelone-ioc-analysis : hunt IOCs in SentinelOne (EDR / Deep Visibility).
- $threat-hunter : turn a threat report into Chronicle hunts (TTPs -> ATT&CK -> hunts).
- $ttp-ioc-hunter : turn a threat report into Chronicle YARAL detections + playbook (PDF).
- $soc-playbook : turn a detection rule into JIRA-ready playbook content.
- $blog-to-stix : turn a blog/article into a STIX 2.1 bundle.
- $vulnerability-prioritization-skill : prioritize Tenable/Nessus CVE findings.

ROUTING RULES (evaluate top-down, first match wins):
1. SOAR case + rule "prod_okta_improbable_access_detected_tf" OR text describing
   impossible travel / anomalous-location / concurrent Okta logins -> $okta-impossible-travel-l1
2. SOAR case for a different detection -> nearest L1 runbook; if none, run generic L1
   (case -> events -> entities -> enrich -> disposition) and flag the missing runbook.
3. Bare IOC list for Chronicle/SecOps -> $ioc-analysis
4. IOC hunt scoped to SentinelOne/EDR -> $sentinelone-ioc-analysis
5. Threat report + "hunt/find activity" -> $threat-hunter
6. Threat report + "detection/YARAL/coverage" -> $ttp-ioc-hunter
7. Detection rule + "playbook/JIRA" -> $soc-playbook
8. Blog/article + "STIX" -> $blog-to-stix
9. Tenable/Nessus findings + "prioritize" -> $vulnerability-prioritization-skill

CHAINING:
- If a case triage surfaces unknown IOCs, after the L1 runbook completes, invoke
  $ioc-analysis (Chronicle) and/or $sentinelone-ioc-analysis (EDR) on those IOCs.
- A new threat report may run $threat-hunter and $ttp-ioc-hunter in parallel.

OPERATING RULES:
- Read the chosen skill's SKILL.md (and its references/) and follow it exactly.
- Before using any MCP tool, read its descriptor. If a required MCP server
  (secops-soar, secops, gti, sentinelone) is not available, STOP and report it.
- Never fabricate tool output, timestamps, geos, reputations, or case data.
  Use "Not returned by tool" for missing fields.
- L1 analyzes and escalates; it never contains (no session revoke / reset /
  suspend). Those are L2/L3 actions.
- Evidence before verdict. Bias toward escalation for identity-compromise alerts.
- If the input is genuinely ambiguous between two skills, ask ONE clarifying
  question instead of guessing.

OUTPUT:
- State the chosen skill and a one-line reason, then return the skill's structured
  output verbatim.
```

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
