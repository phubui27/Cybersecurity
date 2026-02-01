# Day 7 – Security Automation 101 (Theory Notes)

## 1) What is an enrichment pipeline?
An **enrichment pipeline** is an automation workflow that adds **context** to a raw alert before a human makes a decision.

- **Input:** raw alert (log/alert JSON from SIEM/EDR/Cloud)
- **Process:** pull context from APIs or internal data sources
- **Output:** **triage-ready** alert (context + decision support)

**Key insight:** Good automation is not “auto-close”.  
It is **auto-context**.

---

## 2) Why SOC needs enrichment
Raw alerts usually miss 3 critical dimensions:
1) **Who/What:** how important is this user/asset?
2) **Where:** is the source location/IP unusual?
3) **So what:** what is the risk/impact to the business?

Enrichment helps:
- reduce investigation time
- reduce mistakes caused by missing context
- prepare clean inputs for SOAR playbooks

---

## 3) Common context sources (2026)
You can enrich from APIs or mock datasets. Typical sources:

### Identity context
- user role (admin vs normal)
- baseline login history (new IP/new country?)
- MFA used? (if available)

### Asset context
- asset criticality (prod vs dev)
- asset owner/team
- internet exposure (yes/no)

### Network / IP context
- geo, ASN
- IP reputation / threat intel
- allowlists (VPN ranges, office egress)

### Behavior context
- correlation in last 30–60 minutes:
  - fail → success
  - login → privilege
  - download spike
- frequency baseline:
  - is this action normal for this user/service?

---

## 4) Decisioning: turning context into a decision
Enrichment adds data, but you still need **decisioning**:

Outputs you should produce:
- `decision`: Benign / Suspicious / Malicious / FalsePositive
- `risk_score`: 0–100 (rule-based scoring is enough at this stage)
- `why`: short bullet reasons
- `recommended_next_steps`: 3 practical actions

Rule of thumb:
If critical context is missing, **avoid strong conclusions**.

---

## 5) Human-in-the-loop (approval gates)
Human-in-the-loop means:
Automation does what machines do best, humans own high-risk decisions.

Automation is good at:
- enrichment and correlation
- building timelines
- generating summaries + “next questions”
- opening tickets + attaching evidence

Humans must:
- confirm incidents using business context
- decide containment actions (avoid self-inflicted outages)
- scope impact (hosts/users/data) and prioritize response

---

## 6) Blast radius & approval triggers
**Blast radius** = how much damage automation can cause if wrong.

Never auto-execute without approval:
- disable accounts / revoke sessions
- isolate hosts
- firewall blocks
- delete access keys / remove roles

Always include:
- `approval_required: true/false`

---

## 7) Safety design (3 hard rules)
1) **Fail-closed**
   - If key data is missing (user role, asset criticality, source IP),
     do not auto-close and do not auto-contain.

2) **Audit trail**
   - Record input + enrichment + decision + timestamp for review/forensics.

3) **Deterministic output**
   - Keep a stable output schema (JSON + summary) so it can plug into SOAR later.

---

## 8) What Day 7 builds (and why it’s “career-aligned”)
You are building a “mini SOAR pre-processor”:
- no vendor platform needed
- same thinking as real security automation engineering

It proves you can connect:
- SOC thinking (triage & risk)
- detection thinking (context & correlation)
- automation thinking (pipeline & safety)
