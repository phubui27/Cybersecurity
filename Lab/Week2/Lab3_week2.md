# Week 2 – Day 3 (Lab Solution)
## Vendor-agnostic SOAR Playbooks (Cloud-first)

---

## Lab A — Playbook A: AWS ConsoleLogin Anomaly (ATO candidate)

### Objective
Handle suspicious AWS console login events and prevent privilege abuse with human-approved containment.

### Trigger (Input)
- Alert type: `aws_console_login_anomaly`
- Minimum fields required:
  - user / principal
  - source_ip (+ geo/ASN if available)
  - timestamp
  - target account (prod/dev)
  - outcome (success/failure)

### Preconditions (Telemetry)
- CloudTrail Management Events available
- Ability to query recent related events (last 30–60 minutes)

### Steps (Vendor-agnostic, numbered)
1) **Validate input + fail-closed**
   - If missing user/source_ip/timestamp/account → set decision Suspicious, require human review.

2) **Enrich (auto)**
   - Lookup user role (admin vs user)
   - Check account criticality (prod vs dev)
   - Check IP allowlist/badlist + geo/ASN
   - Check baseline anomaly (new country/ASN for this user)
   - Check out-of-hours

3) **Decisioning (auto)**
   - Compute risk_score (0–100) using explainable rules.
   - Map to decision:
     - <20 Benign, 20–59 Suspicious, >=60 Malicious

4) **Build evidence bundle (auto)**
   - Pull timeline last 60 minutes for the same principal/account:
     - ConsoleLogin (failures if available)
     - AssumeRole (especially AdminRole)
     - IAM changes: CreateAccessKey, AttachPolicy, CreateUser
     - Discovery: ListBuckets/DescribeInstances spikes
   - Output: short summary + list of key events (time-ordered)

5) **Ticket + notify (auto)**
   - Create incident ticket with:
     - decision, risk_score, why bullets
     - evidence bundle (timeline)
     - recommended next steps
   - Notify on-call channel for Suspicious/Malicious.

6) **Approval gate (human required)**
   If `approval_required=true` (Malicious or admin+prod):
   - Ask for human approval before:
     - revoke sessions
     - disable IAM user / disable SSO account
     - rotate/delete access keys

7) **Containment (execute only after approval)**
   - Revoke sessions / force re-auth
   - Rotate credentials
   - Temporarily restrict high-priv actions (if your org supports it)

8) **Close vs Escalate**
   - If verified benign (travel/change request): close with notes + update baseline/allowlist
   - If incident: escalate to IR (scope affected resources, check data access)

9) **Feedback loop**
   - If FP: update allowlist/VPN ASN/baseline hours
   - If FN or late detection: add correlation rule (login anomaly → privilege actions)

### Outputs
- Ticket with evidence bundle + decision rationale
- A “recommended next steps” checklist
- Audit trail of actions and approvals

### Failure modes (what can go wrong)
- Missing geo/ASN → reduce confidence, keep Suspicious
- Attacker uses trusted VPN → anomaly may not trigger; rely on privilege correlations

---

## Lab B — Playbook B: Azure RBAC Escalation (roleAssignments/write)

### Objective
Detect and respond to suspicious Azure RBAC changes that grant high privileges.

### Trigger (Input)
- Azure Activity Log operation:
  - `Microsoft.Authorization/roleAssignments/write`
- Minimum fields:
  - caller identity
  - target principal
  - role assigned
  - scope (resource group/subscription/management group)
  - timestamp
  - result status

### Preconditions (Telemetry)
- Activity Log accessible and queryable
- Ability to view role assignment history (last 24h)

### Steps (Vendor-agnostic, numbered)
1) **Validate input + fail-closed**
   - If missing caller/role/scope → Suspicious + human review.

2) **Enrich (auto)**
   - Identify caller type:
     - human admin vs service principal (IaC)
   - Check allowlist:
     - approved IaC principals
     - approved admin group
   - Determine blast radius:
     - scope broad? (subscription-wide / management group)
   - Check time anomaly (out-of-hours)
   - Check rarity: has caller ever changed RBAC before?

3) **Decisioning (auto)**
   - High-risk if:
     - role is Owner/Contributor/User Access Admin
     - scope is broad
     - caller not allowlisted
   - Output decision + risk_score.

4) **Build evidence bundle (auto)**
   - Query related events last 24h:
     - other role assignments by same caller
     - role assignments targeting same principal
     - resource changes shortly after RBAC change (VM/network/storage)
   - Output timeline + “what changed” summary.

5) **Ticket + notify (auto)**
   - Create incident ticket with:
     - who granted what role to whom, where (scope), when
     - risk_score/decision/why
     - evidence bundle

6) **Approval gate (human required)**
   Require human approval before:
   - reverting role assignment
   - disabling principal
   - blocking automation pipeline
   (because these can break deployments and production operations)

7) **Containment (execute only after approval)**
   - Revert the role assignment
   - Disable/rotate credentials for suspicious principal
   - Increase monitoring on affected scope

8) **Close vs Escalate**
   - If legitimate change: close + attach change ticket reference + update allowlist
   - If incident: escalate to IR and scope additional subscriptions/resources

9) **Feedback loop**
   - Add “process control”:
     - require change ticket tags for RBAC changes
     - alert only when missing ticket tag (if your org supports)
   - Tune allowlist for IaC service principals with expected scopes

### Outputs
- Ticket with evidence bundle + approval record
- Documented RBAC change and final disposition (benign/incident)

### Failure modes
- IaC pipelines can generate many RBAC changes → must allowlist properly
- If attacker compromises an allowlisted IaC principal → rely on anomaly signals (new IP/time/rare scope)
