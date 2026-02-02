# Week 2 – Day 2 (Lab Solution)
## IAM/RBAC Abuse + Correlation

## Lab A — Classify events (Signal / Context / Noise)
### Prompt
Classify each event as Signal, Context, or Noise (SOC alerting perspective).

Events:
1) AWS: ConsoleLogin Success from new ASN
2) AWS: AssumeRole into AdminRole
3) AWS: CreateAccessKey for user alice
4) AWS: ListBuckets repeated 30 times in 2 minutes
5) AWS: DescribeInstances once
6) Azure: roleAssignments/write granting Owner to a new principal
7) Azure: virtualMachines/write creating a new VM
8) Azure: list resources read-only

### Answer
1) ConsoleLogin Success from new ASN → **Signal**
Reason: identity anomaly (ATO candidate).

2) AssumeRole into AdminRole → **Signal (High-signal)**
Reason: privileged action, high blast radius.

3) CreateAccessKey for user alice → **Signal**
Reason: credential persistence/programmatic access creation.

4) ListBuckets repeated 30 times in 2 minutes → **Context (upgrade to Signal if correlated)**
Reason: discovery spike; alone is noisy, but after identity anomaly it becomes suspicious.

5) DescribeInstances once → **Context**
Reason: single enumeration is low value alone.

6) roleAssignments/write granting Owner to a new principal → **Signal (High-signal)**
Reason: privilege escalation/persistence shortcut in Azure RBAC.

7) virtualMachines/write creating a new VM → **Context (upgrade with correlation)**
Reason: could be normal deploy; suspicious if follows identity/privilege anomalies.

8) list resources read-only → **Noise (standalone alerting)**
Reason: common; keep for hunting/correlation, not alert alone.


---

## Lab B — Write 2 correlation detections (cloud-first)

### Detection 1: Login anomaly → Privilege action chain (AWS)
**Goal**
Detect probable account takeover leading to privilege usage.

**Data required**
- CloudTrail events:
  - ConsoleLogin (success/failure if available)
  - AssumeRole (roleArn/roleName)
- Fields: userIdentity/principal, source IP/ASN/country, timestamp, target role

**Logic (correlation + window)**
Trigger when:
- ConsoleLogin Success is anomalous for the principal (new ASN/country OR out-of-hours)
AND within 10 minutes:
- AssumeRole into a privileged role (e.g., AdminRole)

**Expected false positives**
- On-call engineer login from new VPN ASN
- Planned admin work from new location

**Blind spots / FN**
- Attacker uses same ASN/country as victim (no anomaly)
- Privilege gained via already-privileged principal (no AssumeRole needed)

**Tuning**
- Allowlist known VPN/SSO egress ASNs
- Severity boost if target account is prod
- Require “rare role assumption” baseline (principal rarely assumes AdminRole)


### Detection 2: Privilege change → Credential persistence (Azure or AWS)
Option A (Azure):
**Goal**
Detect RBAC escalation followed by persistence.

**Data required**
- Azure Activity Log:
  - roleAssignments/write
  - (optional) any credential-related events from identity provider logs (if available)
- Fields: caller, target principal, role, scope, timestamp

**Logic**
Trigger when:
- roleAssignments/write grants high privilege (Owner/Contributor/User Access Admin)
AND within 30 minutes:
- a second privileged change occurs by the same caller or on the same scope
  (e.g., another role assignment, broadened scope, or unusual resource creation)

**Expected false positives**
- IaC pipeline applying a change set
- Legit access grant during onboarding

**Blind spots / FN**
- Attacker already has Owner and doesn’t need new assignment
- Missing identity provider telemetry for credential changes

**Tuning**
- Allowlist IaC service principals
- Require change ticket tag/process to lower severity
- Severity boost if scope is subscription-wide or management group

Option B (AWS):
**Goal**
Detect privileged role usage followed by access key creation.

**Data required**
- CloudTrail:
  - AssumeRole (into privileged role)
  - CreateAccessKey (for any user)
- Fields: principal, target user, timestamps

**Logic**
Trigger when:
- AssumeRole into privileged role
AND within 15 minutes:
- CreateAccessKey occurs (especially for a different user than the principal)

**Expected false positives**
- Admin rotating keys during scheduled maintenance

**Blind spots / FN**
- Attacker uses existing keys (no creation)
- Key creation done by automation principal already trusted

**Tuning**
- Allowlist known key rotation automation
- Require correlation with login anomaly to raise confidence


---

## Key takeaway
- Single events are often noisy.
- High-confidence cloud detections are **chains**:
  identity anomaly → privilege → persistence/discovery/impact.
