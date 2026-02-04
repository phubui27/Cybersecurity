# Week 2 – Day 4 (Lab)
## Detection-as-Code Basics + Threat Hunting Queries (Vendor-agnostic)

> Goal: Turn cloud detections into **version-controlled artifacts** and write **vendor-agnostic hunting queries**.

---

## Lab A — Write 2 Detection-as-Code artifacts (Sigma-style thinking)

### Requirement
Create **2 detection artifacts** in a YAML-like format (vendor-agnostic).  
Each artifact must include:

- `title`
- `id` (you define)
- `status` (experimental/stable)
- `logsource` (product + service)
- `detection` (selection + condition)
- `level` (low/medium/high)
- `falsepositives` (at least 2)
- `fields_required` (at least 5 fields)
- `tags` (MITRE ATT&CK technique IDs if possible)
- `notes.tuning` (at least 2 tuning ideas)

### Detection artifact #1 (AWS)
**Scenario:** AWS CloudTrail `ConsoleLogin` success anomaly  
Detect successful console logins that are **anomalous** based on:
- **new country or new ASN** for the user (baseline anomaly), OR
- **out-of-hours** login

**Expected outcome:** a rule that would be reasonable to run continuously without flooding (after tuning).

### Detection artifact #2 (Azure)
**Scenario:** Azure Activity Log RBAC escalation  
Detect `Microsoft.Authorization/roleAssignments/write` where a **high-privilege role**
(e.g., Owner/Contributor/User Access Administrator) is granted at a **broad scope**
(e.g., subscription-wide or management group).

**Expected outcome:** a rule with clear blast-radius logic and tuning for IaC.

---

## Lab B — Write 2 Threat Hunting queries (vendor-agnostic pseudo-query)

### Requirement
Write **2 hunting queries** in a pseudo-query format (not tied to any SIEM).
Each hunt must include:

- Goal (1–2 sentences)
- Data source (CloudTrail / Azure Activity Log)
- Time window (e.g., 60m / 2h / 24h)
- Filters (what events)
- Correlation logic (how events connect)
- Output fields (what you want to print)

### Hunt #1 (AWS)
**Goal:** Find **discovery spikes** after suspicious login.  
Hunt for sequences like:
- suspicious `ConsoleLogin` success (new country/ASN OR out-of-hours)
- followed by bursts of discovery activity within 60 minutes:
  - `ListBuckets`, `DescribeInstances`, or similar list/describe calls

### Hunt #2 (Azure)
**Goal:** Find RBAC escalation followed by infrastructure changes.  
Hunt for:
- `roleAssignments/write` granting high privileges
- followed within 2 hours by “write” operations on:
  - VMs, networking, storage (e.g., virtualMachines/write, NSG write, storageAccounts/write)

---

## Submission (what you must produce)
Create a single markdown file with two sections:

1) `## Lab A – Detection artifacts`  
   - paste both YAML-like artifacts

2) `## Lab B – Hunting queries`  
   - paste both pseudo-queries

File name suggestion:
- `blue-detection-foundations/notes/week2_day4_lab.md`
### Rule 1 — AWS ConsoleLogin Anomaly (New Country / Out-of-hours)

```yaml
title: AWS ConsoleLogin Success Anomaly (New Country / Out-of-hours)
id: W2D4-AWS-001
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: ConsoleLogin
    outcome: Success
  anomaly_country:
    country_is_new_for_user: true
  anomaly_time:
    out_of_hours: true
  condition: selection and (anomaly_country or anomaly_time)
level: medium
falsepositives:
  - legitimate travel
  - new corporate VPN egress / proxy ASN
  - first-time login by new employee
fields_required:
  - userIdentity
  - sourceIPAddress
  - eventTime
  - outcome
  - country (or geo enrichment)
  - out_of_hours (derived) OR timestamp parsing
tags:
  - attack.t1078   # Valid Accounts (cloud account takeover pattern)
notes:
  tuning:
    - allowlist trusted VPN/proxy IP ranges
    - severity boost if user is admin or account is prod
    - correlation upgrade: ConsoleLogin anomaly -> AssumeRole/Admin actions within 10 minutes
Rule 2 — Azure RBAC Escalation (roleAssignments/write high privilege)
title: Azure RBAC High-Privilege Role Assignment (Potential Escalation)
id: W2D4-AZ-001
status: experimental
logsource:
  product: azure
  service: activitylog
detection:
  selection:
    operationName: Microsoft.Authorization/roleAssignments/write
    result: Success
  high_priv_role:
    role: [Owner, Contributor, User Access Administrator]
  broad_scope:
    scope: subscription_or_management_group
  condition: selection and high_priv_role and broad_scope
level: high
falsepositives:
  - legitimate admin access grant (approved change request)
  - IaC pipeline applying planned RBAC changes
fields_required:
  - caller
  - target_principal
  - role
  - scope
  - timestamp
  - result
tags:
  - attack.t1098   # Account Manipulation (permission/role changes)
notes:
  tuning:
    - allowlist known IaC service principals + expected scopes
    - require ticket/change-id tag if your org enforces it
    - correlation upgrade: login anomaly -> role assignment within 10 minutes
Lab B — Write 2 hunting queries (pseudo-query, vendor-agnostic)
Prompt
Write 2 hunting queries:

Find discovery spikes after suspicious login in AWS

Find RBAC changes followed by suspicious resource creation in Azure

Hunt 1 — AWS: Discovery spikes after suspicious login
Goal: find sequences like login anomaly -> ListBuckets/DescribeInstances burst.

Pseudo-query

Find ConsoleLogin Success events where:

country/ASN is new OR out-of-hours

Then within 60 minutes for same principal/account:

count(ListBuckets + DescribeInstances) > threshold (e.g., 20)

Pseudo

LET suspicious_logins = CloudTrail
  WHERE eventName == "ConsoleLogin" AND outcome == "Success"
  AND (country_is_new_for_user == true OR out_of_hours == true);

FOR EACH login IN suspicious_logins:
  FIND CloudTrail events within 60m of login
    WHERE userIdentity == login.userIdentity
    AND eventName IN ("ListBuckets", "DescribeInstances")
  GROUP BY userIdentity, accountId
  HAVING COUNT(*) > 20;
What you expect to learn

Which compromised accounts perform fast discovery after login.

Hunt 2 — Azure: RBAC change followed by suspicious resource creation
Goal: find roleAssignments/write that grants high privilege, followed by VM/network/storage changes.

Pseudo-query

Filter Activity Log for roleAssignments/write where role is Owner/Contributor/User Access Admin

Then within 2 hours on same subscription/scope:

find resource write events (e.g., virtualMachines/write, networkSecurityGroups/write, storageAccounts/write)

Pseudo

LET rbac_escalations = AzureActivity
  WHERE operationName == "Microsoft.Authorization/roleAssignments/write"
  AND result == "Success"
  AND role IN ("Owner","Contributor","User Access Administrator");

FOR EACH rbac IN rbac_escalations:
  FIND AzureActivity within 2h of rbac
    WHERE scope == rbac.scope
    AND operationName ENDSWITH "/write"
    AND operationName IN (
      "Microsoft.Compute/virtualMachines/write",
      "Microsoft.Network/networkSecurityGroups/write",
      "Microsoft.Storage/storageAccounts/write"
    );
What you expect to learn

Whether RBAC changes immediately enabled infrastructure actions (possible staging/mining/exfil setup).

Key takeaway
Detection-as-code = logic + fields + FP + tuning + ATT&CK mapping.

Hunting queries = explore behaviors and validate what should become detections.

