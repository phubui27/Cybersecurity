# Day 6 – Cloud Logs 101 (AWS CloudTrail / Azure Activity Log)

## Key insights
- Cloud logs are **API behavior logs**: “who did what, where, when”.
- Highest-signal areas in cloud detection:
  - Identity events (logins, auth anomalies)
  - Privilege events (AssumeRole, RBAC role assignments, access key creation)
  - Control-plane changes (create/modify resources)
- Read-only listing/enumeration is often **context**, not a standalone alert.

---

## Lab A – Signal vs Context vs Noise (SOC perspective)

1) AWS CloudTrail: `ConsoleLogin` success from new country  
Classification: **Signal**  
Reason: Identity anomaly (possible account takeover).

2) AWS CloudTrail: `AssumeRole` into `AdminRole` at 02:00 AM  
Classification: **Signal (High-signal)**  
Reason: Privilege action + unusual time. High impact if malicious.

3) AWS CloudTrail: `CreateAccessKey` for a user  
Classification: **Signal**  
Reason: Credential persistence / programmatic access creation is frequently abused post-compromise.

4) Azure Activity Log: `Microsoft.Authorization/roleAssignments/write`  
Classification: **Signal (High-signal)**  
Reason: RBAC change = privilege escalation / persistence path in Azure.

5) Azure Activity Log: `Microsoft.Compute/virtualMachines/write`  
Classification: **Context (upgrade to Signal with context)**  
Reason: Could be normal deployment or attacker creating/modifying compute. Needs identity + baseline context.

6) AWS CloudTrail: `DescribeInstances`  
Classification: **Context**  
Reason: Enumeration/recon behavior; low value as standalone alert but useful in correlation.

7) AWS CloudTrail: `ListBuckets`  
Classification: **Context (can be higher severity for sensitive environments)**  
Reason: S3 enumeration is common recon step; value increases if user role/baseline is unusual.

8) Azure Activity Log: read-only operation (list resources)  
Classification: **Noise/Ignore (alerting)**  
Reason: Very common; better used for hunting/correlation than alerting alone.

---

## Lab B – Detection drafts (2)

### Draft 1: AWS ConsoleLogin anomaly (new country / unusual login)
**Goal**  
Detect suspicious AWS console sign-ins that may indicate account takeover.

**Data required**  
- CloudTrail Management Events
- Event: `ConsoleLogin`
- Fields: userIdentity, sourceIPAddress, userAgent, eventTime, responseElements (Success/Failure), additionalEventData (MFAUsed if present), awsRegion

**Logic (context + baseline)**  
- Alert when `ConsoleLogin` = Success AND
  - source country/ASN is new for that user in last X days OR
  - login occurs outside baseline hours (e.g., 00:00–05:00) OR
  - preceded by multiple login failures within short window (fail → success correlation)
- Increase severity if:
  - MFA not used (if field available)
  - user is privileged (admin / root-equivalent)

**Expected false positives**  
- Legit travel
- New VPN exit IP / new corporate proxy
- First-time login from new location for new employee

**Blind spots / false negatives**  
- Attacker uses a previously seen IP/VPN
- Token/session theft without console login
- Compromise of federated identity not surfaced cleanly in CloudTrail (depends on setup)

**Tuning ideas**  
- Allowlist corporate VPN/proxy egress ranges
- Baseline by user role (admin vs non-admin)
- Add correlation: “ConsoleLogin anomaly → privilege actions within 10 minutes” = higher severity

---

### Draft 2: AWS AssumeRole into AdminRole anomaly (privilege misuse)
**Goal**  
Detect suspicious privilege elevation / admin role assumption that may indicate compromise or misuse.

**Data required**  
- CloudTrail Management Events
- Event: `AssumeRole` (STS)
- Fields: userIdentity (principal), roleArn/roleName, sourceIPAddress, eventTime, requestParameters, responseElements

**Logic (correlation + context)**  
- Alert when `AssumeRole` targets `AdminRole` (or any high-priv role) AND
  - occurs outside baseline hours OR
  - source IP is new/unusual for the principal OR
  - the principal rarely assumes this role (baseline frequency)
- Strong correlation (upgrade severity):
  - ConsoleLogin anomaly (Draft 1) occurred within 10 minutes before AssumeRole
  - Followed by IAM changes (CreateUser, AttachPolicy, CreateAccessKey) within 15 minutes

**Expected false positives**  
- On-call engineers doing emergency work
- Automation pipelines that legitimately assume admin roles (should be allowlisted and tagged)

**Blind spots / false negatives**  
- Attacker compromises existing automation role already trusted
- Privilege gained via other paths not visible as AssumeRole (depends on architecture)

**Tuning ideas**  
- Maintain allowlist of known automation principals + expected roles
- Require additional context for “human principals” vs “service principals”
- Add asset criticality tags (prod accounts higher severity)

---

## Key takeaway
Cloud-first detection focuses on identity and privilege actions.
Most cloud incidents start with identity misuse and quickly move into control-plane changes.
