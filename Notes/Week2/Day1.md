# Week 2 – Day 1 (Theory)  
## Cloud Logs 101 (AWS CloudTrail / Azure Activity Log) – Identity & API Behavior

### Core mindset (SOC 2026)
- Modern SOC is **hybrid**: cloud + on-prem.  
- In cloud, **everything important is an API call** → detection is **API behavior detection**.
- Highest-signal areas are **Identity + Privilege + Control-plane changes**.

---

## 1) AWS CloudTrail — what you must remember (SOC view)

### What CloudTrail is
- CloudTrail is an **audit log of AWS account activity**.
- It records actions from **AWS Console, CLI, SDK, and API calls**.
- It helps answer: **who did what, where, and when**.

### What matters most for security (high-signal categories)
- **Identity & authentication**
  - e.g., `ConsoleLogin` events
- **Privilege / role actions**
  - e.g., `AssumeRole` (STS) into privileged roles
- **Credential persistence**
  - e.g., `CreateAccessKey`, `CreateUser`
- **IAM / permission changes**
  - attach policies, modify roles/users (high impact)

### Key idea
CloudTrail is not “system logs”.  
It is **governance / identity and API control** visibility.

---

## 2) Azure Activity Log — what you must remember (SOC view)

### What Activity Log is
- Azure Activity Log is the platform log for **control-plane operations**.
- It records **create/update/delete** actions on resources.
- Think of it as: “Who changed what in Azure”.

### What matters most for security (high-signal categories)
- **RBAC / permission changes**
  - e.g., `Microsoft.Authorization/roleAssignments/write`
- **Resource modifications**
  - create/update critical resources (VMs, networking, storage)
- **Deployment failures / unexpected changes**
  - useful context for identifying malicious or misconfigured activity

### Key idea
Activity Log is strongest at answering:
- **who changed permissions**
- **who modified cloud resources**

---

## 3) 3 identity abuse patterns to detect first (cloud-first)

### Pattern 1 — Suspicious Console Login
Signals:
- successful login from **new country / new IP / new ASN**
- login **outside baseline hours**
- failure burst → success (if you track both)

Why it matters:
- Many cloud incidents begin with **account takeover**.

---

### Pattern 2 — Privilege actions (Privilege escalation / misuse)
Signals:
- AWS: `AssumeRole` into an admin role (especially unusual time/source)
- Azure: RBAC changes (`roleAssignments/write`)

Why it matters:
- Privilege events have **high blast radius** and enable follow-on actions.

---

### Pattern 3 — Persistence via credentials
Signals:
- AWS: `CreateAccessKey` (programmatic access persistence)
- New user + admin policy attachment
- Attempts to weaken visibility (disable logging / reduce monitoring), if observed

Why it matters:
- Attackers try to maintain access even after sessions expire.

---

## 4) Signal vs Context vs Noise (cloud SOC rule of thumb)

### Signal (alert-worthy)
- authentication success anomalies
- role/permission changes
- access key creation / IAM modifications
- suspicious control-plane changes on critical assets/accounts

### Context (correlation / investigation)
- enumeration actions (e.g., list/describe)
- normal resource writes (e.g., VM write) unless correlated to identity anomalies

### Noise (don’t alert alone)
- common read-only listing that happens constantly
- low-value standalone events without risk context

---

## Key takeaway
Cloud-first detection is primarily:
- **identity anomaly detection**
- **privilege and permission monitoring**
- **control-plane change awareness**

If you detect these well, automation/SOAR becomes realistic and safe.
