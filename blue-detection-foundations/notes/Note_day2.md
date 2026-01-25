# Log Engineering – SOC / Detection Perspective

## Core Question
Do these logs reflect human/attacker behavior or only system state?

### Answer
Authentication and privilege-related logs primarily reflect **human or attacker behavior**, while relying on system state only to record the action.

- System state confirms the service was running and processed a request.
- Log content records an **entity attempting to cross a security boundary**.

This makes these logs valuable for security detection.

---

## Log vs Detection vs Evidence

### 1. Log (Raw Data)
Logs are raw security-relevant records ingested by tools such as Winlogbeat or Filebeat.

**Windows Security Logs**
- **4624 – Successful Logon**  
  Records who logged in and from where.
- **4625 – Failed Logon**  
  Records unsuccessful authentication attempts.
- **4634 – Logoff**  
  Marks session termination.
- **4672 – Special Privileges Assigned**  
  Indicates privileged rights granted during logon.

**Linux Authentication Logs**
- Failed SSH authentication attempts  
  Example: `Failed password for root from 10.0.2.2`
- Successful SSH authentication  
  Example: `Accepted password for user from 10.0.2.2`

Logs alone do not indicate compromise. They only describe events.

---

### 2. Detection (Logic Layer)
Detection is logic applied on logs to identify suspicious or malicious behavior.

**Authentication Failure Logic**
- Single failure → likely human error.
- High-volume failures in short time → brute force or password spraying.

**Privilege Context Logic**
- Successful logon (4624) followed by privilege assignment (4672)
- On sensitive systems or unusual users → possible credential misuse or privilege escalation.

**Session Duration Logic**
- Very short sessions at unusual hours (e.g., 3 seconds at 3 AM)
- Often indicate automated scripts or attacker reconnaissance.

Detection combines:
- Frequency
- Context
- Timing
- Asset sensitivity

---

### 3. Evidence (Incident Confirmation)
Once an incident is declared, logs become **evidence**.

- **Who**: Account name in authentication logs
- **Where**: Source IP address
- **When**: Timestamps used to reconstruct timelines

Evidence supports investigation, attribution, and reporting.

---

## Human vs Attacker Behavior Indicators

| Log Event | Legitimate Scenario | Malicious Scenario |
|----------|---------------------|-------------------|
| 4625 / SSH Fail | Occasional typo | Brute force or password spraying |
| 4624 / SSH Success | Business-hour access | Unusual hour or new IP |
| 4672 Privileges | Admin maintenance | Privilege escalation or takeover |

---

## Key Insight
Authentication and privilege logs are **high-signal security logs** because they capture intent and outcome of human or attacker actions.

They are foundational for:
- Behavior-based detection
- UEBA
- Incident confirmation

Not all logs deserve detection logic.  
These logs do.
