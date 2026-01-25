# Day 2 Lab Output – Log Engineering (Signal vs Context vs Noise)

## Lab goal (what this lab is really teaching)
This lab is NOT about deciding whether a log is malicious or benign.

It trains one core skill:
- Which logs are worth building detections on (**Signal logs**),
- Which logs are best used to support investigations (**Context logs**),
- Which logs will flood the SOC without improving security (**Noise / Ignore**).

Why this matters:
- SIEM/SOAR cost and analyst workload scale with log volume.
- SOC burnout is usually caused by noise, not attackers.
- Automation and AI only work well if the input logs are high-signal and well-contextualized.

---

## Part 1 — Log classification (no tools)

### 1) SSH login success after 8 failures
Classification: **Signal log**

Why:
- This represents a valuable behavioral pattern: many failures followed by a success.
- It can be benign (user typo) or malicious (brute-force success / stolen credential), but either way it is human/attacker behavior, not system health.
- It is a strong candidate for detection because it indicates an authentication boundary being pressured and possibly crossed.

---

### 2) Windows Event 4624 — login from new IP
Classification: **Signal log**

Why:
- A successful login from a new IP is a behavioral change.
- This is a foundation for identity-anomaly detections (new location, new device, compromised credentials).
- It is not automatically malicious, but it is worth detecting because it can reveal account takeover early.

---

### 3) Windows Event 4672 — special privileges assigned
Classification: **Signal log (high-signal)**

Why:
- 4672 indicates privileged rights were granted during logon.
- Privileged activity is a high-value target for attackers and a high-value signal for defenders.
- Alone it does not prove compromise, but it is a powerful detection ingredient.

---

### 4) Linux cron job executed
Classification: **Context log**

Why:
- Cron executions are normal and frequent, so alerting on them alone creates noise.
- However, cron is also a common persistence mechanism.
- This log becomes valuable when correlated with other suspicious signals (unexpected login, new user, privilege escalation).

Best use:
- Investigation context and timeline building, not standalone alerting.

---

### 5) Windows file access event
Classification: **Context log**

Why:
- File access occurs constantly and becomes noisy very quickly.
- Alone it does not reliably indicate malicious behavior.
- In real incidents (data theft / ransomware / insider threat), file access logs are crucial to confirm scope and impact.

Best use:
- Confirming what was accessed after a suspicious identity or process event is detected.

---

### 6) CPU usage reached 95%
Classification: **Noise / Ignore (SOC perspective)**

Why:
- This is primarily IT Ops monitoring, not security detection.
- CPU spikes do not directly reflect attacker behavior.
- It tends to generate frequent alerts that consume analyst time without improving detection.

Exception (rare):
- CPU spike may matter only when correlated with process telemetry (suspicious process, crypto-mining indicators, abnormal commands).
- In that case, the signal is the process activity, not CPU percentage alone.

---

## Classification summary
- **Signal logs**:  
  1) SSH success after failures  
  2) 4624 login from new IP  
  3) 4672 special privileges assigned

- **Context logs**:  
  4) cron executed  
  5) file access event

- **Noise / Ignore**:  
  6) CPU usage 95%

---

## Part 2 — Detection candidate thinking

### A) Detection candidate #1: SSH success after multiple failures

Detection idea:
- Trigger when a successful SSH login happens shortly after many failed attempts.

Basic logic:
- If the same user (or same target host) has ≥ N failed logins within T minutes,
  and then a login success occurs,
  flag: **Suspicious successful authentication after repeated failures**.

Why it’s useful:
- Captures a common attacker pattern (try many → eventually succeed).
- Higher signal than alerting on failures alone.

Where it can be wrong (without context):
- User forgets password and retries many times.
- Automation scripts retry due to configuration issues.
- NAT/proxy makes “same IP” represent many users.

Context that improves accuracy:
- Baseline: does this user often fail logins?
- Known corporate VPN ranges allowlist.
- Geo / ASN reputation of source IP.
- Asset criticality (prod server vs dev box).
- Time-of-day pattern.

---

### B) Detection candidate #2: Windows 4624 login from new IP

Detection idea:
- Flag successful logons from an unseen source IP for that user.

Basic logic:
- If Event 4624 occurs,
  and source IP not previously observed for this user in the past X days,
  flag: **New source login anomaly**.

Why it’s useful:
- Early signal of account takeover.
- A building block for more advanced identity detections.

Where it can be wrong (without context):
- DHCP changes IP frequently.
- User travels or uses mobile networks.
- VPN usage changes apparent source IP.

Context that improves accuracy:
- Known VPN ranges allowlist.
- Device identity / host fingerprint (if available).
- Historical baseline by user (normal countries, normal time).
- Role sensitivity (admin vs regular employee).

---

## Bonus: A stronger detection by correlating signals (4624 + 4672)

Stronger detection idea:
- A new-IP login becomes more concerning if it is also a privileged logon.

Logic:
- If 4624 (successful login from new IP)
  AND within a short time window there is 4672 (special privileges assigned),
  flag: **Privileged login anomaly**.

Why this is better:
- Reduces false positives compared to using 4624 or 4672 alone.
- Combines behavior change (new IP) + privilege (high impact).
- This is how detection engineering improves signal quality.

---

## Key takeaway
More logs do not automatically mean better security.

- **Signal logs** drive detections.
- **Context logs** make investigations accurate.
- **Noise logs** destroy SOC capacity and make automation useless.

Automation and AI are only as good as the detection inputs you choose.
