# Week 1 Capstone – SOC Thinking → Logs → Detection → ATT&CK

## Step 1 – Triage classification
1) 12 failed SSH logins from same IP in 3 minutes (root)  
Classification: Suspicious  
Reason: Brute-force pattern, but no confirmed access yet.

2) 1 successful SSH login from the same IP (root)  
Classification: Malicious  
Reason: Fail → success on root strongly indicates compromise candidate.

3) New cron job created for root  
Classification: Malicious  
Reason: Persistence-like action immediately after suspicious root access.

4) DNS query to a random long domain  
Classification: Suspicious (upgrade to Malicious if confirmed or host-correlated)  
Reason: Potential C2/DGA signal; needs context but high risk given surrounding events.

5) Windows 4625 failures for admin from one IP  
Classification: Suspicious  
Reason: Failed auth burst suggests brute force/spraying attempt.

6) Windows 4624 success for admin from same IP  
Classification: Malicious  
Reason: Fail → success indicates likely credential compromise.

7) Windows 4672 privileges assigned to admin  
Classification: Malicious  
Reason: Privileged session after suspicious login increases impact; treat as incident chain.

8) User downloaded 18GB to external destination  
Classification: Suspicious → Malicious (context-dependent)  
Reason: Could be legitimate, but in presence of auth anomalies it may indicate exfiltration.

9) HTTPS access to company website  
Classification: Benign  
Reason: Normal expected activity.

---

## Step 2 – Attack story (evidence-based)
- External IP performed SSH brute-force attempts against root on a Linux host.
- A successful root login occurred from the same IP shortly after repeated failures.
- A new cron job was created for root, consistent with persistence after compromise.
- DNS queries to a random long domain occurred, possibly indicating C2/DGA or staging activity.
- Separately, Windows admin account experienced failed logon bursts followed by a successful logon from the same IP.
- A privileged session (4672) was assigned to admin, increasing likelihood of admin credential misuse.
- Large external download (18GB) may represent exfiltration if correlated to the compromised user/host/time window.
- HTTPS access to the company website appears unrelated benign noise.

---

## Step 3 – Signal vs Context vs Noise
- Signal:
  - SSH failed burst (root), SSH success after failures
  - Cron job creation (root)
  - Windows 4625 burst → 4624 success
  - 4672 after suspicious login
  - Large external download (potential exfil signal)
- Context:
  - DNS random long domain (valuable corroboration)
  - Large download details (user role, destination allowlist, data type)
- Noise:
  - HTTPS access to company website

---

## Step 4 – Detection ideas (3) + SOAR playbook (1)

### Detection 1: SSH suspicious success after repeated failures (root)
- Logic: failures >= 10 within 5 minutes per (source IP, user=root, host) AND success within 10 minutes.
- Tuning: allowlist VPN/office ranges; increase severity for root and prod hosts.

### Detection 2: Windows privileged takeover chain (4625 → 4624 → 4672)
- Logic: 4625 burst >= N within T minutes, followed by 4624 success from same IP, then 4672 within 5 minutes.
- Tuning: allowlist jumpbox/VPN; add time-of-day and asset criticality.

### Detection 3: Potential exfil correlated with auth anomaly
- Logic: outbound download > 10GB to external destination within 1–2 hours AND correlated with suspicious auth (fail→success/new IP) OR suspicious DNS.
- Tuning: exclude sanctioned backup jobs; whitelist approved destinations; require user role.

### SOAR playbook idea: Privileged compromise containment (human approval gate)
- Auto: enrich IP/domain + baseline + asset criticality; build timeline; open ticket with evidence bundle.
- Approval gate: disable account / revoke sessions / isolate host / block IP.
- After approval: execute containment + notify stakeholders + start incident scoping checklist.

---

## Step 5 – AI vs Human boundary
- AI can: build timelines, correlate events, enrich reputation/geo, draft summaries, propose next questions.
- Humans must: confirm incident in business context, decide containment actions, scope impact (hosts/users/data), and prioritize response.
- Approval gates should protect: account disablement, host isolation, and network blocks to prevent self-inflicted outages.
