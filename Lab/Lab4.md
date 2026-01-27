# Day 4 – Lab Solution (MITRE ATT&CK Mapping)
Chọn T1110 Brute Force và làm bảng này:

Technique: T1110 Brute Force

Possible telemetry sources:

Linux auth.log (SSH)

Windows 4625 / 4624

VPN logs (nếu có)

Detection ideas (ít nhất 3):

fail burst (threshold + window)

fail → success correlation

distributed attempts (per IP across many users)

Expected false positives:

typo, password resets, automation

Blind spots / evasions:

low-and-slow, password spraying, botnet

📌 Bạn đang làm “detection coverage thinking”, không viết Sigma/Splunk query.

🧠 Lab B — Viết 1 mini attack path (text diagram)

Tạo một đường tấn công đơn giản dạng chữ:

Ví dụ (bạn có thể dùng hoặc tự làm):

Initial Access
  → Credential Access (Brute Force T1110)
    → Successful Login (4624 / SSH Accepted)
      → Privilege Misuse (4672)
        → Persistence (cron job)


👉 Nhiệm vụ:

Với mỗi bước, ghi:

Log nào hỗ trợ phát hiện?

Detection point nào khả thi?

Chỗ nào bạn mù (no telemetry)?
## Lab A — Technique → Telemetry → Detection ideas
### Technique
- **T1110 Brute Force** (Credential Access) 

### What the attacker is trying to do (plain language)
Adversary repeatedly attempts credentials to obtain access to valid accounts when passwords are unknown.
This can happen during initial access or later in the intrusion.

### Possible telemetry sources (what logs can show it)
- **Linux**: `/var/log/auth.log` (SSH failed/success auth)
- **Windows**: Security Event Logs
  - **4625** failed logon attempts
  - **4624** successful logon (for correlation)
- **VPN / Identity Provider logs** (if present): failed auth bursts, new locations, risky sign-in patterns
- (Optional) Firewall/WAF logs: repeated auth attempts to exposed services

### Detection ideas (at least 3)
1) **Burst failures (threshold + short window)**
   - Trigger when failed logons > N within T minutes per (user) or per (source IP).
   - Value: catches noisy brute force quickly.

2) **Failure → Success correlation (higher signal)**
   - Trigger when failures are followed by a success within a short time window.
   - Value: better signal quality than failures alone.

3) **Password spraying pattern (cross-user, same source)**
   - Trigger when one source IP attempts 1–2 failed logons across many distinct usernames within a longer window.
   - Why: password spraying is a common brute force variant and avoids per-user thresholds. 

4) **Multi-window approach (catch fast + slow)**
   - Rule A: >N failures in 1–2 minutes (fast)
   - Rule B: >M failures in 30–60 minutes (low-and-slow)

### Expected false positives (common benign causes)
- Users mistyping passwords repeatedly
- Service accounts misconfigured and retrying
- VPN instability causing repeated auth retries
- Password reset events during IT maintenance window

### Blind spots / evasions (how attackers avoid your rules)
- **Low-and-slow** attempts (evade short windows)
- **Distributed botnet** attempts (evade per-IP thresholds)
- **Password spraying** (evade per-user thresholds) 
- Use of already-valid credentials without any prior failures (no brute-force signature)

---

## Lab B — Mini attack path (text diagram) + detection points

### Mini attack path (simple)
Initial Access
  → Credential Access (T1110 Brute Force)
    → Valid Account Access (successful login)
      → Privilege Use / Misuse (admin rights)
        → Persistence (scheduled task / cron)

### Step-by-step mapping

#### 1) Credential Access – Brute Force (T1110)
- Evidence/telemetry:
  - Linux: repeated `Failed password` entries
  - Windows: 4625 bursts
- Detection points:
  - Burst failures
  - Password spraying across users
  - Failure→Success correlation

#### 2) Successful login (post brute force)
- Evidence/telemetry:
  - Linux: `Accepted password`
  - Windows: 4624
- Detection points:
  - Success after burst failures
  - New IP / unusual time login (needs baseline/context)

#### 3) Privilege use / misuse
- Evidence/telemetry:
  - Windows: 4672 (special privileges assigned) (if enabled/visible)
- Detection points:
  - 4624 from new IP + 4672 within short window = “Privileged login anomaly”
  - Privileged activity outside baseline hours (context)

#### 4) Persistence (cron / scheduled)
- Evidence/telemetry:
  - Linux: cron execution logs
  - Windows: scheduled task creation logs (depends on telemetry configuration)
- Detection points:
  - New cron job creation (high signal) vs cron job execution (context-heavy)
  - Correlate persistence action after suspicious login

### Coverage gaps (blind spots you should explicitly note)
- If you lack:
  - source IP fields, you can’t do “new IP” logic
  - baseline history, you can’t do “unusual” well
  - scheduled task/cron creation telemetry, persistence detection becomes weak
- ATT&CK mapping exposes what you cannot detect due to missing telemetry. 

---

## Key takeaway
ATT&CK mapping turns detection into a coverage plan:
behavior → telemetry → detection ideas → known false positives → known blind spots.
