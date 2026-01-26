## Lab A – "Alert if >5 failed logins in 1 minute (per user)"
This lab teaches one thing:
A rule can be logically correct but operationally dangerous.

### 1) Why false positives happen (3 examples)
FP happens when the rule matches normal behavior patterns.

Example FP scenarios:
1) User forgets password and retries quickly
- Multiple failures in short time but not an attack.

2) Mobile/VPN instability causing repeated auth retries
- The user is legitimate but the network causes repeated failures.

3) Automation/account sync issues
- A legit service might retry quickly due to a misconfiguration.

Key idea:
False positives happen because the rule sees "pattern" but lacks **intent + context**.

### 2) Why false negatives happen (3 examples)
FN happens when attackers avoid your window/threshold.

Example FN scenarios:
1) Slow brute force ("low and slow")
- Attacker tries 1 attempt every 2 minutes.
- Your 1-minute window never triggers.

2) Password spraying
- Attacker does 1 attempt per user across many users.
- "per user threshold" never triggers.

3) Distributed attempts from many IPs/bots
- Each IP makes few attempts.
- Your rule based on one source pattern misses the whole picture.

Key idea:
False negatives happen because attackers adapt to your detection knobs.

### 3) Tuning plan (3+ improvements)
Tuning is not "make it stricter" or "make it looser".
Tuning is "add intelligence".

Tuning options:
1) Add correlation: failures -> success
- Alert only when failures are followed by a success.
- This reduces noise and increases relevance.

2) Add context: known VPN ranges / office IP allowlist
- Reduce alerts when failures originate from trusted infrastructure.

3) Add multi-window logic
- Keep the 1-minute rule, but also add a longer window
  (e.g., 20 failures in 30 minutes) to catch slow attacks.

4) Add per-IP and per-user dimensions
- Detect both:
  - many failures for one user (targeted guessing)
  - many failures from one IP across many users (spraying)

5) Add asset sensitivity and account type
- Higher sensitivity for:
  - admin accounts
  - prod servers
- Lower sensitivity for:
  - dev boxes
  - non-privileged accounts

Key takeaway of Lab A:
Detection engineering is about designing rules that remain useful in real operations.

---

## Lab B – Detection draft (example: SSH failures -> success)

### Goal
Detect suspicious SSH access that may indicate brute-force success or credential compromise.

### Data required
- Linux auth.log:
  - failed login events (Failed password)
  - successful login events (Accepted password)
- Fields needed:
  - username
  - source IP
  - target host
  - timestamp

### Logic (threshold + window + correlation)
1) Count failed SSH logins per (username, source IP) in 2 minutes.
2) If failures >= 8 AND a success occurs within 5 minutes after,
   create an alert: "SSH suspicious authentication success after repeated failures".

### Expected false positives
- User typing wrong password multiple times then succeeds.
- Automation scripts with retry behavior.
- Shared NAT environment where IP represents multiple users.

### Known blind spots / false negatives
- Password spraying (1 attempt per user).
- Distributed attacks across many IPs.
- Use of valid credentials without prior failed attempts.

### Tuning ideas
- Exclude known corporate VPN IP ranges.
- Add baseline: alert only if this user rarely fails logins.
- Add asset criticality: higher severity on prod servers.
- Add additional correlation:
  - new IP + after-hours + privileged user => higher severity.

---

## Key takeaway
A detection is not just "if X then alert".
A good detection:
- uses the right logs (signal)
- chooses the right thresholds/windows (engineering trade-off)
- adds context and correlation (intelligence)
- has lifecycle and tuning (stays accurate over time)