# Day 3 – Detection Thinking (Why detections fail)

## What this day is about
Detection is NOT "a rule that catches attacks".
Detection is a **living product** that must balance:
- catching real attacks (reduce False Negatives)
- not exhausting analysts (reduce False Positives)
- adapting as environments change (avoid detection drift)

---

## Core vocabulary (must be clear)

### Signal vs Noise (at detection level)
- Signal: an event/pattern that is strongly related to attacker behavior.
- Noise: events that happen frequently in normal operations and trigger alerts without security value.

Important:
A **signal log** can still become **noise** if the detection logic is poorly designed.

### Threshold + Time window
Every rule has at least 2 hidden knobs:
- Threshold (how many times)
- Window (in how much time)

These two knobs decide whether you create:
- too many False Positives (burn the SOC)
- or too many False Negatives (miss real attacks)

### Context vs Correlation
- Context: information that makes a rule smarter
  (user role, asset criticality, known VPN ranges, business hours, baseline)
- Correlation: connecting multiple signals to form a story
  (fail -> success, login -> privilege, download -> DNS anomaly)

---

## 5 common detection failure modes (practical)
1) Bad data / missing telemetry
- You cannot detect what you do not collect.
- Example: no source IP field -> "new IP login" becomes impossible.

2) No context (rules treat everything the same)
- Admin login at 3AM is different from intern login at 3AM.
- A login into prod is different from a login into dev.

3) Over-sensitive thresholds (FP explosion)
- Rules trigger on normal operations.
- Result: alert fatigue and ignored alerts.

4) Under-sensitive thresholds (FN risk)
- Rules miss slow, distributed, or stealthy attacks.
- Result: you only see the attack after damage is done.

5) No lifecycle (detection drift)
- Environments change: new apps, new VPN, new workflows.
- A rule that worked last month can be wrong today.
- If you never review/tune, your SOC degrades over time.
