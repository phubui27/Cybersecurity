1. 10 failed SSH logins from same IP in 2 minutes
2. 1 failed login attempt from user
3. User downloaded 15GB data
4. Admin login at 03:00 AM
5. DNS request to random long domain
6. HTTPS access to company website

Benign        → Normal behavior
Suspicious    → Investigate further
Malicious     → Incident, act now
False Positive→ Fix detection, not user


# SOC Thinking – Alerts vs Incidents

## Key insight
Alerts are signals, not conclusions.

## Alert classification exercise

1. Alert: 10 failed SSH logins in 2 minutes  
Classification: Escalate  
Reason: Repeated authentication failures on sensitive service.

2. Alert: Single failed login  
Classification: Auto-close  
Reason: Common user behavior.

3. Alert: User downloaded 15GB data  
Classification: Need more context  
Reason: Large data transfer may be normal (backup, analytics, media files) or indicate data exfiltration depending on user role, data sensitivity, destination, and timing.

4. Alert: Admin login at 03:00 AM  
Classification: Need more context  
Reason: After-hours admin access can be part of maintenance or incident response, but may also indicate credential compromise. Requires verification of user, source IP, and historical behavior.

5. Alert: DNS request to random long domain  
Classification: Escalate  
Reason: Randomized or unusually long domain names are commonly associated with malware command-and-control or data exfiltration techniques.

6. Alert: HTTPS access to company website  
Classification: Auto-close  
Reason: Normal and expected behavior with no inherent security risk.


## Why these classifications matter

- Auto-close alerts should not consume analyst time.
- Escalated alerts indicate patterns, not proof of compromise.
- "Need more context" alerts are where human judgment is most valuable.


## What makes an alert dangerous?
- Repetition
- Sensitive asset
- Unusual timing
- Uncommon behavior
