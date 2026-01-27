# Day 4 – MITRE ATT&CK Mapping (Blue Team)

## What ATT&CK is (useful definition)
MITRE ATT&CK is a knowledge base of real-world adversary behavior.
It provides a common language to describe attacker actions and helps defenders plan detection coverage. 

### Structure you must not confuse
- **Tactic** = attacker goal / objective (the “why/what”)
- **Technique** = attacker method (the “how”)
- **Sub-technique** = more specific variation of a technique 
### Enterprise Matrix platforms (why this matters)
Enterprise Matrix covers multiple platforms (e.g., Windows, macOS, Linux, Identity Provider, SaaS, IaaS, Containers, Network Devices, ESXi).
So “mapping” must always consider WHERE the behavior happens and what telemetry exists there.

---

## Chosen tactic & technique for Week 1
- **Tactic:** TA0006 Credential Access 
- **Technique:** T1110 Brute Force 

---

## TA0006 – Credential Access (core idea)
Credential Access means the adversary is trying to obtain credentials (usernames, passwords, tokens).
Techniques include things like keylogging and credential dumping.
Using legitimate credentials can make adversaries harder to detect and can help them create additional accounts to achieve goals. 
---

## T1110 – Brute Force (core idea)
Brute Force is when adversaries repeatedly attempt credentials to gain access when passwords are unknown (or when hashes are obtained).
Brute force can appear at different stages of a breach, not only initial access.
Attackers may leverage knowledge gathered post-compromise (e.g., account discovery, password policy discovery) to increase success. 

### Important variants to remember (why your rules miss attacks)
- **Password Spraying**: try one/common passwords across many accounts to avoid lockouts. 
- (Also commonly discussed under T1110: credential stuffing, password guessing/cracking)

---

## Defender mindset: ATT&CK is for coverage, not “memorization”
ATT&CK helps you:
- map attacker behavior → required telemetry → detection ideas
- identify blind spots (no log/no field/no visibility = you’re blind)
- communicate detections and gaps in a structured way 

---
