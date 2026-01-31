# Day 7 – Mini Alert Enrichment Pipeline (Human-in-the-loop)

## What it does
Converts a raw alert JSON into a triage-ready output by adding context and producing:
- risk_score (0-100)
- decision (Benign/Suspicious/Malicious/FalsePositive)
- why (explainable reasons)
- recommended_next_steps
- approval_required gate

## Safety design
- Fail-closed if critical fields are missing
- Audit trail written to audit.log
- Approval gate for high-blast-radius scenarios (no auto-containment)

## How to run
python3 enrich_alert.py
