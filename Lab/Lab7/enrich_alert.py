import json
from pathlib import Path
from datetime import datetime, timezone

# -----------------------------
# Mock enrichment data (no APIs)
# -----------------------------
BAD_IPS = {"185.10.10.10"}                 # pretend threat intel
ALLOWLIST_IPS = {"10.0.0.1", "203.0.113.10"}  # corporate VPN/office egress

USER_ROLES = {"alice": "admin", "bob": "user"}
ASSET_CRITICALITY = {"aws-prod-account": "prod", "aws-dev-account": "dev"}

# baseline: where the user normally logs in from
KNOWN_COUNTRIES_BY_USER = {"alice": {"VN", "SG"}, "bob": {"VN"}}

REQUIRED_FIELDS = ["alert_type", "user", "source_ip", "timestamp", "asset"]


def load_json(path: str) -> dict:
    """Load a JSON file into a dict."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def parse_timestamp(ts: str) -> datetime:
    """Parse ISO timestamp that may end with 'Z'."""
    # 'Z' means UTC; convert to +00:00 for fromisoformat
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def is_out_of_hours(ts: str) -> bool:
    """
    Very simple out-of-hours logic:
    treat 00:00-05:59 UTC as out-of-hours for the lab.
    (In real life you'd use org timezone + per-user baseline.)
    """
    dt = parse_timestamp(ts)
    hour = dt.astimezone(timezone.utc).hour
    return 0 <= hour <= 5


def fail_closed_if_missing(alert: dict) -> dict | None:
    """
    Fail-closed rule:
    If critical fields are missing, do not auto-close.
    Return a safe output object; otherwise return None to continue pipeline.
    """
    missing = [f for f in REQUIRED_FIELDS if not alert.get(f)]
    if not missing:
        return None

    return {
        "input_alert": alert,
        "risk_score": 50,
        "decision": "Suspicious",
        "why": [f"Missing critical fields {missing} → fail-closed (no auto-close)."],
        "recommended_next_steps": [
            "Collect missing fields and re-run enrichment.",
            "Check upstream parser/mapping for the missing fields.",
            "Escalate to human review if the alert has high impact."
        ],
        "approval_required": True
    }


def enrich(alert: dict) -> dict:
    """Add context fields to the alert (mock enrichment)."""
    user = alert["user"].lower()
    asset = alert["asset"]
    ip = alert["source_ip"]
    country = alert.get("country")

    alert["user_role"] = USER_ROLES.get(user, "unknown")
    alert["asset_criticality"] = ASSET_CRITICALITY.get(asset, "unknown")

    alert["ip_is_bad"] = ip in BAD_IPS
    alert["ip_is_allowlisted"] = ip in ALLOWLIST_IPS

    known_countries = KNOWN_COUNTRIES_BY_USER.get(user, set())
    alert["country_is_new_for_user"] = bool(country) and (country not in known_countries)

    alert["out_of_hours"] = is_out_of_hours(alert["timestamp"])
    return alert


def score(enriched: dict) -> int:
    """
    Rule-based scoring (0-100).
    Keep it explainable: each indicator adds points.
    """
    s = 0
    if enriched["ip_is_bad"]:
        s += 40
    if enriched["country_is_new_for_user"]:
        s += 15
    if enriched["out_of_hours"]:
        s += 10
    if enriched["user_role"] == "admin":
        s += 25
    if enriched["asset_criticality"] == "prod":
        s += 20

    # small bump based on alert type (optional)
    if enriched.get("alert_type") == "aws_console_login_anomaly":
        s += 10

    # clamp to [0, 100]
    return max(0, min(100, s))


def decision_from_score(s: int) -> str:
    """Map score to decision buckets."""
    if s >= 60:
        return "Malicious"
    if s >= 20:
        return "Suspicious"
    return "Benign"


def build_why(enriched: dict) -> list[str]:
    """Create 3-5 explainable bullets for humans."""
    why = []
    if enriched["ip_is_bad"]:
        why.append("Source IP matches known badlist/threat intel.")
    if enriched["country_is_new_for_user"]:
        why.append("Login from a country not seen for this user (baseline anomaly).")
    if enriched["out_of_hours"]:
        why.append("Activity occurred outside typical business hours (out-of-hours).")
    if enriched["user_role"] == "admin":
        why.append("User has admin privileges (higher impact if compromised).")
    if enriched["asset_criticality"] == "prod":
        why.append("Target asset is production-critical (higher blast radius).")

    if not why:
        why.append("No strong risk indicators found after enrichment.")
    return why[:5]


def recommended_next_steps(decision: str) -> list[str]:
    """Always return actionable next steps."""
    base = [
        "Check recent sign-in history (new IPs/countries, failures before success).",
        "Validate whether the activity is expected (on-call, change request, travel).",
        "Pull related events in the last 30–60 minutes (AssumeRole, IAM changes, access key creation).",
    ]
    if decision == "Malicious":
        # still don't execute; just recommend pending approval
        base[2] = "Pull related events (AssumeRole/IAM changes) and prepare containment actions pending approval."
    return base[:3]


def approval_required(enriched: dict, decision: str) -> bool:
    """
    Approval gate:
    Require human approval if high-risk or high-blast-radius.
    """
    if decision == "Malicious":
        return True
    if enriched["user_role"] == "admin" and enriched["asset_criticality"] == "prod":
        return True
    return False

def write_audit(output: dict, audit_path="audit.log") -> None:
    line = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "alert_type": output["input_alert"].get("alert_type"),
        "user": output["input_alert"].get("user"),
        "source_ip": output["input_alert"].get("source_ip"),
        "asset": output["input_alert"].get("asset"),
        "risk_score": output.get("risk_score"),
        "decision": output.get("decision"),
        "approval_required": output.get("approval_required"),
    }
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


def run_pipeline(input_path: str | None = None, output_path: str | None = None) -> dict:
    """Main pipeline orchestration."""
    script_dir = Path(__file__).resolve().parent
    resolved_input = Path(input_path) if input_path else script_dir / "sample_alert.json"
    resolved_output = Path(output_path) if output_path else script_dir / "output_sample.json"

    alert = load_json(str(resolved_input))

    # LAB B rule 1: fail-closed if missing critical fields
    safe_output = fail_closed_if_missing(alert)
    if safe_output is not None:
        write_audit(safe_output)  
        resolved_output.write_text(json.dumps(safe_output, indent=2), encoding="utf-8")
        return safe_output

    enriched = enrich(alert)
    s = score(enriched)
    dec = decision_from_score(s)

    output = {
        "input_alert": alert,
        "risk_score": s,
        "decision": dec,
        "why": build_why(enriched),
        "recommended_next_steps": recommended_next_steps(dec),
        "approval_required": approval_required(enriched, dec),
    }

    write_audit(output)  
    resolved_output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return output



if __name__ == "__main__":
    result = run_pipeline()
    print(json.dumps(result, indent=2))
