# Week 2 – Day 2 (Theory)
## Cloud Detection Engineering – IAM/RBAC Abuse + Correlation

## 1) Cloud detection khác on-prem ở điểm nào?
- On-prem: nhiều detection dựa vào process/host telemetry.
- Cloud: phần “đáng tiền” nhất là **identity + privilege + control-plane actions**.
- Cloud incidents thường đi theo chuỗi:
  1) Identity compromise (login/risky sign-in)
  2) Privilege change (AssumeRole/RBAC)
  3) Persistence (CreateAccessKey/new admin principal)
  4) Discovery (list/describe)
  5) Impact (exfil/resource abuse)

## 2) Ba nhóm hành vi cần ưu tiên detect
### A) Identity anomaly (Account Takeover candidates)
High-signal triggers:
- Success login from new country/ASN/IP (baseline anomaly)
- Out-of-hours success login
- Failures → Success correlation (nếu có failures)

### B) Privilege actions (blast radius cực lớn)
AWS:
- AssumeRole into privileged roles
- IAM policy attachment/permission changes (attach admin policy)
Azure:
- roleAssignments/write (RBAC changes), especially Owner/Contributor at broad scope

### C) Persistence via credentials
- CreateAccessKey (AWS), new service principal credentials (Azure side)
- New admin principal creation
- Attempts to reduce visibility (logging config changes) nếu bạn quan sát được

## 3) Signal vs Context vs Noise (rule of thumb)
- Signal: identity + privilege + credential creation + broad control-plane changes
- Context: list/describe/enumeration, VM write (khi chưa có identity anomaly)
- Noise: read-only phổ biến (standalone alerting thường gây mệt)

## 4) Detection engineering mindset (đúng nghề)
- Một detection tốt phải có:
  - Goal (behavior-based)
  - Data required (fields must exist)
  - Logic (threshold/window + context/correlation)
  - Expected FP (đoán trước noise nguồn nào)
  - Blind spots/FN (attacker né kiểu gì)
  - Tuning plan (allowlist + baseline + severity by asset/user)

## 5) Correlation patterns “đáng tiền” (cloud-first)
- Login anomaly → Privilege action within 5–15 minutes
- Privilege action → CreateAccessKey within 15–30 minutes
- Identity anomaly → Discovery spikes (ListBuckets/DescribeInstances)
- Privilege action → broad resource changes (VM/network/storage) trong thời gian ngắn

## 6) Human-in-the-loop boundary
Automation có thể:
- enrich context, build timeline, group events, suggest actions
Nhưng phải có approval gate với:
- disabling principals, revoking keys/sessions
- blocking IPs
- removing RBAC/roles (risk outage)

## Key takeaway
Cloud detection “đúng” là detection theo chuỗi hành vi (correlation),
không phải alert từng event đơn lẻ.
