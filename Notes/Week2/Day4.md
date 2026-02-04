# Week 2 – Day 4 (Theory)
## Detection-as-Code Basics + Threat Hunting Queries (Vendor-agnostic)

## 1) Detection-as-Code là gì?
Detection-as-Code = viết detection theo dạng “code artifact” có:
- version control (Git)
- reviewable changes (PR mindset)
- testable assumptions (fields, log sources, false positives)
- reusable logic across tools/vendors

Nó giúp bạn thoát khỏi kiểu:
- “rule viết trong UI, không ai biết ai sửa”
- “không có changelog”
- “không rollback được”

## 2) Sigma-style thinking (không cần thuộc Sigma)
Bạn chỉ cần nắm cấu trúc tư duy:
- Title + ID (optional)
- Logsource (cloudtrail / azure activity / windows security / linux auth)
- Detection logic (selection + condition)
- Level (low/medium/high)
- False positives (expected noise)
- Tags (MITRE ATT&CK technique IDs)
- Fields required

## 3) Detection vs Hunting query khác nhau chỗ nào?
- Detection rule: chạy liên tục, phải tối ưu noise, phải có tuning plan.
- Hunting query: dùng để khám phá/điều tra, chấp nhận noise cao hơn, thường ad-hoc.

Rule of thumb:
- Hunting = “find weird”
- Detection = “alert on likely bad, reliably”

## 4) Cloud-first hunting patterns đáng nhớ
### Identity anomaly
- success login from new country/ASN/IP
- out-of-hours login
- failures → success

### Privilege changes
- AssumeRole into privileged roles (AWS)
- roleAssignments/write granting Owner/Contributor (Azure)

### Persistence by credentials
- CreateAccessKey (AWS)
- repeated role assignments to new principals (Azure)

### Discovery spikes
- ListBuckets/DescribeInstances bursts

## 5) Field discipline (quan trọng hơn query syntax)
Một detection fail thường do:
- thiếu field (source IP, principal, role name)
- inconsistent naming across sources
- timezone mismatch
- ingestion delays

Bạn phải luôn ghi:
- fields required
- assumptions
- fallback if field missing (fail-closed / lower confidence)

## 6) Output chuẩn cho portfolio
Mỗi detection artifact nên có:
- 1 “rule file” (YAML-like)
- 1 “hunting query” version (pseudo)
- 1 “test cases” section (2–3 sample events + expected match)
- 1 “tuning notes” section (allowlists/baselines)

## Key takeaway
Detection engineering 2026 = code + process + evidence.
Query chỉ là tool; tư duy mới là thứ bạn mang đi được.
