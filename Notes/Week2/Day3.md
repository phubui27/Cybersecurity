# Week 2 – Day 3 (Theory)
## SOAR Playbook Design (Vendor-agnostic) + Human-in-the-loop

## 1) Playbook ≠ Script
- **Script**: code làm một tác vụ cụ thể (ví dụ: enrich alert, lookup IP, create ticket).
- **Playbook**: workflow end-to-end để xử lý một tình huống (triage → evidence → decision → containment → documentation).
- Script là “brick”, playbook là “building”.

## 2) SOAR playbook luôn có 5 khối chuẩn
1) **Trigger**: loại alert/event nào kích hoạt playbook?
2) **Enrichment**: thêm context gì để ra quyết định nhanh hơn?
3) **Decision**: quy tắc/score để phân loại (Benign/Suspicious/Malicious).
4) **Actions**: ticket + notify + query thêm + evidence bundle.
5) **Containment**: bước nào có blast radius và cần approval gate?

## 3) Human-in-the-loop là luật sống còn
Automation làm tốt:
- Enrich, correlate, build timeline, open ticket, notify, attach evidence.
Human phải làm:
- Disable accounts / revoke sessions
- Rotate/delete access keys
- Revert RBAC changes
- Block network actions
=> Các bước “cắt quyền/cắt mạng” luôn phải có **approval gate**.

## 4) Blast radius: thứ quyết định bạn có được auto hay không
- Blast radius cao: ảnh hưởng prod, nhiều user, outage risk.
- Trong cloud, blast radius thường tăng mạnh khi liên quan:
  - admin identities
  - prod accounts/subscriptions
  - subscription-wide RBAC scope
  - key/session revocation

## 5) Evidence bundle là output quan trọng nhất của playbook
Một playbook tốt phải tạo được “gói bằng chứng” để analyst đọc 1 lần là hiểu:
- timeline 30–60 phút
- identity (who), source (where), actions (what), time (when)
- related events (AssumeRole, CreateAccessKey, roleAssignments/write, etc.)
- risk score + decision + why

## 6) Failure modes: thiếu dữ liệu thì xử lý thế nào
- Nếu thiếu field/log quan trọng → **fail-closed**
  - decision không được là Benign
  - escalate/human review
- Playbook phải ghi rõ “what to do if missing data”.

## 7) Tuning feedback loop (để giảm FP/FN)
Sau khi xử lý xong case, playbook nên yêu cầu:
- cập nhật allowlist (VPN, IaC principal)
- cập nhật baseline (user travel, new ASN)
- cập nhật detection thresholds/windows
- ghi lại root cause của FP/FN để cải tiến

## Key takeaway
SOAR playbook đúng nghề là:
Trigger → Enrich → Decide → Evidence → (Approval) Contain → Document → Improve.
