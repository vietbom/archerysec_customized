# Khôi phục định danh theo phiên bản dùng trong đồ án

> **Tài liệu lịch sử — không còn là chính sách hiện hành từ 17/11/2026.**
> Người dùng đã cho phép cải tiến lại. Xem
> [đặc tả v2 và bảng sửa quyển](scanner-upgrade-2026-11-17.md).
> Các công thức dưới đây còn dùng tính `dup_hash` tương thích, không còn là
> khóa đối chiếu chính của finding đã chuyển sang v2.

Ngày 14/11/2026: khôi phục riêng công thức fingerprint cho Gitleaks, Semgrep,
Trivy và OWASP ZAP. Không khôi phục toàn bộ parser cũ. Giữ UI, References,
notification, kiểm tra báo cáo hợp lệ, lịch sử scan và bảo toàn false positive.
Không sửa DOCX hay cấu hình GitLab/Jenkins.

## Công thức dùng để đối chiếu

Vẫn dùng `build_fingerprint()` chuẩn hóa biểu diễn JSON và băm SHA-256.
Khóa đối chiếu là `organization + project + scanner + dup_hash`.

| Nhóm | Các trường trong payload fingerprint |
| --- | --- |
| Gitleaks có Fingerprint nguồn | scanner, report_fingerprint |
| Gitleaks không có Fingerprint nguồn | scanner, rule, file, start_line, commit |
| Semgrep | scanner, check_id, severity, path, message, metadata, end, lines |
| Trivy vulnerability | scanner, artifact_type, vulnerability_id, package, installed_version, fixed_version, title, severity, target, type, class |
| Trivy secret | scanner, artifact_type, type=secret, title, severity, target, match, category, start_line, end_line |
| Trivy config | scanner, artifact_type, type=config, title, severity, target, message, resolution, resource, provider, code, start_line, end_line |
| ZAP | scanner, title, severity, scan_url, alert, instance, description, reference |

Semgrep không dùng native fingerprint/match ID để thay thế công thức cũ. ZAP
không gộp các alert khác bộ instances chỉ vì chúng cùng site/rule. Các thuộc
tính tham gia hash thay đổi có thể tạo finding mới và Auto-Close finding trước;
báo cáo giống nhau không tạo thêm finding. Báo cáo trả lại payload cũ sẽ tìm và
mở lại UUID cũ, trừ finding đã được xác nhận FP.

Informational vẫn là mức hiển thị cho Semgrep INFO/INFORMATION và ZAP riskcode 0.
Riêng severity đưa vào hash cho các trường hợp này vẫn là Low như bản cũ.
ZAP dùng text gốc của description/reference và cách xử lý markup trong instance
của parser cũ để tính hash; References dùng để hiển thị vẫn hỗ trợ cả CDATA và
HTML lồng nhau. Sửa định dạng link không làm đổi fingerprint của cùng đầu vào.

## Dữ liệu chuyển tiếp

- Không thêm migration cho lần khôi phục này và không xóa cột hay dữ liệu cũ.
- `identity_hash` vẫn có trong schema để tương thích migration đã có, nhưng
  không còn được đọc/ghi để quyết định finding trùng. Finding mới để cột này rỗng.
- Bản ghi có cùng dup_hash được tái sử dụng kể cả khi identity_hash đã có giá trị.
  Giữ UUID, thời điểm tạo, note, FP và liên kết Jira; nhớ scan cũ trước khi cập
  nhật scan_id mới nhất.
- Không đoán lại hash từ mô tả đã định dạng. Bản trung gian có thể đã cập nhật
  nội dung nhưng giữ dup_hash của lần tạo đầu. Hash đầu vào không khớp thì tạo
  finding theo quy tắc cũ; không dùng identity_hash để tự gộp lại.
- Không thể tự tách lại đầy đủ các quan sát từng bị bản trung gian gộp, hoặc
  phục hồi scan history đã mất, nếu thiếu báo cáo gốc. Không tự xóa hay reset DB.
- Bảng liên kết report–finding vẫn hoạt động. Chi tiết và triage được dùng chung;
  số đếm báo cáo liên kết vẫn được tính lại khi người dùng thay đổi triage.

Database đã áp dụng các migration của bộ sửa trước không cần migrate thêm vì
lần khôi phục này. Với database chưa áp dụng bộ sửa trước, vẫn cần các migration
lịch sử scan đã ghi trong `four-scanner-lifecycle.md` trước khi triển khai code.

## Kiểm tra

```powershell
.venv\Scripts\python.exe manage.py test scanners.test_legacy_fingerprints scanners.test_finding_lifecycle dashboard.test_regressions archerysecurity.test_references archerysecurity.test_scanner_references webscanners.test_zap_reimport --settings=archerysecurity.settings.test_dashboard --noinput
.venv\Scripts\python.exe tools/verify_scanner_migrations.py
```

11 hash mẫu được lấy bằng cách chạy hàm parser gốc trong Git tới lời gọi
build_fingerprint rồi dừng trước truy vấn/ghi database. Fixture được lưu tại
`scanners/fixtures/legacy_fingerprints.json`; kiểm tra không phụ thuộc Git lúc chạy.
Bộ kiểm tra còn bao phủ upload UI/API, không cộng trùng, Open–Closed–Re-open,
report rỗng/lỗi, FP, lịch sử/xóa scan, References, thông báo và chuyển tiếp cả bản
ghi chưa có hoặc đã có identity_hash. Tất cả dùng SQLite riêng, không gọi scanner,
SMTP hay Jira thật và không truy cập database ứng dụng đang triển khai.
