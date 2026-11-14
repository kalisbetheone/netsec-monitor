# OWASP CRS 4.25.0 cho Cổng 2

- `coreruleset-4.25.0-minimal.tar.gz` — bản phát hành chính thức (LTS) tải từ
  https://github.com/coreruleset/coreruleset/releases/tag/v4.25.0 ngày 12/11/2026 (người dùng đồng ý tải).
  SHA-256 `409a0da1f4daed0719150fcee5173c351e08ffa33b5b2f8936f30968b3ad4ff0`, khớp giá trị GitHub công bố cho tệp này;
  Dockerfile kiểm tra lại mã băm lúc build. `*.asc` là chữ ký GPG của nhóm CRS (chưa kiểm bằng gpg).
- `owasp-crs4.load` — thứ tự nạp: crs-setup.conf → plugin config/before → rules → plugin after.
- Cấu hình: `crs-setup.conf` = `crs-setup.conf.example` của bản phát hành, không đổi gì (paranoia 1, ngưỡng 5).
  Muốn đổi (vd thêm `text/plain` vào Content-Type cho phép khi bảo vệ ứng dụng thật) thì sửa ở Dockerfile.
- Giữ ModSecurity 2.9.7 của Debian (`libapache2-mod-security2`): CRS 4 hỗ trợ ModSecurity 2.9.x trên Apache, và bộ mô
  phỏng của rulegen (`services/secrule.py`) chép theo mã C của 2.9.7.
- Khác CRS 3.3.4 cần biết: thêm nhóm luật 934 chung (SSRF 934110/934120, prototype pollution...); các gói ngoại lệ cho
  WordPress/Drupal... chuyển thành plugin (không cài); một số mã luật/điểm thay đổi — số đo Cổng 2 trước và sau khi lên
  CRS 4 không so trực tiếp được, phải chạy lại `tools/parity.sh` và các kịch bản.
