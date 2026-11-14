#!/usr/bin/env bash
# tools/nsmctl.sh — CÔNG CỤ QUẢN TRỊ: xem và sửa danh sách chặn / miễn trừ khi hệ thống đang chạy,
# KHÔNG xoá trạng thái của responder (khác với tools/reset.sh là xoá hết). Chạy trên HOST, từ thư mục nsm:
#   bash tools/nsmctl.sh blocks                  liệt kê IP đang bị chặn, thời gian còn lại
#   bash tools/nsmctl.sh unblock 10.10.10.66     gỡ chặn MỘT IP ngay (các IP khác giữ nguyên)
#   bash tools/nsmctl.sh exempt                  liệt kê dải miễn trừ (cấu hình + thêm lúc chạy)
#   bash tools/nsmctl.sh exempt-add 10.10.10.0/28    thêm dải miễn trừ, có hiệu lực ngay, giữ qua khởi động lại
#   bash tools/nsmctl.sh exempt-del 10.10.10.0/28    bỏ một dải đã thêm bằng exempt-add
# Cách hoạt động: lệnh được gửi vào topic Kafka nsm.control bằng tài khoản 'ctl' (tài khoản duy nhất có
# quyền ghi topic này); responder thi hành và ghi nhật ký kiểm toán (bảng "Quyết định của responder" trên
# Grafana: decision = unblock / exempt_add / exempt_del, reason = manual). Script chờ responder xác nhận.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0
fi
CP=(docker compose -f "$D/docker-compose.yml")
if ! "${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r' | grep -qx responder; then
  echo "!! responder chưa chạy — chạy 'docker compose up -d' trước." >&2; exit 1
fi
# container dùng một lần (profile "tools" trong docker-compose.yml); --no-deps: không khởi động lại gì khác
Q=(); "${CP[@]}" --progress quiet version >/dev/null 2>&1 && Q=(--progress quiet)   # ẩn dòng "Container ... Created" nếu compose hỗ trợ
docker compose ${Q[@]+"${Q[@]}"} -f "$D/docker-compose.yml" run --rm --no-deps -T nsmctl "$@"
