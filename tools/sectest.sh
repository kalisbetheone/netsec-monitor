#!/usr/bin/env bash
# tools/sectest.sh — KIỂM TRA XÁC THỰC & PHÂN QUYỀN trên stack đang chạy (dưới 1 phút). Chạy trên HOST:
#     bash tools/sectest.sh
# Đóng vai kẻ đã vào được mạng giám sát: thử đọc Elasticsearch và ghi các topic Kafka nhạy cảm khi không có
# mật khẩu, sai mật khẩu, hoặc dùng tài khoản của thành phần khác vai trò (vd lấy mật khẩu của filebeat để
# ra lệnh chặn IP). Mọi phép thử phải bị từ chối; script thoát mã 1 nếu có phép thử nào lọt.
# Không ghi gì vào hệ thống (lệnh bị từ chối; nếu lọt thì chỉ là danh sách chặn rỗng).
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
IMG="${BENCH_IMAGE:-nsm-classifier}"
docker image inspect "$IMG" >/dev/null 2>&1 \
  || { echo "!! không thấy image $IMG — dựng bằng 'docker compose up -d --build'." >&2; exit 1; }
docker network inspect nsm_monitor_net >/dev/null 2>&1 \
  || { echo "!! stack chưa chạy — chạy 'docker compose up -d' trước." >&2; exit 1; }
# mật khẩu đi vào container qua --env-file (không hiện trên dòng lệnh hay màn hình)
docker run --rm --network nsm_monitor_net --env-file "$D/.env" -v "$D/tools:/tools:ro" \
  --entrypoint python "$IMG" -B /tools/sectest.py
