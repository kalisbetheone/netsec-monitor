#!/usr/bin/env bash
# tools/reset.sh — RESET bài test tấn công: gỡ sạch blocklist + bộ đếm của responder, dọn container demo.
# KHÔNG đụng tới dữ liệu ES hay model. Chạy trên HOST (terminal Ubuntu).
#   dùng:  bash tools/reset.sh
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
CP=(docker compose -f "$D/docker-compose.yml")

echo ">> dọn container demo còn sót ..."
docker ps -aqf "name=demo_" | xargs -r docker rm -f >/dev/null 2>&1 || true

echo ">> dừng responder, xoá tệp trạng thái (blocklist + bộ đếm), chạy lại ..."
# dừng TRƯỚC khi xoá: responder lưu trạng thái lúc thoát, xoá khi nó còn chạy sẽ bị ghi lại
"${CP[@]}" stop -t 5 responder >/dev/null 2>&1
"${CP[@]}" run --rm --no-deps --entrypoint sh responder -c 'rm -f /state/responder.json' >/dev/null 2>&1 \
  || echo "   (không xoá được /state/responder.json — kiểm tra 'docker compose ps')"
"${CP[@]}" up -d responder >/dev/null 2>&1

echo ">> xong — blocklist trống, mọi IP đã được gỡ chặn. Có thể chạy demo.sh lại."
