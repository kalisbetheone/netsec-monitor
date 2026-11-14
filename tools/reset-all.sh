#!/usr/bin/env bash
# tools/reset-all.sh — RESET SÂU để trình bày demo lại từ đầu:
#   - gỡ toàn bộ blocklist + bộ đếm (responder)
#   - xoá lịch sử ES: mọi sự kiện tấn công, cảnh báo, quyết định  -> dashboard về TRẮNG phần tấn công
#   - xoá toàn bộ luật tự sinh: rulegen state + rule-status + active.conf -> luật = NONE
# GIỮ LẠI: model, cấu hình, và CORPUS LÀNH TÍNH (sự kiện benign của client lành tính BENIGN_SRC).
#   Corpus này là thứ rulegen dùng để kiểm chứng luật; xoá nó thì rulegen sẽ (đúng thiết kế) từ chối
#   sinh luật cho tới khi tích đủ MIN_BENIGN sự kiện mới.
# Chạy trên HOST (terminal Ubuntu).   dùng:  bash tools/reset-all.sh
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
CP=(docker compose -f "$D/docker-compose.yml")
BENIGN_SRC="${BENIGN_SRC:-10.10.10.20}"
# ES() (gọi Elasticsearch có xác thực) được định nghĩa trong _host.sh

echo ">> [1/4] dọn container demo + gỡ blocklist + đảm bảo ModSec ở chế độ chặn ..."
docker ps -aqf "name=demo_" | xargs -r docker rm -f >/dev/null 2>&1 || true
"${CP[@]}" stop -t 5 responder rulegen >/dev/null 2>&1
"${CP[@]}" run --rm --no-deps --entrypoint sh responder -c 'rm -f /state/responder.json' >/dev/null 2>&1 || true
# phòng khi ruledemo bị ngắt giữa chừng (để CRS ở DetectionOnly)
"${CP[@]}" exec -T apache sh -c "sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful" 2>/dev/null || true

echo ">> [2/4] xoá lịch sử ES (giữ corpus lành tính của $BENIGN_SRC) ..."
ES -X POST "localhost:9200/web-events-*/_delete_by_query?refresh=true&conflicts=proceed&ignore_unavailable=true" \
   -H "Content-Type: application/json" \
   -d "{\"query\":{\"bool\":{\"must_not\":[{\"bool\":{\"filter\":[{\"term\":{\"label.keyword\":\"benign\"}},{\"term\":{\"source.keyword\":\"web\"}},{\"term\":{\"src_ip.keyword\":\"$BENIGN_SRC\"}}]}}]}}}" >/dev/null; echo
ES -X POST "localhost:9200/audit-decisions-*/_delete_by_query?refresh=true&conflicts=proceed&ignore_unavailable=true" \
   -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' >/dev/null

echo ">> [3/4] xoá luật tự sinh (rulegen state + chỉ mục rule-status) ..."
"${CP[@]}" run --rm --no-deps --entrypoint sh rulegen -c 'rm -f /state/rules.json' >/dev/null 2>&1 || true
ES -X DELETE "localhost:9200/rule-status?ignore_unavailable=true" >/dev/null; echo

echo ">> [4/4] chạy lại responder + rulegen (phát lại trạng thái rỗng) ..."
"${CP[@]}" up -d responder rulegen >/dev/null 2>&1
sleep 10
echo ">> xong:"
echo "   - blocklist = rỗng"
echo "   - dashboard: hết sự kiện tấn công / quyết định (chỉ còn lưu lượng lành tính của $BENIGN_SRC)"
echo "   - luật tự sinh = none (rulegen vừa phát tệp luật rỗng -> apache active.conf trống)"
