#!/usr/bin/env bash
# tools/baseline.sh — CHẠY TOÀN BỘ PHÉP ĐO của hệ thống theo đúng một thứ tự, từ trạng thái sạch, để có MỐC SỐ ĐO
# cho cấu hình hiện tại (so trước/sau mỗi đợt thay đổi). Chạy trên HOST, từ thư mục nsm, khi stack đang chạy:
#   bash tools/baseline.sh [nhãn]          nhãn mặc định = ngày giờ; kết quả: eval/results/baseline-<nhãn>/
# Thứ tự: reset-all -> demo -> sectest -> parity -> tier1sync -> 33+ kịch bản -> ruledemo -> ruledemo-multi -> bench
#         -> reset-all. Khoảng 1 giờ 45 phút. Mỗi bước ghi nhật ký riêng; bước lỗi KHÔNG dừng các bước sau.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
TAG="${1:-$(date +%Y%m%d-%H%M%S)}"
OUT="$D/eval/results/baseline-$TAG"
mkdir -p "$OUT" || exit 1
step(){  # step <tên> <lệnh...>
  local name="$1"; shift
  local t0; t0=$(date +%s)
  echo ">> [$(date +%H:%M:%S)] $name ..."
  "$@" > "$OUT/$name.log" 2>&1
  local rc=$?
  echo "$name rc=$rc $(( $(date +%s) - t0 ))s" | tee -a "$OUT/steps.txt"
}
{
  echo "commit: $(git -C "$D" rev-parse --short HEAD 2>/dev/null) $(git -C "$D" status --short 2>/dev/null | wc -l) tệp chưa commit"
  echo "bắt đầu: $(date '+%F %T')"
  docker compose -f "$D/docker-compose.yml" images 2>/dev/null
} > "$OUT/env.txt"
step reset0     bash "$D/tools/reset-all.sh"
step demo       bash "$D/tools/demo.sh"
step reset1     bash "$D/tools/reset-all.sh"
step sectest    bash "$D/tools/sectest.sh"
step parity     bash "$D/tools/parity.sh"
step tier1sync  bash "$D/tools/tier1sync.sh"
step reset2     bash "$D/tools/reset-all.sh"
step scenarios  bash "$D/tools/scenario.sh" ${BASELINE_SCENARIOS:-}
step reset3     bash "$D/tools/reset-all.sh"
step ruledemo   bash "$D/tools/ruledemo.sh"
step ruledemo-multi bash "$D/tools/ruledemo-multi.sh"
step reset4     bash "$D/tools/reset-all.sh"
step bench      bash "$D/tools/bench.sh"
step reset5     bash "$D/tools/reset-all.sh"
echo "kết thúc: $(date '+%F %T')" >> "$OUT/env.txt"
echo ">> xong: $OUT"
