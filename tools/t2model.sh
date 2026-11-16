#!/usr/bin/env bash
# tools/t2model.sh — ĐO MỘT MODEL TẦNG 2 (kèm cấu hình quyết định) trên stack đang chạy. Chạy trên HOST, từ thư mục nsm:
#   bash tools/t2model.sh <nhãn> <tệp trong models/> <ngưỡng> <argmax|mass> <cổng 0|1> [kb]
#   bash tools/t2model.sh restore            trả classifier về mặc định trong docker-compose.yml
# Ví dụ:  bash tools/t2model.sh v4 tier2_v4_ungvien.joblib 0.91 mass 0 kb
# Mỗi lượt: đặt model và cấu hình cho classifier (biến môi trường, export cho MỌI lệnh con) -> bench pha detect -> kịch bản đếm
# nhãn (scenarios/tang-2/do-nhan: bộ thử 52 payload + hai danh sách đối chứng). Có tham số `kb` thì chạy thêm 5 kịch bản phụ
# thuộc tầng 2 (02, 13, 25, 41, 42). Kết quả ghi vào eval/results/t2model-<nhãn>.txt, đọc bằng tools/t2gate.py.
# Các mốc đạt của model mới: eval/PROTOCOL.md (mục 15/11/2026 23:00). Chỉ đo hệ thống của dự án.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # có export MSYS_NO_PATHCONV=1: đường dẫn /models/... không bị Git Bash đổi
CP=(docker compose -f "$D/docker-compose.yml")
wait_classifier(){
  for _ in $(seq 1 60); do
    "${CP[@]}" logs classifier 2>/dev/null | grep -q "classifier started" && return 0
    sleep 2
  done
  echo "!! classifier không khởi động lại được" >&2; return 1
}
if [ "${1:-}" = "restore" ]; then
  unset TIER2_MODEL_PATH TIER2_THRESHOLD TIER2_DECISION TIER2_SYNTAX_GATE
  "${CP[@]}" up -d classifier >/dev/null 2>&1; wait_classifier
  "${CP[@]}" logs classifier 2>/dev/null | grep "tier2 model loaded" | tail -1 | cut -c1-200
  "${CP[@]}" exec -T classifier env | grep -E '^(MODEL_PATH|TIER2_THRESHOLD|TIER2_DECISION|TIER2_SYNTAX_GATE)=' | tr '\r\n' '  '; echo
  exit 0
fi
[ $# -ge 5 ] || { sed -n 2,5p "${BASH_SOURCE[0]}"; exit 2; }
tag="$1"; model="$2"; theta="$3"; dec="$4"; gate="$5"; kb="${6:-}"
[ -f "$D/models/$model" ] || { echo "!! không có models/$model" >&2; exit 2; }
export TIER2_MODEL_PATH="/models/$model" TIER2_THRESHOLD="$theta" TIER2_DECISION="$dec" TIER2_SYNTAX_GATE="$gate"
cd "$D" || exit 1
want="MODEL_PATH=/models/$model TIER2_DECISION=$dec TIER2_SYNTAX_GATE=$gate TIER2_THRESHOLD=$theta"
cfg(){ "${CP[@]}" exec -T classifier env | grep -E '^(MODEL_PATH|TIER2_THRESHOLD|TIER2_DECISION|TIER2_SYNTAX_GATE)=' | tr -d '\r' | sort | tr '\n' ' ' | sed 's/ $//'; }
"${CP[@]}" up -d classifier >/dev/null 2>&1; wait_classifier || exit 1
got="$(cfg)"; [ "$got" = "$want" ] || { echo "!! classifier đang chạy với [$got], không phải [$want]" >&2; exit 1; }
"${CP[@]}" logs classifier 2>/dev/null | grep "tier2 model loaded" | tail -1 | cut -c1-200
sleep 15
bash tools/bench.sh detect > "eval/results/t2model-$tag-bench.log" 2>&1; echo "bench detect: mã thoát $?"
bench_dir="$(ls -1d bench-results/*/ 2>/dev/null | tail -1)"
SC_DIR=scenarios/tang-2 SC_OUT_NAME="t2model$tag" bash tools/scenario.sh do-nhan > "eval/results/t2model-$tag-donhan.log" 2>&1; echo "đếm nhãn: mã thoát $?"
nhan_dir="$(ls -1d eval/results/t2model$tag-2*/ 2>/dev/null | tail -1)"
bash tools/t2test.sh fetch "${nhan_dir}do-nhan" 2>&1 | tail -1
kb_dir=""
if [ "$kb" = "kb" ]; then
  SC_OUT_NAME="t2model${tag}kb" bash tools/scenario.sh 02-a1-nguoi-dung 13-d1-nat 25-d4-luat-qua-rong 41-luat-ap-dung-ngay-go-lai \
    42-phat-lai-mau-khong-trung > "eval/results/t2model-$tag-kichban.log" 2>&1; echo "kịch bản: mã thoát $?"
  kb_dir="$(ls -1d eval/results/t2model${tag}kb-2*/ 2>/dev/null | tail -1)"
fi
got="$(cfg)"; [ "$got" = "$want" ] || echo "!! SAU LƯỢT ĐO classifier đang chạy với [$got] — kết quả lượt này KHÔNG dùng được"
printf 'gate=%s (%s, %s, θ=%s)\nbench=%s\nnhan=%s\nkichban=%s\nclassifier_sau=%s\n' "$gate" "$model" "$dec" "$theta" "$bench_dir" "$nhan_dir" "$kb_dir" "$got" | tee "eval/results/t2model-$tag.txt"
