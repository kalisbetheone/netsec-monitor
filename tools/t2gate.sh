#!/usr/bin/env bash
# tools/t2gate.sh — ĐO MỘT CẤU HÌNH CỔNG CÚ PHÁP của tầng 2 trên stack đang chạy. Chạy trên HOST, từ thư mục nsm:
#   bash tools/t2gate.sh 0        cổng tắt (cấu hình hiện tại)
#   bash tools/t2gate.sh 1        cổng bật
#   bash tools/t2gate.sh restore  trả classifier về mặc định trong docker-compose.yml
# Mỗi lượt: đặt TIER2_SYNTAX_GATE cho classifier -> bench pha detect -> kịch bản đếm nhãn (scenarios/tang-2/do-nhan) ->
# các kịch bản phụ thuộc tầng 2 (02, 13, 25, 41, 42). Biến TIER2_SYNTAX_GATE được export cho MỌI lệnh con, để một lệnh
# `docker compose up` bên trong bench/kịch bản không dựng lại classifier với giá trị mặc định.
# Kết quả: eval/results/t2gate<g>-<thời điểm>/ (đếm nhãn), eval/results/t2gate<g>kb-<thời điểm>/ (kịch bản),
# bench-results/<thời điểm>/; tên các thư mục được in ra cuối lượt và ghi vào eval/results/t2gate-<g>.txt.
# Tiêu chí so hai cấu hình: eval/PROTOCOL.md (mục 15/11/2026, bước 1 của việc cải thiện tầng 2). Chỉ đo hệ thống của dự án.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
CP=(docker compose -f "$D/docker-compose.yml")
g="${1:-}"
wait_classifier(){            # chờ classifier nạp model xong và in dòng cấu hình tầng 2
  for _ in $(seq 1 60); do
    "${CP[@]}" logs --since 3m classifier 2>/dev/null | grep -q "classifier started" && return 0
    sleep 2
  done
  echo "!! classifier không khởi động lại được" >&2; return 1
}
if [ "$g" = "restore" ]; then
  unset TIER2_SYNTAX_GATE
  "${CP[@]}" up -d classifier >/dev/null 2>&1; wait_classifier
  "${CP[@]}" exec -T classifier env | grep TIER2_SYNTAX_GATE
  exit 0
fi
case "$g" in 0|1) ;; *) sed -n 2,5p "${BASH_SOURCE[0]}"; exit 2;; esac
export TIER2_SYNTAX_GATE="$g"
cd "$D" || exit 1
"${CP[@]}" up -d classifier >/dev/null 2>&1; wait_classifier || exit 1
got="$("${CP[@]}" exec -T classifier env | grep '^TIER2_SYNTAX_GATE=' | tr -d '\r')"
[ "$got" = "TIER2_SYNTAX_GATE=$g" ] || { echo "!! classifier đang chạy với $got, không phải $g" >&2; exit 1; }
"${CP[@]}" logs --since 3m classifier 2>/dev/null | grep "tier2 model loaded" | tail -1
sleep 15                                                    # classifier bắt kịp hàng đợi sau khi khởi động lại
before_b="$(ls -1d bench-results/*/ 2>/dev/null | tail -1)"
bash tools/bench.sh detect > "eval/results/t2gate-$g-bench.log" 2>&1; echo "bench detect: mã thoát $?"
bench_dir="$(ls -1d bench-results/*/ 2>/dev/null | tail -1)"
[ "$bench_dir" != "$before_b" ] || echo "!! bench không tạo thư mục kết quả mới"
SC_DIR=scenarios/tang-2 SC_OUT_NAME="t2gate$g" bash tools/scenario.sh do-nhan > "eval/results/t2gate-$g-donhan.log" 2>&1; echo "đếm nhãn: mã thoát $?"
nhan_dir="$(ls -1d eval/results/t2gate$g-2*/ 2>/dev/null | tail -1)"
bash tools/t2test.sh fetch "${nhan_dir}do-nhan" 2>&1 | tail -1
SC_OUT_NAME="t2gate${g}kb" bash tools/scenario.sh 02-a1-nguoi-dung 13-d1-nat 25-d4-luat-qua-rong 41-luat-ap-dung-ngay-go-lai \
  42-phat-lai-mau-khong-trung > "eval/results/t2gate-$g-kichban.log" 2>&1; echo "kịch bản: mã thoát $?"
kb_dir="$(ls -1d eval/results/t2gate${g}kb-2*/ 2>/dev/null | tail -1)"
got="$("${CP[@]}" exec -T classifier env | grep '^TIER2_SYNTAX_GATE=' | tr -d '\r')"
[ "$got" = "TIER2_SYNTAX_GATE=$g" ] || echo "!! SAU LƯỢT ĐO classifier đang chạy với $got — kết quả lượt này KHÔNG dùng được"
printf 'gate=%s\nbench=%s\nnhan=%s\nkichban=%s\nclassifier_sau=%s\n' "$g" "$bench_dir" "$nhan_dir" "$kb_dir" "$got" | tee "eval/results/t2gate-$g.txt"
