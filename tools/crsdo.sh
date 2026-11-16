#!/usr/bin/env bash
# tools/crsdo.sh — ĐO CỔNG 2 (CRS) MỘT LƯỢT: chặn nhầm trên lưu lượng hợp lệ thật + chặn tấn công. Dùng TRƯỚC và SAU một thay đổi
# tinh chỉnh CRS để so. Chạy trên HOST, từ thư mục nsm, khi stack đang chạy (nên giữ khoá stack):
#   bash tools/crsdo.sh <nhãn>            ví dụ: bash tools/crsdo.sh truoc ; (đổi tinh chỉnh, dựng lại apache) ; bash tools/crsdo.sh sau
# Mỗi lượt:
#   1. phát lại hai mẫu lưu lượng hợp lệ thật (scenarios/crs/quan-sat, kiem-tra; 2 000 request mỗi mẫu);
#   2. tools/crsfp.sh: mẫu quan sát in chi tiết theo luật, mẫu kiểm tra CHỈ in tổng (--tong);
#   3. bench pha detect (65 tấn công, 55 mẫu hợp lệ);
#   4. kịch bản tấn công 01 (ma trận), 20 (GoTestWAF), 21 (waf-bypass), 36 (khai thác thật), 47 (cổng đặt chỗ).
# Kết quả: eval/results/crs-<nhãn>-*.txt|log và các thư mục eval/results/crs<nhãn>-*/, crs<nhãn>atk-*/. Chỉ đo hệ thống của dự án.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
[ $# -ge 1 ] || { sed -n 2,4p "${BASH_SOURCE[0]}"; exit 2; }
tag="$1"; cd "$D" || exit 1; R=eval/results
SC_DIR=scenarios/crs SC_OUT_NAME="crs$tag" bash tools/scenario.sh quan-sat kiem-tra > "$R/crs-$tag-phatlai.log" 2>&1; echo "phát lại: mã thoát $?"
d="$(ls -1d $R/crs$tag-2*/ 2>/dev/null | tail -1)"
bash tools/crsfp.sh "$d" quan-sat 250 > "$R/crs-$tag-quan-sat.txt" 2>&1
bash tools/crsfp.sh "$d" kiem-tra --tong 250 > "$R/crs-$tag-kiem-tra.txt" 2>&1
head -3 "$R/crs-$tag-quan-sat.txt"; head -3 "$R/crs-$tag-kiem-tra.txt"
bash tools/bench.sh detect > "$R/crs-$tag-bench.log" 2>&1; echo "bench detect: mã thoát $?"
b="$(ls -1d bench-results/*/ 2>/dev/null | tail -1)"
bash tools/scenario.sh 01-ma-tran-tan-cong 20-gotestwaf 21-waf-bypass 36-khai-thac-that-du-hai-lop 47-chen-sql-o-tim-chuyen \
  > "$R/crs-$tag-tancong.log" 2>&1; echo "kịch bản tấn công: mã thoát $?"
a="$(ls -1d $R/scenarios-2*/ 2>/dev/null | tail -1)"
printf 'tag=%s\nphatlai=%s\nbench=%s\ntancong=%s\n' "$tag" "$d" "$b" "$a" | tee "$R/crs-$tag.txt"
