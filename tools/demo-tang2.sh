#!/usr/bin/env bash
# tools/demo-tang2.sh — TRÌNH DIỄN PHỤ (khoảng 4 phút rưỡi): đường từ tầng 2 (học máy) tới việc chặn.
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy (và đang giữ khoá stack nếu nhiều người dùng chung hệ thống):
#   bash tools/demo-tang2.sh
# Không nằm trong tools/present.sh (buổi chính đã dùng khoảng 740 trong 900 giây); chạy riêng, trước hoặc sau buổi chính.
#
# Điều phần này cho thấy — và KHÔNG cho thấy:
#   - Tầng 2 KHÔNG chặn request và KHÔNG tự khoá IP. Nó gắn nhãn SAU khi request đã được phục vụ.
#   - Đường duy nhất để nhãn của tầng 2 thành chặn: bộ sinh luật viết luật từ các nhãn đó, rồi Cổng 2 chặn payload cùng dạng.
#   - Luật chỉ chặn được MỘT PHẦN payload chưa từng gửi (kịch bản 44 ngày 16/11: 6/18; ngưỡng đánh giá 50 % không đạt).
# Mọi "tấn công" là lưu lượng thử do bộ kiểm thử của dự án sinh ra, chỉ gửi vào hệ thống của dự án.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
cd "$D" || exit 1
CTL=(bash tools/nsmctl.sh)

echo "======================================================================"
echo "TRÌNH DIỄN PHỤ — Tầng 2 (học máy): payload Cổng 2 bỏ lọt -> nhãn tầng 2 -> luật tự sinh -> Cổng 2 chặn"
echo "LỆNH:              reset.sh; SC_CONT=1 scenario.sh td-8-tang-2-hoc-may (thư mục scenarios/tang-2); nsmctl rules; nsmctl rule-revoke-all"
echo "NHÌN TRÊN GRAFANA: Phát hiện theo tầng (dòng 'Tầng 2 — học máy'); Tấn công LỌT (chưa bị chặn); Luật tự sinh (ban hành);"
echo "                   Vòng đời luật tự sinh; Chặn tại Cổng 2 (ModSec 403)"
echo "KỲ VỌNG:           khoảng 70 giây đầu: 'Tầng 2' và 'Tấn công LỌT' tăng, 'Chặn tại Cổng 2' đứng yên (Cổng 2 bỏ lọt);"
echo "                   sau đó có luật tự sinh và 'Chặn tại Cổng 2' bắt đầu tăng; từ giây 110 một IP mới gửi 18 payload"
echo "                   chưa từng gửi và bị chặn MỘT PHẦN; khách hợp lệ gõ văn bản thường không bị chặn"
echo "----------------------------------------------------------------------"
t0=$(date +%s)
bash tools/reset.sh >/dev/null 2>&1
# SC_CONT=1: giữ luật tự sinh sau kịch bản để in ra bên dưới (bình thường kịch bản xoá luật trước và sau)
out="$(env SC_DIR=scenarios/tang-2 SC_OUT_NAME=trinhdien SC_CONT=1 bash tools/scenario.sh td-8-tang-2-hoc-may 2>&1)"
printf '%s\n' "$out"
ok=0
printf '%s\n' "$out" | grep -q '=> "verdict": "ĐẠT"' || ok=1
echo
echo ">> luật tự sinh sau kịch bản (đều sinh từ nhãn của tầng 2: tầng 1 không gắn nhãn request nào của kịch bản này;"
echo "   trường 'evidence' = tier2 của từng luật nằm trong results.jsonl của lượt chạy):"
"${CTL[@]}" rules 2>&1
echo ">> dọn: gỡ mọi luật tự sinh và danh sách chặn"
"${CTL[@]}" rule-revoke-all >/dev/null 2>&1
bash tools/reset.sh >/dev/null 2>&1
echo ">> xong sau $(( $(date +%s) - t0 )) giây — $([ "$ok" -eq 0 ] && echo 'ĐẠT' || echo 'KHÔNG ĐẠT')"
exit "$ok"
