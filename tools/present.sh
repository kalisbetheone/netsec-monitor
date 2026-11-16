#!/usr/bin/env bash
# tools/present.sh — CHẠY TRỌN BUỔI TRÌNH DIỄN NSM (≤ 15 phút), từ trạng thái sạch, không sửa tay.
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy (và đang giữ khoá stack nếu nhiều người dùng chung hệ thống):
#   bash tools/present.sh                    dừng chờ phím Enter giữa hai bước (trình diễn trước người xem)
#   PRESENT_AUTO=1 bash tools/present.sh     chạy liền, không dừng (chạy thử / lượt đo)
# Mỗi bước in ba dòng LỆNH / NHÌN TRÊN GRAFANA / KỲ VỌNG rồi chạy lệnh. Kịch bản dùng bản rút gọn trong
# scenarios/trinh-dien/ (chép từ kịch bản gốc, chỉ giảm số lượng). Cuối cùng in bảng thời gian từng bước.
# Mã thoát: 0 khi mọi kịch bản ĐẠT, mọi bước có kết quả đúng và tổng thời gian ≤ PRESENT_MAX_S (mặc định 900 giây).
# Script gọi tools/reset-all.sh ở đầu và cuối, và luôn trả responder về chế độ chặn thật (enforce) kể cả khi bị ngắt.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
cd "$D" || exit 1
AUTO="${PRESENT_AUTO:-0}"
MAX_S="${PRESENT_MAX_S:-900}"
LIMITS_DOC="$(cd "$D/.." && pwd)/Danh-sach-gioi-han-NSM.md"
SC=(env SC_DIR=scenarios/trinh-dien SC_OUT_NAME=trinhdien bash tools/scenario.sh)
CTL=(bash tools/nsmctl.sh)

STEP_NAMES=(); STEP_SECS=(); STEP_OK=()
FAILS=0
T_ALL0=$(date +%s)

restore_enforce() {
  "${CTL[@]}" mode enforce >/dev/null 2>&1 || true
}
on_exit() {
  trap - EXIT INT TERM
  restore_enforce
}
trap on_exit EXIT
trap 'echo; echo "!! bị ngắt — trả responder về enforce ..."; exit 130' INT TERM

pause() {
  [ "$AUTO" = 1 ] && return 0
  read -r -p ">> Nhấn Enter để sang bước tiếp theo ... " _ </dev/tty || true
}

banner() {   # $1 = tiêu đề bước  $2 = lệnh  $3 = bảng Grafana  $4 = kỳ vọng
  echo
  echo "======================================================================"
  echo "$1"
  echo "======================================================================"
  echo "LỆNH:              $2"
  echo "NHÌN TRÊN GRAFANA: $3"
  echo "KỲ VỌNG:           $4"
  echo "----------------------------------------------------------------------"
}

run_sc() {   # chạy kịch bản rút gọn; in kết quả; trả 0 khi MỌI kịch bản ĐẠT
  local out n_all n_ok
  out="$("$@" 2>&1)"; printf '%s\n' "$out"
  n_all=$(printf '%s\n' "$out" | grep -c '=> "verdict": ')
  n_ok=$(printf '%s\n' "$out" | grep -c '=> "verdict": "ĐẠT"')
  echo ">> kết quả: $n_ok/$n_all kịch bản ĐẠT"
  [ "$n_all" -gt 0 ] && [ "$n_ok" -eq "$n_all" ]
}

finish_step() {   # $1 = tên  $2 = giây bắt đầu  $3 = 0 (đúng) | khác 0 (sai)
  local dt=$(( $(date +%s) - $2 ))
  STEP_NAMES+=("$1"); STEP_SECS+=("$dt")
  if [ "$3" -eq 0 ]; then STEP_OK+=("đúng"); else STEP_OK+=("SAI"); FAILS=$((FAILS + 1)); fi
  echo ">> bước '$1': ${dt} giây — ${STEP_OK[${#STEP_OK[@]}-1]}"
}

# ---------------------------------------------------------------- chuẩn bị
echo ">> [chuẩn bị] làm sạch hệ thống: bash tools/reset-all.sh"
t=$(date +%s)
bash tools/reset-all.sh >/dev/null 2>&1; rc=$?
"${CTL[@]}" mode enforce >/dev/null 2>&1
finish_step "chuẩn bị (reset-all)" "$t" "$rc"

# ---------------------------------------------------------------- bước 1
banner "BƯỚC 1 — Hệ thống sạch; khách thường của cổng đặt chỗ đang dùng bình thường" \
  "nsmctl blocks; nsmctl rules; nsmctl mode; docker compose ps client-booking" \
  "Nhịp tim gần nhất của từng dịch vụ; Lưu lượng theo nguồn cảm biến" \
  "Không IP nào bị chặn, không luật tự sinh nào, responder ở enforce, client-booking đang chạy"
pause
t=$(date +%s); ok=0
b="$("${CTL[@]}" blocks 2>&1)"; printf '%s\n' "$b"
r="$("${CTL[@]}" rules 2>&1)"; printf '%s\n' "$r"
m="$("${CTL[@]}" mode 2>&1)"; printf '%s\n' "$m"
docker compose ps --format '{{.Service}}  {{.Status}}' client-booking 2>/dev/null
printf '%s\n' "$b" | grep -q "Không có IP nào đang bị chặn" || ok=1
printf '%s\n' "$r" | grep -q "Không có luật tự sinh nào" || ok=1
printf '%s\n' "$m" | grep -qi "enforce" || ok=1
finish_step "1. hệ thống sạch" "$t" "$ok"

# ---------------------------------------------------------------- bước 2
banner "BƯỚC 2 — Không lớp nào chặn thì bộ thử khai thác được DVWA; bật đủ hai lớp thì không" \
  "scenario.sh td-2a-khai-thac-khong-lop-nao-chan td-2b-khai-thac-du-hai-lop" \
  "Chặn tại Cổng 2 (ModSec 403); Tấn công LỌT (chưa bị chặn)" \
  "td-2a: một phần payload khai thác được (Cổng 2 chỉ ghi nhận); td-2b: 0 payload khai thác được"
pause
t=$(date +%s)
run_sc "${SC[@]}" td-2a-khai-thac-khong-lop-nao-chan td-2b-khai-thac-du-hai-lop; rc=$?
finish_step "2. khai thác thật" "$t" "$rc"

# ---------------------------------------------------------------- bước 3
banner "BƯỚC 3 — Nguồn tấn công bị khoá IP trong vài giây" \
  "scenario.sh td-3-tan-cong-co-ban" \
  "Lệnh chặn IP; Phát hiện theo tầng; IP đã bị chặn; Quyết định của responder" \
  "Cả 4 IP tấn công (sqli, xss, lfi, rce) bị chặn trong 15 giây"
pause
t=$(date +%s)
run_sc "${SC[@]}" td-3-tan-cong-co-ban; rc=$?
finish_step "3. khoá IP" "$t" "$rc"

# ---------------------------------------------------------------- bước 4
banner "BƯỚC 4 — Luật tự sinh áp dụng ngay, có cảnh báo, gỡ bằng một lệnh" \
  "reset.sh; SC_CONT=1 scenario.sh td-4-luat-ap-dung-ngay; nsmctl rules; nsmctl rule-revoke <mã>" \
  "Luật tự sinh (ban hành); Vòng đời luật tự sinh; Thao tác trên luật và đổi chế độ (kiểm toán); Cảnh báo đang bật ('NSM: luật tự sinh vừa được ban hành')" \
  "Có luật lớp rce chặn IP mới; gỡ một luật xong thì luật đó không còn trong danh sách"
pause
t=$(date +%s); ok=0
bash tools/reset.sh >/dev/null 2>&1      # IP cấp tự động của bước này trùng bước 3; SC_CONT bỏ qua bước xoá chặn
# SC_CONT=1: luật tự sinh được GIỮ sau kịch bản để trình diễn việc gỡ (bình thường kịch bản xoá luật trước và sau)
run_sc env SC_CONT=1 "${SC[@]}" td-4-luat-ap-dung-ngay || ok=1
r="$("${CTL[@]}" rules 2>&1)"; printf '%s\n' "$r"
rid=$(printf '%s\n' "$r" | awk '$1 ~ /^99[0-9]+$/ {print $1; exit}')
if [ -n "$rid" ]; then
  echo ">> gỡ luật $rid: nsmctl rule-revoke $rid"
  "${CTL[@]}" rule-revoke "$rid" || ok=1
  r2="$("${CTL[@]}" rules 2>&1)"; printf '%s\n' "$r2"
  printf '%s\n' "$r2" | awk '{print $1}' | grep -qx "$rid" && { echo "!! luật $rid vẫn còn"; ok=1; }
else
  echo "!! không có luật tự sinh nào để gỡ"; ok=1
fi
"${CTL[@]}" rule-revoke-all >/dev/null 2>&1    # dọn các luật còn lại trước bước 5 (không phải phần trình diễn)
finish_step "4. luật tự sinh" "$t" "$ok"

# ---------------------------------------------------------------- bước 5
banner "BƯỚC 5 — Nhồi tài khoản vào cổng đặt chỗ và flood: bị khoá và bị giới hạn tốc độ" \
  "scenario.sh td-5a-nhoi-tai-khoan-cong-dat-cho td-5b-flood-mot-ip" \
  "IP đã bị chặn; Request bị Cổng 1 giới hạn tốc độ (429), theo IP; Request bị Cổng 1 từ chối, theo IP" \
  "td-5a: phần lớn 50 IP nhồi tài khoản vào trang đăng nhập booking.local bị khoá; td-5b: IP flood nhận 429 rồi bị khoá; khách hợp lệ không bị ảnh hưởng"
pause
t=$(date +%s)
run_sc "${SC[@]}" td-5a-nhoi-tai-khoan-cong-dat-cho td-5b-flood-mot-ip; rc=$?
finish_step "5. nhồi tài khoản + flood" "$t" "$rc"

# ---------------------------------------------------------------- bước 6
banner "BƯỚC 6 — Gỡ chặn nhầm một IP; chuyển sang chạy thử rồi trả về chặn thật" \
  "nsmctl blocks; nsmctl unblock <IP>; nsmctl mode dryrun; nsmctl mode enforce" \
  "Thao tác trên luật và đổi chế độ (kiểm toán); Cảnh báo đang bật ('NSM: có thay đổi thủ công (nsmctl)')" \
  "IP được gỡ khỏi danh sách chặn; chế độ đổi sang dryrun rồi về enforce"
pause
t=$(date +%s); ok=0
b="$("${CTL[@]}" blocks 2>&1)"; printf '%s\n' "$b"
ip=$(printf '%s\n' "$b" | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
if [ -n "$ip" ]; then
  echo ">> gỡ chặn $ip: nsmctl unblock $ip"
  "${CTL[@]}" unblock "$ip" || ok=1
  "${CTL[@]}" blocks 2>&1 | awk '{print $1}' | grep -qx "$ip" && { echo "!! $ip vẫn bị chặn"; ok=1; }
else
  echo "!! không có IP nào đang bị chặn để gỡ"; ok=1
fi
"${CTL[@]}" mode dryrun || ok=1
"${CTL[@]}" mode 2>&1 | grep -qi "dryrun" || ok=1
"${CTL[@]}" mode enforce || ok=1
"${CTL[@]}" mode 2>&1 | grep -qi "enforce" || ok=1
finish_step "6. gỡ chặn + chạy thử" "$t" "$ok"

# ---------------------------------------------------------------- bước 7
banner "BƯỚC 7 — Giới hạn đã biết" \
  "(in danh sách)" \
  "—" \
  "Người xem thấy những gì hệ thống chưa làm được và vì sao"
pause
t=$(date +%s); ok=0
echo "Tài liệu: $LIMITS_DOC"
if [ -f "$LIMITS_DOC" ]; then
  sed -n '/^## Tóm tắt/,/^## 1\./p' "$LIMITS_DOC" | sed '$d'
else
  echo "!! không thấy tệp"; ok=1
fi
finish_step "7. giới hạn đã biết" "$t" "$ok"

# ---------------------------------------------------------------- dọn
echo
echo ">> [dọn] bash tools/reset-all.sh"
t=$(date +%s)
bash tools/reset-all.sh >/dev/null 2>&1; rc=$?
restore_enforce
finish_step "dọn (reset-all)" "$t" "$rc"

# ---------------------------------------------------------------- tổng kết
TOTAL=0; for s in "${STEP_SECS[@]}"; do TOTAL=$((TOTAL + s)); done
WALL=$(( $(date +%s) - T_ALL0 ))
echo
echo "========================== BẢNG THỜI GIAN =========================="
printf '%-32s %8s  %s\n' "bước" "giây" "kết quả"
for i in "${!STEP_NAMES[@]}"; do
  printf '%-32s %8s  %s\n' "${STEP_NAMES[$i]}" "${STEP_SECS[$i]}" "${STEP_OK[$i]}"
done
printf '%-32s %8s\n' "TỔNG (không tính lúc chờ Enter)" "$TOTAL"
printf '%-32s %8s\n' "thời gian thực từ đầu tới cuối" "$WALL"
RC=0
[ "$FAILS" -gt 0 ] && { echo "!! $FAILS bước có kết quả SAI"; RC=1; }
[ "$TOTAL" -gt "$MAX_S" ] && { echo "!! tổng thời gian $TOTAL giây vượt $MAX_S giây"; RC=1; }
[ "$RC" -eq 0 ] && echo ">> TRÌNH DIỄN ĐẠT: mọi bước đúng, tổng $TOTAL giây (giới hạn $MAX_S giây)"
exit "$RC"
