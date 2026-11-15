#!/usr/bin/env bash
# tools/ngaynen.sh — CHẠY "NGÀY NÉN 12 LẦN": 24 khung giờ (scenarios/ngay-nen/gio-00 … gio-23), mỗi khung khoảng 5 phút
# thật, responder ở chế độ CHẠY THỬ (dryrun: chỉ ghi "sẽ chặn", không chặn), các mốc thời gian của hệ thống nén 12 lần.
# Mục đích: xem trong một "ngày" vận hành có khách hợp lệ nào "sẽ bị chặn" hay không. Thay cho đợt chạy thử 24 giờ.
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy và sạch (không chặn, không luật tự sinh). Khoảng 2 giờ.
#   bash tools/ngaynen.sh                     cả 24 khung giờ
#   NN_HOURS="00 01" bash tools/ngaynen.sh    chỉ vài khung giờ (để thử công cụ)
# Trình tự: kiểm trước -> đặt tham số nén và tạo lại responder + rulegen -> bật 6 khách thường trú (nn_res_*) -> chạy các
# khung giờ liền mạch (SC_CONT=1) -> đếm quyết định "sẽ chặn" theo vai (wouldblock) -> tổng kết -> KHÔI PHỤC tham số gốc
# và dọn (kể cả khi bị ngắt). Kết quả: eval/results/ngaynen-<thời điểm>/tong-ket.md.
# Tham số nén (giá trị gốc trong ngoặc): LONG_WINDOW_S 7200 (86400), TTL_STEPS_S 75,300,7200 (900,3600,86400),
# MAX_TTL_S 7200 (86400), SHARED_TTL_S 300 (3600), RULE_TTL_S 7200 (86400). Sinh lại các khung giờ: tools/ngaynen.py sinh.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án
CP=(docker compose -f "$D/docker-compose.yml")
PY="${PYTHON:-python}"
SCN="scenarios/ngay-nen"
IMG_CLIENT="curlimages/curl:8.10.1"               # cùng image với dịch vụ client / client-booking trong docker-compose.yml
NET_EXT=nsm_external_net
HOURS="${NN_HOURS:-}"
WANT=("nsm-responder-1 RESPONDER_MODE dryrun" "nsm-responder-1 LONG_WINDOW_S 7200" "nsm-responder-1 TTL_STEPS_S 75,300,7200"
      "nsm-responder-1 MAX_TTL_S 7200" "nsm-responder-1 SHARED_TTL_S 300" "nsm-rulegen-1 RULE_TTL_S 7200")
envof(){ docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | tr -d '\r' | sed -n "s/^$2=//p" | head -1; }
show_params(){ for w in "${WANT[@]}"; do set -- $w; printf '   %s %s=%s\n' "$1" "$2" "$(envof "$1" "$2")"; done; }

# ---------------------------------------------------------------- 1. kiểm trước
n=$("${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r' | grep -c .)
[ "$n" = 17 ] || { echo "!! $n dịch vụ đang chạy, cần 17 — chạy 'docker compose up -d' trước." >&2; exit 1; }
bash "$D/tools/nsmctl.sh" blocks 2>/dev/null | grep -q "Không có IP nào đang bị chặn" \
  || { echo "!! đang có IP bị chặn — chạy: bash tools/reset-all.sh" >&2; exit 1; }
bash "$D/tools/nsmctl.sh" rules 2>/dev/null | grep -q "Không có luật tự sinh nào đang sống" \
  || { echo "!! đang có luật tự sinh — chạy: bash tools/reset-all.sh" >&2; exit 1; }
[ -f "$D/$SCN/nguon.json" ] && [ "$(ls "$D/$SCN"/gio-*.toml 2>/dev/null | grep -c .)" = 24 ] \
  || { echo "!! thiếu tệp trong $SCN — chạy: $PY -X utf8 -B tools/ngaynen.py sinh" >&2; exit 1; }
SEL=()
for h in $HOURS; do
  [ -f "$D/$SCN/gio-$h.toml" ] || { echo "!! không có khung giờ '$h' (dùng hai chữ số, ví dụ NN_HOURS=\"00 01\")" >&2; exit 1; }
  SEL+=("gio-$h")
done
[ -z "$(docker ps -aqf 'name=nn_')" ] || { echo "!! còn container nn_ của lần chạy trước — xoá: docker ps -aqf name=nn_ | xargs docker rm -f" >&2; exit 1; }

# ---------------------------------------------------------------- 7. khôi phục (luôn chạy, kể cả khi bị ngắt)
RESTORED=0
restore(){
  [ "$RESTORED" = 1 ] && return; RESTORED=1
  echo ">> khôi phục: xoá khách thường trú, trả tham số gốc, reset-all ..."
  docker ps -aqf "name=nn_" | xargs -r docker rm -f >/dev/null 2>&1
  unset RESPONDER_MODE LONG_WINDOW_S TTL_STEPS_S MAX_TTL_S SHARED_TTL_S RULE_TTL_S
  "${CP[@]}" up -d responder rulegen >/dev/null 2>&1
  bash "$D/tools/reset-all.sh" >/dev/null 2>&1 || echo "   !! reset-all lỗi — chạy tay: bash tools/reset-all.sh"
  echo ">> tham số sau khôi phục (gốc: enforce / 86400 / 900,3600,86400 / 86400 / 3600 / 86400):"; show_params
}
trap restore EXIT
trap 'echo; echo "!! bị ngắt — khôi phục ..."; exit 130' INT TERM HUP

# ---------------------------------------------------------------- 2. tham số nén
export RESPONDER_MODE=dryrun LONG_WINDOW_S=7200 TTL_STEPS_S=75,300,7200 MAX_TTL_S=7200 SHARED_TTL_S=300 RULE_TTL_S=7200
echo ">> đặt tham số nén, tạo lại responder (reset.sh) và rulegen ..."
bash "$D/tools/reset.sh" >/dev/null 2>&1 || { echo "!! reset.sh lỗi" >&2; exit 1; }
"${CP[@]}" up -d rulegen >/dev/null 2>&1 || { echo "!! không tạo lại được rulegen" >&2; exit 1; }
sleep 8
echo ">> tham số trong container:"; show_params
for w in "${WANT[@]}"; do
  set -- $w
  [ "$(envof "$1" "$2")" = "$3" ] || { echo "!! $1 $2='$(envof "$1" "$2")', cần '$3' — DỪNG, không chạy tiếp." >&2; exit 1; }
done

# ---------------------------------------------------------------- 3. khách thường trú (suốt đợt thử, không miễn trừ)
echo ">> bật 6 khách thường trú (nn_res_*) ..."
for i in 1 2 3; do            # như dịch vụ client: tools/benign.sh trên DVWA
  docker run -d --name "nn_res_dvwa_$i" --network "$NET_EXT" --ip "10.10.4.$i" -v "$D/tools:/tools:ro" \
    --entrypoint /bin/sh "$IMG_CLIENT" -c "tr -d '\\r' < /tools/benign.sh | sh" >/dev/null \
    || { echo "!! không bật được nn_res_dvwa_$i" >&2; exit 1; }
done
for i in 11 12 13; do         # như dịch vụ client-booking: tools/benign_booking.sh trên cổng đặt chỗ
  docker run -d --name "nn_res_booking_$i" --network "$NET_EXT" --ip "10.10.4.$i" -e PAUSE=2 -e TYPOS=1 \
    -v "$D/tools:/tools:ro" --entrypoint /bin/sh "$IMG_CLIENT" \
    -c "tr -d '\\r' < /tools/benign_booking.sh > /tmp/b.sh && exec sh /tmp/b.sh" >/dev/null \
    || { echo "!! không bật được nn_res_booking_$i" >&2; exit 1; }
done

# ---------------------------------------------------------------- 4 + 5. chạy các khung giờ
T0=$(date +%s)
echo ">> bắt đầu $(date '+%F %T') (epoch $T0); khung giờ: ${HOURS:-00 … 23}"
SC_DIR="$SCN" SC_CONT=1 SC_OUT_NAME=ngaynen bash "$D/tools/scenario.sh" ${SEL[@]+"${SEL[@]}"}
T1=$(date +%s)
OUT=$(ls -d "$D"/eval/results/ngaynen-* 2>/dev/null | sort | tail -1)
{ [ -n "$OUT" ] && [ -f "$OUT/results.jsonl" ] && [ "$(date -r "$OUT/results.jsonl" +%s)" -ge "$T0" ]; } \
  || { echo "!! không thấy thư mục kết quả của lượt này" >&2; exit 1; }
printf '%s\n' "$T0" > "$OUT/t0.txt"; printf '%s\n' "$T1" > "$OUT/t1.txt"
show_params > "$OUT/thamso.txt"
if [ -n "$HOURS" ]; then "$PY" -X utf8 -B "$D/tools/ngaynen.py" nguon --hours "$HOURS" --out "$OUT/nguon.json"
else cp "$D/$SCN/nguon.json" "$OUT/nguon.json"; fi

# ---------------------------------------------------------------- 6. đếm và tổng kết
echo ">> chờ 60 giây cho đường ống ghi hết dữ liệu ..."; sleep 60
bash "$D/tools/wouldblock.sh" "$T0" 0 "$OUT/nguon.json" "$OUT" > "$OUT/wouldblock.md" 2> "$OUT/wouldblock.err"; WB=$?
"$PY" -X utf8 -B "$D/tools/ngaynen.py" tongket "$OUT" --json "$OUT/tongket.json" > "$OUT/tongket-vai.md" 2>> "$OUT/wouldblock.err"
bash "$D/tools/nsmctl.sh" rules > "$OUT/rules.txt" 2>&1
bash "$D/tools/nsmctl.sh" mode > "$OUT/mode.txt" 2>&1
{
  echo "# Ngày nén 12 lần — lượt $(basename "$OUT")"
  echo
  echo "Sinh tự động bởi \`tools/ngaynen.sh\`. Responder ở chế độ chạy thử (dryrun): chỉ ghi \"sẽ chặn\", không chặn."
  echo "Mọi \"tấn công\" ở đây là lưu lượng thử của bộ kiểm thử, gửi vào chính hệ thống của dự án."
  echo
  echo "- Bắt đầu: $(date -d "@$T0" '+%F %T'); kết thúc các khung giờ: $(date -d "@$T1" '+%T'); thời lượng $(( (T1 - T0) / 60 )) phút $(( (T1 - T0) % 60 )) giây."
  echo "- Khung giờ đã chạy: ${HOURS:-00 … 23 (đủ 24)}."
  echo "- Tham số trong container lúc chạy:"
  echo
  echo '```'; cat "$OUT/thamso.txt"; echo '```'
  echo
  echo "## 1. Các tiêu chí"
  echo
  "$PY" -X utf8 -B "$D/tools/ngaynen.py" tieuchi "$OUT" 2>&1
  echo
  echo "## 2. Quyết định \"sẽ chặn\" theo vai (mã thoát của wouldblock: $WB; 0 = không IP hợp lệ nào)"
  echo
  cat "$OUT/wouldblock.md"
  echo
  echo "## 3. Lưu lượng theo vai"
  echo
  cat "$OUT/tongket-vai.md"
  echo
  echo "## 4. Luật tự sinh và chế độ của responder lúc kết thúc"
  echo
  echo '```'; cat "$OUT/rules.txt"; echo; cat "$OUT/mode.txt"; echo '```'
  echo
  echo "## 5. Kết quả chấm từng khung giờ (kỳ vọng ghi trong tệp khung giờ)"
  echo
  sed -n '/^## 1\./,/^## 2\./p' "$OUT/report.md" 2>/dev/null | sed '1d;$d'
} > "$OUT/tong-ket.md"
echo ">> tổng kết: ${OUT#"$D"/}/tong-ket.md"
sed -n '/^## 1\. Các tiêu chí/,/^## 2\./p' "$OUT/tong-ket.md" | sed '$d'
# bước 7 (khôi phục) chạy qua trap EXIT
