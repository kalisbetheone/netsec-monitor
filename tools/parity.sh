#!/usr/bin/env bash
# tools/parity.sh — KIỂM CHỨNG KHỚP giữa dữ liệu đã chuẩn hoá (eval/normalize.py) và hệ thống THẬT.
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy:
#   bash tools/parity.sh                 mặc định 400 request mỗi nguồn
#   PARITY_PER_SOURCE=100 bash tools/parity.sh
# Các bước:
#   1. chọn mẫu từ eval/data/normalized + sinh một tập LUẬT DÒ (chỉ ghi nhận, không chặn)
#   2. nạp luật dò vào ModSecurity (tệp riêng, nạp TRƯỚC CRS), miễn trừ tạm IP phát lại
#   3. gửi lại NGUYÊN VĂN từng request (phương thức, đường dẫn, query, thân, Content-Type)
#   4. so: bản ghi Elasticsearch của hệ thống ↔ bản ghi chuẩn hoá; luật dò khớp trong ModSecurity thật ↔ bộ mô phỏng
# Kết quả: eval/results/parity-<thời điểm>/report.md. Tự gỡ luật dò và miễn trừ khi xong hoặc khi bấm Ctrl-C.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
CP=(docker compose -f "$D/docker-compose.yml")
PYIMG="${BENCH_IMAGE:-nsm-classifier}"; NET_EXT=nsm_external_net; NET_MON=nsm_monitor_net
IP=10.10.10.241; EXEMPT=10.10.10.240/29
PER="${PARITY_PER_SOURCE:-400}"
PROBE=/etc/modsecurity/00-nsm-probe.conf
AUDIT=/var/log/apache-json/modsec_audit.json
RUN="$(date +%Y%m%d-%H%M%S)"
OUT="$D/eval/results/parity-$RUN"
log(){ echo ">> $*"; }

RUNNING=$("${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r')
for s in nginx apache classifier responder elasticsearch kafka filebeat; do
  printf '%s\n' "$RUNNING" | grep -qx "$s" || { echo "!! dịch vụ $s chưa chạy — chạy 'docker compose up -d' trước." >&2; exit 1; }
done
ls "$D"/eval/data/normalized/*.jsonl.gz >/dev/null 2>&1 \
  || { echo "!! chưa có dữ liệu chuẩn hoá — chạy: python -I -X utf8 -B eval/normalize.py" >&2; exit 1; }
mkdir -p "$OUT" || exit 1
USEROPT=(); [ "$(uname -s)" = Linux ] && USEROPT=(--user "$(id -u):$(id -g)")   # tệp kết quả thuộc về người chạy
MNT=(-v "$D/tools:/tools:ro" -v "$D/services:/svc:ro" -v "$D/eval:/eval:ro")
py(){ docker run --rm -i "${USEROPT[@]}" "${MNT[@]}" "$@"; }

PROBE_ON=""; EXEMPT_ON=""; TAIL_ON=""
TAILPID=/tmp/nsm-parity-tail.pid
cleanup(){
  trap - EXIT INT TERM
  [ -n "$TAIL_ON" ] && "${CP[@]}" exec -T apache sh -c "kill \$(cat $TAILPID) 2>/dev/null; rm -f $TAILPID" >/dev/null 2>&1
  docker ps -aqf "name=parity_" | xargs -r docker rm -f >/dev/null 2>&1
  if [ -n "$PROBE_ON" ]; then
    echo ">> gỡ luật dò khỏi ModSecurity ..."
    "${CP[@]}" exec -T apache sh -c "rm -f $PROBE && apache2ctl -k graceful" >/dev/null 2>&1 \
      || echo "!! chưa gỡ được $PROBE trong container apache — hãy xoá tay rồi apache2ctl -k graceful"
  fi
  if [ -n "$EXEMPT_ON" ]; then
    echo ">> bỏ miễn trừ tạm $EXEMPT ..."
    bash "$D/tools/nsmctl.sh" exempt-del "$EXEMPT" >/dev/null 2>&1 || echo "!! chưa bỏ được miễn trừ — chạy: bash tools/nsmctl.sh exempt-del $EXEMPT"
  fi
}
trap cleanup EXIT
trap 'echo; echo "!! bị ngắt — dọn dẹp ..."; exit 130' INT TERM

log "[1/5] chọn mẫu ($PER request mỗi nguồn) và sinh luật dò ..."
py -v "$OUT:/o" --entrypoint python "$PYIMG" -B /tools/parity.py --run "$RUN" sample --per-source "$PER" \
   --conf /o/probe.conf --probes /o/probes.json > "$OUT/sample.jsonl" || { echo "!! không chọn được mẫu" >&2; exit 1; }

log "[2/5] nạp luật dò vào ModSecurity và miễn trừ tạm $EXEMPT ..."
if ! "${CP[@]}" exec -T apache sh -c "cat > $PROBE && apache2ctl -t >/dev/null 2>&1 && apache2ctl -k graceful" < "$OUT/probe.conf"; then
  "${CP[@]}" exec -T apache sh -c "rm -f $PROBE" >/dev/null 2>&1
  echo "!! Apache từ chối tệp luật dò (apache2ctl -t)" >&2; exit 1
fi
PROBE_ON=1
bash "$D/tools/nsmctl.sh" exempt-add "$EXEMPT" >/dev/null || { echo "!! không thêm được miễn trừ" >&2; exit 1; }
EXEMPT_ON=1
sleep 3
# Theo dõi nhật ký kiểm toán LIÊN TỤC trong lúc phát lại: hệ thống cắt tệp này về 0 khi vượt LOG_MAX_MB,
# nên đọc "từ dòng N" sau khi phát lại có thể mất dữ liệu. tail -F bám tiếp được khi tệp bị cắt.
"${CP[@]}" exec -T apache sh -c "echo \$\$ > $TAILPID; exec tail -F -n 0 $AUDIT 2>/dev/null" \
  | grep --line-buffered -aF "nsm-replay/$RUN/" > "$OUT/audit.jsonl" &
TAIL_ON=1
sleep 2

log "[3/5] gửi lại $(wc -l < "$OUT/sample.jsonl" | tr -d ' ') request từ $IP ..."
docker run --rm -i --name "parity_$RUN" --network "$NET_EXT" --ip "$IP" "${MNT[@]}" -v "$OUT:/o:ro" \
  --entrypoint python "$PYIMG" -B /tools/parity.py --run "$RUN" replay --input /o/sample.jsonl > "$OUT/sent.jsonl"
sleep 5

log "[4/5] lấy bản ghi Elasticsearch và nhật ký kiểm toán ModSecurity ..."
py --network "$NET_MON" -e ES_URL=http://elasticsearch:9200 -e ES_USER=elastic --env-file "$D/.env" -v "$OUT:/o:ro" \
   --entrypoint python "$PYIMG" -B /tools/parity.py --run "$RUN" collect --input /o/sent.jsonl > "$OUT/es.jsonl"
sleep 3
"${CP[@]}" exec -T apache sh -c "kill \$(cat $TAILPID) 2>/dev/null; rm -f $TAILPID" >/dev/null 2>&1
TAIL_ON=""
wait 2>/dev/null
# bổ sung từ tệp hiện tại và bản đã xoay (tail -F có thể hụt dòng nếu tệp xoay liên tục); trùng dòng không sao
"${CP[@]}" exec -T apache sh -c "cat $AUDIT.1 $AUDIT 2>/dev/null | grep -aF 'nsm-replay/$RUN/'" >> "$OUT/audit.jsonl" 2>/dev/null
echo "   nhật ký kiểm toán: $(grep -aoE "nsm-replay/$RUN/[0-9]+" "$OUT/audit.jsonl" | sort -u | wc -l | tr -d ' ') request của lượt phát lại"

log "[5/5] so sánh ..."
py -v "$OUT:/out:ro" --entrypoint python "$PYIMG" -B /tools/parity.py --run "$RUN" compare > "$OUT/report.md" \
  || { echo "!! lỗi khi so sánh — dữ liệu thô nằm trong eval/results/parity-$RUN/" >&2; exit 1; }
echo
cat "$OUT/report.md"
echo
echo ">> báo cáo: eval/results/parity-$RUN/report.md"
