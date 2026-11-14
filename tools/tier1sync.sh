#!/usr/bin/env bash
# tools/tier1sync.sh — KIỂM CHỨNG luật tầng 1 đồng bộ ở Cổng 2 (web/apache/nsm-tier1.conf) khớp tầng 1 của classifier.
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy:
#   bash tools/tier1sync.sh                       mặc định 3000 lành tính thật + 600 request mỗi nguồn tấn công
#   T1S_BENIGN=500 T1S_PER=100 bash tools/tier1sync.sh
# Các bước:
#   0. luật tự sinh đang chạy (id 9900000+) cũng được tạm gỡ: chúng nạp trước và chặn trước luật NSM
#   1. kiểm tra tệp luật khớp mã nguồn classifier (tools/gen_tier1_modsec.py --check)
#   2. TẠM gỡ luật chấm điểm chặn của CRS (949110) và bật ghi kiểm toán cho request đo — để luật NSM luôn được xét
#   3. gửi thẳng tới Apache (mạng app_net, không qua nginx nên responder không chặn IP)
#   4. so: luật NSM (id 1000200–1000399) có ghi trong nhật ký kiểm toán ↔ tầng 1 của classifier trên cùng request
# Kết quả: eval/results/tier1sync-<thời điểm>/report.md. Tự khôi phục CRS khi xong hoặc khi bấm Ctrl-C.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
export MSYS_NO_PATHCONV=1
PYIMG="${BENCH_IMAGE:-nsm-classifier}"
APACHE=nsm-apache-1
TMP=/etc/apache2/conf-enabled/zzz-nsm-t1sync.conf
AUDIT=/var/log/apache-json/modsec_audit.json
RUN="$(date +%Y%m%d-%H%M%S)"
OUT="$D/eval/results/tier1sync-$RUN"
log(){ echo ">> $*"; }

docker inspect -f '{{.State.Running}}' "$APACHE" 2>/dev/null | grep -q true || { echo "!! $APACHE chưa chạy" >&2; exit 1; }
python -X utf8 -B "$D/tools/gen_tier1_modsec.py" --check || exit 1
docker exec "$APACHE" test -f /etc/modsecurity/nsm-sync/tier1.conf || { echo "!! Apache chưa nạp nsm-tier1.conf (build lại apache)" >&2; exit 1; }
cmp -s <(docker exec "$APACHE" cat /etc/modsecurity/nsm-sync/tier1.conf) "$D/web/apache/nsm-tier1.conf" \
  || { echo "!! tệp luật trong container khác web/apache/nsm-tier1.conf (build lại apache)" >&2; exit 1; }
mkdir -p "$OUT" || exit 1

restore(){ docker exec "$APACHE" sh -c "rm -f $TMP && apache2ctl -k graceful" >/dev/null 2>&1; log "đã khôi phục CRS"; }
trap 'restore; exit 130' INT TERM
docker exec -i "$APACHE" sh -c "cat > $TMP" <<'EOF'
# TẠM THỜI — tools/tier1sync.sh (tự gỡ khi xong)
<IfModule security2_module>
    SecRuleRemoveById 949110
    SecRuleRemoveById 9900000-9999999
    SecRule REQUEST_HEADERS:User-Agent "@contains nsm-t1sync/" "id:1000099,phase:1,pass,nolog,ctl:auditEngine=On"
</IfModule>
EOF
docker exec "$APACHE" sh -c "apache2ctl -t >/dev/null 2>&1 && apache2ctl -k graceful" || { restore; echo "!! cấu hình tạm lỗi" >&2; exit 1; }
sleep 2

MNT=(-v "$D/tools:/tools:ro" -v "$D/services:/svc:ro" -v "$D/eval:/eval:ro" -v "$OUT:/o")
log "dựng tập request ..."
docker run --rm "${MNT[@]}" --entrypoint python "$PYIMG" -B /tools/tier1sync.py --run "$RUN" build \
  --benign "${T1S_BENIGN:-3000}" --per "${T1S_PER:-600}" > "$OUT/requests.jsonl" || { restore; exit 1; }
log "gửi thẳng tới Apache ..."
docker run --rm --network nsm_app_net "${MNT[@]}" --entrypoint python "$PYIMG" -B /tools/tier1sync.py --run "$RUN" \
  send --input /o/requests.jsonl > "$OUT/sent.jsonl"
sleep 3
# nhật ký có thể XOAY giữa chừng (entrypoint.sh: quá LOG_MAX_MB) -> đọc cả tệp cũ, lọc theo mã lượt chạy
docker exec "$APACHE" sh -c "grep -h -F 'nsm-t1sync/$RUN/' $AUDIT.1 $AUDIT 2>/dev/null" > "$OUT/audit.jsonl"
restore
trap - INT TERM
log "so sánh ..."
{
  echo "# Kiểm chứng luật tầng 1 đồng bộ — $RUN"
  echo
  echo "Tạo bởi \`tools/tier1sync.sh\`. \"Cả hai\" = classifier (tầng 1, độ tin cậy ≥ 0,9) và luật NSM ở ModSecurity cùng"
  echo "chặn; \"chỉ classifier\" = Cổng 2 bỏ lọt cái classifier bắt (sẽ lại phải chờ đường ống); \"chỉ ModSecurity\" ="
  echo "Cổng 2 chặn cái classifier không bắt (có thể là chặn nhầm). CRS 949110 được tạm gỡ trong lúc đo."
  echo
  docker run --rm -i "${MNT[@]}" --entrypoint python "$PYIMG" -B /tools/tier1sync.py --run "$RUN" \
    compare --input /o/requests.jsonl --sent /o/sent.jsonl < "$OUT/audit.jsonl"
} > "$OUT/report.md"
log "kết quả: $OUT/report.md"
