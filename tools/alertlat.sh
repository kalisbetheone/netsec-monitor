#!/usr/bin/env bash
# tools/alertlat.sh — ĐO ĐỘ TRỄ TỪNG KHÂU của đường cảnh báo trên stack đang chạy. Chạy trên HOST, từ thư mục nsm:
#   bash tools/alertlat.sh            đủ ba pha (~9 phút)
#   ALERTLAT_N=4 bash tools/alertlat.sh   mỗi pha 4 lần thử (mặc định 8)
# Đường cảnh báo: Apache ghi nhật ký -> Filebeat -> Kafka (web.logs, web.audit) -> classifier -> Kafka (alerts) -> responder.
# Cách đo: mỗi lần thử là MỘT request tấn công thử (bị Cổng 2 chặn) từ một IP riêng, mang User-Agent đánh dấu
# `alertlat/<lượt>/<pha>/<số>`. Ba topic được đọc kèm DẤU THỜI GIAN của Kafka (thời điểm Filebeat / classifier gửi), rồi so
# với thời điểm Apache xử lý request (ts_ms trong nhật ký truy cập). Mọi mốc thời gian lấy từ các container của cùng một
# máy nên không lệch đồng hồ.
# Ba pha:
#   post-idle  POST có thân, cách nhau 30 giây -> nhật ký kiểm toán của ModSecurity "nguội" trước mỗi lần thử
#   get        GET, cách nhau 10 giây          -> không cần nhật ký kiểm toán
#   post-busy  POST có thân, cách nhau 6 giây, trong lúc một nguồn khác gửi POST HỢP LỆ mỗi giây -> nhật ký kiểm toán "nóng"
# Mỗi IP chỉ gửi một request tấn công nên không IP nào chạm ngưỡng khoá. Chỉ đọc Kafka (tài khoản quản trị có sẵn TRONG
# container kafka); không sửa cấu hình. Kết quả: eval/results/alertlat-<thời điểm>/ ; tính bằng tools/alertlat.py.
# Lưu lượng thử chỉ gửi vào hệ thống của dự án trong mạng Docker nội bộ.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
CP=(docker compose -f "$D/docker-compose.yml")
N="${ALERTLAT_N:-8}"; NET=nsm_external_net; IMG=curlimages/curl:8.10.1; GATE=http://10.10.10.10
RUN="$(date +%Y%m%d-%H%M%S)"; OUT="$D/eval/results/alertlat-$RUN"; mkdir -p "$OUT"
TOPICS="web.logs web.audit alerts"
PAY="1' UNION SELECT user,password FROM users-- -"
cleanup(){ docker rm -f alertlat_bg >/dev/null 2>&1; "${CP[@]}" exec -T kafka sh -c 'pkill -f "alertlat_" 2>/dev/null; for p in $(ps -ef 2>/dev/null | grep "[a]lertlat_" | awk "{print \$2}"); do kill $p 2>/dev/null; done; true' >/dev/null 2>&1; }
trap cleanup EXIT INT TERM
for t in $TOPICS; do
  "${CP[@]}" exec -T -d kafka sh -c "timeout 1200 /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka:9092 --consumer.config /tmp/hc.properties --topic $t --property print.timestamp=true > /tmp/alertlat_$t.txt 2>/dev/null"
done
echo "đang đọc: $TOPICS ; chờ 15 giây cho các bộ đọc sẵn sàng"; sleep 15
i=10
probe(){            # $1 = pha, $2 = số thứ tự, $3 = GET|POST
  i=$((i + 1)); local ip="10.10.12.$i" ua="alertlat/$RUN/$1/$2" code
  if [ "$3" = "POST" ]; then
    code="$(docker run --rm --network "$NET" --ip "$ip" "$IMG" -s -o /dev/null -w '%{http_code}' -m 10 -A "$ua" -H "Host: dvwa.local" --data-urlencode "q=$PAY" "$GATE/index.php")"
  else
    code="$(docker run --rm --network "$NET" --ip "$ip" "$IMG" -s -o /dev/null -w '%{http_code}' -m 10 -A "$ua" -H "Host: dvwa.local" -G --data-urlencode "q=$PAY" "$GATE/index.php")"
  fi
  echo "$1 $2 $3 $ip $code" | tee -a "$OUT/probes.txt"
}
echo "== pha post-idle"; for n in $(seq 1 "$N"); do sleep 30; probe post-idle "$n" POST; done
echo "== pha get";       for n in $(seq 1 "$N"); do sleep 10; probe get "$n" GET; done
echo "== pha post-busy (một nguồn khác gửi POST hợp lệ mỗi giây)"
docker run -d --rm --name alertlat_bg --network "$NET" --ip 10.10.12.250 --entrypoint sh "$IMG" -c \
  "while true; do curl -s -o /dev/null -m 5 -A alertlat-bg -H 'Host: dvwa.local' --data 'name=abc' $GATE/index.php; sleep 1; done" >/dev/null
sleep 8
for n in $(seq 1 "$N"); do sleep 6; probe post-busy "$n" POST; done
docker rm -f alertlat_bg >/dev/null 2>&1
echo "chờ 25 giây cho các thông điệp đến muộn"; sleep 25
for t in $TOPICS; do "${CP[@]}" exec -T kafka cat "/tmp/alertlat_$t.txt" > "$OUT/$t.txt" 2>/dev/null; done
cleanup; trap - EXIT INT TERM
"${CP[@]}" exec -T kafka sh -c 'rm -f /tmp/alertlat_*.txt' >/dev/null 2>&1
wc -l "$OUT"/*.txt | sed 's/^/   /'
PYTHONIOENCODING=utf-8 python -X utf8 -B "$D/tools/alertlat.py" "$OUT" | tee "$OUT/report.txt"
echo "kết quả: ${OUT#"$D"/}"
