#!/usr/bin/env bash
# tools/ruledemo-multi.sh — DEMO sinh NHIỀU luật cùng lúc (rce + sqli + xss + lfi).
# Mỗi họ tấn công CRS bỏ lọt (giả lập bằng DetectionOnly) -> classifier gán nhãn -> rulegen
# gom cụm -> trích bất biến từ GIÁ TRỊ tham số -> 1 luật/họ -> shadow -> active
# -> HIỂN THỊ + KIỂM CHỨNG: BIẾN THỂ payload (chưa từng gửi) từ IP mới bị 403, request lành tính thì không.
# Không còn bước xoá tay dữ liệu trong Elasticsearch. Tự khôi phục cấu hình ở cuối. Chạy trên HOST.
#   dùng:  bash tools/ruledemo-multi.sh
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
NET=nsm_external_net; IMG=curlimages/curl:8.10.1; TOOLS="$D/tools"
CP=(docker compose -f "$D/docker-compose.yml")
FAST="$D/.rulegen-fast.override.yml"      # tệp tạm nằm NGAY TRONG thư mục dự án, tự xoá khi script kết thúc
# ES() (gọi Elasticsearch có xác thực) được định nghĩa trong _host.sh
APACHE(){ "${CP[@]}" exec -T apache sh -c "$1"; }
cleanup_demo() { docker ps -aqf "name=demo_" | xargs -r docker rm -f >/dev/null 2>&1 || true; }
restore() {
  APACHE "sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful" >/dev/null 2>&1
  "${CP[@]}" up -d rulegen >/dev/null 2>&1
  rm -f "$FAST"
}
trap 'cleanup_demo; restore' EXIT

echo ">> [1] dọn luật cũ để bắt đầu sạch (giữ nguyên corpus lành tính) ..."
"${CP[@]}" stop -t 5 rulegen >/dev/null 2>&1
"${CP[@]}" run --rm --no-deps --entrypoint sh rulegen -c 'rm -f /state/rules.json' >/dev/null 2>&1 || true
ES -X DELETE "localhost:9200/rule-status?ignore_unavailable=true" >/dev/null 2>&1
NB=$(ES "localhost:9200/web-events-*/_count?q=label:benign%20AND%20source:web&ignore_unavailable=true" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
echo "   corpus lành tính hiện có: ${NB:-0} sự kiện (rulegen cần >= MIN_BENIGN, mặc định 100)"
[ "${NB:-0}" -lt 100 ] && echo "   !! chưa đủ — để hệ thống chạy thêm vài phút (client lành tính sinh ~20 sự kiện/phút) rồi chạy lại."

echo ">> [2] hạ CRS về DetectionOnly (cho các họ 'lọt' cổng 2 như payload CRS chưa biết) ..."
APACHE "sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful"

echo ">> [3] tăng tốc rulegen (15s/15s) ..."
cat > "$FAST" <<'YML'
services:
  rulegen:
    environment:
      INTERVAL_S: "15"
      SHADOW_S: "15"
      LOOKBACK_S: "900"
YML
if ! "${CP[@]}" -f "$FAST" up -d rulegen >/dev/null; then
  echo "!! không chạy được rulegen với cấu hình tăng tốc ($FAST) — dừng demo."; exit 1
fi
sleep 3

echo ">> [4] phóng 4 họ tấn công từ 8 IP (.131-.138) ..."
for pair in "131 rce" "132 rce" "133 sqli" "134 sqli" "135 xss" "136 xss" "137 lfi" "138 lfi"; do
  set -- $pair
  docker run --rm -d --name "demo_$1" --network "$NET" --ip "10.10.10.$1" \
    -v "$TOOLS:/tools:ro" --entrypoint sh "$IMG" \
    -c "tr -d '\r' < /tools/ruleatk.sh | sh -s $2" >/dev/null
done

echo ">> [5] chờ rulegen gom cụm -> shadow -> active (tối đa ~180s) ..."
for i in $(seq 1 36); do
  sleep 5
  ST=$(ES "localhost:9200/rule-status/_search?size=20&ignore_unavailable=true" 2>/dev/null)
  nact=$(echo "$ST" | grep -o '"state":"active"' | wc -l)
  nall=$(echo "$ST" | grep -o '"state":"[a-z]*"' | wc -l)
  echo "   ...$((i*5))s  luật active=$nact / tổng=$nall"
  [ "$nact" -ge 4 ] && break
done
cleanup_demo

echo
echo "===================== CÁC LUẬT ĐÃ SINH (active.conf) ====================="
APACHE 'cat /etc/modsecurity/autogen/active.conf'
echo "---------------------- rule-status (ES) ----------------------"
ES "localhost:9200/rule-status/_search?size=20&sort=id:asc&_source=id,class,op,target,state,cluster_size,token&pretty" 2>/dev/null \
  | grep -E '"id"|"class"|"op"|"target"|"state"|"cluster_size"|"token"'

echo
echo ">> [6] bật lại SecRuleEngine=On rồi KIỂM CHỨNG bằng BIẾN THỂ chưa từng gửi (IP mới -> kỳ vọng 403) ..."
APACHE "sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful"
sleep 2
N0=$(APACHE "wc -l < /var/log/apache-json/modsec_audit.json" 2>/dev/null | tr -dc 0-9)
R=http://10.10.10.10
req(){ docker run --rm --network "$NET" --ip "10.10.10.$1" "$IMG" -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" -w "%{http_code}" "${@:2}" 2>/dev/null; }
v_rce=$(req 141 --data-urlencode "ip=127.0.0.1;id" --data-urlencode "Submit=Submit" "$R/vulnerabilities/exec/")
v_sqli=$(req 142 -G "$R/vulnerabilities/sqli/" --data-urlencode "id=77' union select a,b from t-- -" --data-urlencode "Submit=Submit")
v_xss=$(req 143 -G "$R/vulnerabilities/xss_r/" --data-urlencode "name=<script>fetch(9)</script>")
v_lfi=$(req 144 -G "$R/vulnerabilities/fi/" --data-urlencode "page=/var/log/../../etc/passwd")
printf "   %-6s %s\n" "rce"  "$v_rce"
printf "   %-6s %s\n" "sqli" "$v_sqli"
printf "   %-6s %s\n" "xss"  "$v_xss"
printf "   %-6s %s\n" "lfi"  "$v_lfi"
echo "   (403 = bị chặn tại Cổng 2. Họ nào CRS đã tự chặn thì luật tự sinh không cần chạy tới;"
echo "    dòng 'luật TỰ SINH đã khớp' bên dưới cho biết luật tự sinh nào là luật ra quyết định.)"
echo "   đối chứng — request LÀNH TÍNH từ IP mới (kỳ vọng KHÁC 403):"
b1=$(req 145 -G "$R/vulnerabilities/sqli/" --data-urlencode "id=laptop" --data-urlencode "Submit=Submit")
b2=$(req 146 -G "$R/vulnerabilities/fi/" --data-urlencode "page=include.php")
b3=$(req 147 --data-urlencode "ip=8.8.8.8" --data-urlencode "Submit=Submit" "$R/vulnerabilities/exec/")
printf "   %-22s %s\n" "sqli/?id=laptop" "$b1" "fi/?page=include.php" "$b2" "exec ip=8.8.8.8" "$b3"

echo "   luật TỰ SINH đã khớp trong các request kiểm chứng (theo nhật ký kiểm toán ModSecurity):"
sleep 2
APACHE "tail -n +$(( ${N0:-0} + 1 )) /var/log/apache-json/modsec_audit.json | grep -o 'autogen [a-z]* active' | sort | uniq -c" 2>/dev/null | sed 's/^/     /' || true
echo
echo ">> [7] khôi phục cấu hình (SecRuleEngine On + rulegen về chu kỳ gốc) ..."
echo ">> xong. Reset cho lượt sau:  bash tools/reset-all.sh"
