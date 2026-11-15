#!/bin/sh
# benign_booking.sh — sinh lưu lượng NGƯỜI DÙNG BÌNH THƯỜNG cho cổng đặt chỗ (booking.local).
# Chỉ dùng sh POSIX + curl (chạy được trong image curlimages/curl: busybox sh). Không có request tấn công nào.
#
# Biến môi trường:
#   TARGET     địa chỉ máy chủ            (mặc định http://10.10.10.10)
#   HOST       tiêu đề Host               (mặc định booking.local)
#   PAUSE      số giây nghỉ giữa 2 request (mặc định 1)
#   MAX_LOOPS  số phiên sẽ chạy, 0 = chạy mãi (mặc định 0)
#   FLOW       ép chỉ chạy một luồng a..f (để thử); bỏ trống = chọn giả ngẫu nhiên
#   TYPOS      1 = thỉnh thoảng người dùng gõ nhầm tên/mật khẩu rồi gõ lại (sinh 404/401 hợp lệ); 0 = tắt (mặc định 1)
#
# Sáu luồng: (a) trang chủ -> tìm chuyến bay -> tìm lần nữa; (b) tra mã đặt chỗ bằng mã + tên có thật;
# (c) đăng nhập tài khoản thử -> hồ sơ -> đăng xuất; (d) ứng dụng di động gọi api.php (login, search, booking, profile);
# (e) tìm bằng từ khoá tự do có dấu tiếng Việt và dấu nháy đơn; (f) giữ chỗ.
# Sáu phiên đầu chạy lần lượt a..f (để lần chạy ngắn nào cũng đi qua đủ các luồng), sau đó chọn giả ngẫu nhiên.
# Mỗi request in một dòng: <luồng> <đường dẫn> <mã HTTP>. Kết thúc (khi MAX_LOOPS > 0) in dòng tổng kết;
# mã thoát khác 0 nếu có phản hồi 5xx.

TARGET="${TARGET:-http://10.10.10.10}"
HOST="${HOST:-booking.local}"
PAUSE="${PAUSE:-1}"
MAX_LOOPS="${MAX_LOOPS:-0}"
FLOW="${FLOW:-}"
TYPOS="${TYPOS:-1}"

PASSWORD='Passw0rd!1'                      # mật khẩu của 20 tài khoản thử user1..user20@example.test (xem seed.php)
UA_WEB='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
UA_APP='BookingApp/3.2 (Android 14)'
JAR="/tmp/benign_booking.$$.jar"
ORIGIN="http://$HOST"

trap 'rm -f "$JAR"' EXIT
trap 'exit 0' INT TERM

# Các cặp "mã đặt chỗ|tên" có thật trong CSDL — chép từ web/apache/booking/benign_pairs.txt (48 cặp)
N_PAIRS=48
PAIRS="VB8LYM|O'Neil
6NGCRM|An
KF9LXX|Smith
JZ7ZMC|D'Angelo
5AZVWY|Bình
2WFPGC|Johnson
4G66YH|O'Brien
RHHVSY|Châu
ABSJVU|Brown
KKWKLX|N'Dour
ZH7ZUH|Dũng
2HD46M|Miller
KPNS4B|O'Connor
5HTN3B|Giang
GEPRBS|Garcia
J56Z5G|D'Souza
L39BXR|Hà
HBH9ZQ|Martin
Y9AR4S|O'Hara
A9XG6S|Hải
NDRRTF|Dubois
TYVLMF|M'Baye
YLUE9P|Hạnh
8D748K|Rossi
LX6XDD|O'Donnell
XQKZ7V|Hiếu
VGCR7E|Schmidt
6XEURL|L'Heureux
F3YCFR|Hoa
LYCQPW|Novak
DJPK67|D'Amico
GPUPGG|Hùng
T23KZY|Silva
9NWGJR|O'Reilly
64K4HU|Khánh
FVH698|Kowalski
ZRPYBM|N'Guessan
AG57DY|Lan
LZYKKY|Nilsson
C8SECJ|O'Sullivan
F9DRL4|Linh
LH4JVL|Baker
6HBVM9|Long
FMT6ZX|Moreau
584NJB|Mai
H96GQ3|Weber
QKPS6J|Nam
G7YUBQ|Yến"

# Từ khoá tự do người dùng hay gõ: có dấu tiếng Việt, có dấu nháy đơn
N_QUERIES=12
QUERIES="O'Neil
Côte d'Ivoire
Hà Nội
Đà Nẵng
Phú Quốc
Sài Gòn
Huế
D'Angelo
NS12
Nha Trang
vé đi Đà Lạt
Hải Phòng"

AIRPORTS="HAN SGN DAD CXR PQC HPH VCA HUI DLI VII"

N_REQ=0
N_5XX=0
N_ERR=0
LCG=$$

# rnd N: đặt RND = số nguyên giả ngẫu nhiên trong 0..N-1 (không dùng $RANDOM vì không thuộc POSIX)
rnd() {
  _r=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' \n')
  case "$_r" in
    ''|*[!0-9]*)
      LCG=$(( (LCG * 1103515245 + 12345) % 2147483648 ))
      _r=$(( LCG / 65536 ))
      ;;
  esac
  RND=$(( _r % $1 ))
}

# req <luồng> <đường dẫn> [tham số curl...]: gửi một request, in "<luồng> <đường dẫn> <mã HTTP>"
req() {
  _flow=$1
  _path=$2
  shift 2
  _code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Host: $HOST" "$@" "$TARGET$_path" </dev/null)
  [ -n "$_code" ] || _code=000
  N_REQ=$((N_REQ + 1))
  case "$_code" in
    5*)  N_5XX=$((N_5XX + 1)) ;;
    000) N_ERR=$((N_ERR + 1)) ;;
  esac
  echo "$_flow $_path $_code"
  sleep "$PAUSE"
}

# web: request kiểu trình duyệt
web() {
  _wf=$1
  _wp=$2
  shift 2
  req "$_wf" "$_wp" -A "$UA_WEB" \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Language: vi-VN,vi;q=0.9,en;q=0.8' "$@"
}

# api <luồng> <thân JSON>: request kiểu ứng dụng di động tới api.php (giữ cookie phiên trong $JAR)
api() {
  req "$1" /api.php -A "$UA_APP" -H 'Accept: application/json' -H 'Content-Type: application/json' \
    -b "$JAR" -c "$JAR" --data-binary "$2"
}

pick_airport() {
  rnd 10
  # shellcheck disable=SC2086
  set -- $AIRPORTS
  shift "$RND"
  AP=$1
}

# Ngày bay trong khoảng dữ liệu có sẵn: 16/11/2026 .. 14/01/2027
pick_date() {
  rnd 60
  _d=$((RND + 1))
  if [ "$_d" -le 15 ]; then
    DATE=$(printf '2026-11-%02d' $((_d + 15)))
  elif [ "$_d" -le 46 ]; then
    DATE=$(printf '2026-12-%02d' $((_d - 15)))
  else
    DATE=$(printf '2027-01-%02d' $((_d - 46)))
  fi
}

pick_pair() {
  rnd "$N_PAIRS"
  _line=$(printf '%s\n' "$PAIRS" | sed -n "$((RND + 1))p")
  P_CODE=${_line%%|*}
  P_LAST=${_line#*|}
}

pick_query() {
  rnd "$N_QUERIES"
  QUERY=$(printf '%s\n' "$QUERIES" | sed -n "$((RND + 1))p")
}

pick_user() {
  rnd 20
  USER_EMAIL="user$((RND + 1))@example.test"
}

# (a) trang chủ -> tìm chuyến bay -> tìm lần nữa với điểm đến khác
flow_a() {
  web a /index.php
  req a /style.css -A "$UA_WEB" -H 'Accept: text/css,*/*;q=0.1'
  pick_airport; _from=$AP
  pick_airport; _to=$AP
  pick_date
  web a /search.php -G --data-urlencode "from=$_from" --data-urlencode "to=$_to" --data-urlencode "date=$DATE"
  pick_airport
  web a /search.php -G --data-urlencode "from=$_from" --data-urlencode "to=$AP"
}

# (b) tra mã đặt chỗ bằng mã + tên có thật (đôi khi gõ mã bằng chữ thường, đôi khi gõ nhầm tên rồi gõ lại)
flow_b() {
  pick_pair
  web b /index.php
  rnd 4
  if [ "$RND" -eq 0 ]; then
    P_CODE=$(printf '%s' "$P_CODE" | tr 'A-Z' 'a-z')
  fi
  rnd 12
  if [ "$TYPOS" = 1 ] && [ "$RND" -eq 0 ]; then
    web b /booking.php -G --data-urlencode "code=$P_CODE" --data-urlencode "last=${P_LAST}n"
  fi
  web b /booking.php -G --data-urlencode "code=$P_CODE" --data-urlencode "last=$P_LAST"
}

# (c) đăng nhập tài khoản thử -> hồ sơ -> đăng xuất
flow_c() {
  rm -f "$JAR"
  pick_user
  web c /login.php -b "$JAR" -c "$JAR"
  rnd 15
  if [ "$TYPOS" = 1 ] && [ "$RND" -eq 0 ]; then
    web c /login.php -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" \
      --data-urlencode "email=$USER_EMAIL" --data-urlencode "password=passw0rd!1"
  fi
  web c /login.php -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" \
    --data-urlencode "email=$USER_EMAIL" --data-urlencode "password=$PASSWORD"
  web c /profile.php -b "$JAR" -c "$JAR"
  web c /logout.php -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" --data ''
}

# (d) ứng dụng di động: đăng nhập, tìm chuyến bay, tra đặt chỗ, xem hồ sơ qua api.php
flow_d() {
  rm -f "$JAR"
  pick_user
  api d "{\"action\":\"login\",\"email\":\"$USER_EMAIL\",\"password\":\"$PASSWORD\"}"
  pick_airport; _from=$AP
  pick_airport; _to=$AP
  pick_date
  api d "{\"action\":\"search\",\"from\":\"$_from\",\"to\":\"$_to\",\"date\":\"$DATE\"}"
  pick_pair
  api d "{\"action\":\"booking\",\"code\":\"$P_CODE\",\"last\":\"$P_LAST\"}"
  api d '{"action":"profile"}'
}

# (e) tìm bằng từ khoá tự do (có dấu tiếng Việt, dấu nháy đơn)
flow_e() {
  web e /index.php
  pick_query
  web e /search.php -G --data-urlencode "q=$QUERY"
  pick_query
  pick_airport
  web e /search.php -G --data-urlencode "from=$AP" --data-urlencode "q=$QUERY"
}

# (f) xem chuyến bay rồi giữ một chỗ
flow_f() {
  rm -f "$JAR"
  pick_airport
  web f /search.php -b "$JAR" -c "$JAR" -G --data-urlencode "to=$AP"
  rnd 2000
  web f /hold.php -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" --data-urlencode "flight_id=$((RND + 1))"
}

n=0
while :; do
  n=$((n + 1))
  if [ -n "$FLOW" ]; then
    f=$FLOW
  elif [ "$n" -le 6 ]; then
    f=$(echo abcdef | cut -c"$n")
  else
    rnd 6
    f=$(echo abcdef | cut -c"$((RND + 1))")
  fi
  case "$f" in
    a) flow_a ;;
    b) flow_b ;;
    c) flow_c ;;
    d) flow_d ;;
    e) flow_e ;;
    f) flow_f ;;
    *) echo "FLOW không hợp lệ: $f (chỉ nhận a..f)" >&2; exit 2 ;;
  esac
  if [ "$MAX_LOOPS" -gt 0 ] && [ "$n" -ge "$MAX_LOOPS" ]; then
    break
  fi
done

echo "done loops=$n requests=$N_REQ http5xx=$N_5XX no_response=$N_ERR"
[ "$N_5XX" -eq 0 ]
