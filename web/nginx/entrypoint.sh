#!/bin/sh
DIR=/etc/nginx/blocklist
MAP="$DIR/blocklist.map"
FPMAP="$DIR/blockfp.map"                 # D1: khoá "<ip>|<User-Agent>"
MIN="${RELOAD_MIN_INTERVAL_S:-5}"     # E5: tối đa 1 lần nạp lại mỗi MIN giây (gom các thay đổi dồn dập)
EXACT="${RELOAD_EXACT_WAIT:-0}"       # 1 = còn trong MIN giây thì ngủ đúng phần còn lại rồi nạp; 0 = ngủ 1 giây rồi quay lại vòng chờ
EXGEO="$DIR/exempt.geo"                 # dải miễn trừ (không giới hạn tốc độ), do enforcer ghi
mkdir -p "$DIR"; [ -f "$MAP" ] || : > "$MAP"; [ -f "$FPMAP" ] || : > "$FPMAP"; [ -f "$EXGEO" ] || : > "$EXGEO"
if grep -qvE '^(#.*|[0-9A-Fa-f:.]+(/[0-9]{1,3})? 1;|[[:space:]]*)$' "$EXGEO"; then
  echo "[boot] exempt.geo có dòng sai định dạng — cất sang exempt.geo.bad, khởi động với danh sách rỗng"
  cp "$EXGEO" "$EXGEO.bad"; : > "$EXGEO"
fi
GLOG=/var/log/nginx-json/gate1.json      # nhật ký request bị Cổng 1 từ chối (Filebeat đọc)
mkdir -p "$(dirname "$GLOG")"; [ -f "$GLOG" ] || : > "$GLOG"

# Tệp chặn hỏng (dòng không đúng dạng "<ip> 1;") không được làm nginx không khởi động nổi:
# cất sang .bad và chạy với danh sách rỗng; enforcer sẽ ghi lại bản đúng ở lần phát kế tiếp.
if grep -qvE '^(#.*|[0-9A-Fa-f:.]+ 1;|[[:space:]]*)$' "$MAP"; then
  echo "[boot] blocklist.map có dòng sai định dạng — cất sang blocklist.map.bad, khởi động với danh sách rỗng"
  cp "$MAP" "$MAP.bad"; : > "$MAP"
fi
if grep -qvE '^(#.*|"[0-9A-Fa-f:.]+[|][^"\\$]*" 1;|[[:space:]]*)$' "$FPMAP"; then
  echo "[boot] blockfp.map có dòng sai định dạng — cất sang blockfp.map.bad, khởi động với danh sách rỗng"
  cp "$FPMAP" "$FPMAP.bad"; : > "$FPMAP"
fi

# C1: sinh cert tự ký cho HTTPS nếu chưa có
CERT=/etc/nginx/certs
mkdir -p "$CERT"
[ -f "$CERT/server.crt" ] || openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$CERT/server.key" -out "$CERT/server.crt" -days 365 \
  -subj "/CN=shop.lab.local" >/dev/null 2>&1

# Theo dõi blocklist.map. So sánh NỘI DUNG (md5) với bản đang áp, nên không bỏ sót thay đổi nào
# dù sự kiện inotify đến lúc đang nạp lại; inotifywait chỉ để phản ứng nhanh (hết 2 giây thì tự kiểm).
(
  applied=$(cat "$MAP" "$FPMAP" "$EXGEO" 2>/dev/null | md5sum); last=0
  while :; do
    inotifywait -q -t 2 -e close_write,moved_to "$DIR" >/dev/null 2>&1
    cur=$(cat "$MAP" "$FPMAP" "$EXGEO" 2>/dev/null | md5sum) || continue
    [ "$cur" = "$applied" ] && continue
    now=$(date +%s)
    if [ $((now - last)) -lt "$MIN" ]; then
      # Cách cũ (EXACT=0): ngủ 1 giây rồi quay lại inotifywait (chờ tới 2 giây nếu không có thay đổi mới), nên một thay đổi
      # đến ngay sau lần nạp trước có thể phải chờ lâu hơn MIN tới 2 giây. EXACT=1: ngủ đúng phần còn lại, đọc lại nội dung, nạp.
      if [ "$EXACT" != 1 ]; then sleep 1; continue; fi
      sleep $((MIN - (now - last)))
      cur=$(cat "$MAP" "$FPMAP" "$EXGEO" 2>/dev/null | md5sum) || continue
      [ "$cur" = "$applied" ] && continue
      now=$(date +%s)
    fi
    if nginx -t -q 2>/dev/null; then nginx -s reload && echo "[watch] blocklist reloaded"
    else echo "[watch] nginx -t failed, giữ cấu hình cũ"; fi
    applied=$cur; last=$now
  done
) &
# Không để nhật ký Cổng 1 lớn mãi (một IP bị chặn có thể bắn rất nhiều request): quá LOG_MAX_MB thì XOAY
# (đổi tên thành gate1.json.1, giữ 1 bản cũ) rồi 'nginx -s reopen'. Không cắt về 0 vì Filebeat có thể mất
# các dòng chưa kịp đọc; tệp đổi tên giữ inode nên Filebeat đọc nốt (paths gồm cả gate1.json.1).
(
  MAXMB="${LOG_MAX_MB:-50}"
  while :; do
    sleep "${LOG_ROTATE_CHECK_S:-60}"
    sz=$(stat -c %s "$GLOG" 2>/dev/null || echo 0)
    if [ "$sz" -gt $((MAXMB * 1024 * 1024)) ]; then
      mv -f "$GLOG" "$GLOG.1" && nginx -s reopen && echo "[log-rotate] $GLOG vượt ${MAXMB} MB — đã xoay"
    fi
  done
) &
exec nginx -g 'daemon off;'
