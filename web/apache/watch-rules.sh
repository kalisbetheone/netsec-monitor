#!/bin/sh
# Nạp tệp luật do enforcer ghi vào tập luật ModSecurity, có kiểm cú pháp và tự khôi phục.
#   watch-rules.sh boot    áp một lần, KHÔNG graceful (gọi TRƯỚC khi Apache khởi động)
#   watch-rules.sh watch   theo dõi liên tục, áp + graceful khi tệp đổi
SRC=/rules/published/autogen.conf
DST=/etc/modsecurity/autogen/active.conf
STATUS=/rules/status.json
mkdir -p /rules/published

status() {   # $1 = sha, $2 = true|false  -> enforcer đọc để báo về rulegen
  printf '{"sha":"%s","ok":%s,"ts":%s}\n' "$1" "$2" "$(date +%s)" > "$STATUS.tmp" && mv "$STATUS.tmp" "$STATUS"
}

apply() {   # $1 = graceful | boot
  [ -f "$SRC" ] || return 0
  SHA=$(sha256sum "$SRC" | cut -c1-16)
  if cmp -s "$SRC" "$DST"; then          # nội dung đang chạy rồi -> vẫn báo kết quả cho đúng sha
    status "$SHA" true; return 0
  fi
  cp "$DST" "$DST.bak"; cp "$SRC" "$DST"
  if apache2ctl -t >/tmp/ct.log 2>&1; then
    [ "$1" = graceful ] && apache2ctl -k graceful
    status "$SHA" true
    echo "[watch] rules applied sha=$SHA"
  else
    cp "$DST.bak" "$DST"
    status "$SHA" false
    echo "[watch] configtest FAILED sha=$SHA, rollback"; cat /tmp/ct.log
  fi
}

if [ "${1:-watch}" = boot ]; then
  apply boot
  exit 0
fi

# So sánh NỘI DUNG với bản đã xử lý gần nhất nên không bỏ sót thay đổi xảy ra lúc đang áp luật;
# inotifywait chỉ để phản ứng nhanh (hết 5 giây thì tự kiểm lại).
seen=$(sha256sum < "$SRC" 2>/dev/null)
while :; do
  inotifywait -q -t 5 -e close_write,moved_to /rules/published >/dev/null 2>&1
  [ -f "$SRC" ] || continue
  cur=$(sha256sum < "$SRC")
  [ "$cur" = "$seen" ] && continue
  sleep 1
  seen=$(sha256sum < "$SRC")
  apply graceful
done
