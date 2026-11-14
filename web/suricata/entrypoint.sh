#!/bin/bash
# web/suricata/entrypoint.sh — bọc entrypoint gốc của image jasonish/suricata để XOAY NHẬT KÝ.
# Trước đây eve.json (và stats.log, fast.log) lớn mãi cho tới khi đầy đĩa. Image có sẵn logrotate nhưng
# không có cron, nên ở đây chạy một vòng lặp nền: cứ LOG_ROTATE_CHECK_S giây kiểm một lần, tệp nào vượt
# LOG_MAX_MB thì đổi tên thành <tên>.1 (giữ đúng 1 bản cũ) và bảo Suricata mở tệp mới.
# Filebeat theo dõi tệp bằng inode: đọc nốt bản vừa đổi tên rồi chuyển sang eve.json mới, không mất dòng.
MAXMB="${LOG_MAX_MB:-200}"
CONF=/tmp/nsm-logrotate.conf
cat > "$CONF" <<EOF
/var/log/suricata/*.log /var/log/suricata/*.json {
    su suricata suricata
    size ${MAXMB}M
    rotate 1
    missingok
    notifempty
    nocompress
    sharedscripts
    postrotate
        suricatasc -c reopen-log-files >/dev/null 2>&1 || true
    endscript
}
EOF
(
  while sleep "${LOG_ROTATE_CHECK_S:-300}"; do
    logrotate -s /tmp/nsm-logrotate.state "$CONF" 2>&1 | sed 's/^/[log-rotate] /'
  done
) &
exec /docker-entrypoint.sh "$@"
