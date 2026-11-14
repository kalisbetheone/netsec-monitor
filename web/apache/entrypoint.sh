#!/bin/sh
set -e
touch /etc/modsecurity/autogen/active.conf

# Nạp luật đã ban hành TRƯỚC khi Apache đọc cấu hình (trước đây chạy nền song song nên có thể
# Apache khởi động với tệp luật rỗng và không nạp lại cho tới khi luật thay đổi).
/usr/local/bin/watch-rules.sh boot || true
/usr/local/bin/watch-rules.sh watch &

# Không để nhật ký lớn mãi: quá LOG_MAX_MB thì XOAY (đổi tên thành <tên>.1, giữ đúng 1 bản cũ) rồi
# 'apache2ctl -k graceful' để Apache và ModSecurity mở tệp mới. KHÔNG cắt về 0 như trước: cắt làm Filebeat
# mất các dòng chưa kịp đọc (đã đo: classifier nhận thiếu thân của 34 request POST trong một lần cắt).
# Tệp đã đổi tên giữ nguyên inode nên Filebeat đọc nốt nó (paths gồm cả <tên>.1) rồi chuyển sang tệp mới.
(
  MAXMB="${LOG_MAX_MB:-200}"
  while :; do
    sleep "${LOG_ROTATE_CHECK_S:-60}"
    rotated=""
    for f in /var/log/apache-json/access.json /var/log/apache-json/modsec_audit.json /var/log/apache-json/error.log; do
      [ -f "$f" ] || continue
      sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
      if [ "$sz" -gt $((MAXMB * 1024 * 1024)) ]; then
        mv -f "$f" "$f.1" && rotated="$rotated $f"
      fi
    done
    if [ -n "$rotated" ]; then
      apache2ctl -k graceful 2>/dev/null
      echo "[log-rotate] vượt ${MAXMB} MB, đã xoay:$rotated"
    fi
  done
) &

exec apache2-foreground
