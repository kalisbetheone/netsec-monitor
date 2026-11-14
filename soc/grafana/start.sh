#!/bin/sh
# soc/grafana/start.sh — chạy trước Grafana (entrypoint). Chép thư mục provisioning (gắn chỉ đọc) sang chỗ ghi
# được, và nếu .env có ALERT_WEBHOOK_URL thì tạo contact point 'nsm-webhook' + chính sách gửi MỌI cảnh báo NSM
# tới đó. Để trống ALERT_WEBHOOK_URL thì cảnh báo chỉ hiện trong Grafana (như trước).
set -e
SRC=/etc/grafana/provisioning-src
DST=/tmp/provisioning
rm -rf "$DST"; mkdir -p "$DST"
cp -R "$SRC/." "$DST/"
if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
  case "$ALERT_WEBHOOK_URL" in
    http://*|https://*) ;;
    *) echo "[nsm] ALERT_WEBHOOK_URL phải bắt đầu bằng http:// hoặc https:// — bỏ qua"; ALERT_WEBHOOK_URL="";;
  esac
fi
if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
  cat > "$DST/alerting/contact-points.yml" <<EOF
apiVersion: 1
contactPoints:
  - orgId: 1
    name: nsm-webhook
    receivers:
      - uid: nsm-webhook
        type: webhook
        settings:
          url: "${ALERT_WEBHOOK_URL}"
          httpMethod: POST
policies:
  - orgId: 1
    receiver: nsm-webhook
    group_by: [alertname]
    group_wait: 10s
    group_interval: 1m
    repeat_interval: 4h
EOF
  echo "[nsm] cảnh báo sẽ được gửi tới webhook đã cấu hình (ALERT_WEBHOOK_URL)"
else
  echo "[nsm] chưa đặt ALERT_WEBHOOK_URL — cảnh báo chỉ hiện trong Grafana"
fi
export GF_PATHS_PROVISIONING="$DST"
exec /run.sh "$@"
