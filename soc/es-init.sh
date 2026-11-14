#!/bin/sh
# soc/es-init.sh — chạy trong container es-init mỗi lần stack khởi động (chạy lại nhiều lần không sao).
# Quyền tối thiểu cho từng vai trò (T8 — trước đây mọi dịch vụ dùng tài khoản quản trị elastic):
#   grafana_ro   chỉ ĐỌC các chỉ mục của hệ thống (Grafana là thành phần duy nhất mở ra trình duyệt)
#   nsm_writer   classifier, tier3, responder, logsink: chỉ THÊM bản ghi, không đọc/sửa/xoá được
#   nsm_rulegen  đọc sự kiện, ghi rule-status + nhịp tim, xoá chỉ mục sự kiện/kiểm toán quá hạn
#   nsm_ctl      công cụ nsmctl: chỉ đọc nhật ký kiểm toán
# Và chính sách vòng đời (ILM) tự xoá chỉ mục cũ (T3).
ES="${ES_URL:-http://elasticsearch:9200}"
call() {   # $1=phương thức  $2=đường dẫn  $3=thân JSON
  code=$(curl -s -o /tmp/out -w '%{http_code}' -u "elastic:$ELASTIC_PASSWORD" -X "$1" "$ES$2" \
           -H 'Content-Type: application/json' -d "$3")
  case "$code" in 2*) ;; *) echo "es-init: $1 $2 -> HTTP $code: $(cat /tmp/out)"; exit 1;; esac
}
call PUT /_security/role/nsm_reader '{
  "cluster": ["monitor"],
  "indices": [{"names": ["web-events-*", "audit-decisions-*", "rule-status", "gate-events-*", "apache-errors-*", "nsm-health-*"],
               "privileges": ["read", "view_index_metadata"]}]}'
call PUT /_security/user/grafana_ro "{\"password\": \"$GRAFANA_ES_PASSWORD\", \"roles\": [\"nsm_reader\"]}"

call PUT /_security/role/nsm_writer '{
  "cluster": ["monitor"],
  "indices": [{"names": ["web-events-*", "audit-decisions-*", "gate-events-*", "apache-errors-*", "nsm-health-*"],
               "privileges": ["create_doc", "create_index", "auto_configure", "view_index_metadata"]}]}'
call PUT /_security/role/nsm_rulegen '{
  "cluster": ["monitor"],
  "indices": [{"names": ["web-events-*"], "privileges": ["read", "view_index_metadata", "delete_index"]},
              {"names": ["audit-decisions-*"], "privileges": ["view_index_metadata", "delete_index"]},
              {"names": ["rule-status", "nsm-health-*"], "privileges": ["read", "write", "create_index", "auto_configure", "view_index_metadata"]}]}'
call PUT /_security/role/nsm_ctl '{
  "cluster": ["monitor"],
  "indices": [{"names": ["audit-decisions-*"], "privileges": ["read", "view_index_metadata"]}]}'
call PUT /_security/user/nsm_writer  "{\"password\": \"$ES_WRITER_PASSWORD\",  \"roles\": [\"nsm_writer\"]}"
call PUT /_security/user/nsm_rulegen "{\"password\": \"$ES_RULEGEN_PASSWORD\", \"roles\": [\"nsm_rulegen\"]}"
call PUT /_security/user/nsm_ctl     "{\"password\": \"$ES_CTL_PASSWORD\",     \"roles\": [\"nsm_ctl\"]}"

# Vòng đời chỉ mục: nhật ký phụ giữ LOG_RETENTION_DAYS ngày; web-events / audit-decisions vốn do rulegen dọn
# (RETENTION_DAYS=30) — ILM ở đây là lưới an toàn khi rulegen không chạy.
SHORT="${LOG_RETENTION_DAYS:-14}d"; LONG="${EVENT_RETENTION_DAYS:-32}d"
call PUT /_ilm/policy/nsm-short "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}}, \"delete\": {\"min_age\": \"$SHORT\", \"actions\": {\"delete\": {}}}}}}"
call PUT /_ilm/policy/nsm-long  "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}}, \"delete\": {\"min_age\": \"$LONG\", \"actions\": {\"delete\": {}}}}}}"
call PUT /_index_template/nsm-short '{"index_patterns": ["gate-events-*", "apache-errors-*", "nsm-health-*"], "priority": 100,
  "template": {"settings": {"index.lifecycle.name": "nsm-short"}}}'
call PUT /_index_template/nsm-long '{"index_patterns": ["web-events-*", "audit-decisions-*"], "priority": 100,
  "template": {"settings": {"index.lifecycle.name": "nsm-long"}}}'
# chỉ mục đã có từ trước khi có chính sách
call PUT "/gate-events-*,apache-errors-*,nsm-health-*/_settings?allow_no_indices=true&expand_wildcards=open" '{"index.lifecycle.name": "nsm-short"}'
call PUT "/web-events-*,audit-decisions-*/_settings?allow_no_indices=true&expand_wildcards=open" '{"index.lifecycle.name": "nsm-long"}'
echo "es-init: tài khoản grafana_ro, nsm_writer, nsm_rulegen, nsm_ctl và chính sách xoá chỉ mục cũ ($SHORT / $LONG) đã sẵn sàng"
