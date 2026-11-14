#!/bin/sh
# soc/es-init.sh — chạy trong container es-init mỗi lần stack khởi động (chạy lại nhiều lần không sao).
# Quyền tối thiểu cho từng vai trò (T8 — trước đây mọi dịch vụ dùng tài khoản quản trị elastic):
#   grafana_ro   chỉ ĐỌC các chỉ mục của hệ thống (Grafana là thành phần duy nhất mở ra trình duyệt)
#   nsm_writer   classifier, tier3, responder, logsink: chỉ THÊM bản ghi, không đọc/sửa/xoá được
#   nsm_rulegen  đọc sự kiện + số lần luật khớp thật (apache-errors), ghi rule-status + nhịp tim + kiểm toán thao tác
#                trên luật, xoá chỉ mục SỰ KIỆN quá hạn. Từ 15/11/2026 KHÔNG còn quyền xoá nhật ký kiểm toán
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
  "indices": [{"names": ["web-events-*", "attack-events-*", "audit-decisions-*", "rule-status", "gate-events-*", "apache-errors-*", "nsm-health-*"],
               "privileges": ["read", "view_index_metadata"]}]}'
call PUT /_security/user/grafana_ro "{\"password\": \"$GRAFANA_ES_PASSWORD\", \"roles\": [\"nsm_reader\"]}"

call PUT /_security/role/nsm_writer '{
  "cluster": ["monitor"],
  "indices": [{"names": ["web-events-*", "attack-events-*", "audit-decisions-*", "gate-events-*", "apache-errors-*", "nsm-health-*"],
               "privileges": ["create_doc", "create_index", "auto_configure", "view_index_metadata"]}]}'
call PUT /_security/role/nsm_rulegen '{
  "cluster": ["monitor"],
  "indices": [{"names": ["web-events-*"], "privileges": ["read", "view_index_metadata", "delete_index"]},
              {"names": ["audit-decisions-*"], "privileges": ["create_doc", "create_index", "auto_configure", "view_index_metadata"]},
              {"names": ["apache-errors-*"], "privileges": ["read", "view_index_metadata"]},
              {"names": ["rule-status", "nsm-health-*"], "privileges": ["read", "write", "create_index", "auto_configure", "view_index_metadata"]}]}'
call PUT /_security/role/nsm_ctl '{
  "cluster": ["monitor"],
  "indices": [{"names": ["audit-decisions-*"], "privileges": ["read", "view_index_metadata"]}]}'
call PUT /_security/user/nsm_writer  "{\"password\": \"$ES_WRITER_PASSWORD\",  \"roles\": [\"nsm_writer\"]}"
call PUT /_security/user/nsm_rulegen "{\"password\": \"$ES_RULEGEN_PASSWORD\", \"roles\": [\"nsm_rulegen\"]}"
call PUT /_security/user/nsm_ctl     "{\"password\": \"$ES_CTL_PASSWORD\",     \"roles\": [\"nsm_ctl\"]}"

# Thời gian lưu (chốt 15/11/2026):
#   nhật ký kiểm toán (audit-decisions) và bản lưu sự kiện TẤN CÔNG (attack-events)   AUDIT_RETENTION_DAYS = 365
#   request bị Cổng 1 từ chối (gate-events)                                            GATE_RETENTION_DAYS  = 90
#   mọi sự kiện request (web-events; rulegen cũng dọn theo RETENTION_DAYS=30)          EVENT_RETENTION_DAYS = 32
#   lỗi Apache, nhịp tim dịch vụ                                                       LOG_RETENTION_DAYS   = 14
# Đơn vị mặc định là ngày; đặt RETENTION_UNIT=h để thử nhanh (tính bằng giờ) khi trình bày.
U="${RETENTION_UNIT:-d}"
SHORT="${LOG_RETENTION_DAYS:-14}$U"; LONG="${EVENT_RETENTION_DAYS:-32}$U"
AUDIT="${AUDIT_RETENTION_DAYS:-365}$U"; GATE="${GATE_RETENTION_DAYS:-90}$U"
call PUT /_ilm/policy/nsm-audit "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}}, \"delete\": {\"min_age\": \"$AUDIT\", \"actions\": {\"delete\": {}}}}}}"
call PUT /_ilm/policy/nsm-gate  "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}}, \"delete\": {\"min_age\": \"$GATE\", \"actions\": {\"delete\": {}}}}}}"
call PUT /_index_template/nsm-audit '{"index_patterns": ["audit-decisions-*", "attack-events-*"], "priority": 110,
  "template": {"settings": {"index.lifecycle.name": "nsm-audit"}}}'
call PUT /_index_template/nsm-gate '{"index_patterns": ["gate-events-*"], "priority": 110,
  "template": {"settings": {"index.lifecycle.name": "nsm-gate"}}}'
call PUT "/audit-decisions-*,attack-events-*/_settings?allow_no_indices=true&expand_wildcards=open" '{"index.lifecycle.name": "nsm-audit"}'
call PUT "/gate-events-*/_settings?allow_no_indices=true&expand_wildcards=open" '{"index.lifecycle.name": "nsm-gate"}'
call PUT /_ilm/policy/nsm-short "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}}, \"delete\": {\"min_age\": \"$SHORT\", \"actions\": {\"delete\": {}}}}}}"
call PUT /_ilm/policy/nsm-long  "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}}, \"delete\": {\"min_age\": \"$LONG\", \"actions\": {\"delete\": {}}}}}}"
call PUT /_index_template/nsm-short '{"index_patterns": ["apache-errors-*", "nsm-health-*"], "priority": 100,
  "template": {"settings": {"index.lifecycle.name": "nsm-short"}}}'
call PUT /_index_template/nsm-long '{"index_patterns": ["web-events-*"], "priority": 100,
  "template": {"settings": {"index.lifecycle.name": "nsm-long"}}}'
# chỉ mục đã có từ trước khi có chính sách
call PUT "/apache-errors-*,nsm-health-*/_settings?allow_no_indices=true&expand_wildcards=open" '{"index.lifecycle.name": "nsm-short"}'
call PUT "/web-events-*/_settings?allow_no_indices=true&expand_wildcards=open" '{"index.lifecycle.name": "nsm-long"}'
echo "es-init: tài khoản grafana_ro, nsm_writer, nsm_rulegen, nsm_ctl và chính sách xoá chỉ mục cũ ($SHORT / $LONG) đã sẵn sàng"
