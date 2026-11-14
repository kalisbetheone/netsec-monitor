#!/bin/sh
# soc/kafka-init.sh — chạy trong container kafka-init (image apache/kafka) mỗi lần stack khởi động:
# tạo các topic còn thiếu và cấp quyền (ACL) cho TỪNG VAI TRÒ. Chạy lại nhiều lần không sao.
#
# Nguyên tắc quyền tối thiểu — mỗi dịch vụ có tài khoản Kafka riêng và chỉ làm được đúng việc của nó:
#   filebeat    chỉ GHI các topic nhật ký (web.logs, net.events, web.audit, gate1.logs, web.errors)
#   classifier  đọc nhật ký, ghi alerts            tier3  đọc web.logs, ghi alerts
#   responder   đọc alerts + nsm.control, là tài khoản DUY NHẤT ghi được enforce.blocklist
#   rulegen     đọc enforce.status,       là tài khoản DUY NHẤT ghi được enforce.rules
#   enforcer    đọc enforce.blocklist/enforce.rules, ghi enforce.status
#   logsink     đọc gate1.logs, web.errors, enforce.status (chỉ đọc)
#   ctl         chỉ ghi nsm.control (công cụ quản trị tools/nsmctl.sh)
# Nhờ vậy, lộ mật khẩu của filebeat/enforcer (nằm trên máy WEB, vùng DMZ) KHÔNG cho phép ra lệnh chặn IP
# hay đẩy luật. Tài khoản không có ACL thì bị từ chối (allow.everyone.if.no.acl.found=false).
BOOT="${BOOT:-kafka:9092}"
B=/opt/kafka/bin
CFG=/tmp/admin.properties
printf 'security.protocol=SASL_PLAINTEXT\nsasl.mechanism=PLAIN\nsasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="admin" password="%s";\n' \
  "$ADMIN_PASSWORD" > "$CFG"

TOPICS="web.logs net.events web.audit gate1.logs web.errors alerts enforce.blocklist enforce.rules enforce.status nsm.control"
have=$($B/kafka-topics.sh --bootstrap-server "$BOOT" --command-config "$CFG" --list) || { echo "không liệt kê được topic"; exit 1; }
for t in $TOPICS; do
  echo "$have" | grep -qx "$t" && continue
  $B/kafka-topics.sh --bootstrap-server "$BOOT" --command-config "$CFG" --create --if-not-exists \
    --topic "$t" --partitions 3 --replication-factor 1 --config retention.ms=604800000 || exit 1
done

# Quyền: liệt kê ACL hiện có MỘT lần rồi chỉ cấp phần còn thiếu. Trước đây cả khối bị bỏ qua khi ACL của 'ctl'
# đã có, nên thêm vai trò/topic ở bản sau sẽ KHÔNG được cấp trên máy đã cài (T7). Cách này vừa nhanh vừa đúng.
$B/kafka-acls.sh --bootstrap-server "$BOOT" --command-config "$CFG" --list 2>/dev/null \
  | sed -n -e 's/.*resourceType=\([A-Z_]*\), name=\([^,]*\),.*/R \1 \2/p' \
           -e 's/.*principal=\([^,]*\), host=[^,]*, operation=\([A-Z_]*\), permissionType=ALLOW.*/P \1 \2/p' \
  | awk '/^R/{t=$2; n=$3; next} {print t, n, $2, $3}' > /tmp/have.txt
has() { grep -qx "$1" /tmp/have.txt; }
added=0
acl() { $B/kafka-acls.sh --bootstrap-server "$BOOT" --command-config "$CFG" --add "$@" >/dev/null || { echo "cấp ACL thất bại: $*"; exit 1; }; added=$((added+1)); }
prod() {      # prod <vai trò> <topic>...  — quyền GHI
  p="$1"; shift; miss=""
  for t in "$@"; do has "TOPIC $t User:$p WRITE" || miss="$miss --topic $t"; done
  if [ -n "$miss" ]; then acl --allow-principal "User:$p" --producer $miss; fi
}
cons() {      # cons <vai trò> <nhóm> <topic>...  — quyền ĐỌC (topic + consumer group)
  p="$1"; g="$2"; shift 2; miss=""
  for t in "$@"; do has "TOPIC $t User:$p READ" || miss="$miss --topic $t"; done
  if [ -n "$miss" ] || ! has "GROUP $g User:$p READ"; then
    acl --allow-principal "User:$p" --consumer --group "$g" $(for t in "$@"; do printf ' --topic %s' "$t"; done)
  fi
}
prod filebeat   web.logs net.events web.audit gate1.logs web.errors
cons classifier classifier web.logs net.events web.audit
prod classifier alerts
cons tier3      tier3 web.logs gate1.logs        # gate1.logs: request bị Cổng 1 giới hạn tốc độ (429) — 15/11/2026
prod tier3      alerts
cons responder  responder alerts nsm.control
prod responder  enforce.blocklist
cons rulegen    rulegen-status enforce.status
cons rulegen    rulegen-ctl nsm.control          # lệnh gỡ luật (nsmctl rule-revoke) — 15/11/2026
prod rulegen    enforce.rules
cons enforcer   enforcer enforce.blocklist enforce.rules
prod enforcer   enforce.status
cons logsink    logsink gate1.logs web.errors enforce.status
prod ctl        nsm.control
echo "ACL: đã cấp thêm $added mục (0 = đã đủ từ trước)"

# Cấu hình topic (áp lại mỗi lần, không đổi thì Kafka bỏ qua):
#  - web.audit chứa THÂN request (có thể có mật khẩu) -> chỉ giữ 1 ngày thay vì 7 (C1)
#  - enforce.blocklist: một snapshot có thể lớn khi chặn hàng chục nghìn IP -> cho phép tới 8 MB (T5)
cfg() { $B/kafka-configs.sh --bootstrap-server "$BOOT" --command-config "$CFG" --alter --entity-type topics \
          --entity-name "$1" --add-config "$2" >/dev/null || { echo "đặt cấu hình topic $1 thất bại"; exit 1; }; }
cfg web.audit "retention.ms=${AUDIT_RETENTION_MS:-86400000}"
cfg enforce.blocklist "max.message.bytes=8388608"
echo "cấu hình topic: web.audit giữ ${AUDIT_RETENTION_MS:-86400000} ms, enforce.blocklist tối đa 8 MB/thông điệp"
