#!/usr/bin/env bash
# tools/init-env.sh — tạo tệp .env chứa BÍ MẬT của hệ thống (mật khẩu Elasticsearch, Kafka, Grafana, CSDL)
# ngay trong thư mục dự án. Chạy MỘT LẦN trước `docker compose up` đầu tiên:
#     bash tools/init-env.sh            # chế độ an toàn (mặc định): DVWA đòi đăng nhập, mức impossible
#     bash tools/init-env.sh --lab      # chế độ LAB: DVWA không cần đăng nhập, mức low (tấn công chạy thật)
#     bash tools/init-env.sh --no-lab   # tắt chế độ lab đã bật trước đó
# - Mỗi mật khẩu là chuỗi ngẫu nhiên; không có mật khẩu mặc định nào nằm trong mã nguồn.
# - Chạy lại bao nhiêu lần cũng được: giá trị ĐÃ CÓ được giữ nguyên, chỉ bổ sung biến còn thiếu.
# - Bản 3 máy ảo: tạo .env trên máy SOC rồi chép NGUYÊN tệp sang máy WEB (hai máy phải dùng chung mật khẩu
#   Kafka), sau đó thêm các biến riêng của từng máy theo .env.example.
# Không đưa .env lên kho mã / không gửi kèm khi chia sẻ dự án.
set -u
NSM_NO_ENV_CHECK=1
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
F="$D/.env"
KEYS="ES_PASSWORD ES_WRITER_PASSWORD ES_RULEGEN_PASSWORD ES_CTL_PASSWORD GRAFANA_ES_PASSWORD GRAFANA_ADMIN_PASSWORD DVWA_DB_PASS
KAFKA_ADMIN_PASSWORD KAFKA_CLASSIFIER_PASSWORD KAFKA_TIER3_PASSWORD KAFKA_RESPONDER_PASSWORD
KAFKA_RULEGEN_PASSWORD KAFKA_LOGSINK_PASSWORD KAFKA_CTL_PASSWORD KAFKA_FILEBEAT_PASSWORD KAFKA_ENFORCER_PASSWORD"

rand(){ head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
[ "$(rand | wc -c)" -eq 36 ] || { echo "!! không sinh được số ngẫu nhiên (/dev/urandom)" >&2; exit 1; }

new=0
if [ ! -f "$F" ]; then
  new=1
  printf '%s\n' "# Bí mật của hệ thống NSM — do tools/init-env.sh sinh. KHÔNG chia sẻ, KHÔNG đưa lên kho mã." \
                "# Đổi một mật khẩu: sửa ở đây rồi tạo lại stack (docker compose down -v && docker compose up -d)." > "$F"
fi
chmod 600 "$F" 2>/dev/null || true
[ -z "$(tail -c 1 "$F")" ] || echo >> "$F"       # bảo đảm tệp kết thúc bằng xuống dòng trước khi nối thêm

added=""
for k in $KEYS; do
  grep -qE "^$k=[[:space:]]*[^#[:space:]]" "$F" && continue     # đã có giá trị -> giữ nguyên
  if grep -qE "^$k=" "$F"; then                  # có dòng nhưng rỗng (hoặc chỉ có chú thích) -> bỏ dòng đó
    grep -vE "^$k=" "$F" > "$F.tmp" && cat "$F.tmp" > "$F"; rm -f "$F.tmp"
  fi
  printf '%s=%s\n' "$k" "$(rand)" >> "$F"
  added="$added $k"
done

# Chế độ LAB (không phải bí mật) — CHỈ bật khi được yêu cầu rõ (--lab). Khi bật, DVWA không đòi đăng nhập và ở mức
# bảo mật thấp: payload thực thi lệnh THẬT trong container apache (mạng app_net của bản một máy không ra Internet).
LAB=0
for a in "$@"; do
  case "$a" in
    --lab) LAB=1 ;;
    --no-lab) LAB=-1 ;;
    *) echo "!! tham số không hiểu: $a (dùng --lab hoặc --no-lab)" >&2; exit 2 ;;
  esac
done
setkv(){ grep -vE "^$1=" "$F" > "$F.tmp"; cat "$F.tmp" > "$F"; rm -f "$F.tmp"; [ -n "$2" ] && printf '%s=%s
' "$1" "$2" >> "$F"; return 0; }
if [ "$LAB" = 1 ]; then
  setkv DVWA_DISABLE_AUTH true; setkv DVWA_SECURITY_LEVEL low; added="$added (bật chế độ lab)"
elif [ "$LAB" = -1 ]; then
  setkv DVWA_DISABLE_AUTH ""; setkv DVWA_SECURITY_LEVEL ""; added="$added (tắt chế độ lab)"
fi
if grep -qE '^DVWA_DISABLE_AUTH=true' "$F"; then
  echo ">> CHẾ ĐỘ LAB đang BẬT: DVWA không đòi đăng nhập, mức bảo mật thấp — chỉ dùng trong lab cô lập (tắt: --no-lab)"
else
  echo ">> chế độ an toàn: DVWA đòi đăng nhập, mức impossible (bật lab cho kịch bản kiểm thử: --lab)"
fi

if [ -n "$added" ]; then
  [ "$new" = 1 ] && echo ">> đã tạo $F" || echo ">> đã bổ sung vào $F:$added"
else
  echo ">> $F đã đủ biến, không thay đổi gì."
fi
echo ">> mật khẩu đăng nhập Grafana (tài khoản admin): xem dòng GRAFANA_ADMIN_PASSWORD trong .env"
echo "     grep GRAFANA_ADMIN_PASSWORD .env"
echo ">> tiếp theo:  docker compose up -d --build"
