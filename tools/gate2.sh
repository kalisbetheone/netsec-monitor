#!/usr/bin/env bash
# tools/gate2.sh — bật/tắt chế độ CHỈ GHI NHẬN cho TỪNG LỚP luật của Cổng 2 (ModSecurity), không đụng lớp khác.
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy:
#   bash tools/gate2.sh status               xem lớp nào đang chặn / chỉ ghi nhận
#   bash tools/gate2.sh crs detect           OWASP CRS chỉ ghi nhận (vẫn ghi nhật ký, không trả 403)
#   bash tools/gate2.sh tier1 detect         luật tầng 1 đồng bộ của NSM (id 1000200–1000399) chỉ ghi nhận
#   bash tools/gate2.sh crs block | tier1 block     chặn lại như bình thường
#   bash tools/gate2.sh all block            mọi lớp chặn lại (xoá tệp cấu hình tạm)
# Dùng khi CHẠY THỬ một lớp trên lưu lượng thật trước khi cho nó chặn, và để đo riêng từng lớp (kịch bản khai thác thật).
# Luật tự sinh có chế độ chạy thử riêng (rulegen RULE_APPLY=shadow). Cả cổng chỉ ghi nhận: SecRuleEngine DetectionOnly.
# Cách làm: ghi /etc/apache2/conf-enabled/zzz-nsm-layers.conf trong container apache (nạp SAU mọi luật) rồi nạp lại mềm.
# Tệp này KHÔNG giữ qua lần tạo lại container: tạo lại apache là mọi lớp trở về chặn.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
export MSYS_NO_PATHCONV=1
CP=(docker compose -f "$D/docker-compose.yml")
F=/etc/apache2/conf-enabled/zzz-nsm-layers.conf
AP(){ "${CP[@]}" exec -T apache sh -c "$1"; }
layer="${1:-status}"; mode="${2:-}"
cur(){ AP "cat $F 2>/dev/null" | tr -d '\r'; }
show(){
  local c; c="$(cur)"
  for l in crs tier1; do
    if printf '%s\n' "$c" | grep -q "^# layer:$l detect"; then echo "$l: CHỈ GHI NHẬN"; else echo "$l: chặn"; fi
  done
}
[ "$layer" = status ] && { show; exit 0; }
case "$layer:$mode" in crs:detect|crs:block|tier1:detect|tier1:block|all:block) ;; *)
  sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;; esac
c="$(cur)"
want_crs=$(printf '%s\n' "$c" | grep -q "^# layer:crs detect" && echo detect || echo block)
want_t1=$(printf '%s\n' "$c" | grep -q "^# layer:tier1 detect" && echo detect || echo block)
case "$layer" in crs) want_crs=$mode;; tier1) want_t1=$mode;; all) want_crs=block; want_t1=block;; esac
if [ "$want_crs" = block ] && [ "$want_t1" = block ]; then
  AP "rm -f $F && apache2ctl -t >/dev/null 2>&1 && apache2ctl -k graceful" >/dev/null 2>&1
  show; exit 0
fi
{
  echo "# TẠM THỜI — tools/gate2.sh (mất khi tạo lại container apache)"
  echo "<IfModule security2_module>"
  if [ "$want_crs" = detect ]; then
    echo "# layer:crs detect"
    # 949110 / 949111: hai luật ra quyết định chặn theo điểm bất thường của CRS 4 -> đổi thành 'pass' (vẫn ghi nhật ký)
    echo '    SecRuleUpdateActionById 949110 "pass"'
    echo '    SecRuleUpdateActionById 949111 "pass"'
  fi
  if [ "$want_t1" = detect ]; then
    echo "# layer:tier1 detect"
    for id in $(AP "grep -o 'id:10002[0-9]*\|id:10003[0-9]*' /etc/modsecurity/nsm-sync/tier1.conf" | tr -d '\r' | cut -d: -f2 | sort -u); do
      echo "    SecRuleUpdateActionById $id \"pass\""
    done
  fi
  echo "</IfModule>"
} | "${CP[@]}" exec -T apache sh -c "cat > $F"
if AP "apache2ctl -t >/dev/null 2>&1"; then
  AP "apache2ctl -k graceful" >/dev/null 2>&1; sleep 2; show
else
  echo "!! cấu hình tạm bị Apache từ chối — gỡ bỏ, mọi lớp vẫn chặn" >&2
  AP "apache2ctl -t 2>&1 | tail -3; rm -f $F"; exit 1
fi
