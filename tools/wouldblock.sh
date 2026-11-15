#!/usr/bin/env bash
# tools/wouldblock.sh — đếm quyết định chặn / "sẽ chặn" (block, would_block) của responder theo từng IP trong một khoảng
# thời gian, đối chiếu với danh sách phân vai. Lớp bọc của tools/wouldblock.py. CHỈ ĐỌC Elasticsearch, không cần khoá stack.
# Chạy trên HOST, từ thư mục nsm:
#   bash tools/wouldblock.sh <epoch bắt đầu> [epoch kết thúc | 0] [tệp nguon.json] [thư mục ra]
# Ví dụ:
#   bash tools/wouldblock.sh "$(date -d '1 hour ago' +%s)"
#   bash tools/wouldblock.sh 1794700000 0 scenarios/ngay-nen/nguon.json eval/results/ngaynen-XXXX
# nguon.json: {"hop_le": [...], "tan_cong": [...], "thuong_tru": [...]} (danh sách IP). Không có tệp: mọi IP là "không rõ".
# Kết quả: bảng Markdown ra màn hình; <thư mục ra>/wouldblock.json nếu có thư mục ra.
# Mã thoát: 0 = không quyết định nào vào IP hợp lệ; 1 = có; 2 = lỗi.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án
[ $# -ge 1 ] || { sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
T0="$1"; T1="${2:-0}"; NGUON="${3:-}"; OUTD="${4:-}"
case "$T0$T1" in *[!0-9.]*) echo "!! epoch phải là số" >&2; exit 2;; esac
PYIMG="${BENCH_IMAGE:-nsm-classifier}"; NET_MON=nsm_monitor_net
abspath(){ case "$1" in /*|[A-Za-z]:*) printf '%s' "$1";; *) printf '%s' "$D/$1";; esac; }
ARGS=(--t0 "$T0" --t1 "$T1"); MNT=(-v "$D/tools:/tools:ro")
if [ -n "$NGUON" ]; then
  NG="$(abspath "$NGUON")"; [ -f "$NG" ] || { echo "!! không thấy $NG" >&2; exit 2; }
  MNT+=(-v "$(dirname "$NG"):/nguon:ro"); ARGS+=(--nguon "/nguon/$(basename "$NG")")
fi
if [ -n "$OUTD" ]; then
  OD="$(abspath "$OUTD")"; mkdir -p "$OD" || exit 2
  MNT+=(-v "$OD:/out"); ARGS+=(--out /out)
fi
USEROPT=(); [ "$(uname -s)" = Linux ] && USEROPT=(--user "$(id -u):$(id -g)")
MSYS_NO_PATHCONV=1 docker run --rm -i ${USEROPT[@]+"${USEROPT[@]}"} --network "$NET_MON" -e ES_URL=http://elasticsearch:9200 \
  -e ES_USER=elastic -e NSM_UTC_OFFSET="$(date +%z)" --env-file "$D/.env" "${MNT[@]}" --entrypoint python "$PYIMG" -B /tools/wouldblock.py "${ARGS[@]}"
