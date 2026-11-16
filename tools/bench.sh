#!/usr/bin/env bash
# tools/bench.sh — BENCHMARK hệ thống NSM trên stack đang chạy. Chạy trên HOST, từ thư mục nsm:
#   bash tools/bench.sh                  đủ 4 pha (~4–5 phút)
#   bash tools/bench.sh detect perf      chỉ chạy một số pha
#   bash tools/bench.sh -r 5 mttr        lặp mỗi kịch bản chặn IP 5 lần (1..8, mặc định 3)
# Các pha:
#   detect  chất lượng phát hiện: ~120 request có nhãn sẵn (sqli, xss, lfi, rce + lành tính thường + lành tính
#           "khó") -> tỉ lệ phát hiện / báo nhầm của Cổng 2 (CRS), của bộ phân loại và của cả hệ thống
#   mttr    thời gian từ request tấn công đầu tiên tới khi IP bị Cổng 1 chặn, và số request lọt trước đó
#           (kịch bản sqli, rce, flood, recon; mỗi lần một IP mới)
#   slow    tấn công rải rác 1 request / 16 s (ca B5): phải bị chặn nhờ cửa sổ dài; ~3–4 phút, chạy nền song song
#   perf    độ trễ & thông lượng qua hai cổng ở 1, 8, 32 kết nối + độ trễ pipeline + CPU/RAM từng container
# Kết quả: bench-results/<thời điểm>/report.md (kèm dữ liệu thô .json), nằm trong thư mục dự án.
# Biến tuỳ chọn: BENCH_PERF_S (giây mỗi mức tải, mặc định 15), BENCH_SCENARIOS (mặc định "sqli rce flood recon"),
#   BENCH_IMAGE (image Python dùng để chạy đo, mặc định nsm-classifier).
#   BENCH_MTTR_STAGGER_S=1   pha mttr: các lần chạy bắt đầu SO LE nhau từng ấy giây và chạy song song (nhiều IP bị khoá sát
#                            nhau, để đo việc nginx gom các lần nạp lại). Không đặt: chạy lần lượt như cũ.
#   BENCH_MTTR_INTERVAL=0.25 pha mttr: khoảng cách giữa hai request của mỗi IP (mặc định theo kịch bản: sqli/rce 0,5 giây).
# LƯU Ý: pha mttr/slow XOÁ blocklist hiện tại lúc bắt đầu (giống tools/reset.sh). Bench tự khôi phục cấu hình
#   responder khi kết thúc hoặc bị ngắt (Ctrl-C).
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
CP=(docker compose -f "$D/docker-compose.yml")
NET_EXT=nsm_external_net; NET_MON=nsm_monitor_net
PYIMG="${BENCH_IMAGE:-nsm-classifier}"
REPS="${BENCH_REPS:-3}"; PERF_S="${BENCH_PERF_S:-15}"
SCENARIOS="${BENCH_SCENARIOS:-sqli rce flood recon}"
EXEMPT_BENCH=10.10.10.192/27        # .192–.223: IP của pha detect/perf, được miễn trừ tạm thời
OVR="$D/.bench-responder.override.yml"

usage(){ sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
PH=""
while [ $# -gt 0 ]; do
  case "$1" in
    -r) REPS="${2:-}"; shift 2 || shift;;
    -h|--help) usage; exit 0;;
    all) PH="detect mttr slow perf"; shift;;
    detect|mttr|slow|perf) PH="$PH $1"; shift;;
    *) echo "!! tham số không hợp lệ: $1" >&2; usage; exit 2;;
  esac
done
[ -n "$PH" ] || PH="detect mttr slow perf"
has(){ case " $PH " in *" $1 "*) return 0;; esac; return 1; }
case "$REPS" in ''|*[!0-9]*) echo "!! -r cần một số nguyên 1..8" >&2; exit 2;; esac
{ [ "$REPS" -ge 1 ] && [ "$REPS" -le 8 ]; } || { echo "!! -r cần một số nguyên 1..8" >&2; exit 2; }
case "$PERF_S" in ''|*[!0-9]*|0) echo "!! BENCH_PERF_S cần một số nguyên dương" >&2; exit 2;; esac
NS=0
for s in $SCENARIOS; do
  case "$s" in sqli|rce|flood|recon) NS=$((NS+1));; *) echo "!! kịch bản không hợp lệ: $s" >&2; exit 2;; esac
done
[ "$NS" -le 4 ] || { echo "!! tối đa 4 kịch bản" >&2; exit 2; }

RUN="$(date +%Y%m%d-%H%M%S)"
OUT="$D/bench-results/$RUN"
T0=$(date +%s)
log(){ echo ">> [$(( $(date +%s) - T0 ))s] $*"; }

# chạy bench.py trong một container ở vùng ngoài với IP nguồn $1
py_ext(){ local ip="$1"; shift
  docker run --rm --name "bench_$ip" --network "$NET_EXT" --ip "$ip" -v "$D/tools:/tools:ro" \
    --entrypoint python "$PYIMG" -B /tools/bench.py --ip "$ip" --run "$RUN" "$@"; }
# chạy bench.py ở vùng giám sát (đọc Elasticsearch, đọc thư mục kết quả); stdin luôn được chuyển hướng
py_mon(){
  docker run --rm -i --network "$NET_MON" -e ES_URL=http://elasticsearch:9200 -e ES_USER=elastic \
    --env-file "$D/.env" -v "$D/tools:/tools:ro" \
    -v "$OUT:/out:ro" --entrypoint python "$PYIMG" -B /tools/bench.py --run "$RUN" "$@"; }   # ES_PASSWORD lấy từ .env
stats(){ local ids; ids=$("${CP[@]}" ps -q 2>/dev/null | tr -d '\r')
  [ -n "$ids" ] && docker stats --no-stream --format '{{json .}}' $ids > "$OUT/$1" 2>/dev/null; }

OVR_ON=""; BG=""
cleanup(){
  trap - EXIT INT TERM
  [ -n "$BG" ] && kill "$BG" 2>/dev/null
  docker ps -aqf "name=bench_" | xargs -r docker rm -f >/dev/null 2>&1
  if [ -n "$OVR_ON" ]; then
    echo ">> khôi phục cấu hình responder gốc ..."
    rm -f "$OVR"
    "${CP[@]}" up -d responder >/dev/null 2>&1 || echo "!! chưa khôi phục được responder — hãy chạy: docker compose up -d responder"
  fi
  rm -f "$OVR"
}
trap cleanup EXIT
trap 'echo; echo "!! bị ngắt — dọn dẹp ..."; exit 130' INT TERM

# ---------------------------------------------------------------- kiểm tra trước
log "kiểm tra stack (pha:$PH) ..."
RUNNING=$("${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r')
MISS=""
for s in nginx apache classifier tier3 responder enforcer filebeat kafka elasticsearch; do
  printf '%s\n' "$RUNNING" | grep -qx "$s" || MISS="$MISS $s"
done
[ -z "$MISS" ] || { echo "!! các dịch vụ chưa chạy:$MISS — chạy 'docker compose up -d' rồi thử lại." >&2; exit 1; }
docker image inspect "$PYIMG" >/dev/null 2>&1 \
  || { echo "!! không thấy image $PYIMG — dựng bằng 'docker compose up -d --build'." >&2; exit 1; }
docker ps -aqf "name=bench_" | xargs -r docker rm -f >/dev/null 2>&1
mkdir -p "$OUT" || exit 1

{
  echo "lần chạy: $RUN"
  echo "máy: $(uname -srm 2>/dev/null)"
  docker info --format 'docker: {{.ServerVersion}}, {{.NCPU}} CPU, RAM {{.MemTotal}} byte' 2>/dev/null
  echo "pha:$PH | lặp: $REPS | kịch bản: $SCENARIOS | mỗi mức tải: ${PERF_S}s"
  for s in classifier tier3 responder nginx; do
    "${CP[@]}" exec -T "$s" printenv 2>/dev/null | tr -d '\r' \
      | grep -E '^(TIER2_|TIER3_|THRESHOLD=|WINDOW_S=|LONG_|MIN_CONFIDENCE=|MAX_AGE_S=|BASE_TTL_S=|DEDUP_S=|RELOAD_MIN_INTERVAL_S=)' \
      | sort | sed "s/^/$s: /"
  done
} > "$OUT/env.txt"
stats stats-idle.jsonl

# ---------------------------------------------------------------- miễn trừ tạm dải đo
apply_override(){   # $1 = reset (xoá luôn trạng thái/blocklist) | keep
  local cur
  cur=$("${CP[@]}" exec -T responder printenv EXEMPT_CIDRS 2>/dev/null | tr -d '\r')
  [ -n "$cur" ] || cur="127.0.0.0/8,10.10.30.0/24,10.10.10.10/32,10.10.10.20/32,172.16.0.0/12"
  case ",$cur," in *",$EXEMPT_BENCH,"*) ;; *) cur="$cur,$EXEMPT_BENCH";; esac
  printf 'services:\n  responder:\n    environment:\n      EXEMPT_CIDRS: "%s"\n' "$cur" > "$OVR"
  OVR_ON=1
  "${CP[@]}" stop -t 5 responder >/dev/null 2>&1
  if [ "$1" = reset ]; then
    "${CP[@]}" run --rm --no-deps --entrypoint sh responder -c 'rm -f /state/responder.json' >/dev/null 2>&1 \
      || echo "   (không xoá được trạng thái responder — kết quả mttr có thể bị ảnh hưởng)"
  fi
  if ! "${CP[@]}" -f "$OVR" up -d responder >/dev/null 2>&1; then
    echo "!! không khởi động được responder với cấu hình đo." >&2; exit 1
  fi
  for _ in $(seq 1 30); do
    "${CP[@]}" logs --tail 30 responder 2>/dev/null | grep -q "started" && break
    sleep 1
  done
  sleep 7      # blocklist mới đi qua enforcer -> nginx nạp lại (RELOAD_MIN_INTERVAL_S)
}
if has mttr || has slow; then
  log "chuẩn bị: miễn trừ tạm dải $EXEMPT_BENCH + xoá blocklist hiện tại ..."
  apply_override reset
else
  log "chuẩn bị: miễn trừ tạm dải $EXEMPT_BENCH ..."
  apply_override keep
fi
py_ext 10.10.10.223 check >/dev/null \
  || { echo "!! request lành tính tới 10.10.10.10/login.php không qua được hai cổng — dừng." >&2; exit 1; }

# ---------------------------------------------------------------- slow (nền)
if has slow; then
  log "pha slow chạy nền (~3–4 phút): 1 SQLi / 16 s từ 10.10.10.230 ..."
  py_ext 10.10.10.230 mttr --scenario slow --rep 1 > "$OUT/slow.jsonl" &
  BG=$!
fi

# ---------------------------------------------------------------- detect
if has detect; then
  log "pha detect: gửi bộ mẫu có nhãn (tấn công từ .192, lành tính từ .193) ..."
  py_ext 10.10.10.192 detect --set attack > "$OUT/detect-attack.json" & p1=$!
  py_ext 10.10.10.193 detect --set benign > "$OUT/detect-benign.json" & p2=$!
  wait "$p1" "$p2"
  log "chờ các sự kiện vào Elasticsearch ..."
  cat "$OUT/detect-attack.json" "$OUT/detect-benign.json" | py_mon collect-detect > "$OUT/detect-es.json"
fi

# ---------------------------------------------------------------- mttr
if has mttr; then
  log "pha mttr: [$SCENARIOS] × $REPS lần, mỗi lần một IP mới ..."
  : > "$OUT/mttr.jsonl"
  i=0; mp=""
  MIV=(); [ -n "${BENCH_MTTR_INTERVAL:-}" ] && MIV=(--interval "$BENCH_MTTR_INTERVAL")
  for s in $SCENARIOS; do
    for r in $(seq 1 "$REPS"); do
      if [ -n "${BENCH_MTTR_STAGGER_S:-}" ]; then
        py_ext "10.10.10.$((160 + i))" mttr --scenario "$s" --rep "$r" "${MIV[@]}" > "$OUT/mttr-$(printf %02d "$i").part" &
        mp="$mp $!"; i=$((i + 1)); sleep "$BENCH_MTTR_STAGGER_S"
      else
        py_ext "10.10.10.$((160 + i))" mttr --scenario "$s" --rep "$r" "${MIV[@]}" >> "$OUT/mttr.jsonl"
        i=$((i + 1)); sleep 2
      fi
    done
  done
  if [ -n "$mp" ]; then wait $mp; cat "$OUT"/mttr-*.part >> "$OUT/mttr.jsonl"; rm -f "$OUT"/mttr-*.part; fi
fi

# ---------------------------------------------------------------- perf
if has perf; then
  log "pha perf: 4 mức tải × ${PERF_S}s ..."
  : > "$OUT/perf.jsonl"
  py_ext 10.10.10.194 perf --label "lành tính, 1 kết nối" --conc 1 --duration "$PERF_S" >> "$OUT/perf.jsonl"
  py_ext 10.10.10.195 perf --label "lành tính, 8 kết nối" --conc 8 --duration "$PERF_S" >> "$OUT/perf.jsonl"
  py_ext 10.10.10.194 perf --label "tấn công SQLi (Cổng 2 chặn), 1 kết nối" --kind attack --conc 1 \
    --duration "$PERF_S" >> "$OUT/perf.jsonl"
  pids=""
  for k in 196 197 198 199; do      # nginx giới hạn 10 kết nối / IP -> 32 kết nối = 4 IP × 8
    py_ext "10.10.10.$k" perf --label "lành tính, 32 kết nối (4 IP × 8)" --conc 8 --duration "$PERF_S" \
      > "$OUT/perf-$k.part" &
    pids="$pids $!"
  done
  ( sleep $((PERF_S / 2)); stats stats-load.jsonl ) &
  pids="$pids $!"
  wait $pids
  cat "$OUT"/perf-*.part >> "$OUT/perf.jsonl"; rm -f "$OUT"/perf-*.part
  log "đo độ trễ pipeline (chờ classifier ghi hết sự kiện vào Elasticsearch) ..."
  py_mon drain < "$OUT/perf.jsonl" > "$OUT/drain.json"
fi

# ---------------------------------------------------------------- tổng hợp
if [ -n "$BG" ]; then
  log "chờ pha slow kết thúc ..."
  wait "$BG"; BG=""
fi
if has mttr || has slow; then
  log "lấy nhật ký quyết định của responder ..."
  cat "$OUT/mttr.jsonl" "$OUT/slow.jsonl" 2>/dev/null | py_mon collect-decisions > "$OUT/decisions.json"
fi
log "lập báo cáo ..."
if ! py_mon report < /dev/null > "$OUT/report.md"; then
  echo "!! lỗi khi lập báo cáo — dữ liệu thô vẫn nằm trong bench-results/$RUN/" >&2; exit 1
fi

echo
sed -n '/^## 1\./,/^## 2\./p' "$OUT/report.md" | sed '$d'
echo ">> báo cáo đầy đủ: bench-results/$RUN/report.md (trong thư mục dự án)"
echo ">> sau bench: các IP đo có thể còn bị chặn tới hết TTL, và payload của bench có thể được rulegen"
echo "   gom thành luật. Trước khi trình diễn hãy chạy:  bash tools/reset-all.sh"
