#!/usr/bin/env bash
# tools/reloadcfg.sh — ĐO MỘT CẤU HÌNH NẠP LẠI DANH SÁCH CHẶN CỦA NGINX (Cổng 1) trên stack đang chạy. Chạy trên HOST, từ nsm:
#   bash tools/reloadcfg.sh <nhãn> <khoảng nạp lại, giây> <chờ đúng 0|1> [sole]
#   bash tools/reloadcfg.sh restore          trả nginx về mặc định trong docker-compose.yml
# Ví dụ:  bash tools/reloadcfg.sh N2 2 0
# Mỗi lượt: tạo lại nginx với RELOAD_MIN_INTERVAL_S / RELOAD_EXACT_WAIT -> (a) bench mttr lần lượt (sqli, rce × 5) ->
# (b) hai lượt mttr SO LE (16 IP cách nhau 1 giây, 4 request/giây) -> (c) kịch bản 39 kèm lấy mẫu container nginx và đếm số
# lần nạp lại -> (d) kịch bản 45. Tham số `sole`: chỉ chạy (b). Kết quả: eval/results/reload-<nhãn>.txt, đọc bằng
# tools/reloadcfg.py. Tiêu chí: eval/PROTOCOL.md (mục 16/11/2026 11:55). Chỉ đo hệ thống của dự án.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
CP=(docker compose -f "$D/docker-compose.yml")
cfg(){ "${CP[@]}" exec -T nginx printenv | grep -E '^(RELOAD_MIN_INTERVAL_S|RELOAD_EXACT_WAIT)=' | tr -d '\r' | sort | tr '\n' ' ' | sed 's/ $//'; }
up_nginx(){
  "${CP[@]}" up -d nginx >/dev/null 2>&1
  for _ in $(seq 1 40); do
    "${CP[@]}" exec -T nginx wget -q -T 3 -O /dev/null http://127.0.0.1/login.php 2>/dev/null && break
    sleep 2
  done
  for _ in $(seq 1 40); do      # suricata khởi động lại theo nginx (dùng chung netns)
    "${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r' | grep -qx suricata && break
    sleep 2
  done
  sleep 15
}
if [ "${1:-}" = "restore" ]; then
  unset RELOAD_MIN_INTERVAL_S RELOAD_EXACT_WAIT
  up_nginx; echo "nginx: $(cfg)"; exit 0
fi
[ $# -ge 3 ] || { sed -n 2,5p "${BASH_SOURCE[0]}"; exit 2; }
tag="$1"; iv="$2"; ex="$3"; only="${4:-}"
export RELOAD_MIN_INTERVAL_S="$iv" RELOAD_EXACT_WAIT="$ex"
cd "$D" || exit 1
want="RELOAD_EXACT_WAIT=$ex RELOAD_MIN_INTERVAL_S=$iv"
up_nginx
got="$(cfg)"; [ "$got" = "$want" ] || { echo "!! nginx đang chạy với [$got], không phải [$want]" >&2; exit 1; }
R="eval/results"; out="$R/reload-$tag.txt"
last_bench(){ ls -1d bench-results/*/ 2>/dev/null | tail -1; }

"${CP[@]}" stop -t 5 rulegen >/dev/null 2>&1       # payload lặp của bench không được rulegen gom thành luật
b1=""
if [ "$only" != "sole" ]; then
  BENCH_SCENARIOS="sqli rce" bash tools/bench.sh -r 5 mttr > "$R/reload-$tag-lanluot.log" 2>&1; echo "mttr lần lượt: mã thoát $?"
  b1="$(last_bench)"
fi
BENCH_SCENARIOS="sqli rce" BENCH_MTTR_STAGGER_S=1 BENCH_MTTR_INTERVAL=0.25 bash tools/bench.sh -r 8 mttr > "$R/reload-$tag-sole1.log" 2>&1
echo "mttr so le 1: mã thoát $?"; b2="$(last_bench)"
BENCH_SCENARIOS="sqli rce" BENCH_MTTR_STAGGER_S=1 BENCH_MTTR_INTERVAL=0.25 bash tools/bench.sh -r 8 mttr > "$R/reload-$tag-sole2.log" 2>&1
echo "mttr so le 2: mã thoát $?"; b3="$(last_bench)"
bash tools/reset.sh >/dev/null 2>&1
"${CP[@]}" run --rm --no-deps --entrypoint sh rulegen -c 'date +%s > /state/not_before' >/dev/null 2>&1
"${CP[@]}" up -d rulegen >/dev/null 2>&1

s39=""; s45=""; reloads=""; bad=""
if [ "$only" != "sole" ]; then
  smp="$R/reload-$tag-nginx.tsv"; : > "$smp"
  ( while :; do
      printf '%s\t%s\n' "$(date +%s)" "$(docker stats --no-stream --format '{{.PIDs}}|{{.MemUsage}}|{{.CPUPerc}}' nsm-nginx-1 2>/dev/null)" >> "$smp"
      sleep 1
    done ) & SP=$!
  t0=$(date +%s)
  SC_OUT_NAME="reload${tag}" bash tools/scenario.sh 39-flood-phan-tan-300-ip > "$R/reload-$tag-kb39.log" 2>&1; echo "kịch bản 39: mã thoát $?"
  kill "$SP" 2>/dev/null
  el=$(( $(date +%s) - t0 ))
  reloads=$("${CP[@]}" logs --since "${el}s" nginx 2>&1 | grep -c "blocklist reloaded")
  bad=$("${CP[@]}" logs --since "${el}s" nginx 2>&1 | grep -c -E '\[emerg\]|\[alert\]|nginx -t failed')
  s39="$(ls -1d $R/reload${tag}-2*/ 2>/dev/null | tail -1)"
  SC_OUT_NAME="reload${tag}b" bash tools/scenario.sh 45-nhoi-tai-khoan-cong-dat-cho > "$R/reload-$tag-kb45.log" 2>&1; echo "kịch bản 45: mã thoát $?"
  s45="$(ls -1d $R/reload${tag}b-2*/ 2>/dev/null | tail -1)"
fi
got="$(cfg)"; [ "$got" = "$want" ] || echo "!! SAU LƯỢT ĐO nginx đang chạy với [$got] — kết quả lượt này KHÔNG dùng được"
printf 'tag=%s\ninterval=%s\nexact=%s\nlanluot=%s\nsole1=%s\nsole2=%s\nkb39=%s\nkb45=%s\nreloads39=%s\nnginx_bad39=%s\nnginx_sau=%s\n' \
  "$tag" "$iv" "$ex" "$b1" "$b2" "$b3" "$s39" "$s45" "$reloads" "$bad" "$got" | tee "$out"
