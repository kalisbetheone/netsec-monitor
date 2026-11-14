#!/usr/bin/env bash
# tools/scenario.sh — CHẠY KHUNG KỊCH BẢN (scenarios/*.toml): vừa kiểm thử (đạt / không đạt so với kỳ vọng),
# vừa đo (benchmark), vừa lưu lại mọi request đã gửi kèm nhãn. Chạy trên HOST, từ thư mục nsm, khi stack đang chạy:
#   bash tools/scenario.sh                        chạy mọi kịch bản
#   bash tools/scenario.sh c4-do-mat-khau e4-tai-pham   chỉ chạy các kịch bản có tên này
#   bash tools/scenario.sh --list                 liệt kê kịch bản
# Mỗi kịch bản: áp cấu hình tạm (nếu có) -> miễn trừ tạm (nếu có) -> chạy các tác nhân (mỗi IP một container,
# tối đa SC_PARALLEL container cùng lúc) và các sự cố (dừng/bật dịch vụ) theo lịch -> chờ -> lấy dữ liệu của hệ
# thống -> chấm. Cấu hình tạm, miễn trừ và dịch vụ bị dừng được khôi phục khi xong hoặc khi bấm Ctrl-C.
# Kết quả: eval/results/scenarios-<thời điểm>/report.md (+ dữ liệu thô).
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
CP=(docker compose -f "$D/docker-compose.yml")
PYIMG="${BENCH_IMAGE:-nsm-classifier}"; NET_EXT=nsm_external_net; NET_MON=nsm_monitor_net
MAXPAR="${SC_PARALLEL:-25}"
SDIR="$D/scenarios"
OVR="$D/.scenario.override.yml"

if [ "${1:-}" = "--list" ]; then
  for f in "$SDIR"/*.toml; do printf '%-28s %s\n' "$(basename "$f" .toml)" "$(grep -m1 '^title' "$f" | cut -d'"' -f2)"; done
  exit 0
fi
SEL=("$@")
FILES=()
for f in "$SDIR"/*.toml; do
  n=$(basename "$f" .toml)
  if [ ${#SEL[@]} -eq 0 ]; then FILES+=("$f"); else for s in "${SEL[@]}"; do [ "$s" = "$n" ] && FILES+=("$f"); done; fi
done
[ ${#FILES[@]} -gt 0 ] || { echo "!! không có kịch bản nào khớp — xem: bash tools/scenario.sh --list" >&2; exit 2; }

# ---------------------------------------------------------------- kiểm tra trước
RUNNING=$("${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r')
for s in nginx apache classifier tier3 responder enforcer filebeat kafka elasticsearch logsink; do
  printf '%s\n' "$RUNNING" | grep -qx "$s" || { echo "!! dịch vụ $s chưa chạy — chạy 'docker compose up -d' trước." >&2; exit 1; }
done
SUB=$(docker network inspect "$NET_EXT" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
[ "$SUB" = "10.10.0.0/20" ] || { echo "!! mạng $NET_EXT đang là '$SUB', cần 10.10.0.0/20 — chạy: docker compose down && docker compose up -d" >&2; exit 1; }
docker image inspect "$PYIMG" >/dev/null 2>&1 || { echo "!! không thấy image $PYIMG" >&2; exit 1; }
# các kịch bản cần DVWA ở chế độ lab (tấn công chạm tới mã dễ tổn thương thật)
grep -qE '^DVWA_DISABLE_AUTH=true' "$D/.env" || { echo "!! DVWA chưa ở chế độ lab — chạy: bash tools/init-env.sh --lab && docker compose up -d apache" >&2; exit 1; }
# luật tự sinh đang ban hành làm sai kết quả (lượt chạy thử 12/11 bị nhiễm luật 9900000): báo, và xoá nếu được yêu cầu
NACT=$("${CP[@]}" exec -T apache sh -c "grep -c '^SecRule' /etc/modsecurity/autogen/active.conf 2>/dev/null" 2>/dev/null | tr -dc 0-9)
if [ "${NACT:-0}" -gt 0 ]; then
  if [ "${SC_CLEAR_RULES:-0}" = 1 ]; then
    "${CP[@]}" exec -T enforcer sh -c ': > /rules/published/autogen.conf' && echo ">> đã gỡ $NACT luật tự sinh (SC_CLEAR_RULES=1); rulegen ban hành lại khi chạy tiếp" && sleep 10
  else
    echo "!! đang có $NACT luật tự sinh được ban hành — kết quả sẽ phản ánh cả các luật này. Gỡ trước khi chạy: SC_CLEAR_RULES=1 bash tools/scenario.sh ..." >&2
  fi
fi

RUN="$(date +%Y%m%d-%H%M%S)"
OUT="$D/eval/results/scenarios-$RUN"
mkdir -p "$OUT" || exit 1
USEROPT=(); [ "$(uname -s)" = Linux ] && USEROPT=(--user "$(id -u):$(id -g)")
MNT=(-v "$D/tools:/tools:ro" -v "$SDIR:/scenarios:ro" -v "$D/eval/data/openappsec:/eval/data/openappsec:ro"
     -v "$D/eval/data/normalized:/eval/data/normalized:ro")
py(){ docker run --rm -i "${USEROPT[@]}" "${MNT[@]}" --entrypoint python "$PYIMG" -B /tools/scenario.py --run "$RUN" "$@"; }
pymon(){ docker run --rm -i --network "$NET_MON" -e ES_URL=http://elasticsearch:9200 -e ES_USER=elastic \
  --env-file "$D/.env" "${MNT[@]}" --entrypoint python "$PYIMG" -B /tools/scenario.py --run "$RUN" "$@"; }

OVR_SVCS=""; EXEMPTS=(); STOPPED=""; BGPIDS=""; MODSEC_SET=0; G2SET=0
modsec(){ "${CP[@]}" exec -T apache sh -c "sed -i 's/^SecRuleEngine .*/SecRuleEngine $1/' /etc/modsecurity/modsecurity.conf && apache2ctl -k graceful" >/dev/null 2>&1; }
# xoá MỌI luật tự sinh (trạng thái rulegen + chỉ mục rule-status + tệp luật đã phát) — trước và sau kịch bản có rulegen,
# để luật của kịch bản này không làm sai kết quả của kịch bản khác. Để rulegen ở trạng thái DỪNG.
clear_rules(){
  "${CP[@]}" stop -t 5 rulegen >/dev/null 2>&1
  "${CP[@]}" run --rm --no-deps --entrypoint sh rulegen -c 'rm -f /state/rules.json' >/dev/null 2>&1
  ES -X DELETE "localhost:9200/rule-status?ignore_unavailable=true" >/dev/null 2>&1
  "${CP[@]}" exec -T enforcer sh -c ': > /rules/published/autogen.conf' >/dev/null 2>&1
}
restore(){
  [ "$MODSEC_SET" = 1 ] && { modsec On; MODSEC_SET=0; }
  [ "$G2SET" = 1 ] && { bash "$D/tools/gate2.sh" all block >/dev/null 2>&1; G2SET=0; }
  docker ps -aqf "name=sc_" | xargs -r docker rm -f >/dev/null 2>&1
  for c in "${EXEMPTS[@]}"; do bash "$D/tools/nsmctl.sh" exempt-del "$c" >/dev/null 2>&1; done
  EXEMPTS=()
  for s in $STOPPED; do "${CP[@]}" start "$s" >/dev/null 2>&1; done
  STOPPED=""
  if [ -n "$OVR_SVCS" ]; then rm -f "$OVR"; "${CP[@]}" up -d $OVR_SVCS >/dev/null 2>&1; OVR_SVCS=""; fi
  rm -f "$OVR"
}
cleanup(){ trap - EXIT INT TERM; [ -n "$BGPIDS" ] && kill $BGPIDS 2>/dev/null; restore; }
trap cleanup EXIT
trap 'echo; echo "!! bị ngắt — khôi phục ..."; exit 130' INT TERM

slot=0
: > "$OUT/results.jsonl"
for f in "${FILES[@]}"; do
  base=$(basename "$f"); name="${base%.toml}"; SD="$OUT/$name"; mkdir -p "$SD"
  py plan "/scenarios/$base" --slot "$slot" > "$SD/plan.txt" || { echo "!! lỗi đọc $base" >&2; slot=$((slot+1)); continue; }
  title=$(grep '^TITLE|' "$SD/plan.txt" | cut -d'|' -f2-)
  maxs=$(grep '^MAXS|' "$SD/plan.txt" | cut -d'|' -f2); settle=$(grep '^SETTLE|' "$SD/plan.txt" | cut -d'|' -f2)
  echo ">> [$name] $title"
  # rulegen dừng trong kịch bản trừ khi kịch bản khai báo  rulegen = true  (cô lập kết quả)
  if [ "$(grep '^RULEGEN|' "$SD/plan.txt" | cut -d'|' -f2)" != 1 ] && printf '%s\n' "$RUNNING" | grep -qx rulegen; then
    "${CP[@]}" stop rulegen >/dev/null 2>&1 && STOPPED="$STOPPED rulegen"
  fi
  # mỗi kịch bản bắt đầu từ trạng thái chặn sạch (IP của kịch bản trước có thể bị dùng lại)
  bash "$D/tools/reset.sh" >/dev/null 2>&1 || echo "   !! không xoá được trạng thái responder"
  SC_RULEGEN=$(grep '^RULEGEN|' "$SD/plan.txt" | cut -d'|' -f2)
  if [ "$SC_RULEGEN" = 1 ]; then echo "   xoá luật tự sinh trước kịch bản ..."; clear_rules; STOPPED="$STOPPED rulegen"; fi
  sleep 8

  # cấu hình tạm
  if grep -q '^OVR|' "$SD/plan.txt"; then
    printf 'services:\n' > "$OVR"
    for svc in $(grep '^OVR|' "$SD/plan.txt" | cut -d'|' -f2 | sort -u); do
      printf '  %s:\n    environment:\n' "$svc" >> "$OVR"
      grep "^OVR|$svc|" "$SD/plan.txt" | while IFS='|' read -r _ _ k v; do printf '      %s: "%s"\n' "$k" "$v" >> "$OVR"; done
      OVR_SVCS="$OVR_SVCS $svc"
    done
    echo "   cấu hình tạm:$OVR_SVCS"
    "${CP[@]}" -f "$OVR" up -d $OVR_SVCS >/dev/null 2>&1 || echo "   !! không áp được cấu hình tạm"
    sleep 12
  fi
  # miễn trừ tạm
  for c in $(grep '^EXEMPT|' "$SD/plan.txt" | cut -d'|' -f2); do
    bash "$D/tools/nsmctl.sh" exempt-add "$c" >/dev/null 2>&1 && EXEMPTS+=("$c")
  done
  [ ${#EXEMPTS[@]} -gt 0 ] && { echo "   miễn trừ tạm: ${#EXEMPTS[@]} dải"; sleep 2; }
  # rulegen bật cho kịch bản này (cấu hình tạm nếu có, đã áp ở trên)
  if [ "$SC_RULEGEN" = 1 ] && ! "${CP[@]}" ps --status running --services 2>/dev/null | tr -d '\r' | grep -qx rulegen; then
    if [ -f "$OVR" ] && grep -q '^  rulegen:' "$OVR"; then "${CP[@]}" -f "$OVR" up -d rulegen >/dev/null 2>&1
    else "${CP[@]}" up -d rulegen >/dev/null 2>&1; fi
    echo "   rulegen đang chạy"; sleep 5
  fi
  MODS=$(grep '^MODSEC_DO|' "$SD/plan.txt" | cut -d'|' -f2)
  G2D=$(grep '^G2DETECT|' "$SD/plan.txt" | cut -d'|' -f2 | tr '\n' ' ')
  for l in $G2D; do bash "$D/tools/gate2.sh" "$l" detect >/dev/null 2>&1 && G2SET=1; done
  [ -n "${G2D// /}" ] && echo "   Cổng 2: lớp chỉ ghi nhận trong kịch bản này: $G2D"
  RELOADS=$(grep '^RELOADS|' "$SD/plan.txt" | cut -d'|' -f2)

  # sự cố theo lịch
  T0=$(date +%s); BGPIDS=""
  T0ISO=$(date -u -d "@$T0" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
  if [ "${MODS:-0}" -gt 0 ]; then                # CRS chỉ ghi nhận trong MODS giây đầu, rồi bật lại
    modsec DetectionOnly; MODSEC_SET=1; echo "   CRS tạm ở DetectionOnly ${MODS}s"
    ( sleep "$MODS"; echo "   CRS bật lại (SecRuleEngine On)"; modsec On ) &
    BGPIDS="$BGPIDS $!"
  fi
  while IFS='|' read -r _ svc at back; do
    ( sleep "$at"; echo "   [sự cố] dừng $svc"; "${CP[@]}" stop "$svc" >/dev/null 2>&1
      if [ "$back" -ge 0 ]; then sleep $((back - at)); echo "   [sự cố] bật lại $svc"; "${CP[@]}" start "$svc" >/dev/null 2>&1; fi ) &
    BGPIDS="$BGPIDS $!"
    STOPPED="$STOPPED $svc"
  done < <(grep '^FAULT|' "$SD/plan.txt")

  # tác nhân
  n_act=0; ACTPIDS=""
  # đếm tác nhân CÒN CHẠY theo đúng PID của chúng (trước 13/11 đếm "mọi job nền trừ số job sự cố": khi bộ hẹn giờ
  # CRS hoặc một sự cố kết thúc sớm, vòng chờ thoát và XOÁ container của tác nhân còn đang chạy)
  alive_actors(){ n=0; for p in $ACTPIDS; do kill -0 "$p" 2>/dev/null && n=$((n + 1)); done; echo $n; }
  while IFS='|' read -r _ i j ip start kind; do
    while [ "$(alive_actors)" -ge "$MAXPAR" ]; do sleep 0.2; done
    ( now=$(( $(date +%s) - T0 )); [ "$start" -gt "$now" ] && sleep $((start - now))
      t0=$(date +%s)
      case "$kind" in
        gotestwaf)       # công cụ bên ngoài: GoTestWAF (MIT), báo cáo JSON vào thư mục kịch bản
          mkdir -p "$SD/gtw_$i"
          docker run --rm --name "sc_${name}_${i}_${j}" --network "$NET_EXT" --ip "$ip" "${USEROPT[@]}" \
            -v "$SD/gtw_$i:/app/reports" wallarm/gotestwaf --url "http://10.10.10.10/" --noEmailReport \
            --reportFormat json --reportPath /app/reports --skipWAFIdentification --wafName nsm \
            --workers "${SC_TOOL_WORKERS:-4}" --sendDelay 20 --randomDelay 20 --passStatusCodes 200,302,404 \
            >> "$SD/gotestwaf.log" 2>&1
          docker run --rm -i "${USEROPT[@]}" "${MNT[@]}" -v "$SD:/sd:ro" --entrypoint python "$PYIMG" -B \
            /tools/scenario.py --run "$RUN" toolparse "/scenarios/$base" --slot "$slot" --index "$i" --ipn "$j" \
            --path "/sd/gtw_$i" --t0 "$t0" --t1 "$(date +%s)" > "$SD/a_${i}_${j}.json" 2>>"$SD/actors.log" ;;
        wafbypass)       # công cụ bên ngoài: waf-bypass (MIT), kết quả JSON ra stdout
          docker run --rm --name "sc_${name}_${i}_${j}" --network "$NET_EXT" --ip "$ip" nemesida/waf-bypass \
            --host=10.10.10.10:80 --json-format --details --no-progress --threads "${SC_TOOL_WORKERS:-4}" \
            --timeout 10 > "$SD/wafbypass_$i.json" 2>>"$SD/actors.log"
          docker run --rm -i "${USEROPT[@]}" "${MNT[@]}" -v "$SD:/sd:ro" --entrypoint python "$PYIMG" -B \
            /tools/scenario.py --run "$RUN" toolparse "/scenarios/$base" --slot "$slot" --index "$i" --ipn "$j" \
            --path "/sd/wafbypass_$i.json" --t0 "$t0" --t1 "$(date +%s)" > "$SD/a_${i}_${j}.json" 2>>"$SD/actors.log" ;;
        *)
          CAP=(); [ "$kind" = botnet ] && CAP=(--cap-add NET_ADMIN)      # botnet: thêm địa chỉ IP nguồn phụ trong container
          docker run --rm -i --name "sc_${name}_${i}_${j}" --network "$NET_EXT" --ip "$ip" ${CAP[@]+"${CAP[@]}"} "${MNT[@]}" \
            --entrypoint python "$PYIMG" -B /tools/scenario.py --run "$RUN" actor "/scenarios/$base" --slot "$slot" \
            --index "$i" --ipn "$j" < /dev/null > "$SD/a_${i}_${j}.json" 2>>"$SD/actors.log" ;;
      esac ) &
    ACTPIDS="$ACTPIDS $!"; n_act=$((n_act + 1))
  done < <(grep '^ACTOR|' "$SD/plan.txt")
  echo "   $n_act tác nhân đang chạy (tối đa ${maxs}s) ..."
  # chờ tác nhân (không chờ tiến trình sự cố quá hạn)
  deadline=$(( $(date +%s) + maxs + 60 ))
  while [ "$(alive_actors)" -gt 0 ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 1; done
  for p in $BGPIDS; do wait "$p" 2>/dev/null; done; BGPIDS=""
  [ "$MODSEC_SET" = 1 ] && { modsec On; MODSEC_SET=0; }
  [ "$G2SET" = 1 ] && { bash "$D/tools/gate2.sh" all block >/dev/null 2>&1; G2SET=0; }
  if [ "${RELOADS:-0}" = 1 ]; then                # E5: số lần nginx nạp lại danh sách chặn trong kịch bản
    NREL=$("${CP[@]}" logs --since "$T0ISO" nginx 2>/dev/null | grep -c "blocklist reloaded")
    printf '{"scenario": "%s", "actor": -1, "name": "nginx", "role": "system", "ip": "-", "kind": "system", "t_start": %s, "t_end": %s, "sent": [], "extra": {"nginx_reloads": %s, "duration_s": %s}}\n' \
      "$name" "$T0" "$(date +%s)" "${NREL:-0}" "$(( $(date +%s) - T0 ))" > "$SD/a_sys.json"
    echo "   nginx nạp lại: ${NREL:-0} lần"
  fi
  docker ps -aqf "name=sc_${name}_" | xargs -r docker rm -f >/dev/null 2>&1
  for s in $STOPPED; do "${CP[@]}" start "$s" >/dev/null 2>&1; done; STOPPED=""
  grep -hv '^\s*$' "$SD"/actors.log 2>/dev/null | tail -n 6 | sed 's/^/ /'
  echo "   chờ ${settle}s cho đường ống ghi dữ liệu ..."; sleep "$settle"

  cat "$SD"/a_*.json > "$SD/runs.jsonl" 2>/dev/null
  pymon observe < "$SD/runs.jsonl" > "$SD/obs.json" 2>>"$SD/actors.log"
  docker run --rm -i "${USEROPT[@]}" "${MNT[@]}" -v "$SD:/sd:ro" --entrypoint python "$PYIMG" -B /tools/scenario.py \
    --run "$RUN" judge "/scenarios/$base" --runs /sd/runs.jsonl --obs /sd/obs.json >> "$OUT/results.jsonl" \
    || echo "   !! lỗi khi chấm $name"
  tail -n 1 "$OUT/results.jsonl" | grep -o '"verdict": "[^"]*"' | sed 's/^/   => /'
  tail -n 1 "$OUT/results.jsonl" | grep -o '"check": "[^"]*", "ok": [a-z]*, "detail": "[^"]*"' | sed 's/^/      /'
  if [ "$SC_RULEGEN" = 1 ]; then echo "   xoá luật tự sinh của kịch bản ..."; clear_rules; STOPPED="$STOPPED rulegen"; fi
  restore
  slot=$((slot + 1))
done

docker run --rm -i "${USEROPT[@]}" "${MNT[@]}" -v "$OUT:/o:ro" --entrypoint python "$PYIMG" -B /tools/scenario.py \
  --run "$RUN" report --results /o/results.jsonl > "$OUT/report.md"
echo
sed -n '/^## 1\./,/^## 2\./p' "$OUT/report.md" | sed '$d'
echo ">> báo cáo: eval/results/scenarios-$RUN/report.md"
