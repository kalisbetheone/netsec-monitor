#!/usr/bin/env bash
# tools/d1grace.sh — KIỂM NHÁNH HẠ CẤP D1 CỦA RESPONDER TRÊN HỆ THỐNG THẬT (SHARED_GRACE_S, sửa 15/11/2026).
# Chạy trên HOST, từ thư mục nsm, khi stack đang chạy và sạch:   bash tools/d1grace.sh
#   1. một IP thử (mặc định 10.10.10.171) gửi hồ sơ 'mix' của tools/attack.sh (User-Agent của curl) cho tới khi bị chặn CẢ IP;
#   2. tiêm một thông điệp ip_profile cho IP đó bằng tài khoản Kafka của tier3 (tools/d1grace_inject.py giải thích vì sao
#      phải tiêm tay: sau khi bị chặn cả IP, tier3 không còn thấy request của IP này);
#   3. trong 15 giây phải thấy: không còn chặn cả IP, có khoá "IP|User-Agent của curl"; kiểm toán có unblock/shared_downgrade
#      và block/shared_downgrade:...; trình duyệt khác cùng IP vào được (khác 403); User-Agent cũ vẫn 403.
#   4. gỡ chặn IP thử. Kết quả: eval/results/d1grace-<thời điểm>/result.txt. Mã thoát 0 = đạt đủ 4 điều.
# Biến: D1_IP (hậu tố trong 10.10.10.x, mặc định 171). Mỗi lần chạy dùng một IP KHÁC (171, 172, …): sau lần đầu, responder
# nhớ IP đó là IP dùng chung trong SHARED_TTL_S (mặc định 1 giờ), nên lần sau chặn ngay theo (IP, User-Agent) — đúng hành vi,
# nhưng không còn dựng được tình huống "chặn cả IP trước" (bước 1 báo "không bị chặn trong 30 giây").
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
CP=(docker compose -f "$D/docker-compose.yml")
NET=nsm_external_net; IMG=curlimages/curl:8.10.1
SUF="${D1_IP:-171}"; IP="10.10.10.$SUF"
UA_OLD="curl/8.10.1"
UA_NEW="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
OUT="$D/eval/results/d1grace-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$OUT"; R="$OUT/result.txt"
say(){ echo "$*" | tee -a "$R"; }
probe(){ docker run --rm --network "$NET" --ip "$IP" "$IMG" -s -A "$1" -H "Host: dvwa.local" -o /dev/null -w "%{http_code}" \
         "http://10.10.10.10/" 2>/dev/null; }
cleanup(){ docker ps -aqf "name=d1_" | xargs -r docker rm -f >/dev/null 2>&1; bash "$D/tools/nsmctl.sh" unblock "$IP" >/dev/null 2>&1; }
trap cleanup EXIT

say ">> d1grace: IP thử $IP — $(date '+%F %T')"
bash "$D/tools/nsmctl.sh" blocks 2>/dev/null | grep -q "$IP" && { say "!! $IP đang bị chặn từ trước — chạy tools/reset.sh rồi chạy lại"; exit 2; }
T0=$(date +%s)
say ">> [1] gửi hồ sơ 'mix' của tools/attack.sh từ $IP (User-Agent: $UA_OLD) ..."
docker run --rm --name "d1_atk" --network "$NET" --ip "$IP" -v "$D/tools:/tools:ro" -e NSM_HOST=dvwa.local \
  --entrypoint sh "$IMG" -c "tr -d '\r' < /tools/attack.sh | sh -s mix" > "$OUT/attack.log" 2>&1
ok=0
for i in $(seq 1 30); do
  bash "$D/tools/nsmctl.sh" blocks 2>/dev/null > "$OUT/blocks_before.txt"
  if grep -E "^\s*$IP(\s|$)" "$OUT/blocks_before.txt" >/dev/null || grep -E "$IP " "$OUT/blocks_before.txt" | grep -qv "|"; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || { say "!! $IP không bị chặn trong 30 giây — không kiểm được nhánh hạ cấp"; cat "$OUT/blocks_before.txt" >> "$R"; exit 3; }
say "   bị chặn cả IP sau $(( $(date +%s) - T0 )) s"; sed 's/^/   | /' "$OUT/blocks_before.txt" | tee -a "$R" >/dev/null
TB=$(date +%s)

say ">> [2] tiêm ip_profile cho $IP bằng tài khoản Kafka của tier3 ..."
"${CP[@]}" run --rm --no-deps -T -v "$D/tools:/tools:ro" --entrypoint python tier3 -B /tools/d1grace_inject.py inject "$IP" \
  > "$OUT/inject.json" 2>>"$OUT/inject.err" || { say "!! tiêm thất bại"; cat "$OUT/inject.err" >> "$R"; exit 4; }
TI=$(date +%s); say "   đã tiêm sau khi chặn $((TI - TB)) s (SHARED_GRACE_S mặc định 30)"

say ">> [3] chờ tối đa 15 giây cho responder hạ cấp ..."
c1=0; c2=0; c3=0; c4=0
for i in $(seq 1 15); do
  bash "$D/tools/nsmctl.sh" blocks 2>/dev/null > "$OUT/blocks_after.txt"
  full=$(grep -F "$IP" "$OUT/blocks_after.txt" | grep -vc "|")
  fp=$(grep -F "$IP|$UA_OLD" "$OUT/blocks_after.txt" | grep -c .)
  if [ "$full" = 0 ] && [ "$fp" -ge 1 ]; then c1=1; break; fi
  sleep 1
done
sleep 4      # để enforcer ghi xong và nginx nạp lại
"${CP[@]}" run --rm --no-deps -T -v "$D/tools:/tools:ro" --entrypoint python nsmctl -B \
  /tools/d1grace_inject.py audit "$IP" "$T0" > "$OUT/audit.jsonl" 2>>"$OUT/inject.err"
grep -q '"decision": "unblock", "reason": "shared_downgrade"' "$OUT/audit.jsonl" && \
  grep -q '"decision": "block", "reason": "shared_downgrade:' "$OUT/audit.jsonl" && c2=1
cn=$(probe "$UA_NEW"); co=$(probe "$UA_OLD")
[ "$cn" != 403 ] && [ -n "$cn" ] && c3=1
[ "$co" = 403 ] && c4=1

mark(){ [ "$1" = 1 ] && echo "ĐẠT" || echo "KHÔNG ĐẠT"; }
say ""
say "| Điều kiện | Kết quả | Chi tiết |"
say "|---|---|---|"
say "| Không còn chặn cả IP; có khoá IP|User-Agent cũ | $(mark $c1) | xem blocks_after.txt |"
say "| Kiểm toán có unblock/shared_downgrade và block/shared_downgrade:… | $(mark $c2) | $(grep -c . "$OUT/audit.jsonl") bản ghi trong audit.jsonl |"
say "| Trình duyệt khác cùng IP vào được | $(mark $c3) | mã $cn |"
say "| User-Agent cũ vẫn bị chặn | $(mark $c4) | mã $co |"
sed 's/^/   | /' "$OUT/blocks_after.txt" >> "$R"; sed 's/^/   audit | /' "$OUT/audit.jsonl" >> "$R"
say ">> kết quả: $R"
[ $((c1 + c2 + c3 + c4)) = 4 ]
