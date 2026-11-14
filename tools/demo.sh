#!/usr/bin/env bash
# tools/demo.sh — CHẠY TRÊN HOST (terminal Ubuntu), KHÔNG chạy trong container.
# Phóng trọn bộ kịch bản tấn công (mỗi loại một IP riêng) + lưu lượng thường,
# rồi probe lại từng IP để in VERDICT: IP nào BỊ CHẶN, IP nào KHÔNG.
#   dùng:  bash tools/demo.sh        (từ thư mục nsm, hoặc gọi bằng đường dẫn bất kỳ)
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"      # đặt D = thư mục dự án (đường dẫn động, xem _host.sh)
NET=nsm_external_net
IMG=curlimages/curl:8.10.1
TOOLS="$D/tools"
T=http://10.10.10.10
# Host: dvwa.local như trình duyệt thật gõ tên miền. Gửi tới địa chỉ IP thì CRS (luật 920350) cộng sẵn 3 điểm cho MỌI request,
# làm số đo chặn nhầm của Cổng 2 bị thổi phồng. Đổi bằng biến NSM_HOST.
HOSTH="Host: ${NSM_HOST:-dvwa.local}"

fire() {    # $1=hậu tố IP  $2=kịch bản trong attack.sh
  docker run --rm -d --name "demo_$1" --network "$NET" --ip "10.10.10.$1" \
    -v "$TOOLS:/tools:ro" -e NSM_HOST="${NSM_HOST:-dvwa.local}" --entrypoint sh "$IMG" \
    -c "tr -d '\r' < /tools/attack.sh | sh -s $2" >/dev/null
}
benign() {  # $1=hậu tố IP : vài yêu cầu hợp lệ rồi thoát
  docker run --rm -d --name "demo_$1" --network "$NET" --ip "10.10.10.$1" \
    -e HOSTH="$HOSTH" --entrypoint sh "$IMG" -c '
      for q in laptop chuot keyboard order; do
        curl -s -H "$HOSTH" -o /dev/null -G "http://10.10.10.10/vulnerabilities/sqli/" \
          --data-urlencode "id=$q" --data-urlencode "Submit=Submit"
      done
      curl -s -H "$HOSTH" -o /dev/null http://10.10.10.10/' >/dev/null
}
probe() {   # $1=hậu tố IP -> in mã HTTP khi gửi 1 request lành
  docker run --rm --network "$NET" --ip "10.10.10.$1" "$IMG" \
    -s -H "$HOSTH" -o /dev/null -w "%{http_code}" "$T/" 2>/dev/null
}

echo ">> (gợi ý: chạy tools/reset.sh trước để bắt đầu từ trạng thái sạch)"
echo ">> phóng lưu lượng tấn công + thường ..."
# --- TẤN CÔNG: mỗi loại một IP. Ngưỡng chặn: 5 cảnh báo / 60 giây (hoặc 12 / 24 giờ) ---
fire 101 mix        # SQLi+XSS+LFI+extractvalue = 8 cảnh báo  -> vượt ngưỡng
fire 102 sqli       # chỉ 3 SQLi                              -> dưới ngưỡng
fire 103 xss        # chỉ 2 XSS                               -> dưới ngưỡng
fire 104 lfi        # chỉ 2 LFI                               -> dưới ngưỡng
fire 105 recon      # 8 lần dò phpmyadmin                     -> vượt ngưỡng
fire 106 flood      # 8 UNION lặp                             -> vượt ngưỡng
fire 107 bigrecon   # 40 đường dẫn 404                        -> tầng 3 'recon' (chặn ngay)
fire 108 bigflood   # 150 request một URI                     -> tầng 3 'flood' (chặn ngay)
fire 109 rceburst   # 10 RCE trong thân POST                  -> vượt ngưỡng
# --- LƯU LƯỢNG THƯỜNG: kỳ vọng KHÔNG bị chặn ---
benign 151
benign 152

echo ">> chờ 45s cho phát hiện bất đồng bộ + responder ra quyết định ..."
sleep 45
docker ps -aqf "name=demo_" | xargs -r docker rm -f >/dev/null 2>&1 || true

echo
echo "===================== VERDICT (probe lại mỗi IP) ====================="
printf "%-15s %-10s %-6s %-12s %s\n" "IP" "loại" "mã" "trạng thái" "kỳ vọng"
verdict() {  # $1=hậu tố IP  $2=nhãn  $3=kỳ vọng (chan|khong)
  c=$(probe "$1")
  if [ "$c" = "403" ]; then st="BỊ CHẶN"; got=chan; else st="không chặn"; got=khong; fi
  if [ "$got" = "$3" ]; then ok="đúng"; else ok="KHÁC KỲ VỌNG"; fi
  printf "%-15s %-10s %-6s %-12s %s\n" "10.10.10.$1" "$2" "$c" "$st" "$ok"
}
for row in "101 mix chan" "102 sqli khong" "103 xss khong" "104 lfi khong" "105 recon chan" \
           "106 flood chan" "107 bigrecon chan" "108 bigflood chan" "109 rceburst chan"; do
  set -- $row; verdict "$1" "$2" "$3"
done
echo "---- lưu lượng thường (kỳ vọng: không chặn) ----"
verdict 151 benign khong
verdict 152 benign khong
echo
echo ">> Ghi chú: tấn công ÍT (sqli 3, xss 2, lfi 2 request) nằm DƯỚI ngưỡng k=5 trong 60 giây"
echo "   nên cố ý KHÔNG chặn (tránh dương tính giả — ca B4). Tấn công nhiều (mix/recon/flood/rceburst)"
echo "   vượt ngưỡng; bigrecon/bigflood do tầng 3 hành vi phát hiện và chặn ngay."
echo ">> Xem trực quan trên Grafana: http://localhost:3000  (dashboard NSM)"
