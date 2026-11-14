#!/bin/sh
# Lưu lượng lành tính liên tục (chạy nền trong container client)
T=http://10.10.10.10
# Host: dvwa.local như trình duyệt thật gõ tên miền. Gửi tới địa chỉ IP thì CRS (luật 920350) cộng sẵn 3 điểm cho MỌI request,
# làm số đo chặn nhầm của Cổng 2 bị thổi phồng. Đổi bằng biến NSM_HOST.
H="Host: ${NSM_HOST:-dvwa.local}"
while true; do
  for q in laptop chuot "ban phim" "" "order by price"; do
    curl -s -H "$H" -o /dev/null -G "$T/vulnerabilities/sqli/" --data-urlencode "id=$q" --data-urlencode "Submit=Submit"
    sleep 3
  done
  curl -s -H "$H" -o /dev/null "$T/"
done
