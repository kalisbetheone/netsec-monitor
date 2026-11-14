# Máy WEB — DMZ (hai cổng chặn + cảm biến)

Chạy trên VM Ubuntu có 3 card: NAT (Internet), ext=VMnet2 (đối diện Kali), int=VMnet3 (tới SOC).

## Yêu cầu trước
- Đã đặt IP tĩnh: ext 10.10.10.10, int 10.10.30.10; `ip_forward=0`.
- Đã cài Docker Engine; user trong nhóm `docker`.
- Máy SOC nên chạy trước (Kafka ở 10.10.30.20); nếu chưa, filebeat/enforcer sẽ tự kết nối lại.

## Cài
Từ thư mục gốc của dự án (nơi có `.env.example`):
```bash
# chép tệp .env từ máy SOC sang (đã có mật khẩu Kafka do tools/init-env.sh sinh trên máy SOC), rồi:
nano .env                 # thêm SURICATA_IFACE = tên card ext (vd ens38), KAFKA_BOOTSTRAP, HOME_NET (xem .env.example)
sudo timedatectl set-ntp true      # đồng hồ phải khớp máy SOC (bộ lọc tuổi cảnh báo)
docker compose --env-file .env -f web/docker-compose.yml up -d --build
docker compose --env-file .env -f web/docker-compose.yml exec suricata suricata-update
docker compose --env-file .env -f web/docker-compose.yml restart suricata
```
Đặt alias cho gọn (gõ khi đang đứng ở thư mục gốc của dự án; `$PWD` được thay bằng thư mục hiện tại ngay
lúc đặt alias, nên sau đó dùng `dcw` từ đâu cũng được):
```bash
alias dcw="docker compose --env-file '$PWD/.env' -f '$PWD/web/docker-compose.yml'"
```

## Khởi tạo DVWA
Trên Kali: mở http://10.10.10.10/setup.php → Create / Reset Database → đăng nhập admin/password.
Vào trang DVWA Security đặt mức Low để tái hiện tấn công.

## Kiểm thử nhanh (từ Kali)
Tấn công đi từ IP .66, truy cập lành tính để mặc định (.20):
```bash
curl --interface 10.10.10.66 -s -o /dev/null -w "sqli: %{http_code}\n" \
  "http://10.10.10.10/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--+-&Submit=Submit"   # 403
curl -s -o /dev/null -w "benign: %{http_code}\n" http://10.10.10.10/                      # 200/302
curl --interface 10.10.10.66 -s -o /dev/null -w "recon: %{http_code}\n" \
  http://10.10.10.10/phpmyadmin/                                                          # 404 (lọt cổng 2)
```

## Thành phần
| Container | Mạng | Vai trò |
|---|---|---|
| nginx | host | Cổng chặn 1: blocklist.map, 403 theo IP |
| apache | appnet | Cổng chặn 2: ModSecurity+CRS+luật tự sinh; chạy DVWA |
| db | appnet | MariaDB cho DVWA |
| suricata | host | IDS trên card ext, ghi eve.json |
| filebeat | appnet | access.json→web.logs, modsec_audit.json→web.audit, eve.json→net.events, gate1.json→gate1.logs, error.log→web.errors (tới Kafka SOC; tài khoản `filebeat`, chỉ được ghi) |
| enforcer | appnet | Nhận enforce.* từ Kafka → ghi blocklist.map / luật |

## Chế độ lab (DVWA chạy lỗ hổng thật)

Mặc định DVWA đòi đăng nhập và ở mức `impossible`. Chế độ lab chỉ bật khi `.env` (chép từ máy SOC) được tạo bằng
`bash tools/init-env.sh --lab`. Khi đó payload thực thi lệnh **chạy thật** trong container apache.

Ở bản một máy, mạng của apache là mạng nội bộ của Docker nên container không ra được Internet. Ở bản 3 máy,
apache cần cổng publish `127.0.0.1:8080` cho nginx, nên mạng `appnet` không đặt `internal` được. Khi bật lab,
chặn đường ra của container bằng tường lửa của máy WEB (chuỗi `DOCKER-USER` do Docker dành cho người dùng):

```bash
# tên bridge của mạng appnet: docker network inspect nsm-web_appnet -f '{{.Id}}' | cut -c1-12  -> br-<id>
sudo iptables -I DOCKER-USER -i br-<id> ! -o br-<id> -m conntrack --ctstate NEW -j DROP
```

Lệnh trên chỉ chặn kết nối MỚI đi ra từ apache/db; phản hồi cho nginx (kết nối do nginx mở) vẫn đi bình thường.
Filebeat và enforcer nằm ở mạng riêng `shipnet` nên vẫn gửi được tới Kafka trên máy SOC.
