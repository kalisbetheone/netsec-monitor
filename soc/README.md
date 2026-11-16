# Máy SOC — vùng giám sát (hàng đợi, phân tích, lưu trữ, sinh luật)

VM Ubuntu, 2 card: NAT (Internet) + int=VMnet3 (10.10.30.20). Dựng TRƯỚC máy WEB.

## Cài
Chuẩn bị máy (làm tay, một lần): đặt IP tĩnh 10.10.30.20 cho card int, cài Docker Engine,
thêm user vào nhóm `docker`, và tăng giới hạn bộ nhớ ánh xạ cho Elasticsearch:
```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf && sudo sysctl --system
sudo timedatectl set-ntp true                    # đồng hồ máy SOC và máy WEB phải khớp nhau (bộ lọc tuổi cảnh báo)
```
Sau đó, từ thư mục gốc của dự án:
```bash
bash tools/init-env.sh                           # sinh .env với mật khẩu ngẫu nhiên (ES, Kafka, Grafana)
nano .env                                        # thêm: SOC_IP=10.10.30.20 (xem .env.example)
docker compose --env-file .env -f soc/docker-compose.yml up -d --build
docker compose --env-file .env -f soc/docker-compose.yml ps
```
Alias gọn (gõ khi đang đứng ở thư mục gốc của dự án; `$PWD` được thay bằng thư mục hiện tại ngay lúc đặt
alias, nên sau đó dùng `dcs` từ đâu cũng được):
```bash
alias dcs="docker compose --env-file '$PWD/.env' -f '$PWD/soc/docker-compose.yml'"
```

## Thành phần
| Container | Vai trò | Cổng |
|---|---|---|
| kafka (+init) | Hàng đợi; 10 topic; SASL/PLAIN + ACL theo vai trò (`kafka-init.sh`) | 10.10.30.20:9092 (cho WEB) |
| elasticsearch (+init) | Lưu sự kiện, kiểm toán, trạng thái luật; bắt buộc đăng nhập | 127.0.0.1:9200 |
| grafana | Dashboard + cảnh báo (`grafana/provisioning/alerting/`) | 3000 |
| classifier | Gắn nhãn (tầng 1 + tầng 2), phát cảnh báo | |
| tier3 | Phát hiện bất thường hành vi theo cửa sổ trượt | |
| responder | Chặn IP (ngưỡng, TTL) → enforce.blocklist | |
| rulegen | Sinh luật có kiểm chứng → enforce.rules | |
| logsink | Gom nhật ký Cổng 1, error.log Apache, heartbeat của enforcer → ES | |
| nsmctl | Công cụ quản trị (không tự chạy, xem dưới) | |

## Kênh với máy WEB (qua Kafka)
- WEB → SOC: web.logs, web.audit (thân request), net.events, gate1.logs, web.errors, enforce.status
- SOC → WEB: enforce.blocklist (responder), enforce.rules (rulegen)
- enforcer trên WEB tự KÉO lệnh về; SOC không kết nối vào WEB.
- Máy WEB đăng nhập Kafka bằng hai tài khoản quyền tối thiểu `filebeat` và `enforcer`: phải chép `.env`
  của máy SOC sang máy WEB (cùng mật khẩu). Kênh SOC↔WEB là SASL_PLAINTEXT, CHƯA mã hoá.

## Quản trị (gỡ chặn / miễn trừ không xoá trạng thái)
```bash
dcs run --rm --no-deps -T nsmctl blocks
dcs run --rm --no-deps -T nsmctl unblock 10.10.10.66
dcs run --rm --no-deps -T nsmctl exempt-add 10.10.10.0/28
```
(`tools/nsmctl.sh` chỉ dùng cho bản một máy.)

## Kiểm tra nhanh
```bash
# topic + ACL đã tạo
dcs logs kafka-init | tail -3
# dịch vụ phân tích khởi động
dcs logs --tail 5 classifier responder rulegen
# sự kiện đổ vào ES (sau khi WEB gửi log)
dcs exec elasticsearch sh -c 'curl -s -u "elastic:$ELASTIC_PASSWORD" "localhost:9200/web-events-*/_count"'
```
Grafana: http://localhost:3000 (admin / `GRAFANA_ADMIN_PASSWORD` trong .env). 6 datasource và các luật cảnh
báo đã provision sẵn.

> Bản 3 máy ảo CHƯA được chạy thử sau các thay đổi về xác thực và nhật ký (chỉ kiểm tra cú pháp bằng
> `docker compose config`).
