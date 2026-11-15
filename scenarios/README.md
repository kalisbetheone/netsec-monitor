# scenarios — khung kịch bản giả lập

Mỗi tệp `.toml` là một kịch bản: ai tấn công / ai dùng hợp lệ, gửi gì, ở đâu, nhịp nào, sự cố gì xảy ra lúc nào,
và **kỳ vọng** hệ thống phản ứng ra sao. Một lần chạy cho ra ba thứ cùng lúc:

- **Kiểm thử:** mỗi kịch bản được chấm ĐẠT / KHÔNG ĐẠT / LỖ HỔNG ĐÃ BIẾT / CHỈ ĐO.
- **Benchmark:** số request, tỷ lệ bị Cổng 2 chặn, tỷ lệ classifier gắn nhãn, số IP bị chặn, thời gian chặn, lý do chặn,
  cảnh báo Suricata, mẫu hình tầng 3.
- **Dữ liệu đa dạng:** mọi request đã gửi được lưu kèm vai, họ tấn công, vị trí, kỹ thuật né (`eval/results/scenarios-*/`).

Chạy (từ thư mục `nsm`, khi stack đang chạy):

```bash
bash tools/scenario.sh --list
```

```bash
bash tools/scenario.sh
```

```bash
bash tools/scenario.sh 09-c4-do-mat-khau 12-e4-tai-pham
```

Lượt chạy đầy đủ lấy mọi tệp `scenarios/*.toml` (45 kịch bản; số 43 và 44 để trống), khoảng 2 giờ. Kết quả:
`eval/results/scenarios-<thời điểm>/report.md`.

Biến môi trường tuỳ chọn của `tools/scenario.sh` (từ 15/11/2026). Không đặt biến nào thì script chạy như trước.

| Biến | Ý nghĩa | Mặc định |
|---|---|---|
| `SC_DIR` | Thư mục kịch bản, tương đối tính từ `nsm/`. Chỉ lấy `*.toml` ngay trong thư mục đó | `scenarios` |
| `SC_OUT_NAME` | Kết quả ghi vào `eval/results/<tiền tố>-<thời điểm>/` | `scenarios` |
| `SC_CONT` | `1` = chạy liền mạch: không dừng rulegen (chưa chạy thì bật), không gọi `reset.sh` giữa các kịch bản, không xoá luật tự sinh (kể cả kịch bản có `rulegen = true`), không đặt mốc `not_before`, nghỉ đầu kịch bản 2 giây. `modsec_detection_only_s`, `exempt`, `override`, `fault` vẫn có tác dụng. Dùng cho ngày nén | `0` |

```bash
SC_DIR=scenarios/trinh-dien bash tools/scenario.sh --list
```

Tên kịch bản truyền làm tham số là tên tệp không có `.toml`, tìm trong `SC_DIR`.

## Hai thư mục con

Lượt chạy đầy đủ chỉ lấy tệp ở thư mục gốc `scenarios/`, nên hai thư mục con dưới đây không bị quét.

- `scenarios/ngay-nen/` — "ngày nén 12 lần": 24 khung giờ của một ngày, mỗi khung 5 phút thật, chạy liền mạch với `SC_CONT=1`
  ở chế độ chạy thử của responder. Công cụ: `tools/ngaynen.sh`, `tools/wouldblock.sh`. Không thay được chạy lâu thật (xem
  `../Danh-sach-gioi-han-NSM.md`, mục 12).
- `scenarios/trinh-dien/` — bản rút gọn của các kịch bản 03, 34, 36, 37, 41, 45 cho buổi trình diễn (`tools/present.sh`, không
  quá 15 phút). Chỉ giảm số request, số payload mỗi họ, số địa chỉ nguồn và thời gian tối đa so với bản gốc; họ payload và kỳ vọng
  giữ nguyên. Riêng bản rút gọn của 45 đổi `bot_offset` 700 → 800 để không trùng dải IP bí danh của 45. Sinh lại từ bản gốc bằng
  `nsm-wip-15-11/phoi-hop/p3_make_td.py`.

## Cấu trúc một kịch bản

```toml
title = "Dò mật khẩu: 60 lần POST đăng nhập từ một IP"
case = "C4"                      # ca tương ứng trong spec
notes = "..."                    # giải thích, in vào báo cáo
max_s = 120                      # thời gian tối đa của tác nhân
settle_s = 15                    # chờ đường ống ghi dữ liệu trước khi chấm
exempt = ["self"]                # (tuỳ chọn) miễn trừ tạm IP của kịch bản, hoặc một dải CIDR
rulegen = false                  # (tuỳ chọn) true = để rulegen chạy trong kịch bản; mặc định rulegen bị dừng (cô lập).
                                 # Kịch bản có rulegen: mọi luật tự sinh bị XOÁ trước và sau kịch bản
modsec_detection_only_s = 70     # (tuỳ chọn) CRS chỉ ghi nhận trong N giây đầu (tấn công "lọt" Cổng 2 để gom cụm sinh luật)

[override.responder]             # (tuỳ chọn) cấu hình tạm cho dịch vụ, tự khôi phục
TTL_STEPS_S = "20,40,80"

[[fault]]                        # (tuỳ chọn) dừng một dịch vụ theo lịch
service = "kafka"
stop_at_s = 5
start_at_s = 65

[[actor]]                        # một hoặc nhiều tác nhân
name = "dò mật khẩu"
role = "attack"                  # attack | benign | tên tuỳ ý (nat, monitor, late...)
ips = 1                          # số IP (mỗi IP một container)
kind = "http"                    # http | matrix | recidivist | slowloris | malformed | replay (phát lại lưu lượng thật)
family = "login"                 # họ payload (xem PAYLOADS trong tools/scenario.py)
families = ["benign", "sqli"]    # hoặc xoay vòng nhiều họ
user_agents = ["Chrome...", "sqlmap/1.8"]   # (tuỳ chọn) mỗi họ trong families một User-Agent riêng (mô phỏng nhiều người sau NAT)
source = "builtin"               # builtin | openappsec (payload thật từ eval/data/openappsec)
placement = "query"              # query form path json xml multipart upload cookie ua referer header param_name
                                 # pad_params pad_value pad_json (payload sau phần đệm — né classifier, N3)
evasion = ["case", "comment"]    # case comment ws fullwidth null html b64 jsuni double_url uni hpp chunked
count = 60
interval_s = 0.2
start_s = 0
https = false
stop_on_block = true
path = "/login.php"              # (tuỳ chọn) đổi đường dẫn / tên tham số / phương thức
param = "password"
shuffle = true                   # (tuỳ chọn) mỗi IP một thứ tự payload riêng
pad_chars = 3000                 # (tuỳ chọn) thêm tham số đệm vào thân form (tạo tải nhật ký)
every = 37                       # (replay) lấy 1 bản ghi / N của tập test_sites
# --- thêm 15/11/2026 (chiều) ---
ip = "10.10.15.250"              # IP nguồn cố định (chuỗi hoặc danh sách), thay cho `ips`; không lấy từ bộ cấp phát và không
                                 # làm lệch IP của tác nhân khác. Người viết tự giữ IP trong dải dành cho mình
fields = [["email", "user{n}@example.test"]]   # trường phụ gửi kèm tham số chính, THAY cho trường phụ mặc định của họ
                                 # payload (vd Submit=Submit). fields = [] = không có trường phụ. {n} = số ngẫu nhiên 1–9999,
                                 # mỗi request một số. Có tác dụng với kiểu http và botnet, ở vị trí query, form, pad_params,
                                 # pad_value; không khai fields thì request như trước

[expect]
attack_blocked = true            # có IP tấn công bị chặn (hoặc false: không IP nào bị chặn)
attack_blocked_min_share = 0.95  # tỷ lệ IP tấn công phải bị chặn
block_within_s = 40              # thời gian chặn trung vị tối đa
attack_block_after_s = 35        # chỉ bị chặn SAU mốc này (kịch bản sự cố)
detected_min_share = 0.8         # tỷ lệ request tấn công bị Cổng 2 chặn hoặc classifier gắn nhãn
block_reason = "behaviour"       # lý do chặn phải chứa chuỗi này
benign_blocked = false           # người dùng hợp lệ không bị chặn (IP hay request)
<vai>_blocked = false            # kỳ vọng cho vai tuỳ ý, vd monitor_blocked
<vai>_block_after_s = 45
collateral = true                # request hợp lệ cùng IP bị chặn theo (NAT)
recidivism_growth = true         # thời hạn chặn tăng dần qua các lần tái phạm
slowloris_capped = 20            # số kết nối nhỏ giọt tối đa còn sống
known_gap = true                 # kịch bản ghi lại giới hạn đã biết: đúng kỳ vọng -> "LỖ HỔNG ĐÃ BIẾT"
# --- thêm 13/11/2026 ---
<vai>_gate2_min_share = 0.8      # tỷ lệ request của vai bị Cổng 2 chặn (min / max)
<vai>_gate2_max_share = 0.0
<vai>_classifier_min_share = 0.9 # tỷ lệ request của vai bị classifier gắn nhãn tấn công (min / max)
<vai>_classifier_max_share = 0.01
rule_classes_active = ["rce"]    # rulegen ban hành luật cho các lớp này trong kịch bản
rules_must_not_contain = ["laptop"]  # không luật nào (token / đặc tả) chứa các chuỗi này
rule_final_state = "expired"     # có luật đi tới trạng thái này
no_rule_created_during = "elasticsearch"  # không luật nào sinh trong lúc dịch vụ (trong [[fault]]) dừng
gate1_after_block_min_share = 0.95  # sau lần chặn đầu, request của IP bị Cổng 1 trả 403
gate1_latency_ms_max = 50        # thời gian phản hồi 403 của Cổng 1 (trung vị)
malformed_recorded_min_share = 0.7  # request dị dạng bị từ chối có bản ghi trong gate-events / apache-errors
nginx_reload_max_per_min = 13    # số lần nginx nạp lại danh sách chặn
secrets_absent = true            # giá trị bí mật (họ "secret") không còn nguyên văn trong Elasticsearch
heartbeat_gap = "tier3"          # nhịp tim của dịch vụ ngừng khi dừng, có lại sau khi bật
alert_fired = "tier3"            # Grafana có lần chuyển cảnh báo (chứa chuỗi này) sang Alerting
bodies_received_min_share = 0.99 # thân POST của vai benign tới được classifier
# --- thêm 15/11/2026 ---
<vai>_ok_min_share = 0.99        # tỷ lệ request của vai nhận phản hồi bình thường (không 403 / 429)
bots_blocked_min_share = 0.8     # tỷ lệ địa chỉ của tác nhân kind = "botnet" bị chặn (min / max)
exploited_min_share = 0.5        # (kind = "exploit") tỷ lệ request mà phản hồi cho thấy ứng dụng đã bị khai thác (min / max)
exploited_max = 0
```

Thêm 15/11/2026 cho tác nhân:

- `kind = "exploit"`: đăng nhập DVWA (mức `low`) rồi gửi các payload mẫu, đọc thân phản hồi để biết ứng dụng có thực sự bị
  khai thác hay không. Dùng để **kiểm chứng bộ thử**: kịch bản 34 tắt mọi lớp chặn để chứng minh payload có tác dụng thật,
  35 và 36 bật lại từng lớp để đo lớp nào ngăn được.
- `kind = "botnet"`: một container mang `bots` địa chỉ nguồn (bí danh trên cùng giao diện mạng, cần `NET_ADMIN`), dùng để thử
  các tình huống nhiều nguồn cùng lúc (nhồi tài khoản quy mô lớn, flood phân tán, cao điểm hợp lệ) mà không phải tạo hàng
  trăm container.
- `host = "booking.local"`: đổi tên miền đích (mặc định `dvwa.local`) để nhắm vào cổng đặt chỗ giả lập.
- `source = "file:<đường dẫn>"`: lấy payload từ tệp, mỗi dòng một chuỗi hoặc `{"value": ...}`.

Mọi tác nhân chỉ gửi tới máy chủ web của lab trong mạng Docker riêng; mục đích là đo khả năng phát hiện, chặn và chặn nhầm của
NSM, không dùng ngoài lab.

IP của tác nhân lấy trong `10.10.11.1 – 10.10.15.254` (mạng `external_net` là `10.10.0.0/20`). Trước mỗi kịch bản, trạng thái
chặn của responder được xoá (như `tools/reset.sh`), nên các kịch bản không ảnh hưởng nhau.
Đích duy nhất của mọi tác nhân là máy chủ web của lab, `10.10.10.10`.

## Danh sách kịch bản theo ca của spec

| Ca | Kịch bản |
|---|---|
| A1 | 02, 32 (lưu lượng thật), 42 (lưu lượng thật, phần dữ liệu chưa dùng để tinh chỉnh) |
| B1 / B2 / B3 / B4 / B5 | 01, 03 / 27 / 22 / 04 / 23 |
| C1 / C2 / C3 / C4 | 06 / 08 / 07 / 09, 10 |
| D1 / D2 / D3 / D4 | 13 / 24 / 11, 14 / 25 |
| E1 / E2 / E3 / E4 / E5 | 15 / 16, 19 / 17, 26 / 12 / 18 |
| Đợt nâng cấp 15/11 | 34–36 (kiểm chứng bộ thử bằng khai thác thật), 37 (giới hạn tốc độ một IP), 38 (nhồi tài khoản 200 IP), 39 (flood phân tán 300 IP — giới hạn đã biết), 40 (cao điểm hợp lệ không bị chặn nhầm), 41 (luật tự sinh áp dụng ngay và gỡ) |
| Cổng đặt chỗ `booking.local` (15/11 chiều) | 45 (nhồi tài khoản vào trang đăng nhập, botnet 100 IP), 46 (dò mã đặt chỗ từ một IP), 47 (Cổng 2 chặn họ `sqli` ở ô tìm chuyến; khách gõ dấu nháy không bị ảnh hưởng) |
| Ngoài spec | 05 (họ mới), 20–21 (bộ thử bên ngoài), 28 (né bằng đệm), 29 (che mật khẩu), 30 (nhịp tim + cảnh báo), 31 (xoay nhật ký), 33 (vòng đời luật) |
