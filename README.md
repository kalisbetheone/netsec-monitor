# Bản MỘT MÁY (Docker, 3 mạng) — mô phỏng topo máy ảo

Chạy toàn bộ hệ thống trên một máy có Docker, dùng các mạng người dùng tự tạo giống hệt
máy ảo. attacker/client là container nội bộ nên nginx thấy IP THẬT.

## Mạng
- external_net 10.10.10.0/24  (vùng ngoài): attacker .66, client .20, nginx .10
- monitor_net  10.10.30.0/24  (vùng giám sát): kafka, elasticsearch, grafana, classifier, tier3, responder, rulegen, logsink, filebeat, enforcer
- app_net      172.31.0.0/24  (nội bộ, internal): nginx↔apache↔db

## Phân vùng
attacker chỉ ở external_net; SOC chỉ ở monitor_net; container không tự định tuyến
giữa 2 mạng → attacker KHÔNG với tới SOC (giống ip_forward=0 trên máy WEB).

## Chạy
```bash
bash tools/init-env.sh                          # MỘT LẦN: sinh tệp .env chứa mật khẩu ngẫu nhiên
                                                # (thêm --lab nếu muốn DVWA chạy lỗ hổng thật — xem dưới)
docker compose up -d --build                    # 10-20 phút lần đầu
docker compose exec suricata suricata-update    # BẮT BUỘC một lần: tải luật ET cho nhánh bắt gói
docker compose restart suricata
```
Không chạy `suricata-update` thì Suricata không có luật nào: nhánh mạng vẫn ghi sự kiện HTTP
nhưng không sinh cảnh báo chữ ký.

Khởi tạo CSDL DVWA (không có trình duyệt ngoài nên làm từ container attacker):
```bash
docker compose exec attacker sh -c "tr -d '\r' < /tools/setup-dvwa.sh | sh"
```

Grafana chỉ mở tại http://localhost:3000 của chính máy host; đăng nhập `admin` với mật khẩu ở dòng
`GRAFANA_ADMIN_PASSWORD` trong `.env` (`grep GRAFANA_ADMIN_PASSWORD .env`). Không còn mật khẩu mặc định.

## Xác thực và bí mật
- Mọi mật khẩu nằm trong `.env` (do `tools/init-env.sh` sinh ngẫu nhiên; chạy lại không ghi đè giá trị đã
  có). Thiếu `.env` thì mọi lệnh `docker compose` dừng lại với thông báo yêu cầu chạy script này.
  Không chia sẻ `.env`; muốn đổi mật khẩu thì sửa `.env` rồi `docker compose down -v && docker compose up -d`.
- **Elasticsearch** bắt buộc đăng nhập, mỗi vai trò một tài khoản (`soc/es-init.sh`): `nsm_writer`
  (classifier, tier3, responder, logsink — chỉ thêm bản ghi), `nsm_rulegen` (đọc sự kiện, ghi `rule-status`,
  xoá chỉ mục quá hạn), `nsm_ctl` (nsmctl — chỉ đọc kiểm toán), `grafana_ro` (Grafana — chỉ đọc). Tài khoản
  quản trị `elastic` chỉ còn dùng cho `es-init` và healthcheck. Bên trong mạng Docker vẫn là HTTP thường.
  Máy đã cài trước 12/11/2026: chạy lại `bash tools/init-env.sh` để sinh mật khẩu cho ba tài khoản mới.
- **Kafka** bắt buộc đăng nhập SASL/PLAIN, mỗi dịch vụ một tài khoản với quyền tối thiểu
  (`soc/kafka-init.sh`): chỉ `responder` ghi được `enforce.blocklist`, chỉ `rulegen` ghi được
  `enforce.rules`, `filebeat` chỉ ghi các topic nhật ký, `enforcer` chỉ đọc `enforce.*`, chỉ `ctl` (công cụ
  quản trị) ghi được `nsm.control`. Lộ mật khẩu của một thành phần ở vùng DMZ không cho phép ra lệnh chặn.
- Tự kiểm tra lại bất cứ lúc nào: `bash tools/sectest.sh` thử 25 truy cập trái phép (không mật khẩu, sai mật
  khẩu, dùng tài khoản của thành phần khác vai trò) và báo lỗi nếu có truy cập nào lọt.
- Gọi Elasticsearch bằng tay:
  `docker compose exec elasticsearch sh -c 'curl -s -u "elastic:$ELASTIC_PASSWORD" "localhost:9200/_cat/indices"'`

## Quản trị khi đang chạy (không xoá trạng thái)
```bash
bash tools/nsmctl.sh blocks                   # IP đang bị chặn, thời gian còn lại
bash tools/nsmctl.sh unblock 10.10.10.66      # gỡ chặn MỘT IP ngay
bash tools/nsmctl.sh exempt                   # dải miễn trừ (cấu hình + thêm lúc chạy)
bash tools/nsmctl.sh exempt-add 10.10.10.0/28 # thêm miễn trừ, hiệu lực ngay, giữ qua khởi động lại
bash tools/nsmctl.sh exempt-del 10.10.10.0/28
```
Lệnh đi qua topic `nsm.control`, responder thi hành và ghi kiểm toán (`decision` = `unblock` /
`exempt_add` / `exempt_del`, `reason` = `manual`).

## Quan sát
- **Cổng 1:** nginx ghi JSON các request nó từ chối (403 vì IP bị chặn, 429 vì vượt giới hạn kết nối) →
  topic `gate1.logs` → chỉ mục `gate-events-*`. Dashboard có hàng "Cổng 1 — IP đang bị chặn vẫn làm gì".
- **error.log của Apache** (ModSecurity, PHP, máy chủ) → topic `web.errors` → chỉ mục `apache-errors-*`.
  Cả hai nguồn được dịch vụ `logsink` gom mỗi 10 giây (một bản ghi kèm `count`), không ghi từng dòng.
- **Nhịp tim:** mỗi dịch vụ Python ghi 30 giây một lần vào `nsm-health-*` (số đã xử lý, thông điệp Kafka
  chưa đọc, dòng log hỏng, lỗi ghi Elasticsearch, lỗi gửi Kafka, số bản ghi phải bỏ). Enforcer gửi nhịp tim qua
  Kafka. Classifier ghi thêm tuổi của sự kiện mới nhất theo từng nguồn (`age_net_events_s`, `age_web_logs_s`,
  `age_web_audit_s`) để biết Suricata / Filebeat / Apache còn gửi hay không; tier3 ghi `model_loaded`.
  `docker compose ps` cho thấy dịch vụ Python nào bị treo (healthcheck dựa trên vòng lặp chính).
- **Cảnh báo Grafana** (Alerting → Alert rules → thư mục NSM), nạp từ
  `soc/grafana/provisioning/alerting/nsm-alerts.yml`: có IP mới bị chặn; luật tự sinh vừa ban hành; có
  thay đổi thủ công; đường ống ứ đọng; một dịch vụ mất nhịp tim; không còn sự kiện từ Suricata / không còn
  nhật ký web; tier3 chạy không có model; gửi Kafka thất bại; bộ đệm Elasticsearch tràn. Nhận cảnh báo ra
  ngoài: đặt `ALERT_WEBHOOK_URL=https://...` trong `.env` rồi `docker compose up -d grafana`
  (`soc/grafana/start.sh` tự tạo contact point). Để trống thì cảnh báo chỉ hiện trong Grafana.
- **Lưu giữ:** chỉ mục `gate-events-*`, `apache-errors-*`, `nsm-health-*` tự xoá sau 14 ngày (ILM, đặt trong
  `soc/es-init.sh`); `web-events-*`, `audit-decisions-*` do rulegen dọn sau 30 ngày, ILM xoá sau 32 ngày nếu
  rulegen không chạy. Topic `web.audit` (chứa thân request) chỉ giữ 1 ngày.
- **Dữ liệu nhạy cảm:** giá trị của tham số / cookie có tên kiểu mật khẩu, token, phiên, thẻ... được thay bằng
  `[redacted]` trước khi lưu vào Elasticsearch (vẫn được quét đầy đủ khi phân loại). Cookie chỉ lưu tên.
- **Xoay nhật ký:** mọi nhật ký (`eve.json`, `gate1.json`, `access.json`, `modsec_audit.json`, `error.log`) được
  xoay khi vượt `LOG_MAX_MB`: đổi tên thành `<tên>.1` (giữ 1 bản cũ) rồi cho dịch vụ mở tệp mới. Filebeat đọc nốt
  bản đã xoay nên không mất dòng. (Trước đây Apache/nginx cắt tệp về 0, làm Filebeat mất các dòng chưa đọc;
  đã đo được classifier mất thân của request POST vì vậy.)

## Test nhanh
```bash
# cổng 2 chặn (CRS):
docker compose exec attacker sh -c "tr -d '\r' < /tools/attack.sh | sh -s sqli"      # 403
# chặn IP (vượt ngưỡng 5 cảnh báo / 60 giây):
docker compose exec attacker sh -c "tr -d '\r' < /tools/attack.sh | sh -s flood"; sleep 10
docker compose exec attacker curl -s -o /dev/null -w "attacker: %{http_code}\n" http://10.10.10.10/   # 403
docker compose exec client   curl -s -o /dev/null -w "client:   %{http_code}\n" http://10.10.10.10/   # 302
# xem IP thật:
docker compose logs --tail 5 nginx        # thấy 10.10.10.66 / 10.10.10.20
```
Kịch bản đầy đủ: `bash tools/demo.sh` (chặn IP), `bash tools/ruledemo-multi.sh` (tự sinh luật),
`bash tools/reset.sh` / `bash tools/reset-all.sh` (làm sạch).

Đo đạc: `bash tools/bench.sh` (~4–5 phút, stack phải đang chạy) đo tỉ lệ phát hiện / báo nhầm trên bộ mẫu
có nhãn, thời gian từ request tấn công đầu tiên tới khi IP bị chặn, ca tấn công rải rác (B5), độ trễ và
thông lượng qua hai cổng. Báo cáo ghi vào `bench-results/<thời điểm>/report.md`. Chạy riêng từng pha:
`bash tools/bench.sh detect`, `mttr`, `slow`, `perf`; `-r N` để lặp mỗi kịch bản chặn IP N lần.

Kịch bản giả lập: `bash tools/scenario.sh` chạy 21 kịch bản trong `scenarios/` (họ tấn công mới, vị trí đặt
payload, kỹ thuật né, hành vi C1–C4, D1, D3, sự cố E1–E5, GoTestWAF, waf-bypass), mỗi kịch bản có kỳ vọng nên
vừa là kiểm thử vừa ra số đo. Xem `scenarios/README.md`. Mạng vùng ngoài là `10.10.0.0/20`. Kịch bản cần chế độ
lab (`bash tools/init-env.sh --lab && docker compose up -d apache`); rulegen bị dừng trong mỗi kịch bản trừ khi
kịch bản khai báo `rulegen = true`, và `SC_CLEAR_RULES=1` gỡ các luật tự sinh đang ban hành trước khi chạy.

Mọi công cụ đo (`scenario.py`, `bench.py`, `demo.sh`, `attack.sh`, `benign.sh`) gửi `Host: dvwa.local` như trình duyệt
thật (đổi bằng `NSM_HOST`). Gửi tới địa chỉ IP thì CRS luật 920350 cộng sẵn 3 điểm cho MỌI request và làm số đo chặn
nhầm của Cổng 2 bị thổi phồng. Kịch bản chấm "phát hiện" theo TỪNG request (Cổng 2 chặn hoặc classifier gắn nhãn) và
tách "người dùng bị khoá IP" (phải bằng 0) khỏi "Cổng 2 chặn một request hợp lệ" (≤ `benign_gate2_max_share`).

Không có đường dẫn cứng nào trong mã: chỉ cần `cd` vào thư mục dự án (đặt ở đâu, tên gì cũng được) rồi
gõ lệnh. Các script nạp `tools/_host.sh` để tự suy ra thư mục dự án từ vị trí của chính chúng, nên gọi
từ thư mục khác cũng chạy; mọi tệp chúng đọc/ghi trên host (kể cả tệp cấu hình tạm của demo sinh luật)
đều nằm trong thư mục dự án. Chạy được trên Linux/WSL và Git Bash (Windows) mà không cần đặt biến môi
trường nào; biến `NSM_DIR` chỉ dùng khi muốn ép sang một thư mục khác.

## Kiểm thử logic (không cần Docker)
```bash
pip install -r services/requirements.txt        # chỉ cần scikit-learn, scipy, joblib
python -B tests/test_logic.py
```
Bộ test giả lập Kafka/Elasticsearch và kiểm tra: tầng 1 không báo nhầm URL lành tính, ngưỡng chặn,
khử đếm trùng giữa cảm biến, cửa sổ hành vi tầng 3, trích bất biến và kiểm chứng luật, enforcer,
lệnh quản trị (nsmctl), đăng nhập Kafka, nhịp tim và bộ gom nhật ký (logsink).

## Tầng 1 chạy đồng bộ ở Cổng 2
Regex tầng 1 của classifier được chép thành luật ModSecurity (`web/apache/nsm-tier1.conf`, nạp sau CRS và luật tự
sinh) để request tấn công ĐẦU TIÊN mà CRS bỏ lọt bị 403 ngay, không phải chờ đường ống phát hiện chặn IP.
```bash
python -X utf8 -B tools/gen_tier1_modsec.py      # sinh lại sau khi sửa regex trong services/classifier.py
docker compose up -d --build apache
bash tools/tier1sync.sh                          # đối chiếu luật ModSecurity ↔ classifier trên dữ liệu thật
```

## Tham số chính (docker-compose.yml)
| Dịch vụ | Tham số | Giá trị | Ý nghĩa |
|---|---|---|---|
| classifier | `TIER2_THRESHOLD` | 0.90 | Ngưỡng tin cậy θ của tầng 2 |
| classifier | `TIER2_SYNTAX_GATE` | 1 | Chỉ hỏi model khi giá trị tham số có ký tự cú pháp tấn công |
| classifier | `TIER2_MODE` | observe | `observe`: nhãn tầng 2 chỉ ghi vào `t2_label`, không dẫn tới chặn (mặc định cho tới khi huấn luyện lại model). `corroborate`: chỉ tính khi ModSecurity cũng chặn request đó. `enforce`: như trước (báo nhầm rất nhiều) |
| classifier | `SCAN_MAX_BYTES` / `SCAN_MAX_PARAMS` | 524288 / 1000 | Trần quét mỗi request; vượt trần (hoặc thân bị ModSecurity cắt) thì gắn nhãn `uninspected` (dưới θ: ghi kiểm toán, không tự chặn) |
| classifier | `REFERER_CONFIDENCE` | 0.6 | Tấn công chỉ thấy trong Referer được ghi nhận dưới θ (nạn nhân XSS phản xạ không bị chặn) |
| responder | `MIN_CONFIDENCE` / `MAX_AGE_S` | 0.90 / 600 | θ và tuổi cảnh báo tối đa (giây) |
| responder | `THRESHOLD` / `WINDOW_S` | 5 / 60 | Ngưỡng chặn k trong cửa sổ ngắn |
| responder | `LONG_THRESHOLD` / `LONG_WINDOW_S` | 12 / 86400 | Cửa sổ dài 24 giờ cho tấn công rải rác. **Phải lớn hơn `THRESHOLD`** |
| responder | `TTL_STEPS_S` / `MAX_TTL_S` | 900,3600,86400 / 86400 | Thời hạn chặn lần 1 / 2 / 3+: 15 phút → 1 giờ → 24 giờ (để trống `TTL_STEPS_S` thì dùng `BASE_TTL_S` nhân đôi như cũ) |
| responder | `SHARED_CIDRS` / `SHARED_ESCALATE` | (trống) / 3 | IP dùng chung (NAT, proxy) đã biết; IP được tier3 báo có nhiều User-Agent cũng được coi là dùng chung trong `SHARED_TTL_S` (3600). IP dùng chung bị chặn theo (IP, User-Agent); đủ 3 dấu vân tay bị chặn thì chặn cả IP |
| tier3 | `TIER3_N_HI`, `TIER3_MIN_404`, … | 100, 10, … | Cổng định hình hành vi (flood, recon, denied, bruteforce, enum) |
| tier3 | `TIER3_MIN_DENY_URI` / `TIER3_MIN_DENY_SINGLE` | 3 / 30 | Mẫu `denied` (401/403 dồn dập) cần ≥ 3 đường dẫn khác nhau, hoặc ≥ 30 lần trên một đường dẫn: người dùng gửi lại một form bị CRS chặn nhầm không làm cả IP bị chặn |
| tier3 | `TIER3_SHARED_MIN_UA` | 4 | Số User-Agent khác nhau / cửa sổ để báo responder đây là IP dùng chung |
| rulegen | `INTERVAL_S` / `SHADOW_S` | 300 / 900 | Chu kỳ và thời gian chạy thử (**giá trị lab**; triển khai thật: 86400) |
| rulegen | `MIN_BENIGN` | 100 | Corpus lành tính tối thiểu; thiếu thì không sinh/ban hành luật |
| rulegen | `EPSILON` | 0 | Tỷ lệ lưu lượng lành tính được phép khớp một ứng viên luật |
| nginx | `RELOAD_MIN_INTERVAL_S` | 5 | Tối đa một lần nạp lại blocklist mỗi N giây |
| apache | `LOG_MAX_MB` | 200 | Xoay `access.json` / `modsec_audit.json` / `error.log` khi vượt kích thước này (giữ 1 bản cũ) |
| apache, nginx | `LOG_ROTATE_CHECK_S` | 60 | Chu kỳ kiểm kích thước nhật ký (giây) |
| nginx | `LOG_MAX_MB` | 50 | Xoay `gate1.json` khi vượt kích thước này |
| classifier | `PENDING_WAIT_S` | 15 | Thời gian tối đa chờ thân request POST từ nhật ký kiểm toán trước khi phân loại không có thân |
| suricata | `LOG_MAX_MB` | 200 | Xoay `eve.json` / `stats.log` / `fast.log` khi vượt kích thước này |
| mọi dịch vụ Python | `HEARTBEAT_S` | 30 | Chu kỳ ghi nhịp tim vào `nsm-health-*` |

## Giới hạn đã biết
- **Model tầng 2 và tầng 3 chưa được huấn luyện lại.** Model tầng 2 gắn nhãn tấn công cho 40,7 % lưu lượng
  lành tính thật (openappsec), nên mặc định chỉ được GHI NHẬN (`TIER2_MODE=observe`). Đổi lại, tỷ lệ request
  tấn công bị classifier gắn nhãn giảm từ 60,9 % xuống 48,7 % (đo trên 300 791 request, xem
  `eval/results/tier-compare-20261112/report.md`); Cổng 2 (CRS) vẫn chặn từng request như cũ.
- Kafka và Elasticsearch đã bắt buộc xác thực nhưng CHƯA mã hoá (SASL_PLAINTEXT, HTTP): ai nghe lén
  được mạng giám sát vẫn đọc được mật khẩu. Ở bản một máy, lưu lượng này chỉ đi trong mạng Docker của máy.
- **Chế độ lab** (`bash tools/init-env.sh --lab`): DVWA không đòi đăng nhập, mức `low` — payload thực thi lệnh
  chạy thật trong container apache (mạng `app_net` không ra Internet). Mặc định là chế độ an toàn: request
  của các script nhận 302, payload vẫn đi qua hai cổng và được phát hiện nhưng không khai thác được thật.
- Giới hạn kết nối ở lớp TCP (stream) của nginx không sinh dòng nhật ký JSON. Các lỗi do khối http của nginx
  sinh ra (403, 429, 400, 414, 431, 505...) đều được ghi vào `gate-events-*`.
- **Cổng 2 dùng OWASP CRS 4.25.0** (từ 13/11/2026, thay gói Debian 3.3.4; tệp phát hành lưu trong `web/apache/crs/`),
  vẫn trên ModSecurity 2.9.7. CRS 4 thêm luật SSRF (934110/934120). Số đo Cổng 2 trước và sau mốc này không so trực
  tiếp được. CRS mặc định không cho phép `Content-Type: text/plain` (luật 920420) — khi bảo vệ ứng dụng thật có dùng
  kiểu này (vd `navigator.sendBeacon`) phải khai báo thêm trong `crs-setup.conf`.
- **Tầng 1 có luật cho 13 họ:** sqli, xss, rce (gồm Log4Shell, Shellshock), lfi, và từ 13/11: xxe, ssti, ssrf, deser,
  nosqli, ldap, crlf, rfi (chỉ tham số kiểu include), redirect (chỉ ghi nhận, độ tin cậy 0,6). NoSQLi/LDAP chỉ thấy
  trong cả thân JSON/XML thì chỉ ghi nhận (không phân biệt được với API dùng toán tử `$lt`... thật). Luật RCE đã siết:
  không áp lên đường dẫn, tên lệnh phải kết thúc đúng chỗ. Dữ liệu độc lập để đo: `eval/data/payloads_independent/`.
- ModSecurity 2.9 ghi thân request vào nhật ký kiểm toán JSON như chuỗi C: thân nhị phân (gzip...) bị cắt ở byte
  0 đầu tiên. Classifier nhận ra (so với `Content-Length`) và gắn nhãn `uninspected`, nhưng không soi được phần
  bị cắt.

## Khác với bản máy ảo
- 1 máy thay vì 3; Kafka 1 listener (kafka:9092) thay vì 2
- Không publish cổng 80 ra host (để tránh gộp IP). Tấn công từ container attacker nội bộ.
- Mọi thứ còn lại (2 cổng, cảm biến, chặn IP, TTL, sinh luật, dashboard) giữ nguyên.
