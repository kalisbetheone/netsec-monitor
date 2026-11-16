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

Từ 15/11/2026:
```bash
bash tools/nsmctl.sh mode                     # responder đang chặn thật (enforce) hay chạy thử (dryrun)
bash tools/nsmctl.sh mode dryrun              # chạy thử: chỉ ghi "sẽ chặn" (would_block), không gửi lệnh chặn
bash tools/nsmctl.sh mode enforce             # chặn thật trở lại
bash tools/nsmctl.sh rules                    # luật tự sinh đang sống (mã, lớp, trạng thái, nội dung, số lần khớp thật)
bash tools/nsmctl.sh rule-revoke 9900012      # gỡ MỘT luật ngay; không được sinh lại trong 24 giờ
bash tools/nsmctl.sh rule-revoke-all          # gỡ mọi luật tự sinh
bash tools/gate2.sh status                    # lớp nào của Cổng 2 đang chặn / chỉ ghi nhận
bash tools/gate2.sh crs detect                # CRS chỉ ghi nhận (tier1 detect: luật tầng 1 đồng bộ); "all block" để trả lại
```
Lệnh `rule-*` do rulegen thi hành. `gate2.sh` ghi một tệp cấu hình tạm trong container apache, mất khi container được
tạo lại. Hướng dẫn từng bước (gỡ chặn nhầm, gỡ luật, chạy thử ↔ chặn thật, khi một thành phần dừng):
`Huong-dan-su-dung-NSM.md`, mục 13.

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
- **Lưu giữ** (từ 15/11/2026, sau khi áp bản vá `soc/es-init.sh`): nhật ký kiểm toán `audit-decisions-*` và bản lưu
  sự kiện tấn công `attack-events-*` giữ 1 năm; `gate-events-*` 90 ngày; `web-events-*` 30 ngày (rulegen dọn, ILM xoá
  sau 32 ngày nếu rulegen không chạy); `apache-errors-*`, `nsm-health-*` 14 ngày. `RETENTION_UNIT=h` trong `.env` đổi
  các con số trên sang giờ để thử nhanh. Sự kiện có nhãn tấn công được ghi THÊM một bản vào `attack-events-*`;
  rulegen không còn xoá nhật ký kiểm toán. Topic `web.audit` (chứa thân request) chỉ giữ 1 ngày.
- **`tools/reset-all.sh`** giữ nhật ký kiểm toán và bản lưu tấn công; chỉ xoá khi gọi `--wipe-audit`. Khi `.env` có
  `NSM_PROFILE=prod` thì cần thêm `--force`.
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

Kịch bản giả lập: `bash tools/scenario.sh` chạy 45 kịch bản trong `scenarios/` (họ tấn công mới, vị trí đặt
payload, kỹ thuật né, hành vi C1–C4, D1–D4, sự cố E1–E5, GoTestWAF, waf-bypass, khai thác thật, botnet, cổng đặt chỗ),
mỗi kịch bản có kỳ vọng nên
vừa là kiểm thử vừa ra số đo. Xem `scenarios/README.md`. Mạng vùng ngoài là `10.10.0.0/20`. Kịch bản cần chế độ
lab (`bash tools/init-env.sh --lab && docker compose up -d apache`); rulegen bị dừng trong mỗi kịch bản trừ khi
kịch bản khai báo `rulegen = true`, và `SC_CLEAR_RULES=1` gỡ các luật tự sinh đang ban hành trước khi chạy.

Công cụ thêm ngày 15/11/2026:

| Lệnh | Việc |
|---|---|
| `bash tools/baseline.sh <tên>` | Lượt đo đầy đủ (demo, sectest, parity, tier1sync, bench, mọi kịch bản…), kết quả trong `eval/results/baseline-<tên>/` |
| `bash tools/present.sh` | Buổi trình diễn 7 bước, không quá 15 phút, từ trạng thái sạch (gọi `reset-all.sh` ở đầu và cuối). `PRESENT_AUTO=1` chạy liền không dừng. Mã thoát khác 0 khi một bước sai hoặc quá 15 phút |
| `bash tools/ngaynen.sh` | Ngày mô phỏng nén 12 lần: 24 khung giờ, mỗi khung khoảng 4 phút thật, mốc thời gian chia 12, responder ở chế độ chạy thử (kịch bản trong `scenarios/ngay-nen/`) |
| `bash tools/wouldblock.sh <epoch bắt đầu> [epoch kết thúc] [nguon.json] [thư mục ra]` | Đếm quyết định chặn / "sẽ chặn" của responder theo từng IP trong một khoảng thời gian, đối chiếu với danh sách phân vai (hợp lệ / tấn công / thường trú). Chỉ đọc Elasticsearch. Mã thoát 1 khi có quyết định rơi vào IP hợp lệ |
| `bash tools/d1grace.sh` | Kiểm nhánh hạ cấp chặn của IP dùng chung (`SHARED_GRACE_S`) trên hệ thống thật: một IP thử bị chặn cả IP, rồi được báo là IP dùng chung; phải thấy lệnh chặn hạ xuống (IP, User-Agent). Kết quả trong `eval/results/d1grace-<thời điểm>/` |

Biến của `tools/scenario.sh`: `SC_DIR` (thư mục kịch bản), `SC_OUT_NAME` (tiền tố thư mục kết quả), `SC_CONT=1` (chạy liền
mạch, cho ngày nén) — xem `scenarios/README.md`.

Biến thay thế khi gọi `docker compose` (15/11/2026, mặc định giữ nguyên giá trị cũ; đặt biến trong shell hoặc `.env` rồi
`docker compose up -d <dịch vụ>`): `LONG_WINDOW_S`, `TTL_STEPS_S`, `MAX_TTL_S`, `SHARED_TTL_S` (responder); `RULE_TTL_S`
(rulegen); `TIER2_THRESHOLD`, `TIER2_DECISION`, `TIER2_MODEL_PATH` (classifier, biến cuối gán vào `MODEL_PATH` trong container).
Lưu ý: `tools/reset.sh` tạo lại responder, nên biến nào không có trong môi trường của shell gọi `reset.sh` (hay `scenario.sh`)
sẽ bị kéo về mặc định.

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
| classifier | `TIER2_THRESHOLD` / `TIER2_DECISION` / `TIER2_CONSTRUCT_GATE` | 0.50 / mass / 1 | Cấu hình tầng 2 từ 16/11: nhãn của model chỉ được tính khi một giá trị tham số có cấu trúc tấn công rõ (`services/constructs.py`); ngưỡng 0,50 kiểu `mass`. Cấu hình trước: 0.67 / argmax / 0. Model là bản 14/11 (bản 12/11 giữ ở `models/tier2_1211.joblib`). Ngưỡng này khác thang θ: điểm vượt ngưỡng được đổi sang 0,90–1,00 trước khi gửi responder (`TIER2_CONF_FLOOR`), điểm gốc lưu ở `t2_conf` |
| classifier | `TIER2_CONSTRUCT_RULES` | 2 | Bộ quy tắc cấu trúc: 1 = bộ gốc, 2 = thêm bộ bổ sung v2b (mặc định từ 16/11 13:10; `services/constructs.py`) |
| classifier | `TIER2_SYNTAX_GATE` | 0 | 1 = chỉ hỏi model khi giá trị tham số có ký tự cú pháp tấn công |
| classifier | `TIER2_MODE` | weighted | `observe`: nhãn tầng 2 chỉ ghi vào `t2_label`. `corroborate`: chỉ tính khi Cổng 2 cũng chặn request đó. `weighted` (15/11, mặc định sau khi áp bản vá): nhãn chỉ do model vẫn thành cảnh báo nhưng mang cờ `weighted` — responder tính nửa trọng số, không tính cửa sổ dài, không khoá ngay; Cổng 2 cũng chặn thì tính đủ. `enforce`: tính đủ mọi nhãn |
| classifier | `ATTACK_ARCHIVE` | 1 | Ghi thêm sự kiện có nhãn tấn công vào `attack-events-*` (giữ 1 năm) |
| classifier | `SCAN_MAX_BYTES` / `SCAN_MAX_PARAMS` | 524288 / 1000 | Trần quét mỗi request; vượt trần (hoặc thân bị ModSecurity cắt) thì gắn nhãn `uninspected` (dưới θ: ghi kiểm toán, không tự chặn) |
| classifier | `REFERER_CONFIDENCE` | 0.6 | Tấn công chỉ thấy trong Referer được ghi nhận dưới θ (nạn nhân XSS phản xạ không bị chặn) |
| responder | `MIN_CONFIDENCE` / `MAX_AGE_S` | 0.90 / 600 | θ và tuổi cảnh báo tối đa (giây) |
| responder | `RESPONDER_MODE` | enforce | `dryrun` = chạy thử, chỉ ghi `would_block`. Đổi lúc chạy: `nsmctl mode ...` (thắng biến này) |
| responder | `TIER2_WEIGHT` | 0.5 | Trọng số của cảnh báo `weighted` (chỉ do tầng 2) |
| responder | `T2_SOLO_BLOCK` | 0 | 0 = chỉ toàn cảnh báo `weighted` thì không bao giờ khoá IP; cần ít nhất một cảnh báo đủ trọng số trong cửa sổ ngắn (15/11, kịch bản 02). 1 = cho phép (10 cảnh báo / 60 giây là khoá) |
| responder | `SHARED_TTL_S` | 3600 | tier3 báo một IP là IP dùng chung thì responder nhớ điều đó trong ngần này giây (ngày nén đặt 300) |
| responder | `SHARED_GRACE_S` | 30 | tier3 báo IP dùng chung trong ngần này giây SAU một lệnh chặn cả IP do đếm ngưỡng -> hạ xuống chặn (IP, User-Agent gây chặn), giữ hạn và số lần vi phạm (tranh chấp thời gian, kịch bản 13, 15/11). Chặn tay / `shared_escalate` không bị hạ |
| responder | `STRONG_WEIGHT` | 1.0 | Trọng số cảnh báo từ luật tầng 1 "rất chắc" (`models/tier1_strong.json`). Mặc định tắt; 2,5 = khoá ở cảnh báo thứ 2 (làm khoá người dùng "mơ hồ" ở kịch bản 02) |
| responder | `OFFENSE_RESET_S` | 2592000 | Nhớ số lần tái phạm 30 ngày (sau khi áp bản vá; trước đó 7 ngày) |
| responder | `THRESHOLD` / `WINDOW_S` | 5 / 60 | Ngưỡng chặn k trong cửa sổ ngắn |
| responder | `LONG_THRESHOLD` / `LONG_WINDOW_S` | 12 / 86400 | Cửa sổ dài 24 giờ cho tấn công rải rác. **Phải lớn hơn `THRESHOLD`** |
| responder | `TTL_STEPS_S` / `MAX_TTL_S` | 900,3600,86400 / 86400 | Thời hạn chặn lần 1 / 2 / 3+: 15 phút → 1 giờ → 24 giờ (để trống `TTL_STEPS_S` thì dùng `BASE_TTL_S` nhân đôi như cũ) |
| responder | `SHARED_CIDRS` / `SHARED_ESCALATE` | (trống) / 3 | IP dùng chung (NAT, proxy) đã biết; IP được tier3 báo có nhiều User-Agent cũng được coi là dùng chung trong `SHARED_TTL_S` (3600). IP dùng chung bị chặn theo (IP, User-Agent); đủ 3 dấu vân tay bị chặn thì chặn cả IP |
| tier3 | `TIER3_N_HI`, `TIER3_MIN_404`, … | 100, 10, … | Cổng định hình hành vi (flood, recon, denied, bruteforce, enum) |
| tier3 | `TIER3_MIN_DENY_URI` / `TIER3_MIN_DENY_SINGLE` | 3 / 30 | Mẫu `denied` (401/403 dồn dập) cần ≥ 3 đường dẫn khác nhau, hoặc ≥ 30 lần trên một đường dẫn: người dùng gửi lại một form bị CRS chặn nhầm không làm cả IP bị chặn |
| tier3 | `TIER3_SHARED_MIN_UA` | 4 | Số User-Agent khác nhau / cửa sổ để báo responder đây là IP dùng chung |
| tier3 | `TIER3_STUFF_MIN_IPS` / `TIER3_STUFF_PER_IP` / `TIER3_STUFF_MIN_TOTAL` | 8 / 3 / 40 | Chiến dịch nhồi tài khoản phân tán (mẫu `stuffing`): ≥ 8 IP, mỗi IP ≥ 3 lần thử đăng nhập, tổng ≥ 40 trong một cửa sổ. "Thử đăng nhập" = POST tới `TIER3_LOGIN_RE` (`/login`) hoặc phản hồi 401 |
| tier3 | `TIER3_MIN_429` / `TIER3_FRAC_429` | 40 / 0.3 | Mẫu `ratelimit`: nguồn vẫn dội request dù bị Cổng 1 trả 429 liên tục (tier3 đọc thêm `gate1.logs` sau khi áp bản vá) |
| rulegen | `RULE_APPLY` | immediate | `immediate` (15/11, mặc định sau khi áp bản vá): luật qua kiểm tra là chặn ngay, kèm cảnh báo có lệnh gỡ. `shadow`: chạy thử `SHADOW_S` trước như tài liệu đặc tả |
| rulegen | `RULE_TTL_S` / `REVOKE_S` | 86400 / 21600 | Luật sống 24 giờ; hết hạn mà trong 6 giờ gần nhất còn chặn được tấn công thì tự gia hạn. Luật không khớp gì trong 6 giờ thì tự gỡ |
| rulegen | `REVOKE_BENIGN_HITS` / `CLEAN_MIN_EVENTS` | 3 / 10 | Tự gỡ luật khi nó chặn 3 request của "nguồn sạch có tiếng" (≥ 10 sự kiện lành tính trong 24 giờ trước khi có luật) |
| rulegen | `RULE_BAN_S` / `T2_MIN_SOURCES` | 86400 / 2 | Luật bị gỡ không được sinh lại trong 24 giờ; luật từ bằng chứng chỉ của tầng 2 cần mẫu từ ≥ 2 IP |
| rulegen | `INTERVAL_S` / `SHADOW_S` | 60 / 900 | Chu kỳ (60 giây sau khi áp bản vá; trước đó 300) và thời gian chạy thử khi `RULE_APPLY=shadow` (**giá trị lab**; triển khai thật: 86400) |
| rulegen | `MIN_BENIGN` | 100 | Corpus lành tính tối thiểu; thiếu thì không sinh/ban hành luật |
| rulegen | `EPSILON` | 0 | Tỷ lệ lưu lượng lành tính được phép khớp một ứng viên luật |
| nginx | `RELOAD_MIN_INTERVAL_S` | 2 | Tối đa một lần nạp lại blocklist mỗi N giây (16/11: 5 -> 2 sau khi đo; `eval/PROTOCOL.md`) |
| tier3 | `TIER3_LOGIN_COUNT` / `TIER3_LOGIN_2XX_OK` | failed / 0 | Bộ đếm chiến dịch nhồi tài khoản: không đếm lần đăng nhập rõ ràng thành công (16/11); `all` = cách cũ; `2XX_OK=1` cho ứng dụng báo thành công bằng 200 |
| nginx (`nginx.conf`) | `limit_req` | 20 r/s (vượt ngắn 40) mỗi IP; POST `/login…` 30/phút (vượt ngắn 10) mỗi IP; tổng 350 r/s | Giới hạn tốc độ ở Cổng 1 (sau khi áp bản vá). Vượt hạn mức → 429. Nguồn miễn trừ (`exempt.geo`, do enforcer ghi từ `EXEMPT_CIDRS` và `nsmctl exempt-add`) không bị giới hạn |
| apache | `LOG_MAX_MB` | 200 | Xoay `access.json` / `modsec_audit.json` / `error.log` khi vượt kích thước này (giữ 1 bản cũ) |
| apache, nginx | `LOG_ROTATE_CHECK_S` | 60 | Chu kỳ kiểm kích thước nhật ký (giây) |
| nginx | `LOG_MAX_MB` | 50 | Xoay `gate1.json` khi vượt kích thước này |
| classifier | `PENDING_WAIT_S` | 15 | Thời gian tối đa chờ thân request POST từ nhật ký kiểm toán trước khi phân loại không có thân |
| suricata | `LOG_MAX_MB` | 200 | Xoay `eve.json` / `stats.log` / `fast.log` khi vượt kích thước này |
| mọi dịch vụ Python | `HEARTBEAT_S` | 30 | Chu kỳ ghi nhịp tim vào `nsm-health-*` |

## Giới hạn đã biết
- **Tầng 2:** model gốc (run_4) gắn nhãn tấn công cho 40,7 % lưu lượng lành tính thật nên từ 12/11 chỉ được ghi nhận.
  Model đã được huấn luyện lại hai lần (12/11 và 14/11, lần sau có văn bản tự do); từ 15/11 dùng chế độ `weighted` để
  nhãn chỉ do model không khoá được người dùng (xem bảng tham số). Số đo: báo cáo kết quả 15/11. Model tầng 3 chưa được
  huấn luyện lại.
- Kafka và Elasticsearch đã bắt buộc xác thực nhưng CHƯA mã hoá (SASL_PLAINTEXT, HTTP): ai nghe lén
  được mạng giám sát vẫn đọc được mật khẩu. Ở bản một máy, lưu lượng này chỉ đi trong mạng Docker của máy.
- **Chế độ lab** (`bash tools/init-env.sh --lab`): DVWA không đòi đăng nhập, mức `low` — payload thực thi lệnh
  chạy thật trong container apache (mạng `app_net` không ra Internet). Mặc định là chế độ an toàn: request
  của các script nhận 302, payload vẫn đi qua hai cổng và được phát hiện nhưng không khai thác được thật.
- Giới hạn kết nối ở lớp TCP (stream) của nginx không sinh dòng nhật ký JSON. Các lỗi do khối http của nginx
  sinh ra (403, 429, 400, 414, 431, 505...) đều được ghi vào `gate-events-*`.
- **Cổng 2 dùng OWASP CRS 4.25.0** (từ 13/11/2026, thay gói Debian 3.3.4; tệp phát hành lưu trong `web/apache/crs/`),
  vẫn trên ModSecurity 2.9.7. CRS 4 thêm luật SSRF (934110/934120). Số đo Cổng 2 trước và sau mốc này không so trực
  tiếp được. Từ 14/11 CRS được tinh chỉnh cho lưu lượng thật (`web/apache/crs/nsm-tuning-*.conf`, gồm cho phép thân
  `text/plain`); bảo vệ một ứng dụng khác thì phải đo và tinh chỉnh lại.
- **Tầng 1 có luật cho 13 họ:** sqli, xss, rce (gồm Log4Shell, Shellshock), lfi, và từ 13/11: xxe, ssti, ssrf, deser,
  nosqli, ldap, crlf, rfi (chỉ tham số kiểu include), redirect (chỉ ghi nhận, độ tin cậy 0,6). NoSQLi/LDAP chỉ thấy
  trong cả thân JSON/XML thì chỉ ghi nhận (không phân biệt được với API dùng toán tử `$lt`... thật). Luật RCE đã siết:
  không áp lên đường dẫn, tên lệnh phải kết thúc đúng chỗ. Dữ liệu độc lập để đo: `eval/data/payloads_independent/`.
- ModSecurity 2.9 ghi thân request vào nhật ký kiểm toán JSON như chuỗi C: thân nhị phân (gzip...) bị cắt ở byte
  0 đầu tiên. Classifier nhận ra (so với `Content-Length`) và gắn nhãn `uninspected`, nhưng không soi được phần
  bị cắt.

## Ứng dụng đặt chỗ giả lập (từ 15/11/2026)
`web/apache/booking/`: cổng đặt chỗ trực tuyến nhỏ (PHP + SQLite, viết an toàn, dữ liệu tổng hợp: 10 000 khách, 50 000
lượt đặt chỗ), vhost `booking.local` trên cùng Apache với DVWA — gửi tới nginx với `Host: booking.local`. Sau khi áp
bản vá, ứng dụng được dựng trong image apache và container `client-booking` (10.10.10.21, **không** miễn trừ) chạy
`tools/benign_booking.sh` liên tục (sáu luồng người dùng bình thường, nghỉ `BOOKING_CLIENT_PAUSE` = 2 giây). Ứng dụng
không có lỗ hổng cài sẵn; kiểm chứng khai thác thật làm trên DVWA. Chi tiết: `web/apache/booking/README.md`.

## Khác với bản máy ảo
- 1 máy thay vì 3; Kafka 1 listener (kafka:9092) thay vì 2
- Không publish cổng 80 ra host (để tránh gộp IP). Tấn công từ container attacker nội bộ.
- Mọi thứ còn lại (2 cổng, cảm biến, chặn IP, TTL, sinh luật, dashboard) giữ nguyên.
