# Mốc số đo NSM — 16/11/2026 (lượt chốt)

Tài liệu này ghi lại **một** lượt đo đầy đủ trên cấu hình cuối cùng của hệ thống, chạy trên **một** commit, bằng đúng công cụ của lượt chốt ngày 15/11 (`tools/baseline.sh`). Sau lượt này việc cải tiến dừng lại; tài liệu chỉ ghi số đo và nguồn. NSM là hệ thống phòng thủ; mọi "tấn công" ở đây là lưu lượng thử do bộ kiểm thử của dự án sinh ra và chỉ gửi vào hệ thống của dự án, trong mạng Docker nội bộ.

Lượt này **không có tiêu chí ghi trước**: đây là lượt ghi nhận, không phải phép thử cho một thay đổi. Ngưỡng đạt/không đạt của từng kịch bản là ngưỡng đã có trong tệp kịch bản từ trước.

## 1. Mốc

| Mục | Giá trị |
|---|---|
| Commit đo | `6161e74`, nhánh `nang-cap-15-11`; nội dung trùng `master` (`c815b73`, pull request số 4) |
| Lệnh | `bash tools/baseline.sh chot1611` (chạy từ thư mục `nsm`) |
| Thời gian | 16/11/2026, 15:22:47 → 17:23:29 (2 giờ 1 phút) |
| Kết quả từng bước | `eval/results/baseline-chot1611/steps.txt` — 14 bước, mọi bước mã thoát 0; bản chép: `baseline-chot1611-steps.txt` |
| Môi trường | một máy Windows 11, Docker 29.8.2, 16 CPU, 20,5 GB RAM cấp cho Docker; 17 dịch vụ; chi tiết image ở `baseline-chot1611-env.txt` |
| Trước lượt đo | `env.txt` ghi 0 tệp chưa commit; mọi image của dự án được dựng lại từ mã của commit đo lúc 15:21; `stack.sh check` sạch |
| Sau lượt đo | `stack.sh check` lúc 17:24: tham số gốc, 17 dịch vụ, Cổng 2 ở chế độ chặn, không IP bị chặn, không luật tự sinh |

Cấu hình đang chạy (ghi trong báo cáo bench): tầng 2 `TIER2_CONSTRUCT_GATE=1`, `TIER2_CONSTRUCT_RULES=2`, `TIER2_DECISION=mass`, `TIER2_THRESHOLD=0.50`, `TIER2_MODE=weighted`; tầng 3 `TIER3_LOGIN_COUNT=failed`, `TIER3_LOGIN_2XX_OK=0`; responder `THRESHOLD=5`, `WINDOW_S=60`, `LONG_THRESHOLD=12`, `TIER2_WEIGHT=0.5`; nginx `RELOAD_MIN_INTERVAL_S=2`.

## 2. Số đo

### 2.1. Bộ kịch bản

Nguồn: `eval/results/scenarios-20261116-153141/`; bản chép: `kich-ban-20261116-153141-report.md`, `-results.jsonl`.

| Kết luận | 15/11 (`8498bcd`) | 16/11 (`6161e74`) | Kịch bản |
|---|---|---|---|
| ĐẠT | 41 | 42 | các kịch bản còn lại; lượt 16/11 có thêm kịch bản 48 |
| LỖ HỔNG ĐÃ BIẾT | 1 | 1 | 04 (xoay vòng 40 IP, mỗi IP dưới ngưỡng) |
| CHỈ ĐO | 3 | 3 | 20 (GoTestWAF), 21 (waf-bypass), 35 (khai thác thật, chỉ CRS) |
| KHÔNG ĐẠT | 0 | 0 | — |
| **Tổng** | **45** | **46** | |

Kết luận của 45 kịch bản chung giống hệt nhau ở hai lượt.

| Kịch bản | 15/11 | 16/11 |
|---|---|---|
| 01 – ma trận 16 họ × 12 vị trí × kỹ thuật né: request bị ít nhất một lớp phát hiện | 83,1 % (Cổng 2 80,3 %, bộ phân loại 74 %) | 82,6 % (Cổng 2 80,3 %, bộ phân loại 72 %) |
| 02 – người dùng hợp lệ: request bị bộ phân loại gắn nhãn tấn công (không ai bị khoá) | 56/300 | 21/300 |
| 03 – tấn công cơ bản, 4 IP | 4/4 bị khoá, trung vị 3,5 s | 4/4, 2,5 s |
| 04 – xoay vòng IP | 0/40 IP bị khoá | 0/40 IP bị khoá |
| 05 – các họ mới, 12 IP | 10/12 bị khoá, 7,0 s | 10/12, 4,0 s |
| 09 – dò mật khẩu từ một IP | khoá sau 11,7 s | 7,6 s |
| 10 – nhồi tài khoản 50 IP: bị khoá khi còn đang tấn công | 41/50 (9 IP bị khoá sau khi đã dừng) | 50/50 |
| 13 – IP dùng chung (NAT) | công cụ tấn công bị chặn sau 14,0 s; 0/75 request hợp lệ bị chặn lây | 15,6 s; 0/75 |
| 18 – bão chặn 150 IP | 150/150, trung vị 6,1 s; nginx nạp lại 4,2 lần/phút | 150/150, 3,3 s; 8,5 lần/phút (ngưỡng của kịch bản: 13) |
| 23 – tấn công rải rác | khoá bởi cửa sổ dài | như 15/11 |
| 27 – IP đã bị chặn: 403 tại Cổng 1 | khoá sau 3,0 s; 75/75; 1,1 ms | 4,6 s; 68/68; 1,1 ms |
| 32 – phát lại 600 request lành tính thật | Cổng 2 chặn 17/600 (2,8 %); bộ phân loại gắn nhãn 5/600 | 17/600; 3/600 |
| 34 – khai thác thật, không lớp nào chặn | 16/32 payload khai thác được | 16/32 |
| 35 – khai thác thật, chỉ CRS | còn 2/32 (`127.0.0.1;id`, `127.0.0.1\nid`) | còn 2/32, cùng hai payload |
| 36 – khai thác thật, đủ hai lớp | 0/32 | 0/32 |
| 37 – flood một IP | khoá sau 5,1 s; 71,3 % request nhận 429 | 3,3 s; 66,8 % |
| 38 – nhồi tài khoản 200 IP | 200/200 có quyết định khoá; 7 bot kịp thấy 403 | 200/200; 200 bot thấy 403 |
| 39 – flood phân tán 300 IP | 300/300; khách hợp lệ nhận 429 ở 2/60 request | 300/300; 5/60 |
| 40 – cao điểm hợp lệ | 6 000/6 000 thành công, 0 lần 429 | như 15/11 |
| 41 – luật tự sinh áp dụng ngay | luật 9900000 (rce); chặn 12/12 request kiểm chứng | như 15/11 |
| 42 – phát lại 1 000 request lành tính thật, phần mẫu chưa dùng | Cổng 2 chặn 35/1 000 (3,5 %; Wilson 95 %: 2,5–4,8 %); bộ phân loại 9/1 000 | 35/1 000; 9/1 000 |
| 45 – nhồi tài khoản vào cổng đặt chỗ, 100 IP | 100/100 có quyết định khoá; 9 bot kịp thấy 403 | 100/100; 79 bot thấy 403 |
| 46 – dò mã đặt chỗ | khoá sau 9,5 s | 8,0 s |
| 47 – chèn cú pháp SQL vào ô tìm chuyến | khoá sau 3,0 s; Cổng 2 chặn 20/20; 0/80 request hợp lệ bị chặn | 5,0 s; 20/20; 0/80 |
| 48 – khách thật đăng nhập đúng 12 lần giữa chiến dịch 100 IP | chưa có | khách không bị khoá (12/12 request đi qua); 100/100 bot bị khoá |
| 20 – GoTestWAF | tấn công bị chặn 317/668 (47,5 %); lành tính đi qua 128/141; điểm 63,08 | giống hệt |
| 21 – waf-bypass | chặn đúng 5 076, lọt 1 663 (75,3 %), chặn nhầm 9, lỗi 81 | giống hệt |

Trong 2 giờ của lượt đo, responder ghi 974 quyết định khoá; **không bản ghi quyết định nào** nhắm vào hai khách thường trú của lab (10.10.10.20 và 10.10.10.21; chỉ mục `audit-decisions-*`, đọc lúc 17:30).

### 2.2. Các phép đo khác của `baseline.sh`

| Phép đo | 15/11 | 16/11 | Nguồn 16/11 |
|---|---|---|---|
| sectest (phân quyền Kafka/ES, cổng nội bộ) | tất cả đạt | tất cả đạt | `baseline-chot1611/sectest.log` |
| parity (bộ mô phỏng luật so với ModSecurity thật) | 0,000 %; 0/1 973 request | 0,000 %; 0/1 973 request | `eval/results/parity-20261116-152503/report.md` |
| tier1sync (tầng 1 của bộ phân loại so với luật đồng bộ ở Cổng 2) | lệch 49/6 003 (0,82 %) | lệch 49/6 003 (0,82 %) | `eval/results/tier1sync-20261116-152924/report.md` |
| ruledemo, ruledemo-multi | luật tự sinh chặn payload chưa từng gửi từ IP mới; đối chứng lành tính 200 | như 15/11 | `baseline-chot1611/ruledemo.log`, `ruledemo-multi.log` |
| demo | 11 dòng đúng, 0 sai | 11 dòng đúng, 0 sai | `baseline-chot1611/demo.log` |

### 2.3. Bench

Nguồn: `bench-results/20261116-171909/report.md`; bản chép: `bench-20261116-171909-report.md`.

| Chỉ số | 15/11 | 16/11 |
|---|---|---|
| Phát hiện tấn công (hệ thống) | 65/65 (KTC 95 %: 94–100 %) | 65/65 (94–100 %) |
| Riêng Cổng 2 | 65/65 | 65/65 |
| Riêng bộ phân loại | 63/65 | 63/65 (tầng 1: 57, tầng 2: 6); hai mẫu sót: `data://…base64…`, `expect://id` |
| Bộ phân loại gắn nhãn nhầm, lành tính thường | 2/28 | 0/28 |
| Bộ phân loại gắn nhãn nhầm, lành tính "khó" | 8/27 | 5/27 |
| Cổng 2 chặn nhầm, lành tính "khó" | 1/27 | 1/27 (`/login.php?redirect=..%2Fhome`) |
| Chặn IP, SQLi | 3/3, trung vị 3,0 s | 3/3, 2,5 s |
| Chặn IP, RCE | 3/3, 4,0 s | 3/3, 2,5 s |
| Chặn IP, dò quét | 3/3, 3,0 s | 3/3, 1,7 s |
| Chặn IP, flood một luồng | 2/3, 3,8 s | 3/3, 1,6 s |
| Từ quyết định tới lúc nginx chặn (12 lần) | không chép lại ở đây | 0,2–0,7 s |
| Tấn công rải rác (B5) | chặn ở cảnh báo thứ 12, 177,8 s | cảnh báo thứ 12, 176,1 s |
| Hiệu năng, 1 kết nối | p50 5,8 ms | p50 5,4 ms |
| Hiệu năng, 8 kết nối | 442 req/s | 516 req/s |
| Hiệu năng, 32 kết nối | 367 req/s, p95 179,7 ms | 443 req/s, p95 129,3 ms |
| Độ trễ pipeline sau khi ngừng tải | ghi đủ sau 3,2 s | ghi đủ sau 2,3 s |
| Tài nguyên: RAM tổng lúc nghỉ / khi tải | 5 528 / 5 648 MiB | 5 834 / 5 945 MiB |
| Tài nguyên: CPU tổng khi tải (% một lõi) | 1 113 | 1 002 |

## 3. Đọc bảng so sánh thế nào

- **Mỗi lượt là một lần chạy.** Chênh lệch giữa hai cột không có khoảng tin cậy. Thời gian khoá IP nhanh hơn ở 03, 05, 09, 18, 37, 46 và ở bench, nhưng chậm hơn ở 13, 27, 47; không kết luận được từ một cặp số.
- **Giữa hai lượt có bốn thay đổi cùng lúc** (cấu hình tầng 2 A2 và bộ quy tắc bổ sung, Filebeat gửi lại nhanh hơn, nginx nạp lại 2 giây, cách đếm đăng nhập của tầng 3). Lượt này không tách được phần của từng thay đổi; số tách riêng nằm ở các phép đo ghi trong `eval/PROTOCOL.md` (các mục 16/11).
- **Thông lượng.** Lượt 15/11 chạy khi máy còn bốn phiên làm việc song song; lượt sáng 15/11 từng đo 535 và 493 req/s. Số 16/11 (516 và 443 req/s) nằm trong khoảng đó: không có bằng chứng hệ thống nhanh lên.
- **Flood 3/3.** Cách bench dừng flood theo số request (mục 19 của danh sách giới hạn) chưa sửa. Ở lượt này cả ba lần IP bị chặn trước mốc 5 000 request (sau 1 164–2 019 request).
- **Số bot "kịp thấy 403" ở 38 và 45** (7 → 200, 9 → 79) là số bot còn đang gửi khi lệnh chặn có hiệu lực. Số IP có quyết định khoá là 200/200 và 100/100 ở cả hai lượt.
- **Kịch bản 01** giảm khoảng 5 request được phát hiện trên 1 152 (83,1 % → 82,6 %): bộ phân loại gắn nhãn ít hơn (852 → 830 request) từ khi nhãn tầng 2 phải qua cổng cấu trúc. Cổng 2 không đổi (925 request).
- **GoTestWAF và waf-bypass giống hệt** lượt 15/11 tới từng con số: các thay đổi ngày 16/11 không chạm vào độ phủ của Cổng 2.
- **CPU lúc nghỉ** trong báo cáo bench ghi Kafka 156 % (lượt 15/11: 2,8 %). Đây là một ảnh chụp tức thời ngay sau pha trước; chưa điều tra.

## 4. Sau commit đo

Sau `6161e74` chỉ có commit tài liệu (tệp này, các bản chép trong `docs/baseline/`, mục "lượt đo chốt" ngày 16/11 của `eval/PROTOCOL.md`). Không commit nào chạm vào `services`, `web`, `models`, `docker-compose.yml`, `nginx.conf`, `scenarios`, `tools`.

Một ngoại lệ, ngoài đường xử lý request: lúc 18:12 ngày 16/11 sửa `soc/grafana/provisioning/dashboards/provider.yml` (một dòng). Tệp này trỏ sai thư mục nên Grafana không nạp dashboard nào, ít nhất từ 12/11; lượt đo chốt vì vậy chạy khi **không có dashboard** (nguồn dữ liệu và luật cảnh báo vẫn nạp đúng, nên kịch bản 30 và 41 không bị ảnh hưởng). Sau khi sửa: dashboard `nsm-overview` được nạp; chạy `tools/demo.sh` thì truy vấn của cả 21 panel trả số, không lỗi (tấn công 0 → 48, lệnh chặn IP 0 → 6). Không số đo nào ở mục 2 phụ thuộc dashboard.

Danh sách đầy đủ các giới hạn: `Danh-sach-gioi-han-NSM.md` và `Bao-cao-chot-NSM-16-11.md` (thư mục `GSANM`, ngoài kho mã).
