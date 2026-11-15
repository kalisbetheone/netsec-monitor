# Mốc số đo NSM — 15/11/2026

Tài liệu này ghi lại **một** lượt đo đầy đủ, chạy trên **một** commit, để mọi con số trong báo cáo chốt đều truy được về tệp nguồn. NSM là hệ thống phòng thủ; mọi "tấn công" ở đây là lưu lượng thử do bộ kiểm thử của dự án sinh ra và chỉ gửi vào hệ thống của dự án, trong mạng Docker nội bộ.

## 1. Mốc

| Mục | Giá trị |
|---|---|
| Commit đo | `8498bcd`, nhánh `nang-cap-15-11`, đã push lên `github.com/kalisbetheone/netsec-monitor` |
| Lệnh | `bash tools/baseline.sh cuoi` (chạy từ thư mục `nsm`) |
| Thời gian | 15/11/2026, 12:32:27 → 14:32:32 (2 giờ) |
| Kết quả từng bước | `nsm/eval/results/baseline-cuoi/steps.txt` — 14 bước, mọi bước mã thoát 0 |
| Môi trường | một máy Windows 11, Docker Compose, 17 dịch vụ; chi tiết image ở `baseline-cuoi/env.txt` |
| Trạng thái sau lượt đo | `stack.sh check` lúc 14:33: tham số gốc, 17 dịch vụ, `SecRuleEngine On`, không IP bị chặn, không luật tự sinh |

**Mã đang chạy có đúng là commit đo không.** Đã kiểm sau lượt đo:
- `git diff 8498bcd -- nginx.conf web services` rỗng: cấu hình nginx, mã các dịch vụ và thư mục dựng image không lệch so với commit đo.
- Tệp `nginx.conf` trong container nginx trùng mã băm với `nsm/nginx.conf` của commit đo.
- Mã trong container enforcer trùng mã băm với image dựng lại lúc 12:28.
- Image của classifier, tier3, responder, rulegen, logsink được dựng lại lúc 12:28, ngay trước lượt đo.
- `env.txt` ghi "5 tệp chưa commit": đó là công cụ ngày nén (`tools/ngaynen.*`, `tools/wouldblock.*`, `scenarios/ngay-nen/`) và bản sửa kịch bản trình diễn (`tools/present.sh`, `scenarios/trinh-dien/`, `scenarios/README.md`). Lượt đo không dùng tệp nào trong số này.

Phiên bản thành phần bên ngoài: nginx (image dựng từ `web/nginx`), Apache + ModSecurity 2.9.7 + CRS 4.25, Kafka 3.7.2, Elasticsearch 8.15.3, Filebeat 8.19.25, Grafana 11.2.0, MariaDB 11.4, Suricata 7.0, curl 8.10.1.

## 2. Số đo

### 2.1. Bộ kịch bản

Nguồn: `nsm/eval/results/scenarios-20261115-124042/` (`results.jsonl`, `report.md`).

| Kết luận | Số kịch bản | Kịch bản |
|---|---|---|
| ĐẠT | 41 | các kịch bản còn lại |
| LỖ HỔNG ĐÃ BIẾT | 1 | 04 (xoay vòng 40 IP, mỗi IP dưới ngưỡng) |
| CHỈ ĐO | 3 | 20 (GoTestWAF), 21 (waf-bypass), 35 (khai thác thật, chỉ CRS) |
| KHÔNG ĐẠT | 0 | — |
| **Tổng** | **45** | |

Đây là lượt đầu tiên cả bộ chạy trọn trên một commit mà không có kịch bản nào không đạt. Con số "38/42" trong bản báo cáo sáng 15/11 là số ghép từ hai lượt; số của lượt này thay cho nó.

| Kịch bản | Số đo |
|---|---|
| 04 – xoay vòng IP | 0/40 IP bị chặn (đúng như kỳ vọng ghi sẵn); 99 % request bị phát hiện (Cổng 2 88 %, classifier 94 %) |
| 13 – IP dùng chung (NAT) | công cụ tấn công bị chặn; 0/75 request hợp lệ bị Cổng 1 chặn lây |
| 34 – khai thác thật, không lớp nào chặn | 16/32 payload khai thác được (SQLi 2, XSS 7, LFI 2, RCE 5) |
| 35 – khai thác thật, chỉ CRS | còn 2/32 khai thác được: `127.0.0.1;id` và `127.0.0.1\nid` (họ RCE) |
| 36 – khai thác thật, đủ hai lớp | còn 0/32; Cổng 2 chặn 32/32 |
| 38 – nhồi tài khoản 200 IP | 200/200 IP bị chặn; 60/60 request hợp lệ thành công |
| 39 – flood phân tán 300 IP | 300/300 IP bị chặn |
| 40 – cao điểm hợp lệ | 6 000/6 000 request thành công; 0 request bị 429; 0 bị Cổng 2 chặn |
| 41 – luật tự sinh áp dụng ngay | luật 9900000 (rce) được ban hành; Cổng 2 chặn 12/12 request kiểm chứng; Grafana chuyển sang Alerting 2 lần |
| 42 – phát lại 1 000 request lành tính thật, phần mẫu chưa dùng | Cổng 2 chặn 35/1 000 (3,5 %; Wilson 95 %: 2,5–4,8 %); classifier gắn nhãn 9/1 000 (0,9 %; Wilson 95 %: 0,5–1,7 %). Bốn IP phát lại được miễn trừ để đo hết request, nên kịch bản này không đo việc khoá IP (xem mục 4, dòng 1b) |
| 45 – nhồi tài khoản vào cổng đặt chỗ, 100 IP | 100/100 IP bị chặn; 60/60 request hợp lệ thành công |
| 46 – dò mã đặt chỗ | IP bị chặn sau 9,5 s (trung vị) |
| 47 – chèn cú pháp SQL vào ô tìm chuyến | IP bị chặn sau 3,0 s; Cổng 2 chặn 20/20 request của vai được miễn trừ; 0/80 request hợp lệ bị chặn |
| 20 – GoTestWAF | tấn công bị chặn 317/668 (47,5 %); lành tính đi qua 128/141 (90,8 %); điểm 63,08 |
| 21 – waf-bypass | theo cặp (payload, vùng đặt): chặn đúng 5 076, lọt 1 663 (75,3 % chặn), chặn nhầm 9, lỗi 81 |

### 2.2. Các phép đo khác của `baseline.sh`

| Phép đo | Kết quả | Nguồn |
|---|---|---|
| sectest (phân quyền Kafka/ES, cổng nội bộ) | tất cả đạt | `baseline-cuoi/sectest.log` |
| parity (mô phỏng luật so với ModSecurity thật) | 0,000 % lệch; 0/1 973 request có luật lệch | `eval/results/parity-20261115-123433/report.md` |
| tier1sync (classifier tầng 1 so với luật đồng bộ ở Cổng 2) | lệch 49/6 003 (0,82 %) | `eval/results/tier1sync-20261115-123834/report.md` |
| ruledemo, ruledemo-multi | luật tự sinh chặn payload chưa từng gửi từ IP mới (403); đối chứng lành tính 200 | `baseline-cuoi/ruledemo.log`, `ruledemo-multi.log` |
| demo | 11 dòng đúng, 0 dòng sai | `baseline-cuoi/demo.log` |

### 2.3. Bench

Nguồn: `nsm/bench-results/20261115-142806/report.md`.

| Chỉ số | Kết quả |
|---|---|
| Phát hiện tấn công (hệ thống) | 65/65 (khoảng tin cậy 95 %: 94–100 %) |
| Riêng Cổng 2 | 65/65 |
| Riêng bộ phân loại | 63/65 (96,9 %) |
| Báo nhầm của bộ phân loại | lành tính thường 2/28; lành tính "khó" 8/27 |
| Chặn IP, SQLi | 3/3 lần, trung vị 3,0 s |
| Chặn IP, RCE | 3/3 lần, trung vị 4,0 s |
| Chặn IP, dò quét | 3/3 lần, trung vị 3,0 s |
| Chặn IP, flood một luồng | **2/3 lần**, trung vị 3,8 s; lần 2 (IP 10.10.10.167) gửi hết 5 000 request mà không thấy 403 ở Cổng 1 |
| Tấn công rải rác (B5) | bị chặn ở cảnh báo thứ 12, 177,8 s sau request đầu |
| Hiệu năng, 1 kết nối | p50 5,8 ms |
| Hiệu năng, 8 kết nối | 442 req/s (cao nhất) |
| Hiệu năng, 32 kết nối | 367 req/s, p95 179,7 ms |

Hai điều phải đọc kèm:
- **Flood 2/3.** Responder ra quyết định chặn ở cả 3 lần (`decisions.json`). Ở lần 2, quyết định có ở giây 4,0 và có hiệu lực tại nginx ở giây 5,5; bench dừng khi đủ 5 000 request, 47 ms sau đó, nên không kịp thấy 403. Đây là giới hạn của cách bench dừng, không phải bỏ sót. Kịch bản 37 (flood một IP, có đo cả 429) đạt 7/7 phép kiểm trong cùng lượt.
- **Thông lượng thấp hơn lượt sáng** (442 so với 535 req/s ở 8 kết nối; 367 so với 493 req/s ở 32 kết nối). Trong lúc đo, máy còn chạy bốn phiên làm việc song song, nên con số này không so sánh được với lượt sáng và không nên đọc là hệ thống chậm đi. Mã trên đường xử lý request (nginx, Apache, luật) không đổi giữa hai lượt.

Bảng theo họ của kịch bản 34–36, 10 luật CRS khớp nhiều nhất ở kịch bản 42 và phần so với mốc trước nâng cấp: `nsm-wip-15-11/phoi-hop/P2-phan-C.md` và `P2-phan-tich.md`.

## 3. Các phép đo ngoài lượt đo đầy đủ (cùng ngày)

| Phép đo | Kết quả | Commit lúc đo | Nguồn |
|---|---|---|---|
| Bảng 2 × 2 của tầng 2 (model × chế độ) | mức tăng báo nhầm trên câu "khó" (1 → 8/27) do chế độ `weighted`, không do model | `bc8ace7` + thay đổi I3 (đã vào `ece03ae`) | `bench-results/20261115-013451/`, `-115213/`, `-115031/`, `-062502/` |
| Kiểm nhánh hạ cấp D1 trên hệ thống thật | đạt 2/2 lần | như trên | `eval/results/d1grace-20261115-115418/`, `-115642/` |
| Kịch bản 47, lần chạy đầu | không đạt 4/5 do lỗi thiết kế cách chấm; sửa rồi chạy lại đúng một lần: đạt 6/6 | trước `a5371b9` | `nsm/eval/PROTOCOL.md`; `nsm-wip-15-11/phoi-hop/47-ban-dau-lan-chay-1.toml` |

## 4. Ngày mô phỏng nén 12 lần

Đây là phép thay cho đợt chạy thử 24 giờ. Nó **không phải 24 giờ thật**: một "ngày" được dựng từ 24 khung giờ, chạy liền nhau trong chưa đầy 90 phút.

| Mục | Giá trị |
|---|---|
| Lệnh | `bash tools/ngaynen.sh` (chạy từ thư mục `nsm`) |
| Công cụ | commit `33faba8` (`tools/ngaynen.*`, `tools/wouldblock.*`, `scenarios/ngay-nen/`); mã của hệ thống vẫn là commit đo `8498bcd` |
| Thời gian | 15/11/2026, 15:04:37 → 16:33:28; 5 331 giây = 88 phút 51 giây; mã thoát 0 |
| Một khung giờ | trung bình 222 giây (3 phút 42 giây) |
| Nguồn | `nsm/eval/results/ngaynen-20261115-150440/tong-ket.md`; bản chép: `nsm/docs/baseline/ngaynen-20261115-150440-tong-ket.md` |

**Hai hệ số nén.**
- Tham số thời gian của hệ thống nén đúng 12 lần: cửa sổ dài 86 400 → 7 200 s; thời hạn chặn 900 / 3 600 / 86 400 → 75 / 300 / 7 200 s; thời gian nhớ IP dùng chung 3 600 → 300 s; thời hạn sống của luật tự sinh 86 400 → 7 200 s.
- Nhịp lưu lượng nén 16,2 lần (86 400 / 5 331), vì mỗi khung giờ chỉ dài 222 giây chứ không phải 300 giây.
- Hệ quả: cửa sổ dài và thời hạn sống của luật (7 200 s) dài hơn cả ngày nén (5 331 s). Lịch sử vi phạm vì vậy được nhớ lâu hơn so với ngày thật, nên phép thử khắt khe hơn một chút với tiêu chí 1.

**Cách chạy.** Responder ở chế độ chạy thử (`dryrun`): chỉ ghi "sẽ chặn", không chặn. Lưu lượng hợp lệ theo bốn loại khung giờ (đêm, thường, văn phòng, cao điểm), cộng 7 khách thường trú chạy suốt đợt. Tấn công thử được gieo từ hai IP cố định ở giờ 01, 09 và 20. Trong 70 giây đầu của giờ 01, Cổng 2 cố ý chỉ ghi nhận, để bộ sinh luật có đầu vào.

**Kết quả theo tiêu chí** (tiêu chí và ngưỡng được ghi trong công cụ trước khi chạy):

| # | Tiêu chí | Số đo | Kết quả |
|---|---|---|---|
| 1 | Không quyết định "sẽ chặn" nào vào IP hợp lệ | 0/814 IP hợp lệ có quyết định | ĐẠT |
| 1c | Không quyết định nào vào IP ngoài danh sách phân vai | 0 IP | ĐẠT |
| 1b | Quyết định vào IP phát lại lưu lượng thật (ghi nhận riêng, không tính vào tiêu chí 1) | **12/12 IP có quyết định "sẽ chặn"**; 33 quyết định; lý do `immediate:behaviour` | ghi nhận |
| 2 | Hai IP gieo tấn công bị "sẽ chặn" ở mỗi giờ gieo, thời hạn tăng dần | cả hai IP: 75 → 300 → 7 200 s | ĐẠT |
| 3 | Vai hợp lệ: 429 ≤ 1 %; Cổng 2 chặn ≤ 1 % (lưu lượng sinh ra), ≤ 5 % (phát lại); thành công ≥ 99 % (sinh ra) | sinh ra: 27 584 request, 0 bị Cổng 2 chặn, 0 lần 429, 100 % thành công; phát lại: 186/4 665 bị Cổng 2 chặn (3,99 %), 0 lần 429 | ĐẠT |
| 4 | Vòng đời luật tự sinh (chỉ ghi nhận) | 1 luật (9900000, lớp rce), còn sống lúc kết thúc, 11 lần khớp thật | ghi nhận |
| 5 | Hệ thống về trạng thái gốc sau đợt thử | `stack.sh check` lúc 16:35: tham số gốc, 17 dịch vụ, `SecRuleEngine On`, không IP bị chặn, không luật tự sinh | ĐẠT |

Cả 24 khung giờ đều được chấm đạt (3/3 phép kiểm mỗi khung). Tổng cộng có 39 quyết định "sẽ chặn" trên 14 IP: 33 vào 12 IP phát lại, 6 vào 2 IP gieo tấn công.

**Số đo khác trong ngày nén.**
- Khách cao điểm: 19 500 request, 100 % thành công, 0 lần 429.
- Bảy khách thường trú: 2 146 đến 2 678 request mỗi khách; không request nào bị Cổng 1 hay Cổng 2 chặn, không lần 429 nào.
- Giờ 20: sáu IP mới gửi biến thể RCE chưa từng gửi; Cổng 2 chặn 12/12 request. Số đo không tách được bao nhiêu request trong số này do luật tự sinh chặn và bao nhiêu do CRS.
- Tỷ lệ Cổng 2 chặn lưu lượng phát lại (3,99 %) cùng mức với kịch bản 42 (3,5 %). Các request lấy từ cùng tập lưu lượng thật, nên đây không phải một mẫu độc lập mới.

**Dòng 1b phải đọc thế nào.**
- Cả 12 IP phát lại lưu lượng thật đều nhận quyết định "sẽ chặn". Ở chế độ chặn thật, cả 12 IP này sẽ bị khoá.
- Nguyên nhân là mẫu dò đường dẫn (`recon`) của tier3: trong cửa sổ 60 giây có ít nhất 15 request, ít nhất 10 phản hồi 404 và tỷ lệ 404 từ 50 %. Mỗi IP phát lại gửi khoảng 30 request mỗi phút; 4 475/4 698 request của 12 IP này (95,3 %) trả 404.
- Lượng 404 đó sinh ra từ cách thử: đường dẫn của những website khác được gửi vào DVWA, nên gần như không đường dẫn nào tồn tại. Khách thật của chính ứng dụng không tạo ra mẫu này. Vì vậy kết quả không cho thấy khách thật bị chặn nhầm.
- Điều chưa đo được: một khách thật gặp nhiều trang 404, chẳng hạn khi ứng dụng đổi cấu trúc đường dẫn hoặc có liên kết hỏng. Muốn đo cần lưu lượng thật của chính ứng dụng.
- IP 10.10.4.16 có hai quyết định cùng thời hạn 75 s và cùng "lần vi phạm 1", khác các IP còn lại (75 → 300 s). Bản ghi của IP này có kèm dấu vân tay User-Agent, nghĩa là có quyết định được ra theo khoá (IP, User-Agent) dành cho IP dùng chung; khoá mới thì đếm lại từ lần 1. Đây là giải thích theo mã (`services/responder.py`) và theo `wouldblock.json`; chưa đối chiếu từng bản ghi kiểm toán trong Elasticsearch.

**Giới hạn của phép thử.**
- Lưu lượng là mô phỏng và phát lại, không phải lưu lượng của khách thật.
- Thời gian thật là 89 phút. Các hiện tượng chỉ xuất hiện theo thời gian thật (rò bộ nhớ, đầy đĩa, xoay nhật ký, trôi đồng hồ) không được kiểm.
- Lượt thử hai khung giờ lúc 14:35 (`eval/results/ngaynen-20261115-143504/`) là lượt kiểm công cụ, không tính vào kết quả. Công cụ không đổi giữa lượt thử và lượt đủ 24 khung giờ.

## 5. Trình diễn

Chưa chạy ba lượt chính thức tại thời điểm ghi mục 1–3. Kết quả sẽ được ghi ở đây sau khi chạy.

## 6. Thay đổi sau commit đo

Sẽ ghi `git diff --stat 8498bcd..HEAD` khi chốt.
