# P2 — phần C: phân tích lượt đo cuối (commit 8498bcd)

Mọi số dưới đây được đếm lại từ dữ liệu thô. Không chạy lại gì, không cần khoá stack, Elasticsearch và nhật ký container chỉ được đọc, và không chép payload nào.

Đường dẫn tính từ `GSANM/nsm/`. Các tên thư mục viết tắt:

| Viết tắt | Thư mục | Ghi chú |
|---|---|---|
| `SC` | `eval/results/scenarios-20261115-124042/` | kịch bản, lượt cuối |
| `SC0` | `eval/results/scenarios-20261115-020159/` | kịch bản, lượt trước nâng cấp, chạy lại trong `baseline-truoc-nang-cap` (xem `steps.txt` và `scenarios.log` của lượt đó) |
| `BE` | `bench-results/20261115-142806/` | bench, lượt cuối |
| `BE0` | `bench-results/20261115-013451/` | bench, lượt trước nâng cấp |
| `BE1` | `bench-results/20261115-062502/` | bench, lượt sau nâng cấp lúc 06:25 |

Bản đầy đủ của hai bảng đầu (kèm định nghĩa từng cột) là `phoi-hop/P2-phan-tich.md`, do `phoi-hop/p2_phan_tich.py` sinh ra.

Đối chiếu với P0.md mục 14:33: **mọi số đều khớp**, không có chỗ nào lệch.

## 1. Khai thác thật trên DVWA theo họ (kịch bản 34, 35, 36)

Nguồn: `SC/34-…/runs.jsonl`, `SC/35-…/runs.jsonl`, `SC/36-…/runs.jsonl`. Mỗi họ có 8 payload, tổng 32.

Cách đọc các cột:
- **Bị ngăn**: Cổng 1 hoặc Cổng 2 trả lời thay cho ứng dụng.
- **Payload có hiệu lực**: payload khai thác được ở cấu hình (a), tức khi không có lớp chặn nào.
- **Còn khai thác được / payload có hiệu lực**: con số nên dùng khi trình bày, vì nó loại các payload vốn không tác dụng với DVWA.

| Họ | Payload có hiệu lực ở (a) | (a) không lớp nào chặn — khai thác được | (b) chỉ CRS — bị ngăn | (b) còn khai thác được / có hiệu lực | (c) CRS + luật tầng 1 — bị ngăn | (c) còn khai thác được / có hiệu lực |
|---|---|---|---|---|---|---|
| sqli | 2 | 2/8 | 7/8 | 0/2 | 8/8 | 0/2 |
| xss | 7 | 7/8 | 8/8 | 0/7 | 8/8 | 0/7 |
| lfi | 2 | 2/8 | 8/8 | 0/2 | 8/8 | 0/2 |
| rce | 5 | 5/8 | 5/8 | 2/5 | 8/8 | 0/5 |
| **Tổng** | **16** | **16/32** | **28/32** | **2/16** | **32/32** | **0/16** |

- Ở (b), 2 payload rce đã lọt qua CRS và khai thác được. Luật tầng 1 đồng bộ chặn được cả hai ở (c).
- Ở (b), 2/32 request tới được ứng dụng nhưng không khai thác được: 1 của sqli, 1 của rce.
- **Hạn chế:** sqli và lfi mỗi họ chỉ có 2 payload có hiệu lực, chưa đủ tiêu chí "mỗi họ ít nhất 5 payload" của kế hoạch. Kết luận cho hai họ này còn yếu.
- **Sửa báo cáo:** "Chỉ CRS: 0/32" trong `GSANM/Ket-qua-nang-cap-NSM-15-11.md` sai. Lượt đêm và lượt cuối đều cho 2/32 (2/16 tính trên payload có hiệu lực). Mục 4.3 của `GSANM/Danh-gia-dot-nang-cap-NSM-15-11.md` sai theo cùng lý do.

## 2. Kịch bản 42: chặn nhầm trên 1 000 request lành tính thật, phần mẫu không trùng

Nguồn số đếm: `SC/42-phat-lai-mau-khong-trung/runs.jsonl` và `SC/results.jsonl` (mục `metrics.benign`).

| Số đo | Kết quả | Khoảng tin cậy Wilson 95 % | So với ngưỡng |
|---|---|---|---|
| Cổng 2 chặn nhầm (403) | 35/1000 = 3,5 % | 2,5 % – 4,8 % | dưới ngưỡng 5 % của kịch bản; chưa đạt mục tiêu 3 % |
| Classifier gắn nhãn tấn công | 9/1000 = 0,9 % | 0,5 % – 1,7 % | điểm ước lượng dưới ngưỡng 1 %; cận trên vượt 1 % |
| IP hợp lệ bị khoá | 0/4 | — | đạt |

- Các kết quả khác của 1 000 request: 964 đi qua, 1 bị Cổng 1 từ chối với mã 414 (URL quá dài).
- Chặn nhầm theo IP: 10.10.15.16 8/250; 10.10.15.17 7/250; 10.10.15.18 16/250; 10.10.15.19 4/250.
- Các request được phát lại từ vài website nên không độc lập hoàn toàn. Khoảng tin cậy thật rộng hơn con số trong bảng.

### 10 luật CRS khớp nhiều nhất trên các IP hợp lệ

Nguồn: chỉ mục Elasticsearch `apache-errors-*`, lọc theo 4 IP vai benign và đúng khoảng t0–t1 trong `SC/42-…/obs.json`. Công cụ: `phoi-hop/p2_es_rules.py`; bản sao đầu ra nằm trong thư mục tạm của phiên P2.

Tổng cộng có 51 bản ghi gộp, 273 lần khớp. Một request bị chặn thường khớp nhiều luật.

| # | Luật | Số lần khớp | Số IP hợp lệ gặp | Ý nghĩa |
|---|---|---|---|---|
| 1 | 920180 | 76 | 4 | POST không có Content-Length và Transfer-Encoding |
| 2 | 942550 | 14 | 4 | SQLi dạng JSON |
| 3 | 942100 | 5 | 2 | SQLi (libinjection) |
| 4 | 920340 | 5 | 4 | thiếu Content-Type khi Content-Length khác 0 |
| 5 | 920640 | 5 | 4 | thiếu Content-Type khi có thân request |
| 6 | 921130 | 4 | 3 | HTTP Response Splitting |
| 7 | 932130 | 4 | 2 | RCE: biểu thức shell Unix |
| 8 | 931120 | 3 | 2 | RFI: URL kết thúc bằng "?" |
| 9 | 932270 | 2 | 2 | RCE: biểu thức shell Unix |
| 10 | 943120 | 2 | 2 | Session fixation: tham số SessionID không có Referer |

- Hai luật điều khiển không tính vào bảng: 949110, luật ra quyết định chặn, khớp 34 lần; 980170, luật tổng kết điểm, khớp 109 lần.
- 949110 khớp 34 lần trong khi có 35 lần 403. Chênh lệch 1 có thể do một bản ghi đến trễ hoặc do một luật khác chặn.
- Nhận xét: nhóm luật kiểm tra giao thức (920180/920340/920640) chiếm phần lớn số lần khớp. Lưu lượng phát lại có các POST thiếu header, nên đây là ứng viên đầu tiên khi tinh chỉnh tiếp CRS. Chi tiết nằm ngoài phạm vi phần C.

## 3. So với lượt trước nâng cấp

| Số đo | Trước (`SC0`, `BE0`) | Cuối (`SC`, `BE`) | Nguồn |
|---|---|---|---|
| Số kịch bản | 33 | 45 | `results.jsonl` |
| ĐẠT / lỗ hổng đã biết / chỉ đo / không đạt | 29 / 2 (04, 10) / 2 / 0 | 41 / 1 (04) / 3 / 0 | `results.jsonl`, trường `verdict` |
| 32 (600 request thật, phần mẫu dùng để tinh chỉnh CRS): Cổng 2 chặn | 17/600 = 2,8 % (Wilson 1,8–4,5 %) | 17/600, giống hệt | `metrics.benign.gates` |
| 32: classifier gắn nhãn | 1/600 = 0,17 % (0,03–0,94 %) | 5/600 = 0,83 % (0,36–1,94 %) | `metrics.benign.classifier_flagged` |
| 33 (vòng đời luật), vai benign: classifier gắn nhãn | 0/40 | 4/40 = 10 % (4,0–23,1 %) | như trên |
| 20 GoTestWAF | điểm 63,08 (tp 317/668 bị chặn, tn 128/141 đi qua) | giống hệt | `extra` của 20 |
| 21 waf-bypass (theo tệp) | PASSED 564, BYPASSED 498, FALSED 3, FAILED 81 | giống hệt | `extra` của 21 |
| Bench: hệ thống bắt được / riêng Cổng 2 / riêng classifier | 65/65 / 100 % / 95,4 % | 65/65 / 100 % / 96,9 % | `report.md` mục tóm tắt |
| Bench: báo nhầm lành tính thường / khó | 0/28 / 1/27 | 2/28 / 8/27 | như trên |
| Bench: chặn IP flood | 3/3, trung vị 4,2 s | 2/3, trung vị 3,8 s (xem mục 4) | như trên |
| Bench: p50 1 kết nối / thông lượng cao nhất | 5,2 ms / 504 req/s | 5,8 ms / 442 req/s | như trên |

**Những gì không so được:**
- Kịch bản 34–42 và 45–47 chưa có ở lượt trước, vì chúng được thêm trong đợt nâng cấp. Riêng 42 (mẫu không trùng) không có số trước nâng cấp. Số gần nhất để so là kịch bản 32, nhưng 32 dùng đúng phần mẫu đã dùng để tinh chỉnh CRS nên lạc quan hơn.
- Hiệu năng chỉ so được thô: lượt trước chưa có `limit_req` ở Cổng 1, và đo trên lab một máy nên giá trị tuyệt đối dao động theo tải nền.

**Đọc bảng:**
- Cổng 2 (CRS) không đổi trên mọi phép đo so được: 32, 20, 21 cho số giống hệt.
- Tỷ lệ classifier gắn nhãn lưu lượng lành tính tăng ở 32, 33 và ở bench (lành tính khó tăng từ 1/27 lên 8/27). Điều này khớp với việc chuyển tầng 2 sang chế độ `weighted`, đã ghi trong bản đánh giá; model 14/11 không phải nguyên nhân.
- Ở cả hai lượt, nhãn của classifier không dẫn tới khoá IP: kịch bản 42 có 0/4 IP bị khoá.

## 4. Bench: vì sao flood chỉ bị chặn IP 2/3 lần

Nguồn:
- `BE/mttr.jsonl`, `BE/decisions.json`, `BE/report.md` mục 4;
- nhật ký container `nsm-enforcer-1` và `nsm-nginx-1`, đọc bằng `docker logs -t` trong khoảng 07:29:20–07:30:00 UTC;
- `tools/bench.py:267-283`, `web/nginx/entrypoint.sh:34-43`.

**Kết luận: hệ thống CÓ chặn IP 10.10.10.167. "Không bị chặn" là giới hạn của phép đo: bench dừng ở 5 000 request, đúng lúc nginx vừa nạp lại blocklist.**

Diễn biến lần 2 (10.10.10.167, tính từ request đầu tiên lúc 07:29:39,00):

| Mốc | Thời điểm (UTC) | Giây | Nguồn |
|---|---|---|---|
| Responder ra quyết định chặn (`immediate:behaviour`) | 07:29:43,00 | 4,0 | `BE/decisions.json` |
| Enforcer ghi blocklist.map (8 IP) | 07:29:44,41 | 5,4 | nhật ký enforcer |
| nginx nạp lại blocklist | 07:29:44,49 | 5,5 | nhật ký nginx (`[watch] blocklist reloaded`) |
| Request thứ 5 000, cũng là request cuối, nhận 429 | 07:29:44,53 | 5,5 | nhật ký truy cập nginx: 5 000 dòng của 10.10.10.167, 0 dòng `blocked=1` |

Nguyên nhân:
1. **Có giới hạn tốc độ, client chạy nhanh hơn nên chạm mốc 5 000 sớm hơn.** Từ 15/11, nginx trả 429 ngay cho phần vượt 20 request/giây. Client của bench không phải chờ Apache nên gửi khoảng 900 request/giây, và chạm mốc `--max-req 5000` (`tools/bench.py:273`) sau khoảng 5,5 s.
   - Ở `BE0` (chưa có giới hạn), client chỉ gửi khoảng 170–200 request/giây. Ba lần flood dừng ở 823, 537 và 776 request, vì bị chặn trước khi chạm mốc 5 000.
   - Mọi lần flood ở `BE1` và `BE` đều gửi 2 700–5 000 request, sát mốc.
2. **Thời gian từ quyết định tới khi nginx thực thi dao động 0,2–3,2 s**, vì hai điểm chờ nối tiếp nhau:
   - Enforcer ghi map sau quyết định 0–1,4 s.
   - nginx nạp lại tối đa một lần mỗi `RELOAD_MIN_INTERVAL_S=5` giây, và vòng kiểm tra tự động chạy mỗi 1–2 s (`entrypoint.sh:38-42`). Ở lần 1, quyết định lúc 07:29:32,63 nhưng nginx chỉ nạp lại lúc 07:29:35,71, vì lần nạp trước (chặn IP rce #3) mới diễn ra lúc 07:29:28,31.
   - Lần 2 quyết định ở giây 4,0, cộng 1,5 s thực thi là vượt mốc dừng của client chừng vài chục mili giây.
3. Lượt 06:25 (`BE1`) có lần 3 (10.10.10.168) cũng dừng đúng ở 5 000 request mà không thấy 403. Dạng giống hệt, nhưng tôi không kiểm nhật ký container của lượt đó.

Ý nghĩa thực tế:
- Trong 5,5 s đó, chỉ 151 request của IP tấn công tới được ứng dụng; 4 849 request còn lại bị nginx trả 429.
- Sau đó IP bị chặn hẳn: map của enforcer có thêm IP lúc 07:29:44,41, và lần nạp kế tiếp nằm trong lượt.

Đề xuất cho P0 (P2 không sửa): bench chỉ nên dừng theo thời gian đối với flood, chẳng hạn bỏ mốc 5 000 hoặc tăng lên cỡ 30 000. Một cách khác là gửi thêm một request kiểm tra sau mốc dừng. Như vậy bench đo được thời gian chặn thật thay vì "không bị chặn". Nếu cần ghi vào báo cáo chốt: "flood 2/3 là giới hạn của bench (dừng ở 5 000 request); hệ thống ra quyết định chặn ở cả 3/3 lần (`BE/decisions.json`)".
