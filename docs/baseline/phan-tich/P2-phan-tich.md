# P2 — phân tích từ lượt đo `scenarios-20261115-124042`

Sinh bởi `nsm-wip-15-11/phoi-hop/p2_phan_tich.py`. Chỉ đếm từ dữ liệu thô của lượt đo; không gửi request nào.

## 1. Kịch bản 34, 35, 36: khai thác thật trên DVWA, theo họ

Mỗi request của tác nhân kiểu `exploit` có ba trường được dùng: `fam` (họ), `gate` (lớp nào đã trả lời) và `exploited` (phản hồi cho thấy ứng dụng đã bị khai thác).

- **Khai thác được** = `exploited` là true.
- **Bị ngăn** = Cổng 1 hoặc Cổng 2 trả lời thay ứng dụng (`gate` khác `pass`).
- **Tới ứng dụng nhưng không khai thác được** = `gate` là `pass` và `exploited` là false. Ở cấu hình (a), đây là payload **không có hiệu lực** với DVWA: nó không chứng minh được gì về phòng thủ.

### (a) không lớp nào chặn — kịch bản 34

| Họ | Số payload | Khai thác được | Bị ngăn | Tới ứng dụng, không khai thác được | Trong số payload có hiệu lực ở (a): còn khai thác được |
|---|---|---|---|---|---|
| sqli | 8 | 2 | 0 | 6 | 2 / 2 |
| xss | 8 | 7 | 0 | 1 | 7 / 7 |
| lfi | 8 | 2 | 0 | 6 | 2 / 2 |
| rce | 8 | 5 | 0 | 3 | 5 / 5 |
| **Tổng** | **32** | **16** | **0** | **16** | **16 / 16** |

### (b) chỉ CRS — kịch bản 35

| Họ | Số payload | Khai thác được | Bị ngăn | Tới ứng dụng, không khai thác được | Trong số payload có hiệu lực ở (a): còn khai thác được |
|---|---|---|---|---|---|
| sqli | 8 | 0 | 7 | 1 | 0 / 2 |
| xss | 8 | 0 | 8 | 0 | 0 / 7 |
| lfi | 8 | 0 | 8 | 0 | 0 / 2 |
| rce | 8 | 2 | 5 | 1 | 2 / 5 |
| **Tổng** | **32** | **2** | **28** | **2** | **2 / 16** |

### (c) CRS + luật tầng 1 đồng bộ — kịch bản 36

| Họ | Số payload | Khai thác được | Bị ngăn | Tới ứng dụng, không khai thác được | Trong số payload có hiệu lực ở (a): còn khai thác được |
|---|---|---|---|---|---|
| sqli | 8 | 0 | 8 | 0 | 0 / 2 |
| xss | 8 | 0 | 8 | 0 | 0 / 7 |
| lfi | 8 | 0 | 8 | 0 | 0 / 2 |
| rce | 8 | 0 | 8 | 0 | 0 / 5 |
| **Tổng** | **32** | **0** | **32** | **0** | **0 / 16** |

### Nhận xét rút từ bảng

- Ở cấu hình (a) có 16/32 payload có hiệu lực (50,0 %). Kế hoạch đặt mức mong muốn là 80 %; kịch bản 34 đặt ngưỡng 50 %.
- Số payload có hiệu lực theo họ: sqli 2, xss 7, lfi 2, rce 5. Họ có dưới 5 payload có hiệu lực: sqli, lfi — với các họ này, bảng chưa đủ để kết luận theo tiêu chí "mỗi họ ít nhất 5 payload" của kế hoạch.
- Cột cuối là con số nên dùng khi trình bày: nó chỉ tính trên các payload đã được chứng minh là khai thác được khi không có phòng thủ.

## 2. Kịch bản 42: Cổng 2 chặn nhầm trên lưu lượng lành tính thật (mẫu không trùng)

| Số đo | Giá trị |
|---|---|
| Request hợp lệ đã gửi | 1000 |
| Bị Cổng 2 chặn (403) | 35 |
| Tỷ lệ chặn nhầm | 3,5 % |
| Khoảng tin cậy Wilson 95 % | 2,5 % – 4,8 % |
| Cận trên so với ngưỡng 5 % của kế hoạch | dưới ngưỡng |
| Cận trên so với mục tiêu 3 % | chưa đạt |
| Các kết quả khác | pass: 964, reject: 1 |

Theo từng IP nguồn (bị chặn / đã gửi): 10.10.15.16 8/250; 10.10.15.17 7/250; 10.10.15.18 16/250; 10.10.15.19 4/250.

Lưu ý khi đọc khoảng tin cậy: các request được phát lại từ vài website, nên chúng không độc lập hoàn toàn (một website có một kiểu URL bị chặn thì nhiều request cùng bị chặn). Khoảng tin cậy thật rộng hơn con số trên.

### 10 mã luật khớp nhiều nhất trên các IP hợp lệ

Nguồn: chỉ mục `apache-errors-*`, 51 bản ghi gộp, 273 lần khớp, 4 IP hợp lệ, đúng khoảng thời gian của kịch bản. Một request bị chặn thường khớp nhiều luật.

| # | Mã luật | Số lần khớp | Số IP hợp lệ gặp | Thông điệp của luật (rút gọn) |
|---|---|---|---|---|
| 1 | 920180 | 76 | 4 | POST without Content-Length and Transfer-Encoding headers |
| 2 | 942550 | 14 | 4 | JSON-Based SQL Injection |
| 3 | 942100 | 5 | 2 | SQL Injection Attack Detected via libinjection |
| 4 | 920340 | 5 | 4 | Content-Type header missing from request with non-zero Content-Length |
| 5 | 920640 | 5 | 4 | Content-Type header missing from request with body |
| 6 | 921130 | 4 | 3 | HTTP Response Splitting Attack |
| 7 | 932130 | 4 | 2 | Remote Command Execution: Unix Shell Expression Found |
| 8 | 931120 | 3 | 2 | Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?) |
| 9 | 932270 | 2 | 2 | Remote Command Execution: Unix Shell Expression Found |
| 10 | 943120 | 2 | 2 | Possible Session Fixation Attack: SessionID Parameter Name with No Referer |

Hai luật điều khiển (không tính vào bảng trên): 949110 = 34 lần (luật ra quyết định chặn theo điểm bất thường (không phải luật phát hiện)); 980170 = 109 lần (luật tổng kết điểm (ghi nhận, không phát hiện)).

Đối chiếu: số lần khớp của 949110 (34) khác số request bị 403 (35); chênh lệch có thể do bản ghi đến trễ hoặc do request bị chặn bởi luật khác (luật tầng 1 đồng bộ, luật tự sinh).

