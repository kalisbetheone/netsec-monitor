# Cổng đặt chỗ trực tuyến (booking.local) — ứng dụng mẫu cho phòng thí nghiệm NSM

Một ứng dụng web nhỏ, bình thường, viết theo cách an toàn: tìm chuyến bay, tra mã đặt chỗ, đăng nhập xem hồ sơ,
giữ chỗ, và một API JSON cho "ứng dụng di động". Mục đích: cho hệ thống giám sát có trang thật và lưu lượng người
dùng bình thường để quan sát. PHP thuần (không framework), CSDL SQLite qua PDO (có sẵn trong image
`php:8.3-apache-bookworm`), không dùng tài nguyên bên ngoài.

**Toàn bộ dữ liệu là giả lập**, sinh tất định bằng `seed.php` (hạt giống cố định): không có người thật, không có
doanh nghiệp thật. Email dùng miền `example.test`; số điện thoại (`0000…`) và số giấy tờ (`9990…`) dùng tiền tố
không tồn tại ngoài đời.

## Cấu trúc

| Tệp | Vai trò |
|---|---|
| `seed.php` | (CLI) tạo CSDL tại `$BOOKING_DB` (mặc định `/var/lib/booking/booking.db`) và ghi `benign_pairs.txt` cạnh CSDL |
| `lib.php` | phần dùng chung: PDO, phiên, thoát ký tự HTML, khung trang, hàm nghiệp vụ. Nằm **ngoài** `public/` |
| `public/` | DocumentRoot: `index.php`, `search.php`, `booking.php`, `login.php`, `profile.php`, `hold.php`, `logout.php`, `api.php`, `health.php`, `style.css` |
| `benign_pairs.txt` | 48 dòng `MÃ<TAB>Tên` có thật trong CSDL (giống hệt tệp do `seed.php` sinh ra) |
| `booking-vhost.conf` | vhost Apache `booking.local` |
| `Dockerfile.snippet` | các dòng thêm vào `web/apache/Dockerfile` |
| `../../../tools/benign_booking.sh` | bộ sinh lưu lượng người dùng bình thường (sh + curl) |

## Dữ liệu do `seed.php` tạo

| Bảng | Số dòng | Ghi chú |
|---|---|---|
| `customers` | 10 000 | họ tên Việt có dấu và tên phương Tây; hơn 400 tên có dấu nháy đơn (O'Neil, D'Angelo, N'Dour…) |
| `flights` | 2 000 | mã `NS1001`…`NS3000`, 10 sân bay (HAN, SGN, DAD, CXR, PQC, HPH, VCA, HUI, DLI, VII), ngày bay 16/11/2026 – 14/01/2027 |
| `bookings` | 50 000 | `code` 6 ký tự chữ hoa + số, duy nhất |
| `holds` | 0 | giữ chỗ tạm, tự xoá sau 10 phút |

- **Tài khoản thử** (cho bộ sinh lưu lượng): `user1@example.test` … `user20@example.test`, mật khẩu `Passw0rd!1`.
  Mỗi tài khoản có ít nhất 2 đặt chỗ. Các khách còn lại có mật khẩu ngẫu nhiên không ai biết (không đăng nhập được).
- **Khách "đánh dấu"**: 5 khách có `full_name` bắt đầu bằng `CANARY-` và `id_number` = `CANARY-ID-0001` … `0005`
  (id 9996–10000, mỗi khách một đặt chỗ). Chỉ để hệ thống giám sát kiểm tra rằng chuỗi `CANARY` không bao giờ
  xuất hiện trong phản hồi HTTP gửi cho khách vãng lai. Không tài khoản nào đăng nhập được vào các khách này.
- **"Tên" khi tra cứu** = từ cuối cùng của họ tên (`Liam O'Neil` → `O'Neil`, `Nguyễn Văn An` → `An`), so sánh
  không phân biệt hoa thường.

Chạy: `BOOKING_DB=/var/lib/booking/booking.db php seed.php` → in một dòng
`seed ok: customers=10000 flights=2000 bookings=50000 holds=0 canary=5 …`; thoát khác 0 nếu lỗi.

## Các trang và mã trạng thái

Mọi ví dụ gửi tới nginx với tiêu đề `Host: booking.local`:
`curl -H 'Host: booking.local' 'http://10.10.10.10/...'`

| Yêu cầu bình thường | Kết quả |
|---|---|
| `GET /` hoặc `GET /index.php` | 200 — biểu mẫu tìm chuyến bay + biểu mẫu tra mã đặt chỗ |
| `GET /search.php?from=HAN&to=SGN&date=2026-12-01` | 200 — bảng chuyến bay (tối đa 50 dòng) |
| `GET /search.php?q=H%C3%A0%20N%E1%BB%99i` (q = `Hà Nội`) | 200 — khớp mã chuyến bay hoặc điểm đến |
| `GET /search.php?q=O%27Neil` | 200 — "Không có chuyến bay phù hợp" |
| `GET /booking.php?code=VB8LYM&last=O%27Neil` | 200 — đặt chỗ + tên hành khách, email/điện thoại đã che |
| `GET /booking.php?code=VB8LYM&last=Smith` (sai tên) hoặc mã không tồn tại | 404 — "Không tìm thấy" (cùng một thông báo) |
| `GET /login.php` | 200 — biểu mẫu |
| `POST /login.php` `email=user1@example.test&password=Passw0rd!1` | 302 → `profile.php`, đặt cookie `BOOKSESS` |
| `POST /login.php` sai email hoặc sai mật khẩu | 401 — biểu mẫu + thông báo lỗi |
| `GET /profile.php` (đã đăng nhập) | 200 — hồ sơ và đặt chỗ của chính khách đó |
| `GET /profile.php` (chưa đăng nhập) | 302 → `login.php` |
| `POST /hold.php` `flight_id=123` | 200 — xác nhận giữ chỗ 10 phút |
| `POST /hold.php` chuyến bay không tồn tại | 404 (sai định dạng: 400; hết chỗ: 409; quá 5 chỗ/phiên: 429) |
| `POST /logout.php` (hoặc GET) | 302 → `index.php` |
| `GET /health.php` | 200 — `ok customers=10000 flights=2000 bookings=50000 holds=N` (CSDL lỗi: 503 `fail`) |
| Sai phương thức (ví dụ `GET /hold.php`, `GET /api.php`) | 405 kèm tiêu đề `Allow` |

### API JSON — `POST /api.php`, `Content-Type: application/json`

| Thân yêu cầu | Kết quả |
|---|---|
| `{"action":"login","email":"user1@example.test","password":"Passw0rd!1"}` | 200 `{"ok":true,"customer":{…}}` + cookie phiên; sai: 401 |
| `{"action":"search","from":"HAN","to":"SGN","date":"2026-12-01","q":""}` | 200 `{"ok":true,"count":N,"flights":[…]}` |
| `{"action":"booking","code":"VB8LYM","last":"O'Neil"}` | 200 `{"ok":true,"booking":{…}}`; không khớp: 404 |
| `{"action":"profile"}` | 200 khi đã đăng nhập (cookie phiên); chưa đăng nhập: 401 |
| JSON hỏng, thiếu `action`, `action` lạ | 400 |
| JSON hợp lệ nhưng Content-Type không phải `application/json` | 415 (thân lớn hơn 8 KB: 413) |

Ví dụ:

```sh
curl -H 'Host: booking.local' -H 'Content-Type: application/json' -c /tmp/j -b /tmp/j \
     --data-binary '{"action":"login","email":"user1@example.test","password":"Passw0rd!1"}' http://10.10.10.10/api.php
curl -H 'Host: booking.local' -H 'Content-Type: application/json' -c /tmp/j -b /tmp/j \
     --data-binary '{"action":"profile"}' http://10.10.10.10/api.php
```

## Sáu luồng người dùng bình thường

`tools/benign_booking.sh` lặp lại sáu luồng này (chọn giả ngẫu nhiên; sáu phiên đầu chạy lần lượt a → f):

| Luồng | Các bước | Mã mong đợi |
|---|---|---|
| a. Tìm chuyến bay | `GET /index.php` → `GET /style.css` → `GET /search.php?from&to&date` → `GET /search.php?from&to` | 200 |
| b. Tra mã đặt chỗ | `GET /index.php` → `GET /booking.php?code&last` với một cặp trong `benign_pairs.txt` (kể cả tên có dấu nháy đơn) | 200 (gõ nhầm tên: 404 rồi 200) |
| c. Đăng nhập | `GET /login.php` → `POST /login.php` → `GET /profile.php` → `POST /logout.php` | 200, 302, 200, 302 (gõ nhầm mật khẩu: thêm một 401) |
| d. Ứng dụng di động | `POST /api.php` × 4: login, search, booking, profile — User-Agent `BookingApp/3.2 (Android 14)` | 200 |
| e. Từ khoá tự do | `GET /search.php?q=…` với `O'Neil`, `Côte d'Ivoire`, `Hà Nội`, `Đà Nẵng`… | 200 |
| f. Giữ chỗ | `GET /search.php?to=…` → `POST /hold.php` `flight_id=1..2000` | 200 |

```sh
# trong container curlimages/curl, cùng mạng với nginx
sh /tools/benign_booking.sh                       # chạy mãi, 1 giây/request
MAX_LOOPS=12 PAUSE=0 sh /tools/benign_booking.sh  # 12 phiên rồi in dòng tổng kết
FLOW=c MAX_LOOPS=1 sh /tools/benign_booking.sh    # chỉ chạy luồng c
```

Biến môi trường: `TARGET` (mặc định `http://10.10.10.10`), `HOST` (`booking.local`), `PAUSE` (1), `MAX_LOOPS`
(0 = mãi mãi), `FLOW` (a..f), `TYPOS` (1 = thỉnh thoảng gõ nhầm tên/mật khẩu như người thật; 0 = tắt).

## Các biện pháp an toàn trong mã

- Mọi câu SQL dùng prepared statement với tham số ràng buộc; từ khoá `LIKE` được thoát ký tự đại diện.
- Mọi dữ liệu in ra HTML đi qua `h()` (`htmlspecialchars`); JSON qua `json_encode`.
- `profile.php` và `api.php` (profile) chỉ lấy mã khách hàng từ phiên, không nhận tham số nào để xem người khác.
- Tra mã đặt chỗ cần đúng cả mã lẫn tên; sai cái nào cũng trả cùng một trang 404. Email/điện thoại luôn bị che,
  số giấy tờ không bao giờ xuất hiện ở trang công khai (và chỉ hiện 3 ký tự cuối trong hồ sơ của chính chủ).
- Mật khẩu lưu bằng bcrypt; đăng nhập đổi mã phiên; thông báo lỗi không phân biệt "sai email" và "sai mật khẩu".
- Cookie phiên `BOOKSESS`: `HttpOnly`, `SameSite=Lax`, `Secure` khi đi qua HTTPS; chế độ phiên nghiêm ngặt.
- Yêu cầu POST có tiêu đề `Origin` khác tên máy trong `Host` bị từ chối (403); API bắt buộc `application/json`.
- Tiêu đề `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`; không in lỗi PHP
  ra trang (lỗi ghi vào nhật ký máy chủ, người dùng nhận trang 500 chung).
- Ứng dụng **không** tự giới hạn số lần thử đăng nhập — việc phát hiện dò mật khẩu thuộc về hệ thống giám sát.

## Tích hợp

Xem `Dockerfile.snippet` và `booking-vhost.conf`. Tóm tắt:

- Mã nguồn ở `/var/www/booking` (DocumentRoot `/var/www/booking/public`), CSDL ở `/var/lib/booking/booking.db`.
- Thư mục `/var/lib/booking` **và** tệp CSDL phải thuộc `www-data` và ghi được: SQLite tạo tệp
  `booking.db-journal` trong thư mục đó khi `hold.php` ghi bảng `holds`. Thiếu quyền thì `hold.php` trả 500,
  các trang chỉ đọc vẫn chạy.
- Vhost đọc đường dẫn CSDL từ `SetEnv BOOKING_DB`. Tên tệp vhost phải xếp sau `000-default.conf` để vhost cũ vẫn
  là mặc định.
- Tệp phiên PHP nằm ở `/tmp` (mặc định của image), `www-data` ghi được sẵn.
