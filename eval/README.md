# eval — so sánh các bộ sinh luật ngoài Docker

Thư mục này đo chất lượng của các bộ sinh luật trên cùng một bộ dữ liệu, không cần stack Docker.
Chạy từ thư mục `nsm` (cần `scikit-learn`, `scipy`, `joblib` đúng phiên bản trong `services/requirements.txt`):

```bash
python -I -X utf8 -B eval/rule_eval.py
```

Mặc định 20 hạt giống, mất vài phút. Kết quả: bảng Markdown in ra màn hình và dữ liệu thô ở `eval/results/<tên>.json`.

| Tuỳ chọn | Ý nghĩa |
|---|---|
| `--seeds N` | Số lượt lặp (mỗi lượt chia dữ liệu khác nhau) |
| `--sizes 10,30,60` | Số payload "vừa quan sát được" cho mỗi lớp tấn công |
| `--gens G0,G1,G2n,G2` | Bộ sinh cần so sánh |
| `--pools` | Chỉ in kích thước các tập dữ liệu |

## Các bộ sinh

| Ký hiệu | Là gì | Mã |
|---|---|---|
| G0 | `rulegen` hiện tại: một chuỗi con chung, cổng ký tự đặc biệt viết tay | `services/rulegen.py` |
| G1 | Thuật toán cải tiến, không học: biến đổi theo lớp, luật 1–2 token, vẫn cổng viết tay | `services/rulegen_ml.py` |
| G2n | Như G1 nhưng thay cổng viết tay bằng mô hình Naive Bayes trên token | `services/rulegen_ml.py` |
| G2 | G2n + gom cụm theo nội dung bằng DBSCAN | `services/rulegen_ml.py` |

Mọi bộ sinh chỉ tạo ra *đặc tả* luật; `services/secrule.py` biên dịch đặc tả thành `SecRule`, kiểm tra tĩnh,
và mô phỏng cách ModSecurity áp luật để chấm điểm.

## Dữ liệu

- `data/seclists/` — payload và văn bản lành tính lấy từ SecLists (xem `data/seclists/SOURCE.md`).
- Payload chỉ được đưa vào tập đánh giá nếu **classifier của chính hệ thống** gắn đúng nhãn lớp, vì đó là
  thứ `rulegen` nhận được khi chạy thật.
- Mỗi lượt chia mỗi tập thành ba phần rời nhau: tri thức nền (40 %), quan sát (30 %), giữ riêng (30 %).

## Giới hạn

- Điểm số tính bằng bộ mô phỏng trong `secrule.py`, chưa đối chiếu với ModSecurity thật.
- Không có CRS trong vòng lặp: mọi payload classifier nhận ra đều được coi là đã lọt Cổng 2.
- Tỷ lệ chặn nhầm tính với giả định xấu nhất là văn bản lành tính nằm đúng tham số mà luật nhắm tới.

## Chuẩn hoá dataset bên ngoài và kiểm chứng khớp với hệ thống

Giao thức (chốt trước khi chạy): `eval/PROTOCOL.md`. Dataset nằm trong `data/` (`seclists/`, `openappsec/`,
`srbh2020/`, `httpparams/`).

**Bước 1 — chuẩn hoá** (không cần Docker; khoảng 12–15 phút, RAM đỉnh khoảng 2 GB):

```bash
python -I -X utf8 -B eval/normalize.py
```

Mỗi request đi qua đúng hàm `_classify_web` của classifier, ra `data/normalized/<nguồn>.jsonl.gz`.
Mặc định 6 tiến trình con. Đã đo: tiến trình chính (đọc, khử trùng, ghi) là nút cổ chai, nên 12 tiến trình
không nhanh hơn 6 mà tốn gần gấp đôi RAM.

**Bước 2 — kiểm tra kết quả:**

```bash
python -I -X utf8 -B eval/check_normalized.py > eval/results/normalized_check.md
```

**Bước 3 — kiểm chứng khớp với hệ thống thật** (stack phải chạy; image classifier và apache phải dựng lại vì
classifier đã có thêm trường `marg_*` và Apache ghi thêm Content-Type):

```bash
docker compose up -d --build
```

```bash
bash tools/parity.sh
```
