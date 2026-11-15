# Bảng 2 × 2 của tầng 2 — tách ảnh hưởng của model và của chế độ (P0, 15/11 khoảng 11:55)

Phép đo: `bash tools/bench.sh detect` (pha phát hiện của bench, cùng một bộ request có nhãn), chỉ đổi model và chế độ tầng 2, mọi thứ khác giữ nguyên.

| Lượt | Model | Chế độ | Lành tính thường bị gắn nhãn | Lành tính "khó" bị gắn nhãn | Bộ phân loại bắt tấn công | Thư mục |
|---|---|---|---|---|---|---|
| a | 12/11 (mass 0,87) | `corroborate` | 0 / 28 | 1 / 27 | 62 / 65 (95,4 %) | `bench-results/20261115-013451/` |
| c | 12/11 (mass 0,87) | `weighted` | 0 / 28 | 8 / 27 | 62 / 65 (95,4 %) | `bench-results/20261115-115213/` |
| d | 14/11 (argmax 0,67) | `corroborate` | 0 / 28 | 1 / 27 | 63 / 65 (96,9 %) | `bench-results/20261115-115031/` |
| b | 14/11 (argmax 0,67) | `weighted` | 2 / 28 | 8 / 27 | 63 / 65 (96,9 %) | `bench-results/20261115-062502/` |

Cả bốn lượt: hệ thống (Cổng 2 hoặc bộ phân loại) bắt 65/65; Cổng 2 riêng 100 %.

## Kết luận

- **Mức tăng báo nhầm trên câu "khó" (1 → 8/27) do chế độ `weighted`, không do model.** Hai model cho cùng 8/27 ở `weighted` và cùng 1/27 ở `corroborate`.
- **Hai mẫu "thường" bị gắn nhầm** (form đăng nhập `username=admin&password=password`) chỉ xuất hiện với model 14/11 ở chế độ `weighted`. Đây là phần duy nhất do model.
- **Chênh lệch khả năng bắt tấn công giữa hai model là 1 request trên 65**, như nhau ở cả hai chế độ. Không đủ để nói model nào bắt tốt hơn.
- **Chế độ `weighted` không làm bộ phân loại bắt thêm tấn công nào trên bộ bench này** (62 = 62, 63 = 63): mọi tấn công trong bench đều đã bị Cổng 2 chặn, nên nhãn "chỉ tầng 2" không thêm gì. Muốn thấy lợi ích của `weighted` phải có bộ payload mà CRS và regex tầng 1 bỏ lọt (việc 4, để sau).

## Ghi chú phương pháp

- Lượt c chạy lần đầu lúc 11:49 bị **hỏng**: Git Bash đổi giá trị biến `TIER2_MODEL_PATH=/models/tier2_1211.joblib` thành `C:/Program Files/Git/models/...`, classifier không nạp được model tầng 2. Kết quả lần đó (`bench-results/20261115-114927/`) bị loại. Chạy lại với `MSYS_NO_PATHCONV=1`, nhật ký classifier xác nhận `tier2 model loaded ... decision=mass θ=0.87`.
- Mỗi cấu hình chạy một lần; bộ bench nhỏ (28 + 27 + 65 request).
