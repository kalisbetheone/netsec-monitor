# scenarios/tang-2 — bộ thử "CRS và regex tầng 1 đều bỏ lọt"

Đo lợi ích của tầng 2 (model) với payload mà Cổng 2 bỏ lọt. Mọi request là lưu lượng thử gửi vào hệ thống của dự án.
Tiêu chí, ngưỡng và kết quả ngày 15/11/2026: `eval/PROTOCOL.md`; bảng số đo: `docs/baseline/t2test-20261115-182204.md`.

| Tệp | Nội dung |
|---|---|
| `bo-thu.jsonl` | 52 payload đã cố định (lớp, phần gieo / giữ lại, lượt lọc nơi payload được gửi lần đầu) |
| `gieo-a.jsonl`, `gieo-b.jsonl`, `gieo-c.jsonl` | 34 payload gieo, ba thứ tự cho ba IP |
| `giu-lai.jsonl` | 18 payload giữ lại, chỉ gửi ở pha kiểm chứng |
| `doi-chung.jsonl` | 60 văn bản hợp lệ của nhóm đối chứng |
| `doc-tay.json` | ghi chép đọc tay: đã đọc bao nhiêu, giữ payload nào |
| `loc-cong-2.toml`, `loc-cong-2b.toml` | bước lọc qua Cổng 2 (cần `ung-vien*.jsonl`, sinh bằng `eval/t2test_candidates.py`) |
| `44-chi-tang-2-thay.toml` | kịch bản đo |
| `td-8-tang-2-hoc-may.toml` | bản TRÌNH DIỄN của kịch bản 44 (2 vòng gieo, pha kiểm chứng ở giây 110, ngưỡng trình diễn); chạy bằng `bash tools/demo-tang2.sh` |

Chạy (từ thư mục `nsm`):

    SC_DIR=scenarios/tang-2 SC_OUT_NAME=t2test bash tools/scenario.sh 44-chi-tang-2-thay
    bash tools/t2test.sh fetch eval/results/t2test-<thời điểm>/44-chi-tang-2-thay
    bash tools/t2test.sh report eval/results/t2test-<thời điểm>

`report` cần các thư mục kết quả của bước lọc ghi trong `bo-thu.jsonl` (trường `loc`) để tính số đo 1.
