# NSM-train — huấn luyện trên Google Colab

Thư mục này được dựng từ `nsm/train/make_notebooks.py`. Đặt nó ở `MyDrive/NSM-train` (đúng đường dẫn notebook mặc định).

```
NSM-train/
  notebooks/01_tier2_classifier.ipynb          huấn luyện lại tầng 2 của classifier
  notebooks/02_rule_selection_ranker_llm.ipynb  bộ chọn luật: ML ranker + 3 LLM (zero-shot, LoRA, GGUF)
  data/tier2_*.jsonl.gz      dữ liệu tầng 2 (train/valid + 3 tập test độc lập)
  data/rulesel_*.jsonl.gz    dữ liệu chọn luật (cụm tấn công + ứng viên đã chấm điểm)
  code/feats.py, secrule.py, rulegen_ml.py     đúng mã của hệ thống (không sửa)
  code/tier2_current.joblib  model tầng 2 đang chạy (để so sánh)
  output/                    notebook tự tạo, kết quả ghi vào đây
```

## Thứ tự chạy

| Notebook | Runtime nên chọn | Thời gian ước tính | Kết quả |
|---|---|---|---|
| 01 | CPU **High-RAM** (không cần GPU; scikit-learn chạy CPU) | 2–3 giờ (bản chạy thử 1/12 dữ liệu mất ~12 phút trên máy 16 luồng) | `output/tier2/tier2_new.joblib`, `metrics.json`, `docker-compose-env.txt` |
| 02 | GPU **L4** (High-RAM) | 1,5–2,5 giờ | `output/rulesel/results.json`, `ranker_g2r.joblib`, `lora_*`, `gguf_*/…gguf` + `Modelfile` |
| 03 | GPU **A100 40 GB** (hoặc A100 80 GB / H100 nếu có). **Không dùng L4** — thiếu VRAM | 3–4 giờ (A100), ~2 giờ (H100) | `output/rulesel_large/results_large.json`, `lora_qwen3.8-27b/` |

Notebook 03 so model Qwen lớn (`Qwen/Qwen3.8-27B`, ~18 GB tải về máy Colab ở dạng 4 bit) với hai model nhỏ của
notebook 02 về chất lượng chọn luật và mức ảo giác. Chạy sau notebook 02 (đọc `results.json` của nó). Nếu runtime
bị ngắt, chạy lại từ đầu: phần đã xong được đọc lại từ `results_large.json` và bỏ qua.

**Mục 8 của notebook 03 (thêm 15/11/2026): đo lại H1 có lưu câu trả lời thô.** H1 ở mục 7 phần lớn do dữ liệu (đa số
cụm không có token nào thoả ngưỡng 80 %), nên mục 8 lưu câu trả lời và chấm riêng trên các cụm có đáp án. Cách chạy:
Run all lần nữa trên **A100 40 GB**. Các mục 4–6 được bỏ qua nhờ `results_large.json` (không tinh chỉnh lại; bản tinh
chỉnh được đo bằng adapter đã lưu trong `output/rulesel_large/lora_qwen3.8-27b`), chỉ mục 8 chạy: khoảng 20–30 phút gồm
cả tải model. Muốn chỉ đo hai model nhỏ thì chọn L4: phần 27B tự bỏ qua khi GPU dưới 34 GB. Kết quả:
`output/rulesel_large/replies/*.jsonl` (câu trả lời thô) và các khoá `_h1v2*` trong `results_large.json`. Bản notebook
và `results_large.json` của lần chạy 15/11 được giữ ở `notebooks/03_large_qwen_hallucination_lan2_15-11.ipynb` và
`output/rulesel_large/results_large_lan2_15-11.json`.

**Notebook 01 chia cho 3 phiên chạy cùng lúc (thêm 15/11/2026).** Thay vì một phiên học lần lượt mọi ứng viên:
- mở `01_tier2_classifier_phien1.ipynb`, `_phien2.ipynb`, `_phien3.ipynb`, mỗi tệp ở một phiên riêng, rồi Run all ở cả
  ba (mỗi phiên vẫn phải cài scikit-learn 1.6.1 và Run all lần hai như mục 4 dưới đây). Loại runtime nào cũng được:
  scikit-learn chỉ dùng CPU, nên L4 chỉ khác ở số CPU và RAM;
- mỗi phiên học phần ứng viên của mình và ghi vào `output/tier2/parts/<tên ứng viên>.joblib` + `.json`. Không mở chung
  một tệp notebook ở hai phiên: Colab sẽ lưu đè lên nhau;
- khi cả ba phiên in "xong phần của mình", chạy bước gộp: `01_tier2_classifier_gop.ipynb` (vài phút, không cần GPU),
  hoặc trên máy cá nhân: `NSM_SHARD=gop NSM_TRAIN_BASE=<thư mục NSM-train> python train/notebooks_src/01_tier2_classifier.py`.
  Bước gộp chọn model theo đúng quy tắc của bản một phiên và ghi `tier2_new.joblib`, `metrics.json`,
  `docker-compose-env.txt` như trước. Thiếu phần của ứng viên nào thì bước gộp dừng và nêu tên;
- bản một phiên `01_tier2_classifier.ipynb` vẫn chạy như cũ. Phần XGBoost nghiên cứu chỉ có ở bản một phiên.

**Đợt cải thiện tầng 2 — thư mục `NSM-train-v3` (vòng 1, 15/11/2026) và `NSM-train-v4` (vòng 2, 16/11/2026).** Vòng 2 = vòng 1 +
1 202 payload SQLi / chèn lệnh từ nguồn tải thêm (`eval/data/payloads_extra/SOURCE.md`); nên chạy vòng 2. Dữ liệu `tier2_*` của
đợt này khác hai đợt trước:
- payload tấn công có cờ `g2` ("pass" = lọt Cổng 2 thật và có cấu trúc tấn công rõ); các payload đó được cấy thêm;
- thêm văn bản hợp lệ "khó" (từ khoá SQL / lệnh shell, ký hiệu) vào train / valid, cờ `hard`;
- hai tập kiểm tra mới: `tier2_test_hardtext` và `tier2_test_residual` (tấn công thật của SR-BH mà Cổng 2 để lọt).
Notebook 01 nhận ra dữ liệu này (in "V2: True") và tự đổi: 6 ứng viên (M2, M3 × trọng số 1 / 3 / 10), mục tiêu chọn là phát
hiện trên payload lọt Cổng 2 (trung bình đều theo lớp), thêm ràng buộc báo nhầm ≤ 5 % trên văn bản hợp lệ khó. Cách chạy:
ba phiên, mỗi phiên một tệp `01_tier2_classifier_phien<i>.ipynb` trong `NSM-train-v4/notebooks`; xong cả ba thì gộp.
Tiêu chí được ghi trước trong `nsm/eval/PROTOCOL.md` (mục 15/11/2026 23:00 và mục 16/11/2026). Dựng lại dữ liệu:
`train/t2_pool.py` (rồi `test`, `extra`) → bước lọc qua Cổng 2 → `train/t2_pool_result.py`, `train/t2_hard_benign.py`, rồi
`train/build_tier2_dataset.py`.

1. Mở notebook trong Colab (chuột phải → Open with → Google Colaboratory).
2. Runtime → Change runtime type → chọn như bảng trên.
3. Runtime → Run all. Ô đầu tiên hỏi quyền truy cập Drive: chấp nhận.
4. Notebook 01 cài đúng scikit-learn 1.6.1 (bản hệ thống dùng) rồi **tự khởi động lại runtime**; khi đó chỉ cần
   Run all thêm một lần nữa.
5. Notebook 02 tải 3 model từ Hugging Face về **máy Colab** (`Qwen/Qwen3-4B`, `microsoft/Phi-4-mini-instruct`,
   `Qwen/Qwen2.5-Coder-3B-Instruct`, tổng ~20 GB ở dạng bf16), không tải gì về máy cá nhân.

Nếu runtime bị ngắt giữa chừng ở notebook 02, chạy lại từ đầu: phần ML chỉ mất vài phút; muốn bỏ qua phần đã xong,
xoá model đó khỏi `MODELS` / `FT` ở ô tương ứng.

## Đưa kết quả về hệ thống

**Tầng 2 (notebook 01)**
1. Chép `output/tier2/tier2_new.joblib` thành `nsm/models/tier2.joblib` (giữ bản cũ để quay lại).
2. Đặt 3 biến trong `output/tier2/docker-compose-env.txt` (`TIER2_THRESHOLD`, `TIER2_DECISION`,
   `TIER2_SYNTAX_GATE`) cho dịch vụ `classifier` trong `docker-compose.yml`.
3. `docker compose up -d --build classifier`, rồi chạy `tools/demo.sh` và `tools/bench.sh` để so trước/sau.

**Bộ chọn luật (notebook 02)** — chưa tích hợp vào `rulegen` đang chạy; kết quả dùng cho báo cáo và quyết định:
- `results.json`: bảng so sánh Oracle / G2n / G1 / G2r / G3-0 / G3-FT trên valid, SR-BH, HttpParams.
- `gguf_<model>/`: chép cả thư mục về máy chạy Ollama, rồi `ollama create nsm-<model> -f Modelfile`.

## Lưu ý

- Không sửa các tập `test_*`; chúng chỉ dùng để báo cáo. Ngưỡng và model được chọn trên `valid`.
- Phần "bình thường" của SR-BH 2020 có nhãn nhầm (khoảng 10 % là tấn công), nên khi đọc tỷ lệ báo nhầm trên
  `test_srbh` hãy xem cột "tầng 2 thêm báo nhầm" thay vì tỷ lệ hệ thống; với bộ chọn luật, lành tính của `test_srbh`
  lấy từ website openappsec chưa thấy.
- 79 % tấn công của SR-BH chỉ nằm ở đường dẫn URL, chỗ tầng 2 không đọc. Muốn đánh giá tầng 2 trên SR-BH, xem các chỉ
  số có hậu tố `_args` (ví dụ `det_sqli_args`) trong `metrics.json`; hậu tố `_path_only` phản ánh regex tầng 1.
- Chi tiết giao thức dữ liệu: `nsm/eval/PROTOCOL.md` trong mã nguồn.
