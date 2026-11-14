# Giao thức dữ liệu và đánh giá bộ sinh luật

**Chốt ngày 11/11/2026, TRƯỚC khi chạy bất kỳ thí nghiệm nào trên các dataset bên ngoài.**
Mọi thay đổi về sau phải ghi vào mục "Lịch sử thay đổi", nêu lý do, và không được sửa vì đã thấy kết quả.

## 1. Nguyên tắc: dữ liệu đi qua đúng mã của hệ thống

Mỗi bản ghi của mọi dataset được đưa về **một request HTTP thô** (phương thức, đường dẫn, query, thân,
Content-Type, User-Agent) rồi chạy qua **chính hàm `_classify_web` của classifier**. Kết quả là đúng bản ghi
mà hệ thống sẽ ghi vào Elasticsearch. Bộ sinh luật đọc bản ghi đó y như khi chạy thật, nên chuyển từ đánh giá
sang chạy thật không có bước đổi định dạng nào.

Hai góc nhìn trong mỗi bản ghi:

| Trường | Góc nhìn | Dùng cho |
|---|---|---|
| `arg_n`, `arg_v` | Classifier: giải mã URL nhiều lần, chữ thường, cắt 512 ký tự | Gắn nhãn (như hệ thống) |
| `marg_n`, `marg_v` | ModSecurity: ARGS giải mã đúng một lần, giữ hoa thường | **Sinh luật và chấm luật**, vì luật được áp ở góc nhìn này |

`secrule.modsec_args` mô phỏng cách ModSecurity tách tham số. Thân JSON/XML/multipart **không** được mô
phỏng (`marg_body = False`). Bản ghi loại này chỉ được dùng ở phần query.

## 2. Ánh xạ nhãn (cố định)

Nhãn gốc của dataset → lớp của hệ thống `ds_class` ∈ {sqli, xss, lfi, rce, benign, other}.

| Dataset | Nhãn gốc | `ds_class` |
|---|---|---|
| SecLists | theo tệp (SQLi / XSS / LFI / command injection) | sqli / xss / lfi / rce |
| openappsec Malicious | sqli, xss, traversal, cmdexe | sqli, xss, lfi, rce |
| | log4shell, shellshock, xxe | other |
| openappsec Legitimate | (toàn bộ) | benign |
| HttpParamsDataset | norm / sqli / xss / path-traversal / cmdi | benign / sqli / xss / lfi / rce |
| SR-BH 2020 | 000 Normal (và không có nhãn tấn công nào) | benign |
| | 66 SQL Injection | sqli |
| | 126 Path Traversal | lfi |
| | 88 OS Command Injection, 248 Command Injection | rce |
| | 242 Code Injection, 272, 16, 310, 153, 274, 194, 34, 33 | other |

Khi một request có nhiều nhãn tấn công, chọn theo thứ tự ưu tiên sqli > xss > lfi > rce > other.
CAPEC 242 (Code Injection) được xếp `other` vì dataset không tách XSS ra khỏi chèn mã nói chung.

Nhãn của hệ thống (`label`, `tier`, `confidence`) được lưu riêng. Nhãn của dataset **không bao giờ** được
sửa theo nhãn của hệ thống.

## 3. Khử trùng và chia tập (cố định)

**Khử trùng** trong từng dataset theo khoá (phương thức, đường dẫn đã giải mã, ARGS kiểu ModSecurity đã sắp
xếp, thân). Mỗi bản ghi giữ lại kèm số lần lặp `dup`.

**Họ payload:** băm SHA-1 của giá trị tham số dài nhất sau khi chữ thường và thay mọi dãy chữ số bằng `0`.
Mọi biến thể chỉ khác chữ số rơi vào cùng một tập.

| Dataset | Vai trò | Cách chia |
|---|---|---|
| SecLists + openappsec Malicious | Tri thức về tấn công | Theo họ payload: 80 % `train`, 20 % `valid` |
| openappsec Legitimate | Lành tính thật | **Theo website**: 40 % `train`, 10 % `valid`, 50 % `test_sites` |
| SR-BH 2020 | Kiểm tra độc lập 1 | Toàn bộ `test_ext1` |
| HttpParamsDataset | Kiểm tra độc lập 2 | Toàn bộ `test_ext2` |

Gán tập bằng băm (họ payload hoặc tên website) nên tái lập được, không phụ thuộc thứ tự đọc.
Bản ghi kiểm tra nào trùng họ payload với tập `train` được đánh dấu `seen_in_train`. Kết quả báo cáo cả
trên toàn bộ tập kiểm tra và trên phần chưa thấy.

**Không** dùng `test_*` để chọn siêu tham số, chọn model, sửa bộ sinh, hay viết thêm khuôn câu.

## 4. Chỉ số

Đo cho mỗi bộ sinh, trên mỗi tập kiểm tra:

- **Chặn tấn công:** tỷ lệ bản ghi `ds_class` ∈ {sqli, xss, lfi, rce} mà ít nhất một luật khớp (theo góc nhìn ModSecurity).
- **Chặn nhầm:** tỷ lệ bản ghi `benign` mà ít nhất một luật khớp.
- **Thông số phụ:** số luật; từng lớp; khoảng tin cậy Wilson 95 %.
- **Nhãn "luật tốt nhất"** (dùng để huấn luyện bộ chọn): trong các ứng viên cho một cụm, luật có số tấn công
  `valid` bị chặn cao nhất, với điều kiện chặn nhầm trên lành tính `valid` bằng 0. Hoà thì chọn luật ít token
  hơn, rồi theo thứ tự chữ.

## 5. Phép thử sức chịu đựng (báo cáo riêng)

Khuôn câu lành tính "khó" và các phép né tránh do người viết (`eval/rule_eval.py`) **chỉ** được báo cáo như
phép thử sức chịu đựng, ghi rõ là tự viết. Không dùng để huấn luyện hay chọn model.

## 6. Kiểm chứng khớp với hệ thống thật

Trước khi dùng dữ liệu đã chuẩn hoá, một mẫu được phát lại qua stack thật (`tools/parity.sh`):

- So bản ghi Elasticsearch của hệ thống với bản ghi chuẩn hoá ngoài Docker: `arg_*`, `marg_*`, `label`, `tier`.
- Nạp một tập luật dò (chỉ ghi nhận, không chặn) vào ModSecurity, so luật nào khớp request nào giữa
  ModSecurity thật và bộ mô phỏng `secrule.matches`.

Mọi chênh lệch được báo cáo kèm ví dụ. Nếu tỷ lệ chênh vượt 1 %, phải sửa lớp chuẩn hoá trước khi dùng.

## Lịch sử thay đổi

- 11/11/2026 — bản đầu tiên.
- 12/11/2026 — trước khi chạy bất kỳ thí nghiệm nào trên bộ sinh luật, chỉ thay đổi cách CHUẨN HOÁ (không đổi
  ánh xạ nhãn, cách chia tập hay chỉ số):
  - mô phỏng thêm bộ xử lý thân JSON của ModSecurity (luật 200001 có sẵn trong `modsecurity.conf`);
  - thân request vượt giới hạn của ModSecurity trong hệ thống (thân không phải multipart > 128 KiB, mọi thân
    > 12,5 MiB → trả 413) được xử lý như hệ thống thật: classifier không thấy thân, đánh dấu `over_limit`;
  - họ payload của request không có tham số tính theo đường dẫn (trước đó mọi request như vậy chung một họ);
    cờ `seen_in_train` chỉ tính cho request có tham số.
- 12/11/2026 (sau lượt kiểm chứng khớp đầu tiên trên stack thật, vẫn trước mọi thí nghiệm bộ sinh luật):
  bộ mô phỏng ModSecurity được sửa cho khớp **mã nguồn ModSecurity 2.9.7** (đúng bản cài trong image) và đối
  chiếu bằng đo đạc trên ModSecurity thật (`tools/tcapture.py`):
  - `normalizePathWin` và `htmlEntityDecode` chép nguyên văn thuật toán C (`apache2/msc_util.c`);
  - tên tham số JSON chép theo `apache2/msc_json.c` (không có tiền tố `json.`, phần tử mảng lặp tên khoá);
  - giữ tới 1000 tham số (SecArgumentsLimit), trước đó chỉ 50.
- 12/11/2026 — dữ liệu HUẤN LUYỆN (thư mục `train/`), chốt trước khi huấn luyện:
  - tầng 2: payload tấn công được **cấy** vào request lành tính thật của website cùng tập (lý do: tấn công trong dataset gần
    như đều ở đường dẫn `/` với tham số `p` → đường tắt). Tiêu chí chọn model: phát hiện cao nhất trên valid khi tầng 2 thêm
    tối đa 0,1 % báo nhầm trên lành tính của valid;
  - chọn luật: lành tính để đo chặn nhầm ở `test_srbh` chỉ lấy từ website openappsec chưa thấy, **không** lấy phần "bình
    thường" của SR-BH (nhãn bẩn ~10 %). Chỉ số báo cáo tách riêng: recall trung bình trên tấn công giữ riêng và tỷ lệ cụm
    mà luật được chọn chặn nhầm ít nhất một giá trị lành tính.
- 12/11/2026 — sau khi đối chiếu với bản rà soát hệ thống (`Ra-soat-do-hoan-thien-he-thong-NSM.md`), vẫn trước khi
  huấn luyện trên Colab:
  - tầng 2 chỉ đọc 2000 ký tự đầu của văn bản query + thân (`feats.make_text`, liên quan lỗi N3). Mẫu cấy mà payload rơi
    ra ngoài cửa sổ đó là nhãn nhiễu (nhãn tấn công nhưng model không thấy gì) → bộ dựng kiểm tra vị trí payload bằng
    một bản cấy đánh dấu cùng vị trí; nếu 256 ký tự đầu của payload (hoặc cả payload nếu ngắn hơn) không nằm trong
    cửa sổ thì cấy lại (vị trí khác của cùng vật mang, sau 3 lần đổi vật mang). Giới hạn 2000 ký tự là một phần của
    model: nếu sau này sửa N3 thì giữ nguyên `make_text` và chấm theo từng cửa sổ, hoặc phải huấn luyện lại;
  - thân có byte rỗng (lỗi C7: hệ thống thật cắt thân tại byte rỗng) bị loại khỏi train/valid và khỏi vật mang; ở tập
    test được giữ lại, gắn cờ `nul` và báo cáo riêng;
  - **điểm mù mới:** tầng 2 không đọc đường dẫn URL. 79 % tấn công của SR-BH (161 044 / 203 173 sau khử trùng) không có
    query lẫn thân — phần lớn payload SQLi nằm ngay trong đường dẫn — nên chỉ regex tầng 1 có thể bắt. Mỗi dòng dữ liệu
    tầng 2 có trường `loc` (`args` / `path_only`); phát hiện trên tập test được báo cáo tách theo `loc`, và chỉ phần
    `args` dùng để đánh giá tầng 2. Dữ liệu chọn luật không bị ảnh hưởng (chỉ lấy giá trị tham số).
- 12/11/2026 — đưa bộ chọn luật **G2r** vào `rulegen` (mặc định `RULEGEN_SELECTOR=g2r`), sau khi có kết quả notebook 02
  trên các tập test. LLM không được đưa vào hệ thống (`Bao-cao-ly-do-khong-dung-LLM-NSM.md`). Để đặc trưng khi chạy cùng thang
  với lúc huấn luyện, kho nền (TokenPrior + Benign của phần train) được đóng băng thành `models/rulesel_prior.json.gz` bằng
  `train/export_rulesel_prior.py`; kiểm chứng an toàn trên lưu lượng sống được làm thêm sau khi G2r chọn. Khác biệt đã biết
  so với lúc huấn luyện: đặc trưng `rank_cov` giữa các ứng viên đồng độ phủ lấy theo thứ tự tất định thay vì thứ tự xáo.
- 13/11/2026 — luật tầng 1 của classifier (không phải bộ sinh luật): thêm 9 họ (xxe, ssti, ssrf, deser, nosqli, ldap,
  crlf, rfi, redirect) và siết luật RCE. **Công khai:** bộ luật mới được chỉnh một lần SAU KHI xem báo nhầm của lượt đo
  đầu trên toàn bộ openappsec Legitimate (`Huong-cai-tien-kich-ban-01-02-05-NSM.md`, mục 4.3), nên con số báo nhầm
  0,0013 % đo trên chính tập đó là lạc quan; kiểm lại trên lành tính của `test_sites` trước khi coi là kết quả.
  Tải thêm dữ liệu tấn công ĐỘC LẬP cho các họ này (`eval/data/payloads_independent/`, PayloadsAllTheThings + SecLists,
  MIT) — chỉ dùng để đo, chưa đo. SSRF, RFI, deserialization vẫn chưa có dữ liệu độc lập.
  Dữ liệu chuẩn hoá đã có (`eval/data/normalized/`) mang nhãn của classifier CŨ; muốn so phải chạy lại phân loại.
- 14/11/2026 — **Cổng 2 (CRS 4.25) có tinh chỉnh của NSM** (`web/apache/crs/nsm-tuning-config.conf`: cho phép
  `text/plain`; `nsm-tuning-before.conf`: ngoại lệ hẹp cho truy vấn GraphQL, id 1000100–1000101). Tinh chỉnh được làm SAU
  KHI xem các request lành tính bị chặn của kịch bản 32 (600 request của `test_sites`), nên con số 2,8 % đo lại trên chính
  600 request đó là lạc quan; đo lại trên một mẫu `test_sites` khác trước khi coi là kết quả.
- 14/11/2026 — **dữ liệu tầng 2 có văn bản tự do lành tính**: câu Tatoeba (Anh + Việt, CC BY 2.0 FR,
  `eval/data/tatoeba/`) cấy vào request lành tính thật; tách theo băm mã câu 70/15/15 (train / valid / `test_freetext`).
  Tập `test_scenario_text` = 39 câu gõ tay của các kịch bản × 20 vật mang — CHỈ để báo cáo, không dùng để chọn (các câu đó
  do chính phiên viết hệ thống viết ra). Tiêu chí chọn thêm điều kiện: tầng 2 thêm tối đa 0,2 % báo nhầm trên văn bản tự
  do của valid (`budget_free`). Model huấn luyện xong (M3 SGD, argmax, θ 0,67) nhưng CHƯA triển khai.
- 14/11/2026 — **tầng 1 của classifier chạy đồng bộ ở Cổng 2** (`web/apache/nsm-tier1.conf`, sinh bằng
  `tools/gen_tier1_modsec.py`, id 1000200–1000399, nạp sau CRS và luật tự sinh). Từ đây "lọt Cổng 2" nghĩa là lọt cả CRS,
  luật tự sinh LẪN regex tầng 1: số đo phát hiện của Cổng 2 trước và sau ngày này không so trực tiếp được, và bộ sinh luật
  (rulegen) chỉ còn nhận cụm từ tấn công mà riêng tầng 2 nhận ra (ở chế độ chặn bình thường). Kiểm chứng khớp bằng
  `tools/tier1sync.sh` (CRS 949110 và luật tự sinh được tạm gỡ trong lúc đo). Khác biệt đã biết: ModSecurity giải mã '+'
  thành dấu cách cả trong ĐƯỜNG DẪN và giải mã `%uXXXX` (classifier thì không) nên bắt thêm SQLi/CRLF dạng đó; nội dung TỆP
  tải lên được soi qua thân thô multipart (`SecStreamInBodyInspection On`).
