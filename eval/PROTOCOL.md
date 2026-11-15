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
- 15/11/2026 — **tầng 2 chế độ `weighted` và thang độ tin cậy.** Nhãn chỉ do model (Cổng 2 không chặn) vẫn thành cảnh báo
  nhưng mang cờ `weighted`: responder tính `TIER2_WEIGHT` = 0,5 vào ngưỡng cửa sổ ngắn, không tính cửa sổ dài, không khoá
  ngay; khi Cổng 2 cũng chặn thì tính đủ. Điểm model trong [ngưỡng, 1] được đổi tuyến tính sang [0,90; 1,00]
  (`TIER2_CONF_FLOOR`) vì ngưỡng của model (chọn trên valid, model 14/11: 0,67) không cùng thang với θ = 0,90 của responder;
  điểm gốc lưu ở `t2_conf`. Hệ quả cho đo đạc: trường `confidence` của nhãn tầng 2 từ ngày này không so trực tiếp được với
  trước; so điểm model thì dùng `t2_conf`. Nhãn `weighted` vào `web-events-*` như nhãn tấn công — khi đếm báo nhầm của
  classifier phải báo riêng phần `weighted`.
- 15/11/2026 — **luật tự sinh áp dụng ngay** (`RULE_APPLY=immediate`): luật qua kiểm tra tĩnh và kho lành tính là chặn
  ngay, không qua chạy thử `SHADOW_S`; tự gỡ khi chặn `REVOKE_BENIGN_HITS` = 3 request của nguồn sạch có tiếng (đếm từ
  `apache-errors-*`), hoặc không khớp gì trong `REVOKE_S`; sống `RULE_TTL_S` rồi tự gia hạn nếu còn chặn được tấn công.
  Hệ quả cho đo đạc: chỉ số "chặn nhầm trong lúc chạy thử" của bộ sinh luật không còn đo được ở cấu hình mặc định —
  muốn đo phải đặt `RULE_APPLY=shadow` cho lượt đo đó và ghi rõ; số request lành tính bị luật tự sinh chặn trước khi luật bị
  tự gỡ là chỉ số mới phải báo cáo.
- 15/11/2026 — **chỉ mục `attack-events-*`**: sự kiện có nhãn tấn công được ghi thêm một bản (giữ 1 năm); `web-events-*`
  vẫn đủ mọi sự kiện. Công cụ đo tiếp tục đọc `web-events-*`; đếm trên `attack-events-*` sẽ trùng với phần tấn công của
  `web-events-*`, không cộng hai chỉ mục.
- 15/11/2026 — **đo khai thác thật** (kiểu tác nhân `exploit` của `tools/scenario.py`, có sau khi áp bản vá
  `p_scenario.py`): đăng nhập DVWA bằng tài khoản mặc định của lab, đặt mức `low`, gửi payload các họ cơ bản vào đúng
  trang có lỗ hổng và đọc THÂN PHẢN HỒI để biết payload có khai thác được thật không. Tiêu chí (chốt trước khi chạy):
  SQLi — trang trả từ hai bản ghi người dùng trở lên (`First name:` ≥ 2) hoặc lộ lỗi cú pháp SQL; RCE — phản hồi có kết quả
  lệnh (`uid=…(`, `root:x:0:0`, `www-data`, chuỗi `Linux <bản> <số>`); LFI — `root:x:0:0`, `[boot loader]`, hoặc mã PHP
  thô; XSS — payload được trả lại nguyên văn và có `<script`, `onerror`, `onload` hoặc `javascript:`. Chỉ request đi qua
  được Cổng 2 (`gate` = `pass`) mới được tính là khai thác được. Chỉ số: tỷ lệ payload khai thác được khi không lớp nào
  chặn (để chứng tỏ bộ thử có nghĩa) và số payload còn khai thác được ở từng cấu hình bảo vệ. Ứng dụng đặt chỗ giả lập
  (`booking.local`) KHÔNG có lỗ hổng cài sẵn nên không dùng cho phép đo này.
- 15/11/2026 — **kiểu tác nhân `botnet`** (sau khi áp bản vá `p_scenario2.py`): một container thêm địa chỉ IP phụ cho giao
  diện mạng (dải 10.10.6.1–10.10.9.254 từ 15/11 04:00, trước đó 10.10.8–9.x; ngoài dải cấp IP của kịch bản; cần NET_ADMIN) và gửi từ hàng trăm IP nguồn, mỗi IP
  một luồng. Dùng cho flood phân tán và nhồi tài khoản quy mô lớn, nơi MỖI IP ở dưới ngưỡng theo từng IP. Kết quả theo IP
  của kiểu này không so trực tiếp được với các kịch bản mỗi IP một container (thời điểm gửi của các IP trùng nhau hơn).
- 15/11/2026 — **ĐÍNH CHÍNH số đo waf-bypass ngày 13/11:** tỷ lệ chặn là **74,2 %** tính theo cặp (payload, vùng đặt) —
  mỗi cặp là một request thật (trường `zones` của `wafbypass_summary`). Con số 53 % trong các báo cáo trước tính theo số
  TỆP payload (trường `files`), trong đó một tệp bị chặn ở vùng này nhưng lọt ở vùng khác nằm trong CẢ danh sách bị chặn
  lẫn danh sách lọt — nên đó không phải tỷ lệ request bị chặn. Từ ngày này chỉ báo tỷ lệ theo cặp; tỷ lệ theo tệp nếu cần
  thì ghi rõ là theo tệp.
- 15/11/2026 03:29–04:30 — **thay đổi SAU KHI đã thấy kết quả kịch bản** (ghi để người đọc biết các con số "sau nâng cấp"
  không phải lượt đầu tiên của cấu hình mới). Lượt đầu `eval/results/scenarios-20261115-032854/` (2/9 đạt) được giữ nguyên.
  Thay đổi HỆ THỐNG: (1) cảnh báo chỉ do tầng 2 không tự khoá IP (`T2_SOLO_BLOCK=0`) — do kịch bản 02 khoá 4/5 người dùng;
  (2) `STRONG_WEIGHT` mặc định 1 (tắt) — do kịch bản 02 khoá người dùng "mơ hồ"; (3) rulegen có mốc `/state/not_before` —
  do rulegen học từ dữ liệu của kịch bản trước. Thay đổi CÔNG CỤ ĐO (không đổi hệ thống): thời gian chặn lấy từ quyết định
  chặn khi tác nhân không kịp thấy 403; botnet tính IP bị chặn theo quyết định của responder; dải IP bot riêng cho từng
  kịch bản (ARP cũ của nginx). Thay đổi KỊCH BẢN: 37 (flood kéo dài thay vì 1,2 giây), 39 (người dùng hợp lệ 1 request/giây
  thay vì 2 — kịch bản cũ tự vượt ngưỡng flood; kỳ vọng theo điều được đo: mẫu 'enum' bắt flood phá bộ đệm), 42 mới.
  Rủi ro lạc quan: (1) và (2) được chọn theo chính kịch bản 02 — cần một kịch bản người dùng hợp lệ KHÁC để kiểm lại (42 là
  lưu lượng thật không trùng, nhưng là lưu lượng 404 trên DVWA, không phải phiên người dùng).
- 15/11/2026 — **A3, chi phí luật tầng 1 đồng bộ** (`bench.sh perf`, cùng máy, cách nhau 2 phút): có luật p50 5,4 ms, 537
  req/s ở 8 kết nối, 472 req/s ở 32; bỏ luật (tệp rỗng tạm thời) p50 5,1 ms, 504 / 447 req/s. Chênh lệch nằm trong dao động
  giữa hai lượt (lượt có luật còn nhanh hơn) -> chi phí không đo được ở mức này. Khi bỏ luật, 198 / 3 370 request SQLi của
  bench đi qua Cổng 2; khi có luật: 0.
- 15/11/2026 — **kịch bản 42 (A4)**: phát lại lưu lượng thật bắt đầu từ dòng 7 000 của tập openappsec Legitimate; kịch bản
  32 (dùng khi tinh chỉnh CRS 14/11) chỉ lấy tới dòng 6 423 với cùng bước 37, nên hai mẫu không trùng.
- 15/11/2026 — **lượt đo đầy đủ sau nâng cấp** (`eval/results/baseline-sau-nang-cap/`, `scenarios-20261115-044706/`):
  37/42 đạt, 13 KHÔNG ĐẠT (62/75 request hợp lệ bị chặn lây). Nguyên nhân từ nhật ký kiểm toán: lệnh chặn cả IP ra 9 ms
  TRƯỚC khi tier3 báo IP dùng chung (cảnh báo nửa trọng số làm đủ ngưỡng sớm hơn: 6,8 s thay vì 12,4 s). Thay đổi HỆ
  THỐNG sau khi thấy kết quả: báo dùng chung đến trong `SHARED_GRACE_S` (30 s) sau lệnh chặn cả IP do đếm ngưỡng -> hạ
  xuống chặn (IP, User-Agent gây chặn). Chạy lại 02, 12, 13 (`scenarios-20261115-063137`): 3/3 đạt, nhưng ở lượt này tier3
  báo trước nên nhánh hạ cấp KHÔNG được kích hoạt trên hệ thống thật — nhánh đó chỉ được kiểm bằng tests/test_logic.py.
  Lượt đầy đủ giữ nguyên, không chạy lại toàn bộ.
- 15/11/2026 (chiều) — **đợt làm song song 4 phiên** (spec `Spec-phan-viec-4-phien-NSM-15-11.md` trong thư mục GSANM;
  trạng thái từng phiên trong `nsm-wip-15-11/phoi-hop/P0..P3.md`).
  - **Bảng 2 × 2 tầng 2** (`bench.sh detect`, chỉ đổi model và chế độ): báo nhầm câu "khó" 1/27 ở `corroborate` với cả hai
    model, 8/27 ở `weighted` với cả hai model -> mức tăng sau nâng cấp là do CHẾ ĐỘ, không do model (bản đầu của báo cáo
    cuối quy cho model — đã đính chính). Model 14/11 + `weighted` gắn nhầm thêm 2/28 mẫu thường (form đăng nhập). Bắt tấn
    công của bộ phân loại không đổi theo chế độ (62/65 với 12/11, 63/65 với 14/11). Lượt (12/11, weighted) chạy lần đầu bị
    LOẠI: Git Bash đổi giá trị biến TIER2_MODEL_PATH=/models/… thành đường dẫn Windows, classifier chạy không có model tầng 2;
    chạy lại với MSYS_NO_PATHCONV=1.
  - **Kiểm nhánh hạ cấp D1 trên hệ thống thật** (`tools/d1grace.sh`): có TIÊM TAY thông điệp ip_profile bằng tài khoản Kafka
    của tier3, vì sau khi IP bị chặn cả ở Cổng 1, tier3 không còn thấy request của IP đó. Đạt 2/2 (IP .171, .172). Lần thứ
    hai trên cùng IP .171 không dựng được tình huống (responder còn nhớ IP dùng chung trong SHARED_TTL_S) — đúng hành vi.
  - **docker-compose.yml**: 8 tham số đổi sang dạng ${BIẾN:-mặc định} (mặc định giữ nguyên) để công cụ đo và "ngày nén" đặt
    tạm được lúc chạy. **rulegen**: thêm một dòng nhật ký khi mốc not_before đang cắt dữ liệu học (không đổi logic).
  - **Kịch bản 47 — sửa cách chấm SAU lần chạy đầu.** Lần đầu (`eval/results/scenarios-20261115-121620/`): KHÔNG ĐẠT 4/5,
    tỷ lệ Cổng 2 của tác nhân thử 8/9 (88,9 %) dưới ngưỡng 95 %. Nguyên nhân là cách chấm: tác nhân bị khoá IP giữa chừng,
    nên mẫu số tính cả request Cổng 1 chặn sau khi khoá. Sửa KỊCH BẢN (không sửa hệ thống): tách thành vai `do_cong2`
    (IP cố định 10.10.10.179, miễn trừ tạm, giữ ngưỡng 95 %) và vai `attack` (phải bị khoá trong 15 s). Chạy lại đúng một
    lần (`scenarios-20261115-122520`): ĐẠT 6/6. Kết quả lần đầu được giữ; bản kịch bản ban đầu ở
    `nsm-wip-15-11/phoi-hop/47-ban-dau-lan-chay-1.toml`.
  - **Thử SC_CONT (chạy liền mạch, không reset giữa các kịch bản):** lượt 11:59 cho kịch bản 02 KHÔNG ĐẠT (4/5 IP người
    dùng nhận 403) vì kịch bản 03 chạy ngay trước dùng đúng các IP đó làm IP tấn công và lệnh chặn còn hạn. Đây là lỗi
    của cách dựng phép thử, đồng thời là bằng chứng SC_CONT giữ trạng thái chặn. Không sửa gì sau khi thấy kết quả này.
  - **Lượt đo chốt** (`tools/baseline.sh cuoi`, commit `8498bcd`, 12:32–14:32; `eval/results/baseline-cuoi/`,
    `scenarios-20261115-124042/`, `bench-results/20261115-142806/`): 45 kịch bản — 41 ĐẠT, 1 LỖ HỔNG ĐÃ BIẾT (04), 3 CHỈ ĐO
    (20, 21, 35), 0 KHÔNG ĐẠT. Chạy một lần, không chạy lại kịch bản nào. Trong lúc đo, máy còn chạy bốn phiên làm việc,
    nên số req/s của bench (442 ở 8 kết nối) KHÔNG so được với lượt đêm (535).
  - **Bench, chặn IP khi flood: 2/3.** Responder ra quyết định ở cả ba lần. Ở lần 2, quyết định có ở giây 4,0, có hiệu lực
    tại nginx ở giây 5,5; bench dừng 47 ms sau đó vì đủ 5 000 request nên không thấy 403. `tools/bench.sh` KHÔNG được sửa
    sau khi thấy kết quả này; con số 2/3 được báo nguyên.
  - **Kịch bản 32 và 42 không đo việc khoá IP.** Cả hai đặt `exempt = ["self"]` để đo hết request, nên responder bỏ qua
    các IP phát lại. "0/4 IP bị khoá" ở hai kịch bản này là hệ quả của việc miễn trừ. Các báo cáo trước ngày 15/11 (chiều)
    có câu "không IP nào bị khoá" cho kịch bản 42 — câu đó đúng về số đo nhưng không phải bằng chứng; đã đính chính.
  - **Ngày mô phỏng nén 12 lần** (`tools/ngaynen.sh`, công cụ ở commit `33faba8`, hệ thống ở `8498bcd`): thay cho đợt chạy
    thử 24 giờ; KHÔNG phải 24 giờ thật và không được gọi như vậy. Responder `dryrun`. Tham số thời gian nén đúng 12 lần
    (LONG_WINDOW_S 7200, TTL_STEPS_S 75,300,7200, MAX_TTL_S 7200, SHARED_TTL_S 300, RULE_TTL_S 7200); `OFFENSE_RESET_S`
    không nén. Nhịp lưu lượng nén 16,2 lần: 24 khung giờ trong 5 331 s (88 phút 51 giây, 15:04:37–16:33:28), mỗi khung
    khoảng 222 s vì `max_s = 250` chỉ là trần. Tiêu chí và ngưỡng ghi trong công cụ TRƯỚC khi chạy. Lượt thử hai khung giờ
    (`eval/results/ngaynen-20261115-143504/`) là lượt kiểm công cụ, không tính; công cụ không đổi sau lượt thử.
    Kết quả (`eval/results/ngaynen-20261115-150440/tong-ket.md`): tiêu chí 1 ĐẠT (0/814 IP hợp lệ có "sẽ chặn"); 1c ĐẠT;
    2 ĐẠT (hai IP gieo: ttl 75 → 300 → 7 200); 3 ĐẠT (sinh ra 27 584 request: 0 bị Cổng 2 chặn, 0 lần 429; phát lại
    186/4 665 = 3,99 % bị Cổng 2 chặn); 24/24 khung giờ đạt.
  - **Ngày nén, dòng 1b — quyết định vào IP phát lại lưu lượng thật.** Việc tách IP phát lại khỏi tiêu chí 1 được quyết
    định khi viết công cụ, trước lượt thử (lý do: đường dẫn của website khác gửi vào DVWA, phần lớn trả 404). Kết quả:
    12/12 IP phát lại nhận "sẽ chặn" (33 quyết định, `immediate:behaviour`, mẫu `recon` của tier3; 4 475/4 698 request
    = 95,3 % trả 404). Ở chế độ chặn thật, 12 IP này sẽ bị khoá. Diễn giải: hiện vật của cách thử, không phải bằng chứng
    khách thật bị chặn nhầm; nhưng trường hợp khách thật gặp nhiều trang 404 CHƯA được đo. Không đổi ngưỡng `recon` sau
    khi thấy kết quả này.
  - **Sự cố phối hợp:** phiên P1 xong lượt thử 14:44 nhưng không nhả khoá stack; P0 gỡ khoá lúc 15:03 sau khi đọc kết quả.
    Mất khoảng 15 phút; lượt thử lại trình diễn của P3 dời xuống ngay trước các lượt chính thức. Không ảnh hưởng số đo.
  - **Trình diễn** (`PRESENT_AUTO=1 bash tools/present.sh`, ba lượt chính thức 16:37–17:14; nhật ký
    `nsm-wip-15-11/present-chinh-thuc-{1,2,3}.log`, kết quả `eval/results/trinhdien-20261115-16*`, `-17*`): ĐẠT 2/3 lượt
    (718, 732, 726 giây). Lượt 2 sai bước 3: 3/4 IP bị khoá khi còn đang tấn công; cảnh báo của IP thử RCE tới responder
    chậm khoảng 8 giây (khâu chậm trước responder, chưa xác định); 12/12 request của IP đó vẫn bị Cổng 2 chặn. KHÔNG sửa
    `present.sh`, kịch bản hay kỳ vọng sau khi thấy kết quả; con số 2/3 được báo nguyên. Thay đổi TRƯỚC ba lượt chính
    thức: bước 5 đổi từ bản rút gọn của kịch bản 38 (DVWA) sang bản rút gọn của kịch bản 45 (cổng đặt chỗ); lượt thử
    12:03 (697 giây, đạt) chạy với bản cũ.
  - **Kịch bản 45 và 46 — lần chạy đầu** (`eval/results/scenarios-20261115-121620/`, cùng lượt với lần đầu của 47): 45 ĐẠT
    4/4 (100/100 IP của botnet bị khoá, mẫu `stuffing` của tier3; khách 60/60 thành công); 46 ĐẠT 4/4 (IP dò mã bị khoá
    sau 8,0 s, mẫu `recon`). Không sửa gì ở hai kịch bản này sau lần chạy đầu.
  - **Trình diễn, lượt ngoài kế hoạch:** 17:17–17:29 một script chạy thử đặt hẹn từ trưa (đã ghi là huỷ nhưng tiến trình nền
    còn) tự chạy thêm một lượt `present.sh` sau ba lượt chính thức: ĐẠT, 729 giây (`nsm-wip-15-11/present-thu-2.log`).
    Lượt này KHÔNG tính vào kết quả 2/3; ghi lại để không ai chọn nó thay cho lượt 2.
- 15/11/2026 (tối) — **bộ thử "CRS và regex tầng 1 đều bỏ lọt" cho tầng 2: ghi TRƯỚC khi đo** (yêu cầu của người dùng:
  "đưa cả ba vào tiêu chí", "lập bộ thử và thử luôn"). Mọi request là lưu lượng thử gửi vào hệ thống của dự án.
  - **Vì sao không dùng `eval/t2only_candidates.jsonl`:** tệp đó chỉ giữ payload mà model tầng 2 ĐÃ gắn nhãn (ngoại
    tuyến), nên tỷ lệ gắn nhãn đo trên nó gần 100 % theo cách dựng. Bộ mới (`eval/t2test_candidates.py`) KHÔNG nạp model
    tầng 2: chỉ loại payload mà regex tầng 1 bắt, trên đúng dạng request sẽ gửi (GET /index.php?q=<payload>).
    Kết quả bước này: 28 822 bản ghi tấn công (phần model chưa thấy) -> 17 208 payload một tham số không trùng -> tầng 1
    bắt 7 919 -> còn 9 289 (sqli 5 293, xss 3 296, lfi 465, rce 235) -> lấy ngẫu nhiên 75 mỗi lớp (hạt giống 20261115)
    = 300 ứng viên, `scenarios/tang-2/ung-vien.jsonl`.
  - **Quy trình còn lại, cố định trước khi chạy:** (1) gửi 300 ứng viên qua Cổng 2 thật từ một IP miễn trừ
    (`scenarios/tang-2/loc-cong-2.toml`), giữ payload KHÔNG bị 403; ở bước này chỉ đọc mã phản hồi, không đọc nhãn của
    classifier. (2) Trong số còn lại, lấy theo thứ tự ngẫu nhiên (hạt giống 20261115) và ĐỌC TAY từng payload; giữ payload
    có cú pháp tấn công của đúng lớp (mệnh đề/toán tử SQL ghép được vào câu lệnh; thẻ HTML, trình xử lý sự kiện hoặc URI
    javascript:; chuỗi leo thư mục hoặc đường dẫn tệp nhạy cảm; lệnh shell có dấu nối lệnh hoặc thế lệnh); loại chữ/số
    thường, mảnh cụt không còn cú pháp, giá trị trông hợp lệ. Việc đọc tay làm khi CHƯA xem nhãn tầng 2. Lấy tối đa 15
    payload mỗi lớp. (3) Chia mỗi lớp: hai phần ba "gieo", một phần ba "giữ lại" (theo thứ tự ngẫu nhiên đó). Lớp có
    dưới 8 payload vẫn tính vào số đo 1 nhưng không tính vào số đo 2 và 3 (một luật cần 5 mẫu khác nhau).
  - **Kịch bản đo** (`scenarios/tang-2/44-chi-tang-2-thay.toml`, rulegen chạy với tham số thật: chu kỳ 60 s, áp dụng
    ngay): 3 IP gửi phần gieo (mỗi IP một thứ tự, 1 request / 2 s, lặp 3 vòng); người dùng hợp lệ gửi văn bản thường và
    "khó" vào cùng tham số suốt kịch bản (đối chứng); một IP mới gửi phần giữ lại, bắt đầu 180 s sau khi phần gieo xong.
    Mọi IP của kịch bản được miễn trừ để đo hết request (như kịch bản 32, 42, 47).
  - **Ba số đo và ngưỡng:** (1) tỷ lệ payload của cả bộ được classifier gắn nhãn tấn công ở lần gửi đầu, ngưỡng >= 60 %;
    (2) tỷ lệ payload phần giữ lại bị Cổng 2 trả 403 ở pha kiểm chứng (mọi payload đã qua bước lọc nên 403 chỉ có thể do
    luật tự sinh), ngưỡng >= 50 %, và không request đối chứng nào bị luật tự sinh chặn; (3) thời gian từ payload đầu của
    một lớp tới lần đầu một request phần gieo của lớp đó bị 403, trung vị theo lớp, ngưỡng <= 120 s; số request của lớp
    đã tới ứng dụng trước mốc đó chỉ ghi nhận. Lớp không có luật: số đo 3 ghi "không có luật", tính là không đạt.
  - **Quyết định:** (1) < 60 % -> `corroborate`; cả ba đạt -> giữ `weighted`; (1) đạt mà (2) hoặc (3) không đạt -> giữ
    `weighted`, ghi giới hạn; luật tự sinh chặn đối chứng -> `corroborate` cho tới khi bàn xong với người dùng.
    Kịch bản 44 chạy MỘT lần; nếu hỏng vì lỗi công cụ thì ghi lại lần hỏng rồi mới chạy lại.
  - **Thay đổi ở bước CHỌN, sau khi thấy kết quả bước lọc và TRƯỚC khi đọc bất kỳ nhãn nào của classifier:** 300 ứng viên
    đầu chỉ cho 33 payload đi qua Cổng 2 (`eval/results/t2loc-20261115-175744/`), không đủ lập bộ thử. Mở rộng bằng đúng
    quy trình và hạt giống đó tới TOÀN BỘ 9 289 payload mà tầng 1 bỏ lọt: đợt 1 gồm 3 700 (`t2loc-20261115-180120/`),
    đợt 2 gồm 5 589 payload sqli và xss còn lại (`t2loc-20261115-180954/`). Kết quả lọc: Cổng 2 chặn 9 085/9 289
    (97,8 %); đi qua 204: lfi 134/465, rce 28/235, sqli 25/5 293, xss 17/3 296.
  - **Đọc tay** (ghi ở `scenarios/tang-2/doc-tay.json`): lfi đọc 56 giữ 15 (loại: mẫu chưa thay `{file}`, chuỗi chỉ gồm
    dấu chấm / chữ a, đường dẫn mất dấu gạch); rce đọc cả 28 giữ 14 (loại: lệnh không có dấu nối lệnh hay thế lệnh, chuỗi
    hỏng mã hoá, `asdf3334`); sqli đọc cả 25 giữ 20, lấy 15 đầu (loại: số thường như `-3752`, `5739-5738`, chuỗi dò ký
    tự); xss đọc cả 17 giữ 8 (loại: mảnh cụt không còn thẻ, thẻ đã mất dấu ngoặc). Bộ thử: 52 payload
    (`scenarios/tang-2/bo-thu.jsonl`): 34 gieo, 18 giữ lại; cả bốn lớp đều có từ 8 payload.
  - **Làm rõ số đo 1 (trước khi đọc nhãn):** "lần gửi đầu" của mỗi payload là lần gửi ở bước lọc — khi đó rulegen dừng và
    không có luật tự sinh, nên nhãn không bị ảnh hưởng bởi kịch bản 44. Nhãn ở vòng gieo đầu của kịch bản 44 được báo
    kèm để đối chiếu.
  - **Giới hạn của công cụ kịch bản tìm ra ở bước này:** `obs.json` chỉ lấy 10 000 bản ghi đầu của `web-events-*` cho mọi
    nguồn (web, net, behaviour), nên với lượt gửi vài nghìn request nó thiếu sự kiện web. `tools/t2test.sh fetch` đọc đủ
    sự kiện web bằng phân trang; `tools/scenario.py` KHÔNG sửa. Các kịch bản của bộ 45 kịch bản gửi dưới mức này nên
    không bị ảnh hưởng, trừ kịch bản dùng botnet (đã đọc quyết định chặn riêng).
  - **Đối chứng:** 60 văn bản hợp lệ (`scenarios/tang-2/doi-chung.jsonl`), cố định trước khi chạy: 36 văn bản có sẵn
    của công cụ kịch bản (thường, "khó", có dấu nháy, địa chỉ IP) và 24 văn bản thêm giống đường dẫn, tên lệnh, thẻ HTML.
  - **Kết quả** (kịch bản 44 chạy MỘT lần, `eval/results/t2test-20261115-182204/`, bảng ở `t2test.md`; bản chép
    `docs/baseline/t2test-20261115-182204.md`): số đo 1 = 40/52 (76,9 %; Wilson 63,9–86,3 %) — ĐẠT (lfi 14/15, rce 5/14,
    sqli 15/15, xss 6/8; mọi nhãn do tầng 2). Số đo 2 = 2/18 (11,1 %) — KHÔNG ĐẠT; chỉ một luật được ban hành (lfi,
    `ARGS:q`, token `.../`, bằng chứng tầng 2, 16 mẫu / 3 IP); 0 văn bản đối chứng bị luật chặn (722 request sau khi có
    luật). Số đo 3: lfi 64 s (29 request đã tới ứng dụng trước đó; sau đó 37 bị chặn, 24 vẫn lọt); rce, sqli, xss không có
    luật — KHÔNG ĐẠT. Nhật ký rulegen: cụm sqli (45–52 mẫu) và rce (11–12 mẫu) "G2r không có ứng viên an toàn đủ điểm" ở
    mọi chu kỳ; xss chỉ có 4 payload gieo được gắn nhãn (dưới MIN_CLUSTER). **Quyết định theo bảng ghi trước: giữ
    `weighted`, ghi giới hạn** — tầng 2 phát hiện được khoảng ba phần tư payload loại này nhưng hầu như chưa chuyển thành
    chặn. KHÔNG đổi ngưỡng, bộ thử, kịch bản hay cấu hình sau khi thấy kết quả. Kỳ vọng `verify_gate2_min_share = 0.5`
    của kịch bản 44 vì vậy KHÔNG ĐẠT và được giữ nguyên. Kết quả phụ: Cổng 2 chặn 9 085/9 289 (97,8 %) payload công khai
    mà regex tầng 1 bỏ lọt.

- 15/11/2026 (22:15) — **Cải thiện tầng 2, bước 1: cổng cú pháp (`TIER2_SYNTAX_GATE`) — tiêu chí GHI TRƯỚC khi đo.**
  Người dùng duyệt lúc 22:00. Bối cảnh: model 14/11 gắn nhãn tấn công cho văn bản hợp lệ có từ khoá SQL / lệnh shell với
  điểm 1,00 (`order by price`, `select a laptop for school`), nên nâng ngưỡng không giúp; cổng cú pháp bỏ qua model khi giá
  trị tham số không có ký tự đặc biệt nào.
  - **Đã biết trước khi ghi tiêu chí (chấm NGOẠI TUYẾN bằng đúng mã classifier, trùng số đo thật 40/52 và 12/60):** cổng bật ->
    bộ thử 52 payload 37/52, danh sách đối chứng cũ 5/60. Hai tập này vì vậy KHÔNG còn là phép kiểm độc lập cho cổng.
  - **Phần chưa biết kết quả:** pha detect của bench với cổng bật; danh sách đối chứng MỚI `scenarios/tang-2/doi-chung-2.jsonl`
    (60 văn bản, viết trước khi chạy, cùng cơ cấu nhóm với danh sách cũ, không trùng giá trị nào); 5 kịch bản 02, 13, 25, 41, 42.
  - **Cách đo:** `tools/t2gate.sh 0` rồi `tools/t2gate.sh 1`, cùng buổi, cùng máy, mỗi cấu hình MỘT lượt: bench pha detect;
    kịch bản đếm nhãn `scenarios/tang-2/do-nhan` (52 payload + đối chứng mới + đối chứng cũ, mỗi giá trị một lần, rulegen
    dừng); 5 kịch bản trên. So bằng `tools/t2gate.py`.
  - **Quy tắc quyết định: giữ cổng BẬT nếu CẢ BỐN điều sau đúng, ngược lại giữ cổng tắt:**
    1. bench, lành tính "khó": số mẫu bị gắn nhãn ở cổng bật <= một nửa số ở cổng tắt (cùng buổi);
    2. đối chứng mới: số văn bản bị gắn nhãn ở cổng bật <= một nửa số ở cổng tắt;
    3. bench: số tấn công bộ phân loại bắt được ở cổng bật >= số ở cổng tắt;
    4. bộ thử 52 payload: cổng bật gắn nhãn >= 32/52 (ngưỡng 60 % đã dùng cho số đo 1 của bộ thử tầng 2).
    Thêm một điều kiện chặn: không kịch bản nào trong 5 kịch bản ĐẠT ở cổng tắt mà KHÔNG ĐẠT ở cổng bật. Nếu một kịch bản
    không đạt ở cả hai cấu hình thì ghi lại, không tính vào quyết định.
  - Không chỉnh ngưỡng `TIER2_THRESHOLD` trong bước này. Không sửa danh sách đối chứng, bộ thử hay kịch bản sau khi thấy kết quả.

- 15/11/2026 (22:52) — **Cải thiện tầng 2, bước 1: KẾT QUẢ đo cổng cú pháp — quyết định theo quy tắc ghi trước: GIỮ CỔNG TẮT.**
  Một lượt mỗi cấu hình, 22:17–22:52 (`tools/t2gate.sh`; `eval/results/t2gate-0.txt`, `t2gate-1.txt`; bench
  `bench-results/20261115-221757` và `-223508`).

  | Phép đo | Cổng tắt | Cổng bật | Điều kiện | Đạt |
  |---|---|---|---|---|
  | bench, lành tính "khó" bị gắn nhãn | 8/27 | 7/27 | bật <= một nửa của tắt (<= 4) | KHÔNG |
  | đối chứng mới bị gắn nhãn | 13/60 | 7/60 | bật <= một nửa của tắt (<= 6) | KHÔNG |
  | bench, bộ phân loại bắt tấn công | 63/65 | 63/65 | bật >= tắt | có |
  | bộ thử 52 payload được gắn nhãn | 40/52 | 37/52 | >= 32/52 | có |
  | 5 kịch bản 02, 13, 25, 41, 42 | 5 đạt | 5 đạt | không kịch bản nào từ đạt thành không đạt | có |

  Ghi thêm (không thuộc quy tắc): bench lành tính thường 2/28 -> 0/28; đối chứng cũ 12/60 -> 5/60. Cổng có ích cho văn bản
  KHÔNG có ký tự đặc biệt, nhưng phần lớn mẫu "khó" của bench có ký tự đặc biệt nên cổng không chạm tới. Hai điều kiện không
  đạt -> cấu hình chạy KHÔNG đổi (`TIER2_SYNTAX_GATE` mặc định 0). Cổng vẫn là một lựa chọn trong bảng chọn model của bước 2
  (notebook 01 chọn cách quyết định × cổng trên valid). Không sửa danh sách đối chứng, bộ thử, kịch bản hay ngưỡng sau khi thấy
  kết quả. Sau lượt đo, classifier được trả về mặc định và `stack.sh check` sạch.
- 15/11/2026 (23:00) — **Cải thiện tầng 2, bước 2: dữ liệu huấn luyện mới và tiêu chí chọn model — GHI TRƯỚC khi huấn luyện.**
  - **Cờ "lọt Cổng 2" (`g2`).** Payload train/valid (seclists, openappsec_mal; giá trị dài nhất ModSecurity thấy, khử trùng theo
    giá trị: 47 607) mà regex tầng 1 bỏ lọt (33 887) được gửi qua Cổng 2 THẬT dạng `GET /index.php?q=<payload>`, 8 tác nhân song
    song, IP miễn trừ, rulegen dừng (`train/t2_pool.py`, `scenarios/tang-2/loc/`, kết quả `eval/results/t2pool-20261115-225610`,
    234 giây): 28 279 bị Cổng 2 chặn, 5 608 lọt. Sau lượt lọc 6 IP thử bị responder khoá (cảnh báo tới sau khi hết miễn trừ);
    đã gỡ bằng `nsmctl unblock` lúc 23:02 — không ảnh hưởng mã phản hồi đã ghi (không request nào bị Cổng 1 chặn).
  - **Lọc chất lượng.** Payload lọt chỉ được đánh dấu `g2 = pass` nếu có CẤU TRÚC TẤN CÔNG rõ theo `train/t2_constructs.py` (biểu
    thức viết tay, viết TRƯỚC khi có model mới nào được chấm; kiểm trên 52 payload đã đọc tay: nhận 50/52); còn lại là
    `pass_weak` và được dùng như payload thường. Lý do: đọc tay 15/11 cho thấy chỉ 57/126 payload lọt là tấn công thật. Kết quả:
    `pass` train sqli 71, xss 19, lfi 4 109, rce 16; valid sqli 18, xss 6, lfi 1 024, rce 8. Lớp LFI lấn át, nên (a) mỗi lớp
    chỉ được cấy thêm tối đa 3 000 dòng (train) / 1 200 dòng (valid), mỗi payload tối đa 10 / 3 vật mang; (b) mục tiêu chọn
    model là trung bình ĐỀU theo lớp.
  - **Văn bản hợp lệ "khó"** (`train/t2_hard_benign.py`): 5 856 câu Tatoeba có từ khoá SQL / lệnh shell (chia theo băm của trình
    dựng dữ liệu) + chuỗi ngắn sinh theo 13 họ mẫu (chia theo băm của chuỗi) + 2 họ CHỈ có ở test (`toan`, `url`). Mọi chuỗi
    trùng một chuỗi của các danh sách kiểm tra (hai danh sách đối chứng, mẫu lành tính của bench, câu của khung kịch bản; 320
    chuỗi) bị loại khỏi dữ liệu sinh. Không sinh câu SQL hoàn chỉnh đứng một mình làm mẫu hợp lệ.
  - **Bộ kiểm tra mới, không dùng để chọn:** `test_hardtext` (phần test của văn bản khó) và `test_residual` — payload tấn công
    THẬT của SR-BH 2020 mà regex tầng 1 bỏ lọt (1 383), gửi qua Cổng 2 (`eval/results/t2pooltest-20261115-225311`): 721 lọt, trong
    đó 205 có cấu trúc tấn công rõ (sqli 149, rce 56; chủ yếu 5 khung của máy quét: `<giá trị>&sleep$mc 15&`,
    `<giá trị>&cat$jj $jj/etc$jj/passwd&`, `<giá trị> ASC  -- `, `<giá trị> DESC  -- `, `<giá trị>-- `). 516 giá trị lọt còn lại
    là giá trị thường của request bị gắn nhãn tấn công hoặc dò bằng một ký tự cuối (`4.2.6'`) — không dùng.
  - **Ứng viên:** M2 (hồi quy logistic, C = 1) và M3 (SGD) × trọng số 1 / 3 / 10 cho dòng `g2 = pass` và dòng văn bản khó
    (6 ứng viên, 2 ứng viên mỗi phiên Colab). Đặc trưng và dạng model không đổi (thay vào classifier được ngay).
  - **Tiêu chí chọn (trên valid, không nhìn tập test):** với mỗi ứng viên × cách quyết định × cổng cú pháp, lấy ngưỡng cho mục
    tiêu cao nhất trong các ngưỡng thoả CẢ BA ràng buộc: tầng 2 thêm <= 0,1 % báo nhầm trên lành tính thường; <= 0,2 % trên văn
    bản tự do; <= 5 % trên văn bản hợp lệ khó. **Mục tiêu = tỷ lệ phát hiện trên payload `g2 = pass`, trung bình đều theo lớp**,
    hoà thì lấy phát hiện chung cao hơn, rồi báo nhầm hệ thống thấp hơn.
  - **Mốc đạt của bước 2, đo trên HỆ THỐNG THẬT sau khi có model (không phải trên valid):** (1) văn bản hợp lệ khó bị gắn nhãn
    <= 5 % trên hai danh sách đối chứng gộp (hiện 25/120) và trên bench "khó" (hiện 8/27; 5 % của 27 làm tròn lên = 2);
    (2) bộ thử 52 payload được gắn nhãn >= 39/52 (75 %), riêng RCE >= 7/14 (hiện 5/14); (3) bench: bộ phân loại bắt tấn công
    không giảm (63/65); (4) 5 kịch bản 02, 13, 25, 41, 42 vẫn đạt. Không đạt đủ thì KHÔNG thay model.
  - **Giới hạn đã biết trước khi huấn luyện:** phần lọt có cấu trúc của SQLi / XSS / RCE trong train chỉ 71 / 19 / 16 payload
    (valid 18 / 6 / 8), nên số đo "lọt Cổng 2" của ba lớp này trên valid dao động mạnh; cả tập train chỉ có 614 giá trị SQLi
    khác nhau. Nguồn SQLi / RCE bổ sung cần tải thêm và chưa được người dùng duyệt -> đợt này (vòng 1) KHÔNG có nguồn mới.
  - **Dữ liệu đã dựng (23:07, `train/build_tier2_dataset.py`, 254 giây).** Số dòng cấy thêm cho payload `g2 = pass`: train
    sqli 710, xss 190, lfi 3 000, rce 220; valid sqli 54, xss 18, lfi 1 024, rce 27 (trình dựng đếm theo payload của từng lớp
    nên số payload RCE là 22 / 9, lệch chút so với 16 / 8 đếm theo giá trị ở trên). Văn bản hợp lệ khó: 44 172 dòng train,
    9 096 dòng valid, 5 028 dòng `test_hardtext`. `test_residual`: 1 025 dòng (sqli 745, rce 280). Bản dữ liệu 14/11 được giữ ở
    `train/data_1411/` và trên Drive (`NSM-train-v2`); đợt này nằm ở `NSM-train-v3`.
  - **Lượt chạy thử nhanh trên máy (23:08–23:15, `NSM_SMOKE=1`, 30 000 dòng train — KHÔNG phải kết quả).** Mục đích: kiểm mã của
    notebook với dữ liệu mới. Lượt này IN RA số trên các tập test, nên các số đó đã được nhìn thấy trước lượt huấn luyện đầy đủ:
    model đang chạy (argmax, 0,67, cổng tắt): `test_hardtext` bị gắn nhãn 12,8 %, `test_residual` phát hiện 58,6 % (sqli 66,6 %,
    rce 37,5 %); model thử nhanh được chọn (M3, trọng số 1): `test_hardtext` 0,9 %, `test_residual` 22,7 %. KHÔNG đổi dữ liệu,
    ứng viên, trọng số hay tiêu chí sau khi thấy các số này. Điều cần theo dõi ở lượt đầy đủ: bớt nhãn nhầm có thể phải trả
    bằng phát hiện trên tấn công thật lọt Cổng 2.

- 16/11/2026 — **Cải thiện tầng 2, bước 2, VÒNG 2: thêm nguồn SQLi và chèn lệnh — GHI TRƯỚC khi lọc, dựng dữ liệu và huấn luyện.**
  Người dùng duyệt việc tải ("Có, tải đi"). Lúc ghi mục này, vòng 1 (`NSM-train-v3`) CHƯA có kết quả huấn luyện đầy đủ nào được
  tôi nhìn thấy; số duy nhất đã thấy là của lượt chạy thử nhanh ghi ở mục trước.
  - **Nguồn** (`eval/data/payloads_extra/`, `SOURCE.md` có commit, kích thước, SHA-256): PayloadsAllTheThings `SQL Injection/Intruder`
    (21 tệp) và `Command Injection/Intruder` (2 tệp), commit `08ea40e`, MIT; fuzzdb `attack/sql-injection/detect` (8 tệp) và ba tệp
    dạng chèn lệnh của `attack/os-cmd-execution`, commit `5656ab2`, BSD 3 điều khoản + CC BY 3.0. 36 tệp, 120 246 byte, chỉ là văn
    bản. Các tệp liệt kê tên lệnh trần của fuzzdb KHÔNG tải (tên lệnh trần là văn bản hợp lệ trong dữ liệu huấn luyện).
  - **Quy tắc giữ payload** (`train/t2_pool.py extra`): mỗi dòng một payload; giữ nếu dài 4–400 ký tự, không còn chỗ trống mẫu
    (`{cmd}`), có cấu trúc tấn công rõ theo `train/t2_constructs.py`, chưa có trong payload train/valid hiện tại, và không trùng giá
    trị nào của các tập kiểm tra (HttpParams, SR-BH, bộ thử 52 payload). Kết quả: 2 457 dòng -> 328 trùng nhau, 134 sai độ dài
    hoặc là mẫu, 397 không rõ cấu trúc, 395 đã có, 0 trùng tập kiểm tra -> **giữ 1 203** (sqli 876 train + 162 valid; rce 143 +
    22). Chia train / valid 85 / 15 theo băm của payload đã che chữ số. Số giá trị SQLi khác nhau của train: 614 -> 1 490.
  - **Phần còn lại KHÔNG đổi so với vòng 1:** gửi phần regex tầng 1 bỏ lọt (401 payload) qua Cổng 2 thật để gắn cờ `g2`; trình dựng
    dữ liệu, văn bản hợp lệ khó, 6 ứng viên, tiêu chí chọn trên valid, và các mốc đạt đo trên hệ thống thật đều như mục 15/11 23:00.
    Hai tập `test_hardtext` và `test_residual` giữ nguyên nội dung.
  - **Cách dùng hai vòng:** dữ liệu vòng 2 nằm ở thư mục Drive riêng `NSM-train-v4`; vòng 1 (`NSM-train-v3`) giữ nguyên. Nếu cả hai
    vòng được huấn luyện thì MỖI vòng chọn model của mình theo tiêu chí trên valid của vòng đó; model đưa đi đo trên hệ thống thật
    là model của vòng 2 (dữ liệu là tập cha của vòng 1). Model vòng 1 chỉ được đo thêm để so sánh, và việc đó được ghi lại.
  - **Đã lọc và dựng (16/11, 00:32–00:41).** 401 payload mới mà regex tầng 1 bỏ lọt qua Cổng 2 thật
    (`eval/results/t2poolextra-20261116-003234`, 125 giây): 247 bị chặn, 154 lọt và đều có cấu trúc tấn công rõ (train sqli 74,
    rce 39; valid sqli 38, rce 3). Một payload không gửi được bị bỏ -> 1 202 payload bổ sung. Dữ liệu vòng 2
    (`train/build_tier2_dataset.py`, 277 giây): dòng cấy thêm cho payload `g2 = pass` — train sqli 1 450 (vòng 1: 710), xss 190,
    lfi 3 000, rce 610 (vòng 1: 220); valid sqli 168 (54), xss 18, lfi 1 024, rce 36 (27). Sau lượt lọc, các IP thử bị khoá muộn
    được gỡ ngay trong script; `stack.sh check` sạch lúc 00:35.
  - **Đính chính câu "hai tập `test_hardtext` và `test_residual` giữ nguyên nội dung":** hai tập có CÙNG tập văn bản và payload như
    vòng 1 (5 028 và 1 025 dòng), nhưng vật mang được chọn lại ngẫu nhiên khi dựng, nên từng dòng không giống hệt vòng 1.
  - Lúc dựng xong vòng 2, thư mục `NSM-train-v3` trên Drive chưa có `output/`: vòng 1 chưa được huấn luyện.

- 16/11/2026 (01:15) — **Khâu chậm trên đường cảnh báo: số đo từng khâu, giả thuyết, và tiêu chí GHI TRƯỚC khi đổi cấu hình.**
  Bối cảnh: bước khoá IP có lúc chậm (trình diễn lượt 2 ngày 15/11: cảnh báo của IP thử RCE tới responder chậm khoảng 8 giây).
  - **Phép đo** (`tools/alertlat.sh`, `tools/alertlat.py`; `eval/results/alertlat-20261116-010449`; 24 request tấn công thử, mỗi
    request một IP, đều bị Cổng 2 chặn; ba topic đọc kèm dấu thời gian Kafka; mốc 0 = lúc Apache xử lý request):

    | Pha (8 lần mỗi pha) | Nhật ký truy cập tới Kafka | Nhật ký kiểm toán tới Kafka | Cảnh báo được phát | Thời gian trong classifier |
    |---|---|---|---|---|
    | POST, nhật ký kiểm toán nguội | 1,11 s [0,13–1,79] | 3,13 s [0,05–5,29] | 3,33 s [1,45–5,30] | 0,01 s [0,00–0,52] |
    | GET | 0,90 s [0,12–1,89] | 2,41 s [0,51–7,83] | 0,92 s [0,13–1,90] | 0,00 s [0,00–0,01] |
    | POST, nhật ký kiểm toán nóng | 1,21 s [0,47–1,94] | 0,85 s [0,15–1,81] | 1,69 s [1,29–2,15] | 0,01 s [0,00–1,01] |

    (trung vị [nhỏ nhất – lớn nhất]). Lượt thử ngắn trước đó (`alertlat-20261116-010248`, mỗi pha một lần) chỉ để kiểm công cụ.
  - **Kết luận từ số đo:** classifier không phải khâu chậm. Khâu chậm là Filebeat ĐỌC TỆP: nhật ký truy cập tới Kafka sau
    0–2 giây; nhật ký kiểm toán của ModSecurity tới sau 0–5 giây khi tệp ít được ghi (có lần 7,8 giây) và 0–2 giây khi tệp được
    ghi liên tục. Request POST có thân phải chờ dòng kiểm toán mới được phân loại (`classifier.handle_web`), nên cảnh báo của POST
    chậm theo. Giả thuyết về nguyên nhân: input `filestream` của Filebeat, khi đọc tới cuối tệp, chờ `backoff.init` (mặc định
    2 giây) rồi mới xem lại, và gấp đôi thời gian chờ tới `backoff.max` (mặc định 10 giây) khi tệp vẫn chưa có dòng mới;
    `web/filebeat/filebeat.yml` không đặt hai giá trị này.
  - **Thay đổi sẽ thử:** `backoff.init: 200ms`, `backoff.max: 1s` cho ba input nằm trên đường cảnh báo (apache-access,
    modsec-audit, suricata-eve). Hai input còn lại (gate1, apache-error) chỉ đi tới logsink, giữ mặc định.
  - **Giữ thay đổi nếu CẢ SÁU điều sau đúng (đo lại cùng buổi, cùng máy, một lượt); ngược lại trả về như cũ:**
    1. nhật ký truy cập tới Kafka: trung vị <= 0,5 s và lớn nhất <= 1,0 s (gộp ba pha);
    2. nhật ký kiểm toán ở pha POST nguội: lớn nhất <= 1,5 s;
    3. cảnh báo ở pha POST nguội: trung vị <= 1,5 s;
    4. không mất dòng: 24/24 lần thử có nhật ký truy cập và cảnh báo, 16/16 lần POST có nhật ký kiểm toán;
    5. `bench.sh -r 5 mttr` với kịch bản sqli và rce: 10/10 lần bị chặn, và trung vị "T quyết định" của mỗi kịch bản không lớn hơn
       mốc đo NGAY TRƯỚC khi đổi cấu hình;
    6. CPU của container filebeat (trung bình 10 mẫu `docker stats`) không tăng quá 3 điểm phần trăm so với mốc.

- 16/11/2026 (01:55) — **Khâu chậm trên đường cảnh báo: KẾT QUẢ sau khi đặt `backoff.init: 200ms`, `backoff.max: 1s` cho ba input của
  Filebeat — cả sáu điều kiện ghi trước đều đạt -> GIỮ thay đổi** (`web/filebeat/filebeat.yml`). Một lượt mỗi cấu hình, cùng buổi.

  | # | Điều kiện | Trước | Sau | Đạt |
  |---|---|---|---|---|
  | 1 | nhật ký truy cập tới Kafka, gộp ba pha: trung vị <= 0,5 s, lớn nhất <= 1,0 s | 1,07 s / 1,94 s | 0,27 s / 0,74 s | có |
  | 2 | nhật ký kiểm toán, pha POST nguội: lớn nhất <= 1,5 s | 5,29 s | 0,86 s | có |
  | 3 | cảnh báo, pha POST nguội: trung vị <= 1,5 s | 3,33 s | 0,80 s | có |
  | 4 | không mất dòng | 24/24, 16/16 | 24/24, 16/16 | có |
  | 5 | bench mttr 5 lần: bị chặn 10/10; trung vị "T quyết định" không tăng | sqli 2,8 s; rce 3,5 s | sqli 2,2 s; rce 2,3 s; 10/10 | có |
  | 6 | CPU filebeat tăng không quá 3 điểm % | 0,43 % | 1,29 % | có |

  Dữ liệu: `eval/results/alertlat-20261116-010449` (trước), `alertlat-20261116-011915` (sau); bench `bench-results/20261116-011423`
  (trước), `20261116-012637` (sau). "T tổng" của bench: sqli 3,5 -> 2,5 s, rce 4,0 -> 3,0 s. Khâu thực thi (quyết định -> nginx
  chặn) KHÔNG đổi và vẫn dao động (0,2–2,9 s trước, 0,2–1,2 s sau): nginx nạp lại danh sách chặn tối đa một lần mỗi 5 giây
  (`RELOAD_MIN_INTERVAL_S`), chưa đụng tới.
  - **Phép kiểm an toàn NGOÀI tiêu chí (thêm sau khi thấy sáu điều kiện đạt):** chạy 4 kịch bản 02, 13, 41, 45 với thiết lập mới
    (`eval/results/alertlatkb-20261116-012955`): 02, 13, 45 đạt; **41 KHÔNG ĐẠT** — luật tự sinh được ban hành rồi bị TỰ GỠ với lý do
    `benign_hit_live`. Nguyên nhân tìm được: bộ cấp phát IP của công cụ kịch bản phụ thuộc danh sách kịch bản của lượt chạy; ba IP
    của vai kiểm chứng lần này (10.10.12.173–.175) từng là người dùng hợp lệ trong lượt chạy tối 15/11 (16 sự kiện lành tính mỗi
    IP trong 24 giờ trước), nên rulegen coi chúng là "nguồn sạch có tiếng" và gỡ luật sau 4 lần luật chặn chúng — đúng thiết kế
    của lưới an toàn, sai do dữ liệu thử. Kiểm chéo: chạy lại kịch bản 41 từ một bản sao tạm với IP chưa từng dùng (10.10.13.x),
    cùng thiết lập Filebeat mới (`eval/results/alertlat41-20261116-014833`): ĐẠT 3/3 phép kiểm. Tệp kịch bản 41 trong kho KHÔNG
    bị sửa; bản sao tạm đã xoá. Chưa chạy lại kịch bản 41 với thiết lập CŨ để đối chiếu trực tiếp.
  - **Giới hạn mới của công cụ đo (ghi nhận, chưa sửa):** chạy các tổ hợp kịch bản khác nhau trong vòng 24 giờ có thể làm một IP
    đóng vai hợp lệ ở lượt này và vai tấn công ở lượt sau; cơ chế "nguồn sạch có tiếng" của rulegen khi đó gỡ luật.
