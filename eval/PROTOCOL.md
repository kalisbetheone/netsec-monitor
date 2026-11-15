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
