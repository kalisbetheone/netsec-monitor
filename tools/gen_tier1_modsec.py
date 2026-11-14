#!/usr/bin/env python3
"""tools/gen_tier1_modsec.py — sinh luật ModSecurity ĐỒNG BỘ từ bảng regex tầng 1 của classifier.

Vì sao: classifier chạy SAU khi Apache đã trả lời (đọc nhật ký qua Kafka). Một tấn công CRS bỏ lọt sẽ tới được
ứng dụng cho tới khi responder chặn IP (đủ THRESHOLD=5 cảnh báo, khoảng 4–6 giây, 5–13 request — benchmark 12/11).
Đưa CHÍNH các regex tầng 1 vào Cổng 2 thì request đầu tiên đã bị 403, không chờ đường ống.

Chỉ chuyển những gì classifier coi là CHẮC CHẮN (độ tin cậy 0,9). Không chuyển:
  * Referer, open redirect, recon, 'uninspected' — classifier chỉ ghi nhận (dưới θ);
  * NoSQLi/LDAP (phạm vi 'named') và RFI ('include') trong cả thân JSON/XML/multipart — classifier chỉ ghi nhận;
  * nội dung TỆP tải lên (ModSecurity không đưa vào ARGS) — vẫn do classifier xử lý bất đồng bộ.
Tầng 2 (học máy) không chuyển được — vẫn bất đồng bộ.

Thứ tự nạp: SAU CRS và SAU luật tự sinh (web/apache/zz-autogen.conf) — CRS hoặc luật tự sinh chặn trước thì giữ
nguyên được ghi công; luật này chỉ bắt phần cả hai bỏ lọt. Ở chế độ DetectionOnly (kịch bản/demo sinh luật) luật
này cũng chỉ ghi nhận như mọi luật khác.

Dùng (từ thư mục nsm):
  python -X utf8 -B tools/gen_tier1_modsec.py           ghi web/apache/nsm-tier1.conf
  python -X utf8 -B tools/gen_tier1_modsec.py --check   báo lỗi (mã 1) nếu tệp đang có khác bản sinh ra
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "services", "classifier.py")
OUT = os.path.join(ROOT, "web", "apache", "nsm-tier1.conf")
ID0 = 1000200                    # dải NSM: 1000100–1000199 tinh chỉnh CRS, 1000200–1000399 tầng 1 đồng bộ

# Chuỗi biến đổi (multiMatch: so khớp sau MỖI bước, nên giá trị gốc, bản chữ thường và các lần giải mã đều được xét).
# Mô phỏng classifier: giải mã %xx tới 3 lần (ModSecurity đã giải mã ARGS 1 lần), chữ thường, gộp khoảng trắng.
# multiMatch giữ cả bản TRƯỚC khi giải mã thêm — urlDecodeUni biến '+' thành dấu cách, classifier thì không
# (vd '{{7%2B7}}' -> '{{7+7}}' phải còn khớp).
T_NORM = "t:none,t:lowercase,t:compressWhitespace,t:urlDecodeUni,t:urlDecodeUni,t:compressWhitespace,multiMatch"
T_RAW = "t:none,t:lowercase,t:urlDecodeUni,t:urlDecodeUni,multiMatch"          # giữ xuống dòng (\r \n)

HDR = "REQUEST_HEADERS:User-Agent"
COOK = "REQUEST_COOKIES|REQUEST_COOKIES_NAMES"
# Biến theo phạm vi của classifier (_in_scope). Đo trên ModSecurity 2.9.7 (14/11/2026):
#   * tham số của thân JSON nằm trong ARGS/ARGS_NAMES, KHÔNG nằm trong ARGS_POST;
#   * thân XML: không có REQUEST_BODY/FULL_REQUEST (kể cả ctl:forceRequestBodyVariable); XML:/* chỉ có văn bản trong
#     thẻ (mất DOCTYPE/ENTITY) -> dùng STREAM_INPUT_BODY (cần SecStreamInBodyInspection On), là thân THÔ.
# Classifier quét CẢ thân JSON/XML/multipart như một giá trị (chữ thường, gộp khoảng trắng, không giải mã %xx).
# Phạm vi 'any'/'nopath'/'raw': mọi tham số (ARGS gồm query, form, JSON, trường văn bản multipart) + cả thân thô của
# XML/multipart. Phạm vi có điều kiện: (biến ngoài thân, biến thân, bộ xử lý thân bị LOẠI) — classifier chỉ ghi nhận ở đó.
STREAM_PROC = "^(?:XML|MULTIPART)$"
COND = {
    "rawonly": ("ARGS_GET", "ARGS_POST", "^(?:JSON|XML)$"),           # chỉ giá trị chưa gộp khoảng trắng của THAM SỐ
    "named":   ("ARGS_GET|ARGS_GET_NAMES|" + COOK + "|" + HDR, "ARGS_POST|ARGS_POST_NAMES", "^(?:JSON|XML|MULTIPART)$"),
}
SKIP_SCOPES = {"redirect"}       # chỉ ghi nhận trong classifier


def load_rules():
    """Đọc _CMD, _CMD_END, INCLUDE_PARAMS, _RULES, SCANNER_UA từ mã nguồn classifier (không import: tránh Kafka/ES)."""
    src = open(SRC, encoding="utf-8").read()
    start = src.index("_CMD = ")
    end = src.index("\nRULES_T1 = ")
    ns = {"re": re, "os": os}
    exec(compile(src[start:end], SRC, "exec"), ns)
    m = re.search(r"^SCANNER_UA = re\.compile\((r\".*?\"), re\.I\)", src, re.M)
    ns["SCANNER_UA"] = eval(m.group(1))
    return ns


def conf_str(p):
    """Mẫu regex -> chuỗi trong dấu nháy kép của tệp cấu hình Apache.
    Apache (substring_conf) đổi '\\\\' thành '\\' và '\\"' thành '"' trong chuỗi có nháy -> nhân đôi dấu gạch chéo
    ngược đứng trước gạch chéo ngược, thoát dấu nháy kép. Các chuỗi thoát khác (\\d, \\s, \\n...) giữ nguyên."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            n = p[i + 1]
            out.append('\\"' if n == '"' else ("\\\\\\\\" if n == "\\" else "\\" + n))
            i += 2
            continue
        out.append('\\"' if c == '"' else c)
        i += 1
    s = "".join(out)
    assert "%{" not in s, "mẫu có '%{' — ModSecurity sẽ hiểu là macro"
    return s


def rule(rid, cls, scope, variables, pattern, transforms, body_cond=None, neg=True):
    msg = f"msg:'NSM tier1 {cls}',tag:'nsm/tier1',tag:'nsm/tier1/{cls}',tag:'nsm/scope/{scope}'"
    act = (f"id:{rid},phase:2,deny,status:403,log,auditlog,{transforms},{msg},"
           f"logdata:'%{{MATCHED_VAR_NAME}}=%{{MATCHED_VAR}}',severity:'CRITICAL'")
    if body_cond:
        return (f'SecRule REQBODY_PROCESSOR "{"!" if neg else ""}@rx {body_cond}" "id:{rid},phase:2,deny,status:403,log,auditlog,'
                f"t:none,{msg},logdata:'%{{MATCHED_VAR_NAME}}=%{{MATCHED_VAR}}',severity:'CRITICAL',chain\"\n"
                f'    SecRule {variables} "@rx {conf_str(pattern)}" "{transforms}"')
    return f'SecRule {variables} "@rx {conf_str(pattern)}" "{act}"'


def build():
    ns = load_rules()
    groups = {}                                   # (lớp, phạm vi) -> [mẫu], giữ thứ tự xuất hiện
    for cls, pat, scope in ns["_RULES"]:
        if scope in SKIP_SCOPES:
            continue
        groups.setdefault((cls, scope), []).append(pat)
    lines = [
        "# SINH TỰ ĐỘNG bởi tools/gen_tier1_modsec.py từ services/classifier.py (_RULES, SCANNER_UA). KHÔNG SỬA TAY:",
        "# sửa regex trong classifier rồi chạy lại bộ sinh (tests/test_logic.py kiểm tra tệp này khớp mã nguồn).",
        "# Mục đích: chặn ĐỒNG BỘ ở Cổng 2 đúng những gì tầng 1 của classifier coi là chắc chắn, nên request tấn công",
        "# ĐẦU TIÊN mà CRS bỏ lọt đã bị 403 thay vì tới ứng dụng rồi mới bị phát hiện. Nạp sau CRS và luật tự sinh.",
        "",
        "# thân THÔ (STREAM_INPUT_BODY) cho thân XML/multipart — ModSecurity 2.9.7 không có biến nào khác giữ thân thô",
        "# khi bộ xử lý XML/multipart chạy",
        "SecStreamInBodyInspection On",
        "",
    ]
    rid = ID0
    for (cls, scope), pats in groups.items():
        alt = "|".join(f"(?:{p})" for p in pats)
        lines.append(f"# {cls} / phạm vi {scope}: {len(pats)} mẫu")
        if scope == "include":
            # ModSecurity tách danh sách biến theo '|' nên không dùng được bộ chọn regex '/^(?:page|file)$/':
            # liệt kê từng tên (so tên tham số không phân biệt hoa thường, như classifier)
            m = re.fullmatch(r"\^\(\?:([\w|]+)\)\$", ns["INCLUDE_PARAMS"].pattern)
            names = m.group(1).split("|")
            lines.append(rule(rid, cls, scope, "|".join(f"ARGS_GET:{n}" for n in names), alt, T_NORM)); rid += 1
            lines.append(rule(rid, cls, scope, "|".join(f"ARGS_POST:{n}" for n in names), alt, T_NORM,
                              "^(?:JSON|XML|MULTIPART)$"))
            rid += 1
        elif scope in COND:
            outer, body, cond = COND[scope]
            tf = T_RAW if scope == "rawonly" else T_NORM
            lines.append(rule(rid, cls, scope, outer, alt, tf)); rid += 1
            lines.append(rule(rid, cls, scope, body, alt, tf, cond)); rid += 1
        else:                                       # any / nopath / raw
            raw = scope == "raw"
            v = ("REQUEST_FILENAME|" if scope == "any" else "") + "ARGS|ARGS_NAMES|" + COOK + "|" + HDR
            lines.append(rule(rid, cls, scope, v, alt, T_RAW if raw else T_NORM)); rid += 1
            lines.append(rule(rid, cls, scope, "STREAM_INPUT_BODY", alt,
                              "t:none,t:lowercase" + ("" if raw else ",t:compressWhitespace"), STREAM_PROC, neg=False))
            rid += 1
        lines.append("")
    lines.append("# công cụ quét tự nhận diện qua User-Agent (classifier: nhãn 'scanner', độ tin cậy 0,9)")
    lines.append(rule(rid, "scanner", "ua", HDR, ns["SCANNER_UA"], "t:none,t:lowercase"))
    rid += 1
    assert rid < 1000400, "hết dải ID"
    return "\n".join(lines) + "\n"


def main():
    text = build()
    if "--check" in sys.argv:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if cur != text:
            print("!! web/apache/nsm-tier1.conf KHÁC bản sinh từ classifier.py — chạy tools/gen_tier1_modsec.py", file=sys.stderr)
            sys.exit(1)
        print("ok: nsm-tier1.conf khớp classifier.py")
        return
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("đã ghi", OUT, f"({text.count('SecRule ') } SecRule)")


if __name__ == "__main__":
    main()
