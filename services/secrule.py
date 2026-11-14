"""secrule: ĐẶC TẢ của một luật tự sinh + MÔ PHỎNG cách ModSecurity áp luật đó.

Một luật tự sinh là một dict (đặc tả), KHÔNG phải một dòng SecRule viết tay:
    {"class": "sqli", "target": "ARGS:id", "transforms": ["urlDecodeUni", ...],
     "op": "contains" | "seq" | "rx_fixed", "tokens": ["union", "select"], "max_gap": 40}
Mọi bộ sinh luật (thuật toán, ML, LLM) chỉ được tạo ra đặc tả; chỉ mô-đun này biên dịch đặc tả
thành SecRule (`render`) và kiểm tra nó (`static_check`). Nhờ vậy không bộ sinh nào bịa được cú
pháp, chỉ thị, mã định danh hay hành động.

`matches()` mô phỏng đúng tập con của ModSecurity 2.9 mà luật tự sinh dùng (phép biến đổi t:…,
toán tử @contains / @rx) để chấm luật NGOÀI Docker. Giá trị đầu vào là giá trị tham số như
ModSecurity nhìn thấy trong ARGS: đã giải mã URL MỘT lần.
"""
import re

# ------------------------------------------------------------------ ARGS như ModSecurity nhìn thấy
_HEX = "0123456789abcdefABCDEF"
URLENCODED = "application/x-www-form-urlencoded"


def modsec_urldecode(s):
    """Giải mã MỘT lần như bộ tách tham số của ModSecurity 2.9 (urldecode_nonstrict):
    '+' -> dấu cách, %XX hợp lệ -> byte, % không hợp lệ giữ nguyên, %uXXXX KHÔNG giải mã ở bước này
    (để dành cho t:urlDecodeUni của luật)."""
    if "%" not in s and "+" not in s:
        return s
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "+":
            out.append(" "); i += 1
        elif c == "%" and i + 2 < n and s[i + 1] in _HEX and s[i + 2] in _HEX:
            out.append(chr(int(s[i + 1:i + 3], 16))); i += 3
        else:
            out.append(c); i += 1
    return "".join(out)


def modsec_split(raw, limit=1000):
    """Chuỗi 'a=1&b=2' -> [(tên, giá_trị)] đã giải mã một lần. Phần không có '=' là TÊN với giá trị rỗng
    (khác classifier: classifier coi đó là giá trị không tên)."""
    out = []
    for part in (raw or "").split("&"):
        if not part:
            continue
        n, sep, v = part.partition("=")
        out.append((modsec_urldecode(n), modsec_urldecode(v) if sep else ""))
        if len(out) >= limit:
            break
    return out


ARGS_LIMIT = 1000           # SecArgumentsLimit mặc định của ModSecurity 2.9.7 (modsecurity.conf của hệ thống không đặt)
JSON_DEPTH_LIMIT = 512      # SecRequestBodyJsonDepthLimit trong modsecurity.conf của hệ thống


def _json_args(b, limit):
    """Thân JSON -> ARGS, chép NGUYÊN VĂN cách đặt tên của bộ xử lý JSON ModSecurity 2.9.7 (apache2/msc_json.c):
    tên = 'prefix.current_key' (không có tiền tố 'json.'); vào một mảng thì prefix nối thêm current_key và
    current_key GIỮ NGUYÊN, nên phần tử mảng mang tên lặp lại (vd {"l":[1,2]} -> 'l.l', 'l.l'); mảng ở gốc
    tên là 'array.array'. Giá trị: chuỗi đã giải mã, số giữ nguyên dạng chữ, true/false, null -> ''.
    Trả None nếu JSON hỏng hoặc vượt giới hạn độ sâu (ModSecurity báo lỗi thân và không thêm ARGS)."""
    import json
    try:
        doc = json.loads(b, object_pairs_hook=lambda kv: ("__map__", kv), parse_float=str, parse_int=str,
                         parse_constant=str)
    except (ValueError, RecursionError):
        return None
    st = {"prefix": None, "key": None, "depth": 0, "bad": False}
    out = []

    def add(value):
        if len(out) >= limit:
            return
        key = st["key"] if st["key"] is not None else ""
        out.append((f'{st["prefix"]}.{key}' if st["prefix"] is not None else key, value))

    def walk(x):
        if st["bad"]:
            return
        if isinstance(x, tuple) and len(x) == 2 and x[0] == "__map__":      # đối tượng (giữ cả khoá trùng)
            opened = st["key"] is not None
            if opened:                                                       # yajl_start_map
                st["prefix"] = f'{st["prefix"]}.{st["key"]}' if st["prefix"] is not None else st["key"]
                st["depth"] += 1
                if st["depth"] > JSON_DEPTH_LIMIT:
                    st["bad"] = True
                    return
            for k, v in x[1]:
                st["key"] = k                                                # yajl_map_key
                walk(v)
            if st["prefix"] is not None:                                     # yajl_end_map
                p = st["prefix"]
                i = p.rfind(".")
                if i >= 0:
                    st["prefix"], st["key"] = p[:i], p[i + 1:]
                else:
                    st["key"], st["prefix"] = p, None
                st["depth"] -= 1
        elif isinstance(x, list):
            if st["key"] is None and st["prefix"] is None:                   # yajl_start_array
                st["prefix"] = st["key"] = "array"
            elif st["prefix"] is not None:
                st["prefix"] = f'{st["prefix"]}.{st["key"]}'
            else:
                st["prefix"] = st["key"]
            st["depth"] += 1
            if st["depth"] > JSON_DEPTH_LIMIT:
                st["bad"] = True
                return
            for v in x:
                walk(v)
            if st["prefix"] is not None:                                     # yajl_end_array
                i = st["prefix"].rfind(".")
                st["prefix"] = st["prefix"][:i] if i >= 0 else None
                st["depth"] -= 1
        elif x is None:
            add("")
        elif isinstance(x, bool):
            add("true" if x else "false")
        else:
            add(str(x))
    walk(doc)
    return None if st["bad"] else out


def modsec_args(query, body="", content_type="", limit=ARGS_LIMIT):
    """-> (ARGS = [(tên, giá_trị)], body_parsed). query: chuỗi query THÔ (có hoặc không có '?').
    Thân được tách như ModSecurity: urlencoded theo Content-Type, JSON khi Content-Type bắt đầu bằng
    application/json. Thân XML/multipart/khác KHÔNG được mô phỏng (body_parsed = False) để khỏi đoán sai."""
    args = modsec_split((query or "").lstrip("?"), limit)
    b = body or ""
    if not b or b == "-":
        return args, True
    ctl = (content_type or "").strip().lower()
    ct = ctl.split(";")[0].strip()
    room = max(0, limit - len(args))
    if ct == URLENCODED:
        return args + modsec_split(b, room), True
    if ctl.startswith("application/json"):
        j = _json_args(b, room)
        return (args + j, True) if j is not None else (args, False)
    return args, False


# ------------------------------------------------------------------ phép biến đổi (t:...)


def t_url_decode_uni(s):
    """%XX, %uXXXX (lấy byte thấp; ký tự toàn chiều rộng FF01–FF5E đổi về ASCII), '+' -> dấu cách.
    Chuỗi % không hợp lệ được giữ nguyên."""
    if "%" not in s:
        return s.replace("+", " ")
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "+":
            out.append(" "); i += 1
        elif c == "%" and i + 5 < n and s[i + 1] in "uU" and all(h in _HEX for h in s[i + 2:i + 6]):
            code = int(s[i + 2:i + 6], 16)
            if 0xFF01 <= code <= 0xFF5E:
                code = (code & 0xFF) + 0x20
            out.append(chr(code & 0xFF)); i += 6
        elif c == "%" and i + 2 < n and s[i + 1] in _HEX and s[i + 2] in _HEX:
            out.append(chr(int(s[i + 1:i + 3], 16))); i += 3
        else:
            out.append(c); i += 1
    return "".join(out)


def t_lowercase(s):
    if s.isascii():
        return s.lower()
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


_WS = set(" \t\n\r\f\v\xa0")
_WS_NEEDS = re.compile("[\t\n\r\f\v\xa0]|  ")


def t_compress_whitespace(s):
    if not _WS_NEEDS.search(s):
        return s
    out, prev = [], False
    for c in s:
        if c in _WS:
            if not prev:
                out.append(" ")
            prev = True
        else:
            out.append(c); prev = False
    return "".join(out)


def t_replace_comments(s):
    """Mỗi chú thích kiểu C (/* ... */) thành một dấu cách; chú thích không đóng thì bỏ tới hết chuỗi."""
    if "/*" not in s:
        return s
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("/*", i):
            j = s.find("*/", i + 2)
            out.append(" ")
            if j < 0:
                break
            i = j + 2
        else:
            out.append(s[i]); i += 1
    return "".join(out)


_ENT = {"quot": '"', "amp": "&", "lt": "<", "gt": ">", "nbsp": "\xa0"}
_HEXD = set("0123456789abcdefABCDEF")
_DIG = set("0123456789")
_ALNUM = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_LONG_MAX = (1 << 63) - 1


def _num_byte(digits, base):
    """(unsigned char) strtol(...): tràn số thì strtol trả LONG_MAX."""
    return chr(min(int(digits, base), _LONG_MAX) & 0xFF)


def t_html_entity_decode(s):
    """Chép NGUYÊN VĂN html_entities_decode_inplace() của ModSecurity 2.9.7 (apache2/msc_util.c) — bản chạy
    trong image apache. Chỉ năm tên thực thể (quot, amp, lt, gt, nbsp), không phân biệt hoa thường; thực thể số
    không giới hạn chữ số, lấy byte thấp; dấu ';' không bắt buộc. (Bản master mới hơn có bảng tên đầy đủ.)"""
    if "&" not in s:
        return s
    n, i, out = len(s), 0, []
    while i < n:
        copy = 1
        if s[i] == "&" and i + 1 < n:
            j = i + 1
            if s[j] == "#":                                   # thực thể số
                copy += 1
                if j + 1 < n:
                    j += 1
                    if s[j] in "xX":                          # thập lục phân
                        copy += 1
                        if j + 1 < n:
                            j += 1
                            k = j
                            while j < n and s[j] in _HEXD:
                                j += 1
                            if j > k:
                                out.append(_num_byte(s[k:j], 16))
                                i = j + 1 if j < n and s[j] == ";" else j
                                continue
                    else:                                     # thập phân
                        k = j
                        while j < n and s[j] in _DIG:
                            j += 1
                        if j > k:
                            out.append(_num_byte(s[k:j], 10))
                            i = j + 1 if j < n and s[j] == ";" else j
                            continue
            else:                                             # thực thể tên
                k = j
                while j < n and s[j] in _ALNUM:
                    j += 1
                if j > k:
                    name = s[k:j].lower()
                    if name in _ENT:
                        out.append(_ENT[name])
                        i = j + 1 if j < n and s[j] == ";" else j
                        continue
                    copy = j - k + 1                          # tên lạ: chép nguyên '&' + tên
        out.append(s[i:i + copy])                             # HTML_ENT_OUT
        i += copy
    return "".join(out)


def t_normalize_path_win(s, win=True):
    """Chép NGUYÊN VĂN thuật toán normalize_path_inplace() của ModSecurity 2.9.7 (apache2/msc_util.c), bản
    chạy trong image apache của hệ thống. Thuật toán quét từng ký tự, không tách theo đoạn: một đoạn kết thúc
    bằng hai dấu chấm (kể cả '....') được coi là tham chiếu lên thư mục cha. Đối chiếu bằng đo đạc trên
    ModSecurity thật (tools/tcapture.py)."""
    if not s:
        return s
    b = list(s)
    end = len(b) - 1
    src = dst = 0
    hitroot = done = False
    relative = not (b[0] == "/" or (win and b[0] == "\\"))
    trailing = b[end] == "/" or (win and b[end] == "\\")
    while not done and src <= end and dst <= end:
        if win:                                            # '\' -> '/' (chỉ bản Windows)
            if b[src] == "\\":
                b[src] = "/"
            if src < end and b[src + 1] == "\\":
                b[src + 1] = "/"
        normalize = True
        if src == end:
            done = True                                    # luôn chuẩn hoá ở cuối chuỗi
        elif b[src + 1] != "/":
            normalize = False                              # chưa tới cuối một đoạn
        skip_copy = False
        if normalize:
            if src != end and b[src] == "/":
                pass                                       # đoạn rỗng: phần copy sẽ gộp '//'
            elif b[src] == ".":
                if dst > 0 and b[dst - 1] == ".":          # tham chiếu lên thư mục cha
                    if relative and (hitroot or dst - 2 <= 0):
                        hitroot = True                     # không chuẩn hoá được: giữ nguyên
                    else:
                        dst -= 3                           # bỏ tham chiếu và đoạn đứng trước
                        while dst > 0 and b[dst] != "/":
                            dst -= 1
                        if dst <= 0:                       # không đi quá thư mục gốc
                            hitroot = True
                            dst = 0
                            if not relative and src == end:
                                dst += 1
                        if done:
                            skip_copy = True
                        else:
                            src += 1
                elif dst == 0:                             # tự tham chiếu ở đầu đường dẫn tương đối
                    if done:
                        skip_copy = True
                    else:
                        src += 1
                elif b[dst - 1] == "/":                    # tự tham chiếu '/./'
                    if done:
                        skip_copy = True
                    else:
                        dst -= 1
                        src += 1
            elif dst > 0:
                hitroot = False                            # gặp một đoạn thường
        if skip_copy:
            continue
        if b[src] == "/":                                  # nhiều '/' liền nhau -> nhảy tới cái cuối
            while src < end and (b[src + 1] == "/" or (win and b[src + 1] == "\\")):
                src += 1
            if relative and dst == 0:                      # không chép '/' vào đầu đường dẫn tương đối
                src += 1
                continue
        b[dst] = b[src]
        dst += 1
        src += 1
    if not trailing and dst > 0 and b[dst - 1] == "/":     # không thêm '/' ở cuối nếu bản gốc không có
        dst -= 1
    return "".join(b[:dst])


def t_remove_nulls(s):
    return s.replace("\x00", "")


TRANSFORMS = {
    "urlDecodeUni": t_url_decode_uni, "removeNulls": t_remove_nulls, "replaceComments": t_replace_comments,
    "htmlEntityDecode": t_html_entity_decode, "normalizePathWin": t_normalize_path_win,
    "compressWhitespace": t_compress_whitespace, "lowercase": t_lowercase,
}
BASE = ("urlDecodeUni", "lowercase")                       # bộ biến đổi của rulegen hiện tại
PROFILE = {                                                # bộ biến đổi theo lớp tấn công
    "sqli": ("urlDecodeUni", "removeNulls", "replaceComments", "compressWhitespace", "lowercase"),
    "xss": ("urlDecodeUni", "removeNulls", "htmlEntityDecode", "compressWhitespace", "lowercase"),
    "lfi": ("urlDecodeUni", "removeNulls", "normalizePathWin", "lowercase"),
    "rce": ("urlDecodeUni", "removeNulls", "compressWhitespace", "lowercase"),
}


def apply(transforms, s):
    for t in transforms:
        s = TRANSFORMS[t](s)
    return s


# ------------------------------------------------------------------ toán tử
_META = set("\\.^$|()[]{}*+?")
_WORD = re.compile(r"[A-Za-z0-9_]")


def rx_escape(tok):
    return "".join("\\" + c if c in _META else c for c in tok)


def atom_rx(tok):
    """Biểu thức cho MỘT token: chuỗi cố định, thêm \\b ở mép nào là ký tự chữ/số."""
    return (r"\b" if _WORD.match(tok[0]) else "") + rx_escape(tok) + (r"\b" if _WORD.match(tok[-1]) else "")


def pattern(spec):
    """Biểu thức chính quy của luật (None nếu luật dùng @contains). Chỉ gồm chuỗi cố định, \\b và
    khoảng trống có giới hạn .{0,N} -> thời gian khớp tuyến tính, không có lượng từ lồng nhau."""
    op, toks = spec["op"], spec["tokens"]
    if op == "rx_fixed":
        return toks[0]
    if op == "contains":
        return None
    gap = ".{0,%d}" % int(spec.get("max_gap", 40))
    return "(?s)" + gap.join(atom_rx(t) for t in toks)


def matcher(spec):
    """-> hàm(giá trị ĐÃ biến đổi) -> bool."""
    p = pattern(spec)
    if p is None:
        tok = spec["tokens"][0]
        return lambda v: tok in v
    rx = re.compile(p, re.ASCII)
    return lambda v: rx.search(v) is not None


def target_name(spec):
    t = spec.get("target", "ARGS")
    return t.split(":", 1)[1] if ":" in t else None


def matches(spec, args, _cache={}):
    """True nếu luật khớp một request có các tham số `args` = [(tên, giá trị)]."""
    key = id(spec)
    m = _cache.get(key)
    if m is None or m[0] is not spec:
        m = (spec, matcher(spec), tuple(spec["transforms"]), target_name(spec))
        _cache[key] = m
        if len(_cache) > 4096:
            _cache.clear(); _cache[key] = m
    _, fn, tr, name = m
    for n, v in args:
        if name is None or n.lower() == name:
            if fn(apply(tr, v)):
                return True
    return False


# ------------------------------------------------------------------ kiểm tra tĩnh + biên dịch
BASE_ID = 9900000
TARGET_OK = re.compile(r"^ARGS(?::[a-z0-9_.\-]{1,32})?$")
TOKEN_OK = re.compile(r"^[a-z0-9 !#$%&'()*+,\-./:;<=>?@\[\]^_`{|}~]+$")       # không có \" và \\ -> không vỡ SecRule
MIN_TOK, MAX_TOK, MAX_TOKENS, MAX_GAP = 3, 40, 3, 80
CLASSES = ("sqli", "xss", "lfi", "rce")


def static_check(spec, fixed_rx=()):
    """(ok, lý_do). `fixed_rx` = các biểu thức viết sẵn được phép dùng với op 'rx_fixed'."""
    if spec.get("class") not in CLASSES:
        return False, "class"
    if not TARGET_OK.match(spec.get("target", "")):
        return False, "target"
    tr = spec.get("transforms") or []
    if not tr or any(t not in TRANSFORMS for t in tr) or len(set(tr)) != len(tr) or tr[0] != "urlDecodeUni":
        return False, "transforms"
    toks, op = spec.get("tokens") or [], spec.get("op")
    if op == "rx_fixed":
        return (len(toks) == 1 and toks[0] in fixed_rx), "rx_fixed"
    if op not in ("contains", "seq"):
        return False, "op"
    if not 1 <= len(toks) <= MAX_TOKENS or (op == "contains" and len(toks) != 1):
        return False, "token_count"
    for t in toks:
        if not (MIN_TOK <= len(t) <= MAX_TOK) or not TOKEN_OK.match(t) or t.strip() != t or "${" in t:
            return False, "token"
    if op == "seq" and not 0 <= int(spec.get("max_gap", 40)) <= MAX_GAP:
        return False, "max_gap"
    return True, ""


def render(spec, rid, state):
    """Đặc tả -> một dòng SecRule. state: 'shadow' (chỉ ghi nhận) | 'active' (chặn)."""
    action = "deny,status:403" if state == "active" else "pass"
    p = pattern(spec)
    operator = ("@contains " + spec["tokens"][0]) if p is None else ("@rx " + p)
    t = ",".join("t:" + x for x in spec["transforms"])
    return (f'SecRule {spec["target"]} "{operator}" '
            f'"id:{rid},phase:2,t:none,{t},{action},log,'
            f'msg:\'autogen {spec["class"]} {state}\',tag:\'autogen/{state}\'"')


def describe(spec):
    toks = " … ".join(spec["tokens"]) if spec["op"] != "rx_fixed" else "(biểu thức viết sẵn)"
    return f'{spec["class"]} @ {spec["target"]}: {toks}'
