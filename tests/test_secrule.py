"""Kiểm thử mô-đun đặc tả/mô phỏng luật (services/secrule.py) và các bộ sinh luật mới (services/rulegen_ml.py).

Chạy KHÔNG cần Docker:   python -B tests/test_secrule.py
"""
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services"))
import secrule as S          # noqa: E402
import rulegen_ml as M       # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


print("== ARGS như ModSecurity")
check("giải mã một lần: '+', %XX; %uXXXX và % hỏng giữ nguyên", S.modsec_urldecode("a+b%27%2527%u0027%zz%4") == "a b'%27%u0027%zz%4")
check("tách query: tên không có '=' là TÊN với giá trị rỗng", S.modsec_split("a=1&flag&b=x%3Dy") == [("a", "1"), ("flag", ""), ("b", "x=y")])
check("thân urlencoded chỉ được tách khi đúng Content-Type",
      S.modsec_args("?q=1", "p=2", "application/x-www-form-urlencoded; charset=utf-8") == ([("q", "1"), ("p", "2")], True)
      and S.modsec_args("q=1", "p=2", "text/plain") == ([("q", "1")], False)
      and S.modsec_args("q=1", "<p>2</p>", "text/xml") == ([("q", "1")], False))
check("thân JSON đặt tên như ModSecurity 2.9.7 (msc_json.c): không có 'json.', phần tử mảng lặp tên khoá",
      S.modsec_args("", '{"a":{"b":"x"},"n":1.50,"l":[true,null]}', "application/json; charset=utf-8")
      == ([("a.b", "x"), ("n", "1.50"), ("l.l", "true"), ("l.l", "")], True),
      repr(S.modsec_args("", '{"a":{"b":"x"},"n":1.50,"l":[true,null]}', "application/json")))
check("JSON: mảng ở gốc và mảng đối tượng",
      S.modsec_args("", '[1,{"k":"v"}]', "application/json") == ([("array.array", "1"), ("array.array.k", "v")], True),
      repr(S.modsec_args("", '[1,{"k":"v"}]', "application/json")))
check("JSON: giữ khoá trùng, sau đối tượng con trở lại đúng tên",
      S.modsec_args("", '{"a":1,"a":2,"o":{"x":3},"z":4}', "application/json")
      == ([("a", "1"), ("a", "2"), ("o.x", "3"), ("z", "4")], True))
check("giới hạn TỔNG số ARGS (query + thân) như SecArgumentsLimit",
      len(S.modsec_args("&".join(f"q{i}=1" for i in range(990)), "&".join(f"b{i}=1" for i in range(50)),
                        "application/x-www-form-urlencoded")[0]) == 1000)
check("thân JSON hỏng -> không tách", S.modsec_args("", "{bad", "application/json") == ([], False))

print("== phép biến đổi")
check("urlDecodeUni: %XX, %uXXXX, '+'", S.t_url_decode_uni("a%27b%u0027c+d%zz%2") == "a'b'c d%zz%2")
check("urlDecodeUni: ký tự toàn chiều rộng về ASCII", S.t_url_decode_uni("%uFF1Cscript") == "<script")
check("lowercase chỉ đổi A-Z", S.t_lowercase("AbC-É") == "abc-É")
check("compressWhitespace", S.t_compress_whitespace("a \t\n b\xa0\xa0c") == "a b c")
check("replaceComments", S.t_replace_comments("a/**/b/* x */c/*d") == "a b c ")
check("htmlEntityDecode", S.t_html_entity_decode("&lt;a&#x3e;&#39;&quot&amp;") == "<a>'\"&")
check("normalizePathWin: \\ // ./ và thư_mục/..", S.t_normalize_path_win("..\\..\\etc//./passwd") == "../../etc/passwd"
      and S.t_normalize_path_win("/var/www/../../etc/passwd") == "/etc/passwd")
check("removeNulls", S.t_remove_nulls("a\x00b") == "ab")
# các cặp vào/ra dưới đây được ĐO trên ModSecurity của hệ thống (luật capture + logdata), không phải tự suy ra
for v, want in (("&LT;b&GT;", "<b>"), ("&Lt;i&gT;", "<i>"), ("&AMP;x", "&x"), ("&#X41;&#x42;", "AB"), ("&lt;ok&gt;", "<ok>")):
    check(f"htmlEntityDecode như ModSecurity: {v!r} -> {want!r}", S.t_html_entity_decode(v) == want,
          repr(S.t_html_entity_decode(v)))
for v, want in (("A://.../b/", "A:/b/"), ("/.../.../x", "/x"), ("a/..../b", "a/b"), ("A:/b/../c", "A:/c"),
                ("x/.../", "x/"), ("...", "..."), ("A:/b", "A:/b")):
    check(f"normalizePathWin như ModSecurity: {v!r} -> {want!r}", S.t_normalize_path_win(v) == want,
          repr(S.t_normalize_path_win(v)))
v = S.apply(S.PROFILE["sqli"], "1'/**/UNION%09SELECT  1,2-- -")
check("bộ biến đổi sqli gộp chú thích + khoảng trắng + chữ thường", v == "1' union select 1,2-- -", repr(v))

print("== toán tử và đích")
seq = {"class": "sqli", "target": "ARGS:id", "transforms": list(S.PROFILE["sqli"]), "op": "seq",
       "tokens": ["union", "select"], "max_gap": 40}
check("seq khớp biến thể chèn chú thích / khoảng trắng / chữ hoa", S.matches(seq, [("id", "1'/**/UnIoN/**/ALL   SELECT 1")]))
check("seq có \\b: 'reunion selection' không khớp", not S.matches(seq, [("id", "reunion selection")]))
check("seq tôn trọng thứ tự", not S.matches(seq, [("id", "select a union")]))
check("seq tôn trọng khoảng cách tối đa", not S.matches(seq, [("id", "union " + "x" * 60 + " select")]))
check("đích ARGS:id không soi tham số khác", not S.matches(seq, [("name", "union select")]))
check("đích ARGS soi mọi tham số", S.matches(dict(seq, target="ARGS"), [("name", "union select")]))
con = {"class": "xss", "target": "ARGS", "transforms": list(S.PROFILE["xss"]), "op": "contains", "tokens": ["</script>"]}
check("contains sau htmlEntityDecode", S.matches(con, [("q", "x&lt;/SCRIPT&gt;")]))

print("== kiểm tra tĩnh và biên dịch")
check("đặc tả hợp lệ qua kiểm tra tĩnh", S.static_check(seq)[0] and S.static_check(con)[0])
for bad, why in ((dict(seq, target="REQUEST_URI"), "đích ngoài ARGS"), (dict(seq, tokens=["a\"b", "select"]), "token có nháy kép"),
                 (dict(seq, tokens=["ab"]), "token quá ngắn"), (dict(seq, transforms=["lowercase", "base64Decode"]), "phép biến đổi lạ"),
                 (dict(seq, op="rx", tokens=["(a+)+"]), "toán tử tự do"), (dict(seq, tokens=["${x}aa", "select"]), "mở rộng macro"),
                 (dict(seq, max_gap=5000), "khoảng cách quá lớn"), (dict(seq, tokens=["a", "b", "c", "d"]), "quá nhiều token")):
    check(f"từ chối: {why}", not S.static_check(bad)[0])
check("rx_fixed chỉ nhận biểu thức trong danh sách cho phép",
      not S.static_check(dict(seq, op="rx_fixed", tokens=["(a+)+"]))[0]
      and S.static_check(dict(seq, op="rx_fixed", tokens=["x"]), fixed_rx=("x",))[0])
line = S.render(seq, 9900007, "shadow")
check("render: một dòng, id trong dải, shadow = pass", "\n" not in line and "id:9900007," in line and ",pass,log," in line
      and line.startswith('SecRule ARGS:id "@rx (?s)\\bunion\\b.{0,40}\\bselect\\b" "'), line)
check("render: active = deny 403", "deny,status:403" in S.render(con, 9900008, "active"))
check("render: token có ký tự regex được thoát", "\\(" in S.render(dict(seq, tokens=["alert(", "cookie"]), 1, "active"))

print("== bộ sinh luật")
att = [f"{i}' union select {c} from users-- -" for i, c in enumerate(["a", "b,c", "pw", "x", "name,pw", "id", "u", "p"])]
samples = [{"cls": "sqli", "ip": f"198.51.100.{i % 3}", "args": [("id", v), ("submit", "submit")]} for i, v in enumerate(att)]
vocab = "\n".join(["union", "select", "from", "users", "submit", "name"])
ben = M.Benign(["laptop", "submit", "please select a table from the list", "o'brien"], vocab, 6)
prior = M.TokenPrior({"sqli": [f"{i} union select x from t" for i in range(20)] + ["' or 1=1"] * 5, "xss": [], "lfi": [], "rce": []}, ben)
r1 = M.generate_g1(samples, ben)
r2 = M.generate_g2(samples, ben, prior, cluster="label")
check("G1 sinh được luật và luật qua kiểm tra tĩnh", bool(r1) and all(S.static_check(sp)[0] for sp, _, _ in r1))
check("G2 sinh được luật và luật qua kiểm tra tĩnh", bool(r2) and all(S.static_check(sp)[0] for sp, _, _ in r2))
for name, rs in (("G1", r1), ("G2", r2)):
    specs = [sp for sp, _, _ in rs]
    check(f"{name}: không luật nào khớp tham số đi kèm 'submit'", not any(S.matches(sp, [("submit", "submit")]) for sp in specs))
    check(f"{name}: không luật nào khớp dữ liệu lành tính đã biết", not any(ben.hits(sp) for sp in specs))
    check(f"{name}: chặn được biến thể chèn chú thích", any(S.matches(sp, [("id", "9'/**/UNION/**/SELECT z FROM users-- -")]) for sp in specs))
    check(f"{name}: luật nhắm đúng tham số id", all(sp["target"] == "ARGS:id" for sp in specs))
check("G2: từ đơn có trong vốn từ nền không thành luật một token",
      not any(len(sp["tokens"]) == 1 and sp["tokens"][0] in ("union", "select", "from", "users") for sp, _, _ in r2))
pois = [dict(s, args=[("id", s["args"][0][1] + " zq'flaherty"), s["args"][1]]) for s in samples]
p2 = M.generate_g2(pois, ben, prior, cluster="label")
check("G2: token lạ do kẻ tấn công chèn không tự thành luật",
      not any(S.matches(sp, [("name", "sean zq'flaherty")]) for sp, _, _ in p2))

print()
if FAILS:
    print(f"THẤT BẠI {len(FAILS)}: " + "; ".join(FAILS)); sys.exit(1)
print("TẤT CẢ ĐỀU ĐẠT")
