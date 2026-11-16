#!/usr/bin/env python3
"""train/t2_hard_benign.py — bước 2 của việc cải thiện tầng 2: sinh VĂN BẢN HỢP LỆ "KHÓ" để huấn luyện.

    python -X utf8 -B train/t2_hard_benign.py        (chạy từ thư mục nsm; ~1 phút)  -> train/data_src/hard_benign.jsonl.gz

Vì sao: model 14/11 gắn nhãn tấn công (điểm 1,00) cho văn bản hợp lệ có từ khoá SQL / lệnh shell hoặc ký hiệu
("order by price", "C# and C++", "ls"). Câu Tatoeba lấy ngẫu nhiên hiếm khi có các từ đó, nên model chưa từng thấy đủ.

Hai nguồn:
  1. Câu Tatoeba (đã có ở eval/data/tatoeba, CC BY 2.0 FR) CÓ TỪ KHOÁ SQL / shell; chia train / valid / test theo đúng hàm băm
     của train/build_tier2_dataset.py, nên không câu nào nằm ở hai tập.
  2. Chuỗi ngắn sinh theo MẪU (ô tìm kiếm, tên sản phẩm, ký hiệu, tên lệnh dùng như từ thường). Mỗi chuỗi vào một tập theo băm
     của chính nó (70 / 15 / 15). Hai họ mẫu (toan, url) CHỈ nằm ở tập test: đo việc tổng quát sang kiểu văn bản chưa thấy.

KHÔNG đưa vào train/valid bất kỳ chuỗi nào trùng (không phân biệt hoa thường) với các danh sách KIỂM TRA: hai danh sách đối
chứng của bộ thử tầng 2, mẫu lành tính của bench, câu lành tính của khung kịch bản. Các danh sách đó vì vậy vẫn là phép kiểm
trên chuỗi model chưa thấy. Không sinh câu SQL hoàn chỉnh đứng một mình ("select * from users") làm mẫu hợp lệ: loại đó
vốn mơ hồ, dạy model coi là hợp lệ sẽ làm mất khả năng bắt dò SQL.
"""
import ast, bz2, gzip, hashlib, itertools, json, os, random, re, sys
from collections import Counter
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "train", "data_src")
TATOEBA = os.path.join(ROOT, "eval", "data", "tatoeba")
SEED = 20261115
CAP_TATOEBA = {"train": 20000, "valid": 4000, "test": 4000}
CAP_FAMILY = {"train": 1500, "valid": 300, "test": 300}          # mỗi họ mẫu, mỗi tập
TEST_ONLY = ("toan", "url")

STRONG_KW = ("select", "union", "insert", "drop", "delete", "update", "exec", "script", "alert", "passwd", "sudo", "chmod",
             "wget", "curl", "whoami", "shell", "cmd", "eval", "database", "null", "sql", "query", "root", "admin")
WEAK_KW = ("from", "where", "order", "group", "table", "join", "having", "like", "count", "cat", "dir", "echo", "ping",
           "type", "kill", "system", "net", "bin", "password", "login", "user", "and", "or", "not", "all", "into", "set")
_WORD = re.compile(r"[a-z]+")


def tatoeba_split(sid):                       # = train/build_tier2_dataset.tatoeba_split, "test_sites" gọi là "test"
    x = int(hashlib.sha1(f"tatoeba:{sid}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "train" if x < 0.70 else ("valid" if x < 0.85 else "test")


def str_split(family, s):
    if family in TEST_ONLY:
        return "test"
    x = int(hashlib.sha1(f"hard:{s.casefold()}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "train" if x < 0.70 else ("valid" if x < 0.85 else "test")


def test_strings():
    """Mọi chuỗi của các danh sách kiểm tra (để LOẠI khỏi train/valid)."""
    out = set()
    for f in ("doi-chung.jsonl", "doi-chung-2.jsonl"):
        p = os.path.join(ROOT, "scenarios", "tang-2", f)
        if os.path.exists(p):
            out |= {json.loads(ln)["value"] for ln in open(p, encoding="utf-8") if ln.strip()}
    for f, names in (("bench.py", ("BENIGN", "BENIGN_HARD")), ("scenario.py", ("PAYLOADS",))):
        tree = ast.parse(open(os.path.join(ROOT, "tools", f), encoding="utf-8").read())
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) in names for t in node.targets):
                out |= {n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    return {s.strip().casefold() for s in out if s.strip()}


def tatoeba_rows(rng):
    res = {s: [] for s in CAP_TATOEBA}; seen = Counter(); kinds = Counter()
    p = os.path.join(TATOEBA, "eng_sentences.tsv.bz2")
    with bz2.open(p, "rt", encoding="utf-8", errors="replace") as f:
        for ln in f:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            t = parts[2].strip()
            if not 3 <= len(t) <= 200:
                continue
            ws = set(_WORD.findall(t.lower()))
            strong = ws.intersection(STRONG_KW)
            if not strong and len(ws.intersection(WEAK_KW)) < 3:
                continue
            s = tatoeba_split(parts[0]); seen[s] += 1
            row = {"value": t, "split": s, "kind": "tatoeba-kw", "family": "tatoeba-kw"}
            if len(res[s]) < CAP_TATOEBA[s]:
                res[s].append(row)
            else:
                j = rng.randrange(seen[s])
                if j < CAP_TATOEBA[s]:
                    res[s][j] = row
    print("   câu Tatoeba có từ khoá (tổng / giữ):", {s: (seen[s], len(res[s])) for s in res}, file=sys.stderr)
    return [r for s in res for r in res[s]]


# ------------------------------------------------------------------ mẫu sinh chuỗi ngắn
ITEMS = ["laptop", "phone", "tablet", "camera", "headphones", "keyboard", "monitor", "printer", "backpack", "watch", "jacket",
         "sneakers", "sofa", "desk lamp", "coffee maker", "bicycle", "guitar", "tent", "suitcase", "perfume", "rice cooker",
         "air fryer", "power bank", "router", "smart tv", "blender", "microwave", "stroller", "helmet", "sunglasses"]
FIELDS = ["price", "date", "name", "rating", "size", "color", "brand", "newest", "popularity", "distance", "duration",
          "departure time", "arrival time", "seat class", "discount", "weight", "stock", "category", "review count", "best match"]
PURPOSES = ["school", "work", "travel", "gaming", "my mom", "the office", "a gift", "kids", "beginners", "students", "running",
            "the kitchen", "camping", "winter", "a small room"]
CITIES = ["hanoi", "saigon", "da nang", "hue", "nha trang", "tokyo", "seoul", "bangkok", "paris", "london", "berlin", "sydney"]
NAMES = ["anna", "minh", "linh", "tom", "sara", "duc", "mai", "john", "hoa", "peter", "lan", "kim"]
NOUNS = ["menu", "list", "cart", "order", "ticket", "booking", "address", "account", "profile", "message", "photo", "review",
         "invoice", "coupon", "wishlist", "seat", "room", "flight"]
ADJ = ["ok", "fine", "great", "late", "ready", "sold out", "on sale", "too big", "very good", "not bad"]
CMDS = ["ls", "dir", "pwd", "cd", "id", "cat", "echo", "type", "date", "time", "who", "whoami", "uname", "ps", "top", "kill",
        "find", "sort", "more", "less", "head", "tail", "env", "set", "tree", "path", "start", "exit", "ping", "curl", "wget",
        "ssh", "ftp", "nc", "sh", "bash", "cmd", "powershell", "python", "perl", "php", "ruby", "node", "java", "net",
        "ipconfig", "ifconfig", "hostname", "systeminfo", "tasklist", "ver", "vol", "sleep", "touch", "mount", "grep", "man"]
CMD_PHRASES = ["cat food", "cat toys", "ping pong table", "kill time game", "find my phone", "sort by size", "head office",
               "tail light", "top 10 phones", "more info", "less sugar", "type c cable", "date night ideas", "time zone",
               "net weight", "python book", "java coffee", "ruby ring", "perl necklace", "bash party", "shell necklace",
               "curl cream", "id card", "who is online", "tree house", "path of exile", "start menu", "exit sign",
               "sleep mask", "touch screen", "mount fuji tour", "man shoes", "echo dot", "node js course", "php tutorial",
               "ssh keychain", "ftp server guide", "power shell case", "host name tag", "task list app", "system info app"]
LANGS = ["C#", "C++", "F#", "Go", "R", "Java", "Node.js", ".NET", "Objective-C", "T-SQL", "PL/SQL", "A*", "Q#", "J#"]
BRANDS = ["AT&T", "H&M", "M&M's", "P&G", "R&D", "Q&A", "B&B", "D&G", "S&P 500", "Barnes & Noble", "Marks & Spencer",
          "Johnson & Johnson", "Ben & Jerry's", "Dolce & Gabbana", "Tiffany & Co."]
SQLWORDS = ["select", "insert", "update", "delete", "drop", "create", "alter", "union", "join", "where", "having",
            "group by", "order by", "null", "primary key", "index", "view", "trigger"]
EXT = ["png", "jpg", "pdf", "xml", "yaml", "json", "txt", "csv", "docx", "xlsx", "mp3", "zip"]
SLUGS = ["gioi-thieu", "lien-he", "san-pham", "tin-tuc", "khuyen-mai", "about-us", "contact", "pricing", "blog", "faq",
         "huong-dan", "bao-gia", "logo", "banner", "avatar", "report", "invoice", "readme"]


def gen(family, rng):
    """Sinh chuỗi của một họ mẫu (có thể trùng; khử trùng ở ngoài)."""
    R = rng.choice
    n = lambda a=1, b=99: rng.randint(a, b)
    if family == "sap-xep":
        return R([f"{R(['order', 'sort', 'group', 'filter'])} by {R(FIELDS)}", f"{R(['order', 'sort'])} by {R(FIELDS)} {R(['asc', 'desc', 'ascending', 'descending'])}",
                  f"{R(ITEMS)} {R(['order', 'sort'])} by {R(FIELDS)}", f"top {n(3, 50)} {R(ITEMS)} order by {R(FIELDS)}",
                  f"limit {n(5, 100)} results", f"show {n(5, 50)} per page order by {R(FIELDS)}"])
    if family == "dong-tu-sql":
        return R([f"select {R(['a', 'the best', 'one', 'my', 'another'])} {R(ITEMS)} for {R(PURPOSES)}", f"select seat {n(1, 40)}{R('ABCDEF')}",
                  f"update my {R(NOUNS)}", f"delete my old {R(NOUNS)} please", f"drop by {R(['tomorrow', 'the store', 'at noon', 'next week'])}",
                  f"drop off at {R(CITIES)}", f"insert {R(['coin', 'card', 'sim', 'battery'])} to {R(['continue', 'start', 'pay'])}",
                  f"create {R(NOUNS)} for {n(1, 12)} people", f"join the {R(['club', 'team', 'tour', 'class', 'waitlist'])}",
                  f"from {R(CITIES)} to {R(CITIES)}", f"where is the {R(NOUNS)}", f"union station {R(['tickets', 'parking', 'hotel'])}",
                  f"table for {n(2, 12)} at {n(5, 9)}pm", f"alter {R(['dress', 'suit', 'booking', 'ticket'])} {R(['size', 'date', 'name'])}",
                  f"having trouble with my {R(NOUNS)}", f"{R(ITEMS)} like {R(ITEMS)} but cheaper", f"count me in for {R(CITIES)}",
                  f"all {R(ITEMS)} in {R(CITIES)}", f"{R(['true', 'yes', 'on', 'left', 'in', 'pass'])} or {R(['false', 'no', 'off', 'right', 'out', 'fail'])}",
                  f"{R(NAMES)} and {R(NAMES)}", f"null and void {R(['meaning', 'contract', 'ticket'])}", f"execute order {n(1, 99)}"])
    if family == "so-sanh":
        a, b, c = rng.sample("abcxyzmnpq", 3)
        return R([f"{a} < {b} and {b} > {c}", f"{a} > {b} or {b} < {c}", f"{a} >= {n()}", f"{a} != {b}", f"{n()}={n()}", f"{(k := n())}={k}",
                  f"{(k := n())}={k} is always true", f"if {a} = {b} then {c}", f"{a} == {b}", f"{n()} < {n()}", f"{a} <> {b}",
                  f"size >= {n(30, 46)}", f"price <= {n(10, 900)}", f"age > {n(12, 21)} only", f"{n(1, 9)} out of {n(10, 20)}"])
    if family == "ten-ky-hieu":
        return R([f"{R(LANGS)} and {R(LANGS)}", f"{R(LANGS)} vs {R(LANGS)}", f"{R(LANGS)} & {R(LANGS)} course", f"learn {R(LANGS)} in {n(7, 60)} days",
                  R(BRANDS), f"{R(BRANDS)} {R(['store', 'near me', 'sale', 'careers', 'gift card'])}", f"{R(ITEMS)} ({R(['new', 'used', '2025', 'pro', 'mini'])})",
                  f"{R(ITEMS)} [{R(['black', 'white', 'blue', 'red'])}]", f"{R(ITEMS)} {{{R(['bundle', 'set', 'pack'])}}}", f"{R(NAMES)}@{R(['home', 'work', 'school'])}"])
    if family == "gia-tien":
        return R([f"price: ${n()}; tax: {n(1, 25)}%", f"total: ${n()}; ship: {n(1, 15)}%", f"{n(5, 90)}% off {R(['today', 'this week', R(ITEMS)])}",
                  f"${n()}-${n(100, 900)}", f"{n(1, 9)} x {n(10, 990)}.000đ", f"under ${n(10, 900)}", f"{n(10, 99)}.{n(10, 99)} USD",
                  f"buy {n(1, 3)} get {n(1, 2)} free!", f"{n(1, 5)}* hotel in {R(CITIES)}", f"save {n(5, 70)}% + free ship", f"#{n(1, 99)} best seller"])
    if family == "dau-ngan":
        w = rng.sample(["a", "b", "c", "x", "y", "z", "one", "two", "left", "right", "this", "that", "red", "blue", "tea", "milk"], 3)
        return R([";".join(w), f"{w[0]} | {w[1]}", f"{w[0]} && {w[1]}", f"{w[0]} || {w[1]}", f"{w[0]}/{w[1]}", f"{w[0]}, {w[1]}; {w[2]}",
                  f"{w[0]} -> {w[1]}", f"{w[0]} => {w[1]}", f"{w[0]} + {w[1]}", f"{w[0]} - {w[1]} - {w[2]}", f"-- {w[0]} --", f"({w[0]})",
                  f"{w[0]}...", f"*{w[0]}*", f"~{w[0]}", f"{w[0]}!", f"{w[0]}?", f"{w[0]}: {w[1]}"])
    if family == "the-tag":
        return R([f"#{R(SLUGS).replace('-', '')}{R(['', str(n(2020, 2026))])}", f"@{R(NAMES)}{n(1, 99)}", f"{n(1, 100)}%", f"*{R(['required', 'optional', 'new'])}",
                  f"#{n(1, 9999)}", f"{R(NAMES)}_{R(NAMES)}", f"{R(SLUGS)}#{R(['top', 'faq', 'section-2'])}", f"${R(ITEMS).split()[0]}"])
    if family == "ten-lenh":
        return R([R(CMDS), R(CMDS), R(CMD_PHRASES), f"{R(CMDS)} {R(['book', 'course', 'tutorial', 'for beginners', 'sticker', 'mug', 't-shirt'])}",
                  f"id {n(1000, 99999)}", f"{R(['what is', 'how to use', 'meaning of'])} {R(CMDS)}", f"{R(CMDS)} la gi", f"{R(CMDS)} {R(['shop', 'store', 'cafe'])}"])
    if family == "duong-dan":
        return R([f"{R(['images', 'img', 'docs', 'files', 'tai-lieu', 'media'])}/{R(SLUGS)}{R(['', '-' + str(n(2019, 2026))])}.{R(EXT)}",
                  f"/{R(['products', 'category', 'blog', 'tin-tuc'])}/{R(ITEMS).replace(' ', '-')}/{R([str(n(1, 99)), R(SLUGS)])}",
                  f"../{R(SLUGS)}", f"./{R(SLUGS)}.{R(EXT)}", f"{R(SLUGS)}.{R(EXT)}", f"C:\\Users\\{R(NAMES)}\\{R(['Documents', 'Desktop', 'Pictures', 'Downloads'])}",
                  f"D:\\{R(['photos', 'music', 'backup'])}\\{n(2018, 2026)}", f"/home/{R(NAMES)}/{R(['music', 'photos', 'docs'])}",
                  f"{R(['windows', 'linux', 'macos'])} {R(['system32', 'home', 'library'])} {R(['error', 'folder full', 'missing'])}",
                  f"{R(['hosts', 'passwd', 'config', 'env'])} file {R(['la gi', 'location', 'example'])}", R(["etc.", "v.v.", "e.g.", "i.e.", "a.k.a."])])
    if family == "html":
        w = R(["in dam", "bold", "title", "note", "xem them", "trang chu", "lien he", "price"])
        return R([f"<b>{w}</b>", f"<i>{w}</i>", f"<u>{w}</u>", f"<em>{w}</em>", f"<p>{w}</p>", f"use <b>bold</b> for {w}", "<br>",
                  f"<a href=\"https://example.com/{R(SLUGS)}\">{w}</a>", f"<h{n(1, 3)}>{w}</h{n(1, 3)}>", f"&lt;{w}&gt;", f"{w} &amp; {w}"])
    if family == "dau-nhay":
        return R([f"{R(NAMES).capitalize()}'s {R(NOUNS)}", f"don't {R(['stop', 'worry', 'forget', 'wait'])}", f"it's {R(ADJ)}", f"that's {R(ADJ)}",
                  f"we'll {R(['see', 'come', 'call', 'pay'])}", f"O'{R(['Brien', 'Neil', 'Connor', 'Hara', 'Reilly', 'Malley'])}",
                  f"D'{R(['Angelo', 'Arcy', 'Souza', 'Amico'])}", f"L'{R(['Oréal', 'Occitane', 'amour', 'atelier'])}", f"'{n(60, 99)}s music",
                  f"{R(['rock', 'salt', 'fish', 'mac'])} 'n' {R(['roll', 'pepper', 'chips', 'cheese'])}", f"{R(BRANDS)}'s", f"\"{R(ITEMS)}\"",
                  f"{n(4, 7)}'{n(0, 11)}\" tall", f"{R(ITEMS)} {n(10, 70)}\" {R(['inch', 'screen'])}"])
    if family == "ip":
        return ".".join(str(rng.randint(1, 254)) for _ in range(4))
    if family == "noi-ve-sql":
        return R([f"{R(['SQL tip', 'note', 'question', 'lesson ' + str(n(1, 20))])}: {R(SQLWORDS)} {R(['basics', 'examples', 'explained', 'vs ' + R(SQLWORDS)])}",
                  f"how to use {R(SQLWORDS)} in {R(['sql', 'mysql', 'excel', 'access'])}", f"what does {R(SQLWORDS)} mean", f"difference between {R(SQLWORDS)} and {R(SQLWORDS)}",
                  f"learn {R(SQLWORDS)} {R(['fast', 'online', 'for free'])}", f"{R(SQLWORDS)} {R(['interview questions', 'cheat sheet', 'tutorial pdf'])}",
                  f"book: {R(['SQL', 'MySQL', 'Postgres'])} {R(['in 10 minutes', 'for dummies', 'cookbook'])}", f"is {(k := n(1, 9))}={k} always true"])
    if family == "toan":                                # CHỈ test
        a, b = n(1, 50), n(1, 50)
        return R([f"{a}+{b}={a + b}", f"{a}*{b}={a * b}", f"{a} + {b} = ?", f"x^2 + y^2 = {a}", f"({a}+{b})*{n(2, 9)}", f"{a}/{b} = ?", f"sqrt({a * a})",
                  f"{a}% of {b * 10}", f"f(x) = {a}x + {b}", f"|{a} - {b}|", f"{a}! = ?", f"{a} > {b} ? {a} : {b}"])
    if family == "url":                                 # CHỈ test
        return R([f"https://example.com/{R(SLUGS)}?page={n(1, 20)}&sort={R(FIELDS).split()[0]}", f"www.example.org/{R(SLUGS)}", f"{R(NAMES)}@example.com",
                  f"http://example.net/{R(SLUGS)}.{R(EXT)}", f"example.com/search?q={R(ITEMS).replace(' ', '+')}", f"{R(NAMES)}.{R(NAMES)}@example.org",
                  f"https://example.com/#{R(SLUGS)}", f"ftp://files.example.com/{R(SLUGS)}.{R(EXT)}", f"mailto:{R(NAMES)}@example.com"])
    raise KeyError(family)


FAMILIES = ("sap-xep", "dong-tu-sql", "so-sanh", "ten-ky-hieu", "gia-tien", "dau-ngan", "the-tag", "ten-lenh", "duong-dan", "html",
            "dau-nhay", "ip", "noi-ve-sql") + TEST_ONLY


def main():
    rng = random.Random(SEED)
    ban = test_strings()
    rows = tatoeba_rows(rng)
    stat = Counter(); dropped = Counter()
    for fam in FAMILIES:
        seen = set(); per = Counter()
        for _ in range(60000):
            s = gen(fam, rng).strip()
            k = s.casefold()
            if not s or k in seen:
                continue
            seen.add(k)
            sp = str_split(fam, s)
            if k in ban:
                dropped[fam] += 1                       # trùng một chuỗi kiểm tra: không dùng ở bất kỳ tập nào
                continue
            if per[sp] >= CAP_FAMILY[sp]:
                continue
            per[sp] += 1
            rows.append({"value": s, "split": sp, "kind": "template", "family": fam})
        for sp in ("train", "valid", "test"):
            stat[(fam, sp)] = per[sp]
    rows = [r for r in rows if r["value"].strip().casefold() not in ban or r["kind"] != "tatoeba-kw"]
    os.makedirs(OUT, exist_ok=True)
    with gzip.open(os.path.join(OUT, "hard_benign.jsonl.gz"), "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"chuỗi kiểm tra bị loại khỏi dữ liệu sinh: {sum(dropped.values())} {dict(dropped)} (trong {len(ban)} chuỗi kiểm tra)")
    print(f"{'họ':14} {'train':>6} {'valid':>6} {'test':>6}")
    for fam in FAMILIES:
        print(f"{fam:14} {stat[(fam, 'train')]:6} {stat[(fam, 'valid')]:6} {stat[(fam, 'test')]:6}")
    c = Counter((r["kind"], r["split"]) for r in rows)
    print("tổng:", {f"{k}/{s}": v for (k, s), v in sorted(c.items())}, "->", os.path.join(OUT, "hard_benign.jsonl.gz"))
    rng2 = random.Random(1)
    print("ví dụ:", [r["value"] for r in rng2.sample([r for r in rows if r["kind"] == "template"], 14)])


if __name__ == "__main__":
    main()
