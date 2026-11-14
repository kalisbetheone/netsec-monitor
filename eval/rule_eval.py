#!/usr/bin/env python3
"""eval/rule_eval.py — so sánh các bộ sinh luật NGOÀI Docker, trên cùng dữ liệu.

    python -I -X utf8 -B eval/rule_eval.py                 (chạy từ thư mục nsm; ~vài phút)
    python -I -X utf8 -B eval/rule_eval.py --seeds 5 --sizes 10,30
    python -I -X utf8 -B eval/rule_eval.py --pools         (chỉ in kích thước các tập dữ liệu)

Bộ sinh:  G0 = rulegen hiện tại · G1 = thuật toán cải tiến (không học) · G2 = học máy (xem rulegen_ml.py)
Dữ liệu:  payload công khai SecLists (eval/data/seclists) đã được CHÍNH classifier của hệ thống gắn nhãn —
          chỉ payload mà classifier nhận ra mới vào tập, đúng như thứ rulegen nhận được khi chạy thật;
          văn bản lành tính = họ tên, tên đường, thành phố (SecLists) + câu sinh từ khuôn, có nhóm "khó".
Mỗi lượt (một hạt giống): chia mỗi tập thành ba phần RỜI nhau
          tri thức nền (G2 học) | quan sát (n payload "vừa bị tấn công") | giữ riêng (tấn công tương lai).
Chấm:     bằng secrule.matches — mô phỏng cách ModSecurity áp luật (xem secrule.py).
Kết quả:  eval/results/<tên>.json + bảng Markdown in ra màn hình.
"""
import argparse, json, os, random, re, statistics, sys, time, types, warnings
from collections import Counter, defaultdict
from urllib.parse import quote, unquote_plus

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVC, DATA = os.path.join(ROOT, "services"), os.path.join(ROOT, "eval", "data", "seclists")
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object
sys.modules.setdefault("confluent_kafka", ck)
es_mod = types.ModuleType("elasticsearch"); es_mod.helpers = types.SimpleNamespace(); es_mod.Elasticsearch = object
sys.modules.setdefault("elasticsearch", es_mod)
sys.path.insert(0, SVC)
os.environ.update({"MODEL_PATH": os.path.join(ROOT, "models", "tier2.joblib"), "TIER2_THRESHOLD": "0.90",
                   "TIER2_SYNTAX_GATE": "1", "TIER2_DECISION": "argmax", "MIN_CLUSTER": "5", "EPSILON": "0",
                   "INTERNAL_CIDRS": "10.10.30.0/24,10.10.10.10/32,172.16.0.0/12"})
import classifier as C          # noqa: E402
import rulegen as R0            # noqa: E402
import rulegen_ml as M          # noqa: E402
import secrule as S             # noqa: E402

CLASSES = ("sqli", "xss", "lfi", "rce")
EP = {"sqli": ("/vulnerabilities/sqli/", "id", "GET"), "xss": ("/vulnerabilities/xss_r/", "name", "GET"),
      "lfi": ("/vulnerabilities/fi/", "page", "GET"), "rce": ("/vulnerabilities/exec/", "ip", "POST")}
FILES = {
    "sqli": ["Fuzzing_Databases_SQLi_Generic-SQLi.txt", "Fuzzing_Databases_SQLi_quick-SQLi.txt",
             "Fuzzing_Databases_SQLi_Generic-BlindSQLi.fuzzdb.txt", "Fuzzing_Databases_SQLi_sqli.auth.bypass.txt",
             "Fuzzing_Databases_SQLi_MySQL.fuzzdb.txt", "Fuzzing_Databases_SQLi_MSSQL.fuzzdb.txt"],
    "xss": ["Fuzzing_XSS_robot-friendly_XSS-Jhaddix.txt", "Fuzzing_XSS_robot-friendly_XSS-RSNAKE.txt",
            "Fuzzing_XSS_robot-friendly_XSS-BruteLogic.txt", "Fuzzing_XSS_robot-friendly_XSS-Somdev.txt",
            "Fuzzing_XSS_robot-friendly_XSS-payloadbox.txt"],
    "lfi": ["Fuzzing_LFI_LFI-Jhaddix.txt", "Fuzzing_LFI_LFI-linux-and-windows_by-1N3_CrowdShield.txt"],
    "rce": ["Fuzzing_command-injection-commix.txt", "Fuzzing_UnixAttacks.fuzzdb.txt"],
}
PER_FILE_CAP = 700


def read_lines(name):
    with open(os.path.join(DATA, name), encoding="utf-8", errors="replace") as f:
        return [ln.rstrip("\r\n") for ln in f]


def clf_norm(v):
    """Giá trị như classifier lưu vào Elasticsearch (giải mã thêm, chữ thường)."""
    return C.decode_p(v, 2).lower()


def label_of(cls, v):
    path, param, method = EP[cls]
    arg = [(param, clf_norm(v)[:2048])]
    enc = f"{param}={quote(v, safe='')}&submit=submit"
    if method == "POST":
        r = C.classify(path, [], arg, "Mozilla/5.0", {"uri": path, "query": "", "body": enc})
    else:
        r = C.classify(path, arg, [], "Mozilla/5.0", {"uri": path, "query": enc, "body": ""})
    return r["label"], r["tier"]


def load_attacks():
    """{lớp: [giá trị]} — payload mà classifier gắn đúng nhãn lớp; kèm thống kê."""
    rng = random.Random(12345)
    pools, stats = {}, {}
    for cls in CLASSES:
        raw = []
        for fn in FILES[cls]:
            lines = [ln for ln in read_lines(fn) if ln.strip() and not ln.startswith("# ")]
            if len(lines) > PER_FILE_CAP:
                lines = rng.sample(lines, PER_FILE_CAP)
            raw += lines
        seen, vals = set(), []
        for ln in raw:
            v = unquote_plus(ln).strip().replace("__TIME__", "5")      # chỗ giữ chỗ của SecLists -> giá trị thật
            if 6 <= len(v) <= 256 and v.lower() not in seen:
                seen.add(v.lower()); vals.append(v)
        lab = Counter(); keep = []; tiers = Counter()
        for v in vals:
            l, t = label_of(cls, v)
            lab[l] += 1
            if l == cls:
                keep.append(v); tiers[t] += 1
        pools[cls] = keep
        stats[cls] = {"dong_doc": len(raw), "khac_nhau": len(vals), "dung_nhan": len(keep),
                      "nhan": dict(lab), "tang": {str(k): v for k, v in tiers.items()}}
    return pools, stats


# ------------------------------------------------------------------ dữ liệu lành tính
NOUNS = "laptop phone table chair book ticket invoice order report camera printer keyboard mouse monitor bag shoe " \
        "jacket coffee tea bread milk rice water garden window door school office market bridge river".split()
ADJS = "red blue green small large cheap fast quiet new old wireless digital soft heavy light fresh".split()
VERBS = "buy sell find send open close print check book cancel update share".split()
DAYS = "monday tuesday wednesday thursday friday saturday sunday".split()
AP_SURNAMES = ["O'Brien", "O'Connor", "O'Neill", "O'Reilly", "O'Sullivan", "O'Donnell", "O'Malley", "O'Hara", "O'Keefe",
               "O'Leary", "O'Rourke", "O'Shea", "O'Grady", "O'Dwyer", "O'Toole", "O'Callaghan", "D'Angelo", "D'Souza",
               "D'Amico", "D'Arcy", "D'Costa", "D'Cruz", "N'Diaye", "N'Golo", "N'Dour", "L'Heureux", "M'Baye",
               "De'Ath", "Ka'ahumanu", "Te'o"]
RESERVED = ["O'Flaherty", "O'Halloran", "D'Alessandro", "N'Zogbia", "O'Shaughnessy", "D'Agostino", "M'Bolhi",
            "L'Estrange", "O'Loughlin", "D'Ambrosio"]          # chỉ xuất hiện ở tập thử đầu độc


def load_vocab():
    """Vốn từ tiếng Anh nền (233 nghìn từ): tri thức có sẵn của hệ thống, không chia tập."""
    words = [w for w in read_lines("Miscellaneous_lang-english.words3-10.txt") if w]
    return "\n".join(words), len(words)


def load_benign(rng):
    """-> (thường, các NHÓM khó). Mỗi nhóm khó là một KIỂU văn bản (một khuôn câu): mỗi lượt đánh giá sẽ
    giữ hẳn một số kiểu ra ngoài, để đo chặn nhầm trên loại văn bản hệ thống chưa từng thấy (ca D4)."""
    first = [x.title() for x in read_lines("Usernames_Names_names.txt") if x.isalpha()]
    family = [x.title() for x in read_lines("Usernames_Names_familynames-usa-top1000.txt") if x.isalpha()]
    surn = [x.title() for x in read_lines("Miscellaneous_Security-Question-Answers_common-surnames.txt") if x.isalpha()]
    streets = [x for x in read_lines("Miscellaneous_Security-Question-Answers_street-names.txt") if x.strip()]
    cities = [x for x in read_lines("Miscellaneous_us-cities.txt") if x.strip()]
    plain_cities = [c for c in cities if "'" not in c]
    ap_cities = [c for c in cities if "'" in c]
    pick = lambda xs, k: rng.sample(xs, min(k, len(xs)))                       # noqa: E731
    normal = pick(first, 2500) + pick(family, 600) + pick(surn, 1500) + pick(streets, 2500) + pick(plain_cities, 2500)
    normal += [f"{rng.choice(first)} {rng.choice(surn)}" for _ in range(2000)]
    normal += [f"{rng.choice(first).lower()}.{rng.choice(family).lower()}@example.com" for _ in range(400)]
    normal += [f"{rng.choice(ADJS)} {rng.choice(NOUNS)}" for _ in range(600)]
    normal += [f"{rng.choice(VERBS)} {rng.choice(ADJS)} {rng.choice(NOUNS)} {rng.choice(DAYS)}" for _ in range(600)]
    normal += [str(rng.randint(1, 99999)) for _ in range(300)]
    normal += [f"{rng.choice(NOUNS)}{rng.randint(1, 9)}.{rng.choice(['php', 'html', 'pdf', 'png', 'txt'])}" for _ in range(300)]
    normal += [f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(200)]
    normal += [f"{rng.choice(NOUNS)}-{rng.choice(NOUNS)}.example.{rng.choice(['com', 'org', 'vn'])}" for _ in range(200)]
    normal += [u for u in read_lines("Usernames_top-usernames-shortlist.txt") if u.strip()]

    n, a, v, d = (lambda: rng.choice(NOUNS)), (lambda: rng.choice(ADJS)), (lambda: rng.choice(VERBS)), (lambda: rng.choice(DAYS))
    num = lambda: rng.randint(2, 99)                                             # noqa: E731
    groups = [list(dict.fromkeys(ap_cities)),
              list(dict.fromkeys(f"{rng.choice(first)} {s}" for s in AP_SURNAMES for _ in range(8)))]
    tmpl = [
        lambda: f"don't forget the {n()}", lambda: f"it's {a()} on {d()}", lambda: f"we can't {v()} the {n()}",
        lambda: f"{rng.choice(first)}'s {a()} {n()}", lambda: f"rock 'n' roll {n()}",
        lambda: f"please select a {n()} from the list", lambda: f"the {n()} union meets on {d()}",
        lambda: f"select {n()} or {n()}", lambda: f"drop the {n()} off on {d()}",
        lambda: f"update my {n()} and delete the old one", lambda: f"where is the {a()} {n()} table",
        lambda: f"order by price and group by {n()}", lambda: f"insert coin; select player {num()}",
        lambda: f"union members select a {a()} leader", lambda: f"from {d()} to {d()} we {v()} {n()}s",
        lambda: f"{num()} < {num()} and {num()} > {num()}", lambda: f"x <= y; y >= z; {num()} = {num()}",
        lambda: f"{num()} * {num()} = {num() * num()}", lambda: f"{num()}% off ({d()} only)",
        lambda: f"price: ${num()}; tax: {num()}%", lambda: f"a={num()}&b={num()}",
        lambda: f"use <b>{a()}</b> for emphasis", lambda: f"i <3 my {a()} {n()}",
        lambda: f"{rng.choice(first)} <{rng.choice(family).lower()}@example.com>", lambda: f"{n()} & {n()} (2-pack)",
        lambda: f"<{n()}> goes here", lambda: f"docs/{n()}/../{n()}.txt",
        lambda: f"C:\\Users\\{rng.choice(first)}\\Documents\\{n()}.txt", lambda: f"see /etc/hosts for the {n()} entry",
        lambda: f"/usr/bin/{n()} is missing", lambda: f"how do i run ls -la; cat {n()}.txt",
        lambda: f"eggs; cat food; id card; {n()}", lambda: f"milk; bread; {n()}; {n()}",
        lambda: f"ping me later; sleep well on {d()}", lambda: f"javascript tutorial for {a()} {n()}",
        lambda: f"script writing tips: {n()}", lambda: f"alert the {n()} manager (urgent)",
        lambda: f"document cookie policy for {n()}", lambda: f"#{n()} #{a()}", lambda: f"-- the {a()} end --",
        lambda: f"\"{a()} {n()}\" said {rng.choice(first)}", lambda: f"({n()}) or ({n()})",
        # văn bản có nháy và từ nối
        lambda: f"'{a()}' or '{a()}' {n()}", lambda: f"\"{n()}\" and \"{n()}\" on {d()}",
        lambda: f"{rng.choice(first)}'s {n()}; {rng.choice(first)}'s {n()}", lambda: f"type: {a()} | size: {num()}",
        # văn bản kỹ thuật thật (diễn đàn lập trình, tài liệu): giống tấn công nhất
        lambda: f"how does the <script> tag load a {n()}", lambda: f"onload vs onclick events for the {n()} page",
        lambda: f"use ../ to go up from the {n()} folder", lambda: f"SELECT name FROM {n()}s -- sample query",
        lambda: f"ls | grep {n()} shows nothing", lambda: f"$(echo {n()}) prints {n()}",
        lambda: f"<img src={n()}.png> is broken", lambda: f"UNION vs UNION ALL when I select {n()} rows",
    ]
    for t in tmpl:
        groups.append(list(dict.fromkeys(t() for _ in range(14))))
    return list(dict.fromkeys(normal)), groups


# ------------------------------------------------------------------ biến thể né tránh
def _case(v, rng):
    return "".join(c.upper() if c.isalpha() and rng.random() < 0.5 else c for c in v)


def _sp_comment(v, rng):
    return "".join("/**/" if c == " " and rng.random() < 0.7 else c for c in v)


def _sp_multi(v, rng):
    return "".join(rng.choice(["  ", "\t", "\n", "   "]) if c == " " and rng.random() < 0.7 else c for c in v)


def _tag_ws(v, rng):
    v = re.sub(r"<(\w+) ", lambda m: f"<{m.group(1)}" + rng.choice(["  ", "\t", "\n"]), v)
    return re.sub(r"(\w)=", lambda m: m.group(1) + rng.choice([" =", "= ", " = "]) if rng.random() < 0.5 else m.group(0), v)


def _slash_double(v, rng):
    return v.replace("/", "//")


def _slash_back(v, rng):
    return v.replace("/", "\\")


def _dot_slash(v, rng):
    return re.sub(r"/(?=[a-zA-Z])", "/./", v)


def _null_suffix(v, rng):
    return v + "\x00"


def _sep_ws(v, rng):
    return re.sub(r"([;|&`]|\$\()\s*", lambda m: m.group(1) + rng.choice([" ", "  ", "\t"]), v)


MUT = {"sqli": [_case, _sp_comment, _sp_multi], "xss": [_case, _tag_ws, _sp_multi],
       "lfi": [_slash_double, _slash_back, _dot_slash, _null_suffix], "rce": [_sep_ws, _sp_multi]}


def mutate(cls, v, rng):
    for op in rng.sample(MUT[cls], rng.choice([1, 2])):
        v = op(v, rng)
    return v


# ------------------------------------------------------------------ bộ sinh G0 (rulegen hiện tại)
def g0_corpus(benign_values, vocab_blob):
    corp = R0.Corpus()
    for v in benign_values:
        corp.add([clf_norm(v)])
    for w in vocab_blob.split("\n"):
        corp.add([w])
    corp.seal()
    return corp


def generate_g0(samples, corp):
    """Lặp lại đúng vòng sinh luật trong rulegen.cycle(), dùng chính các hàm của rulegen.py."""
    by = defaultdict(dict)
    for s in samples:
        a = [(n, clf_norm(v)[:512]) for n, v in s["args"]]
        by[s["cls"]].setdefault((s["ip"], tuple(sorted(v for _, v in a))), a)
    rules = []
    for cls, uniq in by.items():
        xs, made = list(uniq.values())[:300], 0
        while len(xs) >= R0.MIN_CLUSTER and made < R0.MAX_RULES_PER_CLASS:
            tok, op, idx = None, "contains", []
            if cls == "rce":
                idx = [i for i, s in enumerate(xs) if any(R0.RCE_RE.search(v) for _, v in s)]
                if len(idx) >= R0.MIN_CLUSTER and not corp.rejects(rx=R0.RCE_RE):
                    tok, op = R0.RCE_RX, "rx"
            if tok is None:
                tok, idx = R0.invariant(xs, corp)
            if not tok:
                break
            m = (lambda v: bool(R0.RCE_RE.search(v))) if op == "rx" else (lambda v, t=tok: t in v)
            spec = {"class": cls, "target": R0.narrow_target(m, xs, idx), "transforms": list(S.BASE),
                    "op": "rx_fixed" if op == "rx" else "contains", "tokens": [tok]}
            rules.append((spec, len(idx), {})); made += 1
            cov = set(idx)
            xs = [s for i, s in enumerate(xs) if i not in cov]
    return rules


# ------------------------------------------------------------------ chấm điểm
def value_hit(specs, v):
    """Luật nào đó khớp giá trị v (bỏ qua tên tham số: giả định xấu nhất là văn bản nằm đúng tham số đích)."""
    for sp in specs:
        if S.matcher(sp)(S.apply(sp["transforms"], v)):
            return True
    return False


def split3(xs, rng, fr=(0.4, 0.3)):
    xs = list(xs); rng.shuffle(xs)
    a, b = int(len(xs) * fr[0]), int(len(xs) * (fr[0] + fr[1]))
    return xs[:a], xs[a:b], xs[b:]


def as_samples(cls, values, rng, ips=4):
    param = EP[cls][1]
    return [{"cls": cls, "ip": f"198.51.100.{rng.randint(1, ips)}", "args": [(param, v), ("submit", "submit")]}
            for v in values]


COMPANION = "submit"          # mọi request (tấn công lẫn lành tính) đều có tham số đi kèm này
WORD_ONLY = re.compile(r"^[a-z_]+$")


def run(seeds, sizes, gens, pools, vocab, verbose=True):
    rows = []
    vocab_blob, n_vocab = vocab
    for seed in range(seeds):
        rng = random.Random(1000 + seed)
        normal, groups = load_benign(rng)
        gi = list(range(len(groups))); rng.shuffle(gi)
        k = max(1, int(0.3 * len(gi)))                              # 30 % số KIỂU văn bản khó bị giữ hẳn ra ngoài
        bh_unseen = [v for i in gi[:k] for v in groups[i]]
        hard = [v for i in gi[k:] for v in groups[i]]
        bn_bg, bn_corp, bn_test = split3(normal, rng)
        bh_bg, bh_corp, bh_test = split3(hard, rng)
        known = bn_bg + bn_corp + bh_bg + bh_corp + [COMPANION]  # mọi dữ liệu lành tính mà hệ thống "đã thấy"
        benign = M.Benign(known, vocab_blob, n_vocab)
        corp0 = g0_corpus(known, vocab_blob) if "G0" in gens else None
        parts = {c: split3(pools[c], rng) for c in CLASSES}       # tri thức nền | quan sát | giữ riêng
        prior = M.TokenPrior({c: parts[c][0] for c in CLASSES}, benign)
        test = {c: parts[c][2] for c in CLASSES}
        mut = {c: [mutate(c, v, rng) for v in test[c]] for c in CLASSES}
        res_first = [x.title() for x in ("sean", "maria", "john", "linh", "anna")]
        for n in sizes:
            obs = []
            for c in CLASSES:
                obs += as_samples(c, rng.sample(parts[c][1], min(n, len(parts[c][1]))), rng)
            # kịch bản đầu độc: một IP, mọi payload kèm cùng một họ tên hợp lệ nhưng hệ thống chưa từng thấy
            x = RESERVED[seed % len(RESERVED)]
            sep = {"sqli": " -- ", "xss": " ", "lfi": "\x00", "rce": " #"}
            pois = []
            for c in CLASSES:
                for s in as_samples(c, rng.sample(parts[c][1], min(n, len(parts[c][1]))), rng):
                    p, v = s["args"][0]
                    pois.append(dict(s, ip="203.0.113.9", args=[(p, v + sep[c] + x), s["args"][1]]))
            victims = [f"{f} {x}" for f in res_first]
            for g in gens:
                for scen, samples in (("thuong", obs), ("dau_doc", pois)):
                    t0 = time.perf_counter()
                    if g == "G0":
                        rules = generate_g0(samples, corp0)
                    elif g == "G1":
                        rules = M.generate_g1(samples, benign)
                    elif g == "G2":
                        rules = M.generate_g2(samples, benign, prior)
                    elif g == "G2n":                              # bóc tách: cổng học máy nhưng gom cụm theo nhãn
                        rules = M.generate_g2(samples, benign, prior, cluster="label")
                    else:
                        raise SystemExit(f"bộ sinh lạ: {g}")
                    dt = time.perf_counter() - t0
                    specs = [r[0] for r in rules]
                    for sp in specs:
                        ok, why = S.static_check(sp, fixed_rx=(R0.RCE_RX,))
                        if not ok and g != "G0":
                            raise SystemExit(f"{g} sinh luật không qua kiểm tra tĩnh ({why}): {sp}")
                    comp = value_hit(specs, COMPANION)            # luật khớp tham số đi kèm = chặn MỌI request
                    row = {"seed": seed, "n": n, "gen": g, "scen": scen, "rules": len(specs), "time_s": dt,
                           "fp_normal": 1.0 if comp else sum(value_hit(specs, v) for v in bn_test) / max(len(bn_test), 1),
                           "fp_hard": 1.0 if comp else sum(value_hit(specs, v) for v in bh_test) / max(len(bh_test), 1),
                           "fp_unseen": 1.0 if comp else sum(value_hit(specs, v) for v in bh_unseen) / max(len(bh_unseen), 1),
                           "fp_unseen_ex": [v for v in bh_unseen if value_hit(specs, v)][:5],
                           "word_only": sum(1 for sp in specs if sp["op"] != "rx_fixed" and all(WORD_ONLY.match(t) for t in sp["tokens"])),
                           "victim": any(value_hit(specs, v) for v in victims),
                           "specs": [dict(sp, cover=r[1]) for sp, r in zip(specs, rules)]}
                    hit_all = tot_all = mhit_all = 0
                    for c in CLASSES:
                        sp_c = [sp for sp in specs if sp["class"] == c]
                        k = sum(any(S.matches(sp, [(EP[c][1], v)]) for sp in specs) for v in test[c])
                        km = sum(any(S.matches(sp, [(EP[c][1], v)]) for sp in specs) for v in mut[c])
                        row[f"rec_{c}"] = k / max(len(test[c]), 1)
                        row[f"mut_{c}"] = km / max(len(mut[c]), 1)
                        row[f"rules_{c}"] = len(sp_c)
                        hit_all += k; mhit_all += km; tot_all += len(test[c])
                    row["rec"] = hit_all / max(tot_all, 1)
                    row["mut"] = mhit_all / max(tot_all, 1)
                    rows.append(row)
            if verbose:
                print(f"   hạt giống {seed}, n={n}: xong", file=sys.stderr, flush=True)
    return rows


def mean_sd(xs):
    xs = list(xs)
    if not xs:
        return 0.0, 0.0
    return statistics.mean(xs), (statistics.pstdev(xs) if len(xs) > 1 else 0.0)


def pc(xs):
    m, s = mean_sd(xs)
    return f"{100 * m:.1f} ± {100 * s:.1f}".replace(".", ",")


def summarize(rows, sizes, gens):
    out = []
    for n in sizes:
        out.append(f"\n### n = {n} payload quan sát mỗi lớp\n")
        out.append("| Bộ sinh | Số luật | Chặn tấn công giữ riêng (%) | Chặn biến thể né tránh (%) | Chặn nhầm thường (%) | "
                   "Chặn nhầm khó, kiểu đã thấy (%) | Chặn nhầm khó, kiểu CHƯA thấy (%) | Luật chỉ gồm từ thuần chữ | "
                   "Thời gian sinh (s) |")
        out.append("|---|---|---|---|---|---|---|---|---|")
        for g in gens:
            rs = [r for r in rows if r["n"] == n and r["gen"] == g and r["scen"] == "thuong"]
            m, s = mean_sd(r["rules"] for r in rs)
            t, _ = mean_sd(r["time_s"] for r in rs)
            wo, _ = mean_sd(r["word_only"] for r in rs)
            out.append(f"| {g} | {m:.1f} ± {s:.1f} | {pc(r['rec'] for r in rs)} | {pc(r['mut'] for r in rs)} | "
                       f"{pc(r['fp_normal'] for r in rs)} | {pc(r['fp_hard'] for r in rs)} | "
                       f"{pc(r['fp_unseen'] for r in rs)} | {wo:.1f} | {t:.2f} |".replace(".", ","))
        out.append("")
        out.append("| Bộ sinh | " + " | ".join(f"{c}: giữ riêng / biến thể (%)" for c in CLASSES) + " |")
        out.append("|---|" + "---|" * len(CLASSES))
        for g in gens:
            rs = [r for r in rows if r["n"] == n and r["gen"] == g and r["scen"] == "thuong"]
            cells = [f"{100 * mean_sd(r[f'rec_{c}'] for r in rs)[0]:.0f} / {100 * mean_sd(r[f'mut_{c}'] for r in rs)[0]:.0f}"
                     for c in CLASSES]
            out.append(f"| {g} | " + " | ".join(cells) + " |")
        out.append("")
        out.append("| Bộ sinh | Đầu độc thành công (% số lượt) | Chặn tấn công giữ riêng khi bị đầu độc (%) | "
                   "Chặn nhầm khó, kiểu chưa thấy, khi bị đầu độc (%) |")
        out.append("|---|---|---|---|")
        for g in gens:
            rs = [r for r in rows if r["n"] == n and r["gen"] == g and r["scen"] == "dau_doc"]
            v = 100 * sum(r["victim"] for r in rs) / max(len(rs), 1)
            out.append(f"| {g} | {v:.0f} | {pc(r['rec'] for r in rs)} | {pc(r['fp_unseen'] for r in rs)} |".replace(".", ","))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--sizes", default="10,30")
    ap.add_argument("--gens", default="G0,G1,G2n,G2")
    ap.add_argument("--pools", action="store_true")
    ap.add_argument("--out", default="rule_eval")
    a = ap.parse_args()
    t0 = time.time()
    pools, stats = load_attacks()
    normal, groups = load_benign(random.Random(0))
    hard = [v for g in groups for v in g]
    print("## Dữ liệu\n")
    print("| Lớp | Dòng đọc | Payload khác nhau | Classifier gắn đúng lớp | Tầng 1 / tầng 2 | Nhãn khác |")
    print("|---|---|---|---|---|---|")
    for c in CLASSES:
        st = stats[c]
        other = ", ".join(f"{k}: {v}" for k, v in sorted(st["nhan"].items()) if k != c)
        print(f"| {c} | {st['dong_doc']} | {st['khac_nhau']} | {st['dung_nhan']} | "
              f"{st['tang'].get('1', 0)} / {st['tang'].get('2', 0)} | {other} |")
    print(f"\nLành tính: {len(normal)} thường, {len(hard)} khó thuộc {len(groups)} kiểu văn bản. "
          f"(nạp dữ liệu {time.time() - t0:.0f} s)")
    if a.pools:
        return
    sizes = [int(x) for x in a.sizes.split(",")]
    gens = a.gens.split(",")
    rows = run(a.seeds, sizes, gens, pools, load_vocab())
    print(f"\n## Kết quả ({a.seeds} hạt giống; trung bình ± độ lệch chuẩn)")
    print(summarize(rows, sizes, gens))
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    with open(os.path.join(ROOT, "eval", "results", a.out + ".json"), "w", encoding="utf-8") as f:
        json.dump({"stats": stats, "benign": {"normal": len(normal), "hard": len(hard)}, "seeds": a.seeds,
                   "sizes": sizes, "gens": gens, "rows": rows}, f, ensure_ascii=False)
    print(f"\n(tổng thời gian {time.time() - t0:.0f} s; dữ liệu thô: eval/results/{a.out}.json)")


if __name__ == "__main__":
    main()
