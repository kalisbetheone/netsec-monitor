#!/usr/bin/env python3
"""train/build_tier2_dataset.py — dựng dữ liệu huấn luyện TẦNG 2 của classifier từ eval/data/normalized.

    python -I -X utf8 -B train/build_tier2_dataset.py            (chạy từ thư mục nsm; ~5–10 phút)

Vì sao không huấn luyện thẳng trên dữ liệu chuẩn hoá: request tấn công trong dataset gần như đều ở đường dẫn '/'
với tham số 'p' (cách openappsec đóng gói) hoặc ở đúng endpoint DVWA, còn lành tính đến từ hàng trăm website thật.
Model sẽ học "đường dẫn / tên tham số = tấn công" (đường tắt). Ở đây mỗi payload được CẤY vào một request lành
tính thật của website cùng tập (thay giá trị một tham số có sẵn, đặt vào một trường JSON, hoặc thêm tham số mới),
nên tấn công và lành tính có cùng phân bố đường dẫn, tên tham số, độ dài URL — chỉ khác nội dung giá trị.

Request cấy xong chạy qua ĐÚNG hàm `_classify_web` của classifier (eval/normalize.to_doc) để có nhãn tầng 1 và cổng
cú pháp như hệ thống thật. Đầu ra: train/data/tier2_<tập>.jsonl.gz, mỗi dòng:
    split, source, group, ds_class, method, uri, query, body, ct, t1 (nhãn tầng 1 hoặc 'benign'), gate (cổng cú
    pháp mở hay không), old_label, old_tier (nhãn của model hiện tại — để so sánh), injected (True nếu là cấy)
"""
import gzip, hashlib, json, os, random, re, sys, time
from collections import Counter, defaultdict
from multiprocessing import Pool
from urllib.parse import quote, quote_plus, unquote_plus

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
sys.path.insert(0, os.path.join(ROOT, "services"))
import normalize as N          # noqa: E402  (to_doc, apache_uri, over_limit)

NORM = os.path.join(ROOT, "eval", "data", "normalized")
OUT = os.path.join(ROOT, "train", "data")
CLASSES = ("sqli", "xss", "lfi", "rce")
PER_CLASS = {"train": 15000, "valid": 3000}          # số request tấn công cấy cho mỗi lớp
CARRIER_MAX_BODY = 4096
SEED = 20261112


def rows(src):
    with gzip.open(os.path.join(NORM, f"{src}.jsonl.gz"), "rt", encoding="utf-8") as f:
        for ln in f:
            yield json.loads(ln)


def longest(r):
    v = r.get("marg_v") or []
    return max(v, key=len) if v else ""


# ------------------------------------------------------------------ cấy payload vào request lành tính
def _set_param(raw, payload, rng, names):
    """raw = chuỗi 'a=1&b=2' (query hoặc thân urlencoded). Thay giá trị một tham số, hoặc thêm tham số mới."""
    parts = [p for p in raw.split("&") if p] if raw else []
    enc = quote_plus(payload) if rng.random() < 0.5 else quote(payload, safe="")
    idx = [i for i, p in enumerate(parts) if "=" in p]
    if idx and rng.random() < 0.75:
        i = rng.choice(idx)
        n = parts[i].split("=", 1)[0]
        parts[i] = f"{n}={enc}"
    else:
        parts.insert(rng.randrange(len(parts) + 1), f"{rng.choice(names)}={enc}")
    return "&".join(parts)


def _set_json(body, payload, rng):
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    slots = []

    def walk(x, setter):
        if isinstance(x, dict):
            for k in list(x):
                walk(x[k], lambda v, d=x, k=k: d.__setitem__(k, v))
        elif isinstance(x, list):
            for i in range(len(x)):
                walk(x[i], lambda v, l=x, i=i: l.__setitem__(i, v))
        elif isinstance(x, str) and setter is not None:     # chuỗi ở gốc tài liệu: không có chỗ để thay
            slots.append(setter)
    walk(doc, None)
    if not slots:
        return None
    rng.choice(slots)(payload)
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


MARK = "QZXMARKQZX"          # chữ hoa, không chữ số: đi qua unquote/normalize của feats.make_text nguyên vẹn
T2_WINDOW = 2000             # feats.make_text cắt văn bản còn 2000 ký tự -> tầng 2 không thấy gì phía sau


def t2_text_full(query, body):
    """Văn bản tầng 2 KHÔNG cắt (giống feats.make_text, query có '?' như Apache %q)."""
    from feats import normalize, values_only
    q = ("?" + query) if query else ""
    b = "" if (body or "") == "-" else (body or "")
    return normalize(values_only(unquote_plus(q)) + " " + values_only(unquote_plus(b)))


def t2_visible(marked_req, payload):
    """Payload (bản cấy bằng MARK cùng vị trí) có nằm trong cửa sổ tầng 2 không: ít nhất 256 ký tự đầu của payload
    (hoặc cả payload nếu ngắn hơn) phải ở trước ký tự thứ 2000. Không đạt = nhãn tấn công nhưng model không thấy."""
    from feats import normalize
    pos = t2_text_full(marked_req["query"], marked_req["body"]).find(MARK)
    return pos >= 0 and pos + min(len(normalize(payload)), 256) <= T2_WINDOW


def has_nul(r):
    return "\x00" in (r.get("body") or "") or "\x00" in (r.get("query") or "")


def payload_loc(query, body):
    """'args' nếu request có query hoặc thân; 'path_only' nếu chỉ có đường dẫn (tầng 2 không đọc đường dẫn)."""
    return "args" if (query or (body or "").strip() not in ("", "-")) else "path_only"


def inject(carrier, payload, rng, names):
    r = {k: carrier[k] for k in ("method", "path", "query", "body", "ct", "ua", "site")}
    ct = (r.get("ct") or "").lower()
    has_q = "=" in (r["query"] or "")
    if r["body"] and ct.startswith("application/json") and rng.random() < 0.6:
        b = _set_json(r["body"], payload, rng)
        if b is not None:
            r["body"] = b
            return r
    if r["body"] and ct.startswith("application/x-www-form-urlencoded") and (not has_q or rng.random() < 0.5):
        r["body"] = _set_param(r["body"], payload, rng, names)
        return r
    r["query"] = _set_param(r["query"] or "", payload, rng, names)
    return r


def _work(batch):
    out = []
    for req, meta in batch:
        try:
            d = N.to_doc(req)
        except Exception as e:                      # noqa: BLE001
            out.append(None)
            continue
        out.append(make_row(req, d, meta))
    return out


def gate_of(arg_v):
    C = N._load()
    return bool(C.META.search(" ".join(arg_v or [])))


def make_row(req, d, meta):
    """Dòng dữ liệu tầng 2: request thô như classifier nhận (uri = %U của Apache, query thô, thân thô; thân bị
    ModSecurity trả 413 thì classifier không thấy -> để trống) + nhãn tầng 1 + cổng cú pháp + nhãn model cũ."""
    lab, tier = d.get("label"), d.get("tier")
    return {"split": meta["split"], "source": meta["source"], "group": meta["group"], "ds_class": meta["ds_class"],
            "injected": meta.get("injected", False), "method": req["method"], "uri": N.apache_uri(req["path"]),
            "query": req.get("query") or "", "body": "" if d.get("over_limit") else (req.get("body") or ""),
            "ct": req.get("ct") or "", "t1": lab if tier == 1 else "benign", "gate": gate_of(d.get("arg_v")),
            "old_label": lab, "old_tier": tier, "loc": "args", "nul": has_nul(req),
            # 15/11/2026 (cải thiện tầng 2): g2 = "pass" nếu payload LỌT Cổng 2 thật (train/t2_pool*.py); hard = văn bản hợp lệ "khó"
            **({"g2": meta["g2"]} if meta.get("g2") else {}), **({"hard": True} if meta.get("hard") else {})}


def row_from_norm(r, split, source, group):
    """Bản ghi chuẩn hoá có sẵn -> dòng tầng 2 (không cần chạy lại classifier)."""
    lab, tier = r.get("label"), r.get("tier")
    return {"split": split, "source": source, "group": group, "ds_class": r["ds_class"], "injected": False,
            "method": r["method"], "uri": N.apache_uri(r["path"]), "query": r.get("query") or "",
            "body": "" if r.get("over_limit") else (r.get("body") or ""), "ct": r.get("ct") or "",
            "t1": lab if tier == 1 else "benign", "gate": gate_of(r.get("arg_v")), "old_label": lab, "old_tier": tier,
            "cut": bool(r.get("cut")), "nul": has_nul(r),
            "loc": payload_loc(r.get("query"), "" if r.get("over_limit") else r.get("body"))}


def write_rows(f, row, c):
    f.write(json.dumps(row, ensure_ascii=True) + "\n")
    c[(row["ds_class"], row["injected"])] += 1


CARRIERS_PER_SPLIT = 50000
# ---- Dữ liệu bổ sung của việc cải thiện tầng 2 (15/11/2026). Mỗi tệp là TUỲ CHỌN: thiếu tệp nào thì phần đó bị bỏ qua và
# đầu ra giống hệt trước đây. Sinh bằng train/t2_pool.py + t2_pool_result.py (cờ "lọt Cổng 2") và train/t2_hard_benign.py.
SRC2 = os.path.join(ROOT, "train", "data_src")
RESIDUAL_COPIES = {"train": 10, "valid": 3}      # mỗi payload lọt Cổng 2 được cấy thêm vào TỐI ĐA ngần này vật mang khác nhau
RESIDUAL_CAP = {"train": 3000, "valid": 1200}    # ... nhưng mỗi lớp không quá ngần này dòng cấy thêm: lớp LFI có hàng nghìn payload
                                                 # lọt (SQLi, XSS, RCE chỉ vài chục) nên nếu không chặn trên, LFI lấn át
HARD_COPIES = 2                                  # mỗi văn bản hợp lệ "khó" của train/valid cấy vào 2 vật mang
TEST_RESIDUAL_COPIES = 5                         # mỗi payload của bộ kiểm tra "lọt Cổng 2" (SR-BH) cấy vào 5 vật mang test_sites


def read_src2(name):
    p = os.path.join(SRC2, name)
    if not os.path.exists(p):
        return []
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]
# Văn bản tự do LÀNH TÍNH do người viết (Tatoeba, CC BY 2.0 FR) — thêm 14/11/2026: model cũ gắn nhãn tấn công cho câu
# người dùng gõ tay ("rock 'n' roll", "select a laptop for school", "bàn phím cơ"...) nên không bật được TIER2_MODE=enforce.
# Câu được CẤY vào request lành tính thật (như payload tấn công), nhãn benign. Chia theo id câu: 70 % train / 15 % valid /
# 15 % test (tập test_freetext, website test_sites làm vật mang).
TATOEBA = os.path.join(ROOT, "eval", "data", "tatoeba")
FREE_PER_SPLIT = {"train": {"eng": 25000, "vie": 5000}, "valid": {"eng": 5000, "vie": 1000},
                  "test_sites": {"eng": 8000, "vie": 2000}}


def tatoeba_split(sid):
    x = int(hashlib.sha1(f"tatoeba:{sid}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "train" if x < 0.70 else ("valid" if x < 0.85 else "test_sites")


def tatoeba_pools(rng):
    """{tập: {ngôn ngữ: [câu]}} — câu 3–200 ký tự, lấy mẫu đều (reservoir) theo số lượng FREE_PER_SPLIT."""
    import bz2
    pools = {s: {} for s in FREE_PER_SPLIT}
    for lang in ("eng", "vie"):
        p = os.path.join(TATOEBA, f"{lang}_sentences.tsv.bz2")
        if not os.path.exists(p):
            print(f"   !! thiếu {p} — bỏ văn bản tự do {lang}", file=sys.stderr); continue
        res = {s: [] for s in FREE_PER_SPLIT}; seen = Counter()
        with bz2.open(p, "rt", encoding="utf-8", errors="replace") as f:
            for ln in f:
                parts = ln.rstrip("\n").split("\t")
                if len(parts) < 3 or not (3 <= len(parts[2].strip()) <= 200):
                    continue
                s = tatoeba_split(parts[0]); k = FREE_PER_SPLIT[s][lang]; seen[s] += 1
                if len(res[s]) < k:
                    res[s].append(parts[2].strip())
                else:
                    j = rng.randrange(seen[s])
                    if j < k:
                        res[s][j] = parts[2].strip()
        for s in FREE_PER_SPLIT:
            pools[s][lang] = res[s]
    return pools


def scenario_texts():
    """Câu lành tính của khung kịch bản (tools/scenario.py: benign, benign_hard, benign_quote, benign_ip) — TỰ VIẾT, chỉ dùng
    làm tập kiểm tra test_scenario_text, KHÔNG dùng huấn luyện hay chọn model."""
    src = open(os.path.join(ROOT, "tools", "scenario.py"), encoding="utf-8").read()
    i = src.index("PAYLOADS = {"); j = src.index("\n}\n", i) + 3
    ns = {}
    exec(src[i:j], ns)                                  # noqa: S102 — tệp của chính dự án
    return [t for fam in ("benign", "benign_hard", "benign_quote", "benign_ip") for t in ns["PAYLOADS"].get(fam, [])]


def main():
    """Đọc dữ liệu chuẩn hoá theo LUỒNG: chỉ giữ trong RAM một mẫu vật mang (reservoir) và các dòng tấn công đã cấy."""
    t0 = time.time()
    os.makedirs(OUT, exist_ok=True)
    N._load()
    rng = random.Random(SEED)
    # 1) payload theo tập và lớp (giá trị ModSecurity nhìn thấy = ý định của kẻ tấn công)
    payloads = {s: defaultdict(list) for s in ("train", "valid")}
    for src in ("seclists", "openappsec_mal"):
        for r in rows(src):
            if r["ds_class"] in CLASSES and r["split"] in payloads:
                v = longest(r)
                if v:
                    payloads[r["split"]][r["ds_class"]].append((v, src, r["family"]))
    # 1b) cờ "lọt Cổng 2" của payload train/valid, và payload từ nguồn bổ sung (đã có cờ) nếu có
    G2 = {(o["split"], o["value"]): o.get("g2") for o in read_src2("pool_g2.jsonl.gz")}
    n_extra = Counter()
    for o in read_src2("extra_attacks.jsonl.gz"):
        if o.get("cls") in CLASSES and o.get("split") in payloads and o.get("value"):
            payloads[o["split"]][o["cls"]].append((o["value"], o.get("src", "extra"), o.get("family", "extra")))
            G2[(o["split"], o["value"])] = o.get("g2")
            n_extra[(o["split"], o["cls"])] += 1
    if G2:
        print(f"   cờ lọt Cổng 2: {dict(Counter(G2.values()))}; payload bổ sung: {dict(n_extra)}", file=sys.stderr, flush=True)
    # 2) vật mang: mẫu ngẫu nhiên đều (reservoir) các request lành tính GET/POST thân nhỏ, theo tập
    carriers = {s: [] for s in ("train", "valid", "test_sites")}
    seen = Counter()
    names = Counter()
    for r in rows("openappsec_legit"):
        s = r["split"]
        if s == "train":
            names.update(n for n in (r.get("marg_n") or []) if re.fullmatch(r"[A-Za-z_][\w\-\[\].]{0,30}", n))
        if s in carriers and r["method"] in ("GET", "POST") and len(r.get("body") or "") <= CARRIER_MAX_BODY \
                and not r.get("cut") and not r.get("over_limit") and not has_nul(r):
            seen[s] += 1
            item = {k: r.get(k) for k in ("method", "path", "query", "body", "ct", "ua", "site")}
            if len(carriers[s]) < CARRIERS_PER_SPLIT:
                carriers[s].append(item)
            else:
                j = rng.randrange(seen[s])
                if j < CARRIERS_PER_SPLIT:
                    carriers[s][j] = item
    common = [n for n, _ in names.most_common(400)]
    print(f"   vật mang (mẫu/tổng): { {s: (len(carriers[s]), seen[s]) for s in carriers} }", file=sys.stderr, flush=True)
    # 3) cấy payload: mỗi lớp PER_CLASS request; lớp ít payload (sqli) thì một payload đi với nhiều vật mang khác nhau
    #    Payload phải nằm trong cửa sổ 2000 ký tự của tầng 2 (lỗi N3 của bản rà soát): nếu rơi ra ngoài thì cấy lại vào
    #    vị trí khác của cùng vật mang (giữ vật mang dài trong dữ liệu, tránh đường tắt "dài = lành tính"), sau 3 lần
    #    thì đổi vật mang. Bản cấy MARK dùng cùng trạng thái rng nên trùng đúng vị trí với bản cấy payload.
    jobs = []
    vis = Counter()
    for s in ("train", "valid"):
        for c in CLASSES:
            pool = payloads[s][c]
            rng.shuffle(pool)
            for k in range(PER_CLASS[s]):
                v, src, fam = pool[k % len(pool)]
                carrier = rng.choice(carriers[s])
                for attempt in range(9):
                    if attempt and attempt % 3 == 0:
                        carrier = rng.choice(carriers[s])
                    st = rng.getstate()
                    marked = inject(carrier, MARK, rng, common)
                    rng.setstate(st)
                    req = inject(carrier, v, rng, common)
                    if t2_visible(marked, v):
                        vis["ok_first" if attempt == 0 else "ok_retry"] += 1
                        break
                else:
                    vis["dropped"] += 1
                    continue
                jobs.append((req, {"split": s, "source": f"inject:{src}", "group": fam, "ds_class": c, "injected": True,
                                   "g2": G2.get((s, v))}))
    print(f"   cửa sổ tầng 2: {dict(vis)}", file=sys.stderr, flush=True)

    def inject_visible(pool_c, v):
        """Cấy payload vào một vật mang sao cho payload nằm trong cửa sổ 2000 ký tự của tầng 2 (như vòng lặp trên); None nếu không được."""
        carrier = rng.choice(pool_c)
        for attempt in range(9):
            if attempt and attempt % 3 == 0:
                carrier = rng.choice(pool_c)
            st = rng.getstate()
            marked = inject(carrier, MARK, rng, common)
            rng.setstate(st)
            req = inject(carrier, v, rng, common)
            if t2_visible(marked, v):
                return req
        return None

    # 3a') payload LỌT Cổng 2: cấy thêm vào nhiều vật mang khác nhau (vòng 3 chỉ cho mỗi payload vài lần, có payload của valid
    #      không được cấy lần nào) — đây là phần duy nhất mà tầng 2 có giá trị riêng
    n_res = Counter()
    for s in ("train", "valid"):
        for c in CLASSES:
            passers = list({p[0]: p for p in payloads[s][c] if G2.get((s, p[0])) == "pass"}.values())
            copies = max(1, min(RESIDUAL_COPIES[s], RESIDUAL_CAP[s] // max(len(passers), 1)))
            if len(passers) > RESIDUAL_CAP[s]:
                rng.shuffle(passers)
                passers = passers[:RESIDUAL_CAP[s]]
            for v, src, fam in passers:
                for _ in range(copies):
                    req = inject_visible(carriers[s], v)
                    if req is not None:
                        jobs.append((req, {"split": s, "source": f"inject:{src}", "group": fam, "ds_class": c, "injected": True, "g2": "pass"}))
                        n_res[(s, c)] += 1
    # 3d) bộ kiểm tra "lọt Cổng 2" MỚI: payload tấn công thật của SR-BH mà Cổng 2 để lọt, cấy vào website chưa thấy
    for o in read_src2("pool_test_g2.jsonl.gz"):
        if o.get("g2") == "pass" and o.get("cls") in CLASSES:
            for _ in range(TEST_RESIDUAL_COPIES):
                req = inject_visible(carriers["test_sites"], o["value"])
                if req is not None:
                    jobs.append((req, {"split": "test_residual", "source": f"inject:{o.get('src', 'srbh2020')}", "group": o.get("family") or "srbh",
                                       "ds_class": o["cls"], "injected": True, "g2": "pass"}))
                    n_res[("test_residual", o["cls"])] += 1
    # 3e) văn bản hợp lệ "khó" (train/t2_hard_benign.py): train/valid cấy vào vật mang cùng tập; test -> tệp test_hardtext
    n_hard = Counter()
    for o in read_src2("hard_benign.jsonl.gz"):
        s = o["split"]
        tgt, copies, pool_c = (s, HARD_COPIES, carriers[s]) if s in ("train", "valid") else ("test_hardtext", 1, carriers["test_sites"])
        for _ in range(copies):
            req = inject(rng.choice(pool_c), o["value"], rng, common)
            jobs.append((req, {"split": tgt, "source": f"inject:hard-{o['family']}", "group": f"hard-{o['family']}", "ds_class": "benign",
                               "injected": True, "hard": True}))
            n_hard[tgt] += 1
    if n_res or n_hard:
        print(f"   cấy thêm payload lọt Cổng 2: {dict(n_res)}; văn bản hợp lệ khó: {dict(n_hard)}", file=sys.stderr, flush=True)
    # 3b) văn bản tự do LÀNH TÍNH (Tatoeba) cấy vào request lành tính thật; tập test_sites -> tệp test_freetext riêng
    free = tatoeba_pools(rng)
    n_free = Counter()
    for s, by_lang in free.items():
        for lang, sents in by_lang.items():
            for v in sents:
                req = inject(rng.choice(carriers[s]), v, rng, common)
                jobs.append((req, {"split": s if s != "test_sites" else "test_freetext", "source": f"inject:tatoeba-{lang}",
                                   "group": f"tatoeba-{lang}", "ds_class": "benign", "injected": True}))
                n_free[(s, lang)] += 1
    # 3c) câu lành tính TỰ VIẾT của khung kịch bản: chỉ để kiểm tra (mỗi câu 20 lần, vật mang test_sites)
    for v in scenario_texts():
        for _ in range(20):
            req = inject(rng.choice(carriers["test_sites"]), v, rng, common)
            jobs.append((req, {"split": "test_scenario_text", "source": "inject:scenario", "group": "scenario",
                               "ds_class": "benign", "injected": True}))
    print(f"   văn bản tự do: { {f'{s}/{l}': n for (s, l), n in n_free.items()} }", file=sys.stderr, flush=True)
    carriers.clear()
    print(f"   cấy {len(jobs)} request tấn công; chạy qua classifier ...", file=sys.stderr, flush=True)
    batches = [jobs[i:i + 2000] for i in range(0, len(jobs), 2000)]
    att = defaultdict(list)
    with Pool(6) as pool:
        for part in pool.imap(_work, batches):
            for row in part:
                if row:
                    att[row["split"]].append(row)
    del jobs, batches
    # 4) ghi: lành tính đọc lại theo luồng rồi ghi thẳng; tấn công đã cấy ghi tiếp vào cùng tệp (notebook tự xáo trộn)
    files = {s: gzip.open(os.path.join(OUT, f"tier2_{s}.jsonl.gz.tmp"), "wt", encoding="utf-8", compresslevel=6)
             for s in ("train", "valid", "test_sites")}
    cnt = {s: Counter() for s in files}
    nul_dropped = Counter()
    for r in rows("openappsec_legit"):
        s = r["split"]
        if s in ("train", "valid") and has_nul(r):
            # thân nhị phân có byte rỗng: hệ thống thật cắt thân tại byte rỗng (lỗi C7), dataset thì giữ đủ -> lệch
            # train/serve. Bỏ khỏi train/valid; tập test giữ lại và gắn cờ "nul" để báo cáo riêng.
            nul_dropped[s] += 1
            continue
        write_rows(files[s], row_from_norm(r, s, "openappsec_legit", r["site"]), cnt[s])
    for s in ("train", "valid"):
        for row in att[s]:
            write_rows(files[s], row, cnt[s])
    for s, f in files.items():
        f.close()
        os.replace(os.path.join(OUT, f"tier2_{s}.jsonl.gz.tmp"), os.path.join(OUT, f"tier2_{s}.jsonl.gz"))
    for name in ("test_freetext", "test_scenario_text", "test_hardtext", "test_residual"):
        if name in ("test_hardtext", "test_residual") and not att[name]:
            continue                                    # không có dữ liệu bổ sung -> không tạo tệp (như trước 15/11)
        cnt[name] = Counter()
        with gzip.open(os.path.join(OUT, f"tier2_{name}.jsonl.gz.tmp"), "wt", encoding="utf-8", compresslevel=6) as f:
            for row in att[name]:
                write_rows(f, row, cnt[name])
        os.replace(os.path.join(OUT, f"tier2_{name}.jsonl.gz.tmp"), os.path.join(OUT, f"tier2_{name}.jsonl.gz"))
    for name, src, split in (("test_srbh", "srbh2020", "test_ext1"), ("test_httpparams", "httpparams", "test_ext2")):
        cnt[name] = Counter()
        with gzip.open(os.path.join(OUT, f"tier2_{name}.jsonl.gz.tmp"), "wt", encoding="utf-8", compresslevel=6) as f:
            for r in rows(src):
                if r["ds_class"] != "other":
                    write_rows(f, row_from_norm(r, split, src, r["sub"]), cnt[name])
        os.replace(os.path.join(OUT, f"tier2_{name}.jsonl.gz.tmp"), os.path.join(OUT, f"tier2_{name}.jsonl.gz"))
    summary = {k: {f"{c}{'(cấy)' if inj else ''}": n for (c, inj), n in sorted(v.items())} for k, v in cnt.items()}
    for k, v in summary.items():
        print(f"   {k}: {v}", file=sys.stderr, flush=True)
    with open(os.path.join(OUT, "tier2_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": summary, "per_class_injected": PER_CLASS, "seed": SEED, "t2_window": dict(vis),
                   "nul_benign_dropped": dict(nul_dropped),
                   "unique_payloads": {s: {c: len(payloads[s][c]) for c in CLASSES} for s in payloads},
                   "gate2_flags": dict(Counter(str(v) for v in G2.values())),
                   "residual_injected": {f"{s}/{c}": n for (s, c), n in sorted(n_res.items())},
                   "hard_benign_injected": dict(n_hard), "extra_payloads": {f"{s}/{c}": n for (s, c), n in sorted(n_extra.items())},
                   "seconds": round(time.time() - t0)}, f, ensure_ascii=False, indent=1)
    print(f"   xong sau {time.time() - t0:.0f} s", file=sys.stderr)


if __name__ == "__main__":
    main()
