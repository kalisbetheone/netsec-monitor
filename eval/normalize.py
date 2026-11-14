#!/usr/bin/env python3
"""eval/normalize.py — đưa mọi dataset về ĐÚNG bản ghi mà hệ thống ghi vào Elasticsearch (xem eval/PROTOCOL.md).

    python -I -X utf8 -B eval/normalize.py                       (chạy từ thư mục nsm; tất cả nguồn)
    python -I -X utf8 -B eval/normalize.py --sources srbh2020 --limit 2000

Mỗi bản ghi dataset -> một request HTTP thô -> hàm `_classify_web` THẬT của classifier -> bản ghi ES
(arg_*, marg_*, label, tier, ...) + nhãn gốc của dataset (ds_*), họ payload, tập (train/valid/test_*).
Đầu ra: eval/data/normalized/<nguồn>.jsonl.gz và eval/data/normalized/summary.json.
"""
import argparse, csv, glob, gzip, hashlib, io, json, os, re, sys, time, types, warnings, zipfile
from collections import Counter
from multiprocessing import Pool
from urllib.parse import quote, unquote_plus, unquote_to_bytes

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "eval", "data")
OUT = os.path.join(DATA, "normalized")
UA_DEFAULT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
URLENC = "application/x-www-form-urlencoded"
csv.field_size_limit(1 << 30)

# ------------------------------------------------------------------ nạp classifier (giả lập Kafka/ES)
C = None


def _load():
    global C
    if C is not None:
        return C
    ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object
    sys.modules.setdefault("confluent_kafka", ck)
    es_mod = types.ModuleType("elasticsearch"); es_mod.helpers = types.SimpleNamespace(); es_mod.Elasticsearch = object
    sys.modules.setdefault("elasticsearch", es_mod)
    sys.path.insert(0, os.path.join(ROOT, "services"))
    os.environ.update({"MODEL_PATH": os.path.join(ROOT, "models", "tier2.joblib"), "TIER2_THRESHOLD": "0.90",
                       "TIER2_SYNTAX_GATE": "1", "TIER2_DECISION": "argmax",
                       "INTERNAL_CIDRS": "10.10.30.0/24,10.10.10.10/32,172.16.0.0/12"})
    import logging
    logging.disable(logging.INFO)
    import classifier
    C = classifier
    return C


class _Cap:
    def __init__(self): self.docs = []
    def add(self, index, doc, _id=None): self.docs.append(doc)


class _Prod:
    def produce(self, *a, **k): pass
    def poll(self, *a): pass


def apache_uri(path):
    """%U của Apache: đường dẫn đã giải mã %XX (KHÔNG đổi '+'). Byte không phải UTF-8 hợp lệ được Apache ghi
    dạng \\xhh và pipeline đọc lại thành ký tự latin-1 — làm y như vậy."""
    b = unquote_to_bytes(path)
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


# Giới hạn thân request của ModSecurity trong hệ thống (web/apache: modsecurity.conf, SecRequestBodyLimitAction Reject):
# thân KHÔNG phải multipart quá 128 KiB, hoặc mọi thân quá 12,5 MiB, bị trả 413 -> không tới ứng dụng,
# và classifier thật không bao giờ thấy nội dung của nó.
NOFILES_LIMIT, BODY_LIMIT = 131072, 13107200


def over_limit(req):
    b = req.get("body") or ""
    if not b:
        return False
    n = len(b.encode("utf-8", "surrogatepass"))
    multipart = (req.get("ct") or "").lower().startswith("multipart/form-data")
    return n > BODY_LIMIT or (not multipart and n > NOFILES_LIMIT)


def to_doc(req):
    """request thô -> bản ghi ES do classifier THẬT tạo ra."""
    c = _load()
    cap = _Cap()
    c.ES_BUF, c.PROD = cap, _Prod()
    ev = {"ts_ms": 1794214800000, "src_ip": "198.51.100.7", "method": req["method"], "uri": apache_uri(req["path"]),
          "query": ("?" + req["query"]) if req["query"] else "", "status": 0, "ua": req.get("ua") or UA_DEFAULT,
          "ct": req.get("ct") or "-", "req_id": None}
    rejected = over_limit(req)
    c._classify_web(ev, "" if rejected else (req.get("body") or ""))
    d = cap.docs[-1]
    keep = ("target", "label", "confidence", "tier", "matched", "evidence_field", "evidence",
            "arg_n", "arg_v", "marg_n", "marg_v", "marg_body", "has_body")
    out = {k: d.get(k) for k in keep}
    out["over_limit"] = rejected            # True: hệ thống thật trả 413 và không thấy thân
    return out


# ------------------------------------------------------------------ dựng request thô
def get_req(path, params, ua=None):
    return {"method": "GET", "path": path, "query": "&".join(f"{k}={quote(v, safe='')}" for k, v in params),
            "body": "", "ct": "", "ua": ua or UA_DEFAULT}


def post_req(path, params, ua=None):
    return {"method": "POST", "path": path, "query": "", "ct": URLENC, "ua": ua or UA_DEFAULT,
            "body": "&".join(f"{k}={quote(v, safe='')}" for k, v in params)}


def split_url(url):
    path, _, q = (url or "/").partition("?")
    return path or "/", q


# ------------------------------------------------------------------ bộ đọc từng dataset
SECLISTS = {
    "sqli": ["Fuzzing_Databases_SQLi_Generic-SQLi.txt", "Fuzzing_Databases_SQLi_quick-SQLi.txt",
             "Fuzzing_Databases_SQLi_Generic-BlindSQLi.fuzzdb.txt", "Fuzzing_Databases_SQLi_sqli.auth.bypass.txt",
             "Fuzzing_Databases_SQLi_MySQL.fuzzdb.txt", "Fuzzing_Databases_SQLi_MSSQL.fuzzdb.txt"],
    "xss": ["Fuzzing_XSS_robot-friendly_XSS-Jhaddix.txt", "Fuzzing_XSS_robot-friendly_XSS-RSNAKE.txt",
            "Fuzzing_XSS_robot-friendly_XSS-BruteLogic.txt", "Fuzzing_XSS_robot-friendly_XSS-Somdev.txt",
            "Fuzzing_XSS_robot-friendly_XSS-payloadbox.txt"],
    "lfi": ["Fuzzing_LFI_LFI-Jhaddix.txt", "Fuzzing_LFI_LFI-linux-and-windows_by-1N3_CrowdShield.txt"],
    "rce": ["Fuzzing_command-injection-commix.txt", "Fuzzing_UnixAttacks.fuzzdb.txt"],
}
EP = {"sqli": ("/vulnerabilities/sqli/", "id", "GET"), "xss": ("/vulnerabilities/xss_r/", "name", "GET"),
      "lfi": ("/vulnerabilities/fi/", "page", "GET"), "rce": ("/vulnerabilities/exec/", "ip", "POST")}


def read_seclists():
    for cls, files in SECLISTS.items():
        path, param, method = EP[cls]
        for fn in files:
            with open(os.path.join(DATA, "seclists", fn), encoding="utf-8", errors="replace") as f:
                for ln in f:
                    ln = ln.rstrip("\r\n")
                    if not ln.strip() or ln.startswith("# "):
                        continue
                    v = unquote_plus(ln).strip().replace("__TIME__", "5")
                    if not 1 <= len(v) <= 1024:
                        continue
                    params = [(param, v), ("Submit", "Submit")]
                    req = post_req(path, params) if method == "POST" else get_req(path, params)
                    yield dict(req, source="seclists", sub=fn, ds_raw=cls, ds_class=cls, site=None)


OAS_MAL = {"sqli.json": "sqli", "xss.json": "xss", "traversal.json": "lfi", "cmdexe.json": "rce",
           "log4shell.json": "other", "shellshock.json": "other", "xxe.json": "other"}


def _oas_req(r):
    h = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
    path, q = split_url(r.get("url"))
    return {"method": (r.get("method") or "GET").upper(), "path": path, "query": q, "body": r.get("data") or "",
            "ct": h.get("content-type", ""), "ua": h.get("user-agent") or UA_DEFAULT}


def read_openappsec_mal():
    z = zipfile.ZipFile(os.path.join(DATA, "openappsec", "malicious.zip"))
    for name in z.namelist():
        base = name.rsplit("/", 1)[-1]
        if base not in OAS_MAL:
            continue
        for r in json.loads(z.read(name)):
            yield dict(_oas_req(r), source="openappsec_mal", sub=base, ds_raw=base[:-5], ds_class=OAS_MAL[base], site=None)


def read_openappsec_legit():
    z = zipfile.ZipFile(os.path.join(DATA, "openappsec", "legitimate.zip"))
    for name in z.namelist():
        if not name.endswith(".json"):
            continue
        # tệp 'browsing_2024_<site>[_xx].json' — nhiều phiên duyệt của CÙNG một site phải vào cùng một tập
        site = re.sub(r"_[a-z]{2}$", "", re.sub(r"^browsing_\d{4}_", "", name.rsplit("/", 1)[-1][:-5]))
        with z.open(name) as fp:                  # đọc TỪNG phần tử: có tệp tới 734 MB (phiên tải tệp lên)
            for r in iter_json_array(fp):
                if isinstance(r, dict):
                    yield dict(_oas_req(r), source="openappsec_legit", sub=site, ds_raw="legitimate",
                               ds_class="benign", site=site)


def iter_json_array(fp, chunk=1 << 20):
    """Đọc lần lượt từng phần tử của một mảng JSON lớn mà không nạp cả tệp. RAM ~ phần tử lớn nhất."""
    # Dùng CHỈ SỐ trong bộ đệm thay vì cắt chuỗi sau mỗi phần tử (cắt chuỗi = sao chép cả bộ đệm -> chậm O(n²)).
    dec = json.JSONDecoder()
    ws = re.compile(r"[\s,]*")
    rd = io.TextIOWrapper(fp, encoding="utf-8", errors="replace")
    buf, pos, eof = rd.read(chunk), 0, False
    m = re.match(r"\s*\[", buf)
    if not m:
        return
    pos = m.end()
    while True:
        pos = ws.match(buf, pos).end()
        if pos >= len(buf) and eof:
            return
        if pos < len(buf) and buf[pos] == "]":
            return
        try:
            if pos >= len(buf):
                raise json.JSONDecodeError("hết bộ đệm", buf, pos)
            obj, end = dec.raw_decode(buf, pos)
        except json.JSONDecodeError:
            if eof:
                return                            # phần tử cuối hỏng: dừng tệp này
            # phần tử chưa trọn trong bộ đệm: bỏ phần đã đọc, đọc thêm ít nhất bằng phần đang dở (gấp đôi dần)
            buf = buf[pos:]
            pos = 0
            data = rd.read(max(chunk, len(buf)))
            if not data:
                eof = True
            buf += data
            continue
        yield obj
        pos = end


HP = {"norm": "benign", "sqli": "sqli", "xss": "xss", "path-traversal": "lfi", "cmdi": "rce"}


def read_httpparams():
    with open(os.path.join(DATA, "httpparams", "payload_full.csv"), encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            req = get_req("/search", [("q", row["payload"])])
            yield dict(req, source="httpparams", sub=row["attack_type"], ds_raw=row["attack_type"],
                       ds_class=HP.get(row["attack_type"], "other"), site=None)


SRBH_MAP = [("66 - SQL Injection", "sqli"), ("126 - Path Traversal", "lfi"), ("88 - OS Command Injection", "rce"),
            ("248 - Command Injection", "rce")]


def read_srbh():
    with open(os.path.join(DATA, "srbh2020", "data_capec_multilabel.csv"), encoding="utf-8", errors="replace",
              newline="") as f:
        r = csv.reader(f)
        hdr = next(r)
        lab_cols = hdr[24:]
        for row in r:
            d = dict(zip(hdr, row))
            on = [h for h in lab_cols if d.get(h, "").strip() in ("1", "1.0", "True", "true")]
            cls = next((c for col, c in SRBH_MAP if col in on), None)        # thứ tự ưu tiên của PROTOCOL.md
            if cls is None:
                cls = "other" if any(h != "000 - Normal" for h in on) else "benign"
            path, q = split_url(d.get("request_http_request"))
            body = d.get("request_body") or ""
            yield {"method": (d.get("request_http_method") or "GET").upper(), "path": path, "query": q,
                   "body": "" if body in ("-", "nan") else body, "ct": d.get("request_content_type") or "",
                   "ua": d.get("request_user_agent") or UA_DEFAULT, "source": "srbh2020",
                   "sub": (d.get("timestamp") or "")[:10], "ds_raw": "|".join(on), "ds_class": cls, "site": None}


READERS = {"seclists": read_seclists, "openappsec_mal": read_openappsec_mal, "openappsec_legit": read_openappsec_legit,
           "httpparams": read_httpparams, "srbh2020": read_srbh}


# ------------------------------------------------------------------ khử trùng, họ payload, chia tập
def _h(s):
    return int(hashlib.sha1(s.encode("utf-8", "surrogatepass")).hexdigest()[:8], 16) / 0xFFFFFFFF


def dedup_key(req):
    from secrule import modsec_args
    args, _ = modsec_args(req["query"], req["body"], req["ct"])
    return "\x1f".join([req["method"], apache_uri(req["path"]), "\x1e".join(f"{n}={v}" for n, v in sorted(args)),
                        req["body"] if not args else ""])


def family(rec):
    """Họ payload = giá trị tham số dài nhất (chữ thường, chữ số -> 0). Request không có tham số: họ theo
    đường dẫn đã giải mã (trước đây rơi về chuỗi rỗng nên MỌI request không tham số chung một họ)."""
    vals = rec.get("marg_v") or []
    v = max(vals, key=len) if vals else "path:" + apache_uri(rec.get("path") or "/")
    return hashlib.sha1(re.sub(r"\d+", "0", v.lower()).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def assign_split(rec):
    s = rec["source"]
    if s in ("seclists", "openappsec_mal"):
        return "train" if _h(rec["family"]) < 0.8 else "valid"
    if s == "openappsec_legit":
        x = _h("site:" + (rec.get("site") or ""))
        return "train" if x < 0.4 else ("valid" if x < 0.5 else "test_sites")
    if s == "srbh2020":
        return "test_ext1"
    if s == "httpparams":
        return "test_ext2"
    return "unknown"


# ------------------------------------------------------------------ chạy (xử lý LUỒNG — RAM không tăng theo cỡ dataset)
BODY_KEEP, URL_KEEP = 16384, 8192          # lưu tối đa ngần này ký tự thân/URL THÔ (classifier vẫn nhận bản đầy đủ)
CHUNK = 1000


def _digest(req):
    return hashlib.blake2b(dedup_key(req).encode("utf-8", "surrogatepass"), digest_size=16).digest()


def _slim(req):
    """Bản ghi lưu ra đĩa: cắt thân/URL thô quá dài (ghi lại độ dài gốc) — kết quả classifier tính trên bản đầy đủ."""
    r = dict(req)
    r["body_len"] = len(req.get("body") or "")
    cut = False
    if r["body_len"] > BODY_KEEP:
        r["body"] = req["body"][:BODY_KEEP]; cut = True
    if len(req.get("query") or "") > URL_KEEP:
        r["query"] = req["query"][:URL_KEEP]; cut = True
    if len(req.get("path") or "") > URL_KEEP:
        r["path"] = req["path"][:URL_KEEP]; cut = True
    r["cut"] = cut                           # True -> không phát lại nguyên văn được
    return r


def _work2(chunk):
    out = []
    for req, dup in chunk:
        try:
            d = to_doc(req)
            d.pop("target", None)            # không lưu lại: tính được từ path/query
            out.append(dict(_slim(req), dup=dup, **d))
        except Exception as e:               # noqa: BLE001 — ghi lại, không làm hỏng cả lượt
            out.append(dict(_slim(req), dup=dup, error=f"{type(e).__name__}: {e}"[:200]))
    return out


def _unique(src, limit):
    """Hai lượt đọc: lượt 1 chỉ đếm (khoá băm 16 byte mỗi bản ghi), lượt 2 phát bản ghi ĐẦU TIÊN của mỗi khoá
    kèm số lần lặp. Không giữ request nào trong RAM."""
    counts, n_raw = {}, 0
    for req in READERS[src]():
        n_raw += 1
        k = _digest(req)
        counts[k] = counts.get(k, 0) + 1
    print(f"   {src}: {n_raw} bản ghi -> {len(counts)} khác nhau; đang chạy qua classifier ...", file=sys.stderr, flush=True)

    def gen():
        emitted = 0
        for req in READERS[src]():
            k = _digest(req)
            c = counts.pop(k, None)            # mỗi khoá chỉ phát một lần
            if c is None:
                continue
            yield req, c
            emitted += 1
            if limit and emitted >= limit:
                return
    return n_raw, gen()


def _chunks(it, n, max_bytes=16 << 20):
    """Lô tối đa n request HOẶC ~16 MB thân/URL — lô chứa vài thân tải tệp lên không làm phình RAM."""
    buf, size = [], 0
    for x in it:
        req = x[0]
        buf.append(x)
        size += len(req.get("body") or "") + len(req.get("query") or "") + len(req.get("path") or "")
        if len(buf) >= n or size >= max_bytes:
            yield buf
            buf, size = [], 0
    if buf:
        yield buf


def _run_bounded(pool, chunks, workers):
    """Gửi việc cho pool nhưng chỉ giữ tối đa 2 x workers lô đang chờ (Pool.imap đọc hết đầu vào vào hàng đợi)."""
    pending = []
    for ch in chunks:
        pending.append(pool.apply_async(_work2, (ch,)))
        while len(pending) >= 2 * workers:
            yield pending.pop(0).get()
    for p in pending:
        yield p.get()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default=",".join(READERS))
    # đo 11/11: tiến trình chính (đọc, khử trùng, ghi) là nút cổ chai — 6 hay 12 tiến trình con cùng tốc độ,
    # 12 tốn gần gấp đôi RAM. 6 là đủ và để dư CPU cho việc khác.
    ap.add_argument("--workers", type=int, default=max(1, min(6, (os.cpu_count() or 2) - 2)))
    ap.add_argument("--limit", type=int, default=0, help="tối đa N bản ghi KHÁC NHAU mỗi nguồn (0 = tất cả)")
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(ROOT, "services"))
    os.makedirs(OUT, exist_ok=True)
    sp = os.path.join(OUT, "summary.json")
    summary = {}
    if os.path.exists(sp):
        with open(sp, encoding="utf-8") as f:
            summary = json.load(f)
    pool = Pool(a.workers) if a.workers > 1 else None
    try:
        for src in a.sources.split(","):
            t0 = time.time()
            if src not in READERS:
                raise SystemExit(f"nguồn lạ: {src}")
            need = {"openappsec_legit": "openappsec/legitimate.zip", "srbh2020": "srbh2020/data_capec_multilabel.csv"}.get(src)
            if need and not os.path.exists(os.path.join(DATA, need)):
                print(f"!! bỏ qua {src}: chưa có {need}", file=sys.stderr)
                continue
            n_raw, items = _unique(src, a.limit)
            chunks = _chunks(items, CHUNK)
            results = _run_bounded(pool, chunks, a.workers) if pool else (_work2(ch) for ch in chunks)
            cnt = {k: Counter() for k in ("ds_class", "split", "label_vs_ds")}
            n = errs = nobody = cut = noargs = ol = 0
            tmp = os.path.join(OUT, f"{src}.jsonl.gz.tmp")
            with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=3) as f:
                for part in results:
                    for r in part:
                        if "error" in r:
                            errs += 1
                            r["family"] = None
                        else:
                            r["family"] = family(r)
                        r["split"] = assign_split(r)
                        n += 1
                        cnt["ds_class"][r["ds_class"]] += 1
                        cnt["split"][r["split"]] += 1
                        cnt["label_vs_ds"][f"{r['ds_class']}->{r.get('label')}"] += 1
                        nobody += bool(r.get("has_body") and not r.get("marg_body"))
                        cut += bool(r.get("cut"))
                        noargs += not r.get("marg_n")
                        ol += bool(r.get("over_limit"))
                        f.write(json.dumps(r, ensure_ascii=True) + "\n")
                    if n and n % 100000 < CHUNK:
                        print(f"   {src}: {n} ...", file=sys.stderr, flush=True)
            os.replace(tmp, os.path.join(OUT, f"{src}.jsonl.gz"))
            st = {"raw": n_raw, "unique": n, "errors": errs, "ds_class": dict(cnt["ds_class"]),
                  "split": dict(cnt["split"]), "label_vs_ds": dict(cnt["label_vs_ds"].most_common(40)),
                  "no_args": noargs, "marg_body_false": nobody, "cut": cut, "over_limit": ol, "seconds": round(time.time() - t0, 1)}
            summary[src] = st
            with open(sp, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=1)
            print(f"   {src}: xong {st['seconds']} s, lỗi {errs}; {st['ds_class']}; {st['split']}", file=sys.stderr, flush=True)
    finally:
        if pool:
            pool.close()
            pool.join()

    # đánh dấu bản ghi kiểm tra trùng họ payload với phần train (đọc và ghi từng dòng)
    train_fams = set()
    for src in ("seclists", "openappsec_mal", "openappsec_legit"):
        p = os.path.join(OUT, f"{src}.jsonl.gz")
        if os.path.exists(p):
            with gzip.open(p, "rt", encoding="utf-8") as f:
                for ln in f:
                    r = json.loads(ln)
                    if r.get("split") == "train" and r.get("family"):
                        train_fams.add(r["family"])
    for src in ("srbh2020", "httpparams", "openappsec_legit"):
        p = os.path.join(OUT, f"{src}.jsonl.gz")
        if not os.path.exists(p):
            continue
        k, tmp = 0, p + ".tmp"
        with gzip.open(p, "rt", encoding="utf-8") as fi, gzip.open(tmp, "wt", encoding="utf-8", compresslevel=3) as fo:
            for ln in fi:
                r = json.loads(ln)
                # chỉ có nghĩa với request CÓ tham số (payload); request không tham số không thể khớp luật ARGS
                r["seen_in_train"] = ((r.get("family") in train_fams) if r["split"].startswith("test") and r.get("marg_n")
                                      else None)
                k += bool(r["seen_in_train"])
                fo.write(json.dumps(r, ensure_ascii=True) + "\n")
        os.replace(tmp, p)
        summary.setdefault(src, {})["seen_in_train"] = k
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
