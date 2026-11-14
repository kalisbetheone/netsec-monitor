"""rulegen: gom cụm tấn công lọt cổng 2 → trích bất biến → SecRule → kiểm chứng corpus →
pha thử → ban hành/thu hồi. GỬI toàn bộ tệp luật qua Kafka enforce.rules; đọc kết quả
apachectl -t từ enforce.status (do enforcer trên WEB báo về).

Nguyên tắc (tài liệu mô tả, mục 2.3 và 5.4):
  * Bất biến được trích từ GIÁ TRỊ tham số (đúng thứ ModSecurity so khớp qua ARGS), không từ
    cả URL — nên tên endpoint / tên tham số không thể trở thành 'luật'.
  * Phần biến thiên (chữ số) bị loại trước, lấy chuỗi chung dài nhất còn lại (vd "' union select").
  * Đích luật hẹp nhất có thể: ARGS:<tên> khi cả cụm nằm ở cùng một tham số, ngược lại ARGS.
  * Corpus lành tính chỉ lấy từ nguồn SẠCH (IP không có sự kiện tấn công nào) và phải đủ lớn;
    thiếu corpus hoặc Elasticsearch lỗi -> KHÔNG sinh, KHÔNG ban hành luật (an toàn khi hỏng).

Bộ chọn luật (RULEGEN_SELECTOR):
  * g2r (mặc định) — học máy: bộ sinh ML liệt kê luật ứng viên 1–2 token trên góc nhìn ModSecurity (marg_v,
    biến đổi theo lớp — secrule.PROFILE), model G2r (rulesel_g2r.py) chấm và chọn. Luật là ĐẶC TẢ (secrule),
    được kiểm chứng trên lưu lượng lành tính sống bằng đúng phép so khớp của ModSecurity trước khi chạy thử.
    Thiếu model/kho nền -> KHÔNG sinh luật mới (vẫn quản lý luật đang có).
  * g0 — thuật toán cũ (token @contains trên arg_v), giữ để quay lui.
  LLM KHÔNG được dùng để sinh hay chọn luật: đo trên dữ liệu độc lập, LLM tự viết token ảo giác 87–88 %, bản tinh
  chỉnh chặn nhầm 14 % số cụm trên SR-BH (Bao-cao-ly-do-khong-dung-LLM-NSM.md).
"""
import hashlib, json, os, re, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from elasticsearch import helpers
from common import (Heartbeat, atomic_write, consumer, day_index, es_client, install_stop, iso, load_json, log,
                    producer, running)
import rulegen_ml as M
import secrule as S

L = log("rulegen")
E = lambda k, d: float(os.getenv(k, d))
INTERVAL, LOOKBACK = E("INTERVAL_S", "300"), E("LOOKBACK_S", "1800")
BENIGN_LOOKBACK = E("BENIGN_LOOKBACK_S", str(7 * 86400))       # corpus nền 7 ngày
SHADOW = E("SHADOW_S", "86400")                                # chạy thử tối thiểu 24 giờ
RULE_TTL, REVOKE = E("RULE_TTL_S", str(30 * 86400)), E("REVOKE_S", str(14 * 86400))
MIN_CLUSTER = int(E("MIN_CLUSTER", "5"))                       # số mẫu KHÁC NHAU tối thiểu một luật phải phủ
MIN_BENIGN = int(E("MIN_BENIGN", "500"))                       # số sự kiện lành tính tối thiểu để được kiểm chứng
EPSILON = E("EPSILON", "0")                                    # tỷ lệ benign được phép khớp (0 = một mẫu khớp là loại)
MAX_RULES_PER_CLASS = int(E("MAX_RULES_PER_CLASS", "3"))       # phủ tập tham lam: tối đa N luật/lớp/chu kỳ
RETENTION_DAYS = int(E("RETENTION_DAYS", "30"))                # xoá chỉ mục sự kiện cũ hơn N ngày (0 = không xoá)
ATTACKER_MIN_EVENTS = int(E("ATTACKER_MIN_EVENTS", "3"))       # IP bị loại khỏi corpus lành tính khi có >= N sự kiện tấn công
ATTACKER_MIN_SHARE = E("ATTACKER_MIN_SHARE", "0.1")            # ... và chúng chiếm >= tỷ lệ này lưu lượng của IP
SELECTOR = os.getenv("RULEGEN_SELECTOR", "g2r").lower()        # g2r | g0
RULESEL_MODEL = os.getenv("RULESEL_MODEL", "/models/rulesel_g2r.joblib")
RULESEL_PRIOR = os.getenv("RULESEL_PRIOR", "/models/rulesel_prior.json.gz")
RULESEL_MIN_SCORE = E("RULESEL_MIN_SCORE", "0")                # điểm dự đoán tối thiểu (< 0 = model đoán sẽ chặn nhầm)
RULESEL_SUBSAMPLE = int(E("RULESEL_SUBSAMPLE", "24"))          # số payload đưa vào bộ liệt kê (= cỡ cụm lúc huấn luyện 8–24)
RULESEL_MAX_LEN = 400                                          # payload dài hơn bị bỏ, như dữ liệu huấn luyện
MIN_TOK, MAX_TOK, BASE_ID = 5, 40, 9900000
STATE_PATH, SEED = "/state/rules.json", "/app/benign_seed.txt"
ATTACK_LABELS = ("sqli", "xss", "lfi", "rce")                  # chỉ nhãn THEO NỘI DUNG mới sinh luật nội dung
# 9 nhãn mới của classifier (xxe, ssti, ssrf, deser, nosqli, ldap, crlf, rfi, redirect) CỐ Ý không sinh luật: G2r
# chỉ được huấn luyện và chỉ có bộ biến đổi (secrule.PROFILE) cho 4 lớp trên.
SAFE = re.compile(r"^[a-z0-9 !#$&'()*+,\-./:;<=>?@\[\]^_`{|}~]+$")   # loại " và \ để không vỡ SecRule
# --- cổng đặc hiệu: token phải chứa CÚ PHÁP TẤN CÔNG. '=' và '&' KHÔNG tính (có trong mọi query) ---
STRONG = set("'\"<>;|(){}$`")
GRAMMAR = re.compile(r"\.\./|\.\.\\|/\*|\*/|--|/etc/|php://|file://|\bon[a-z]+=")
IP_OR_NUM = re.compile(r"^[0-9.]+$")
ARG_NAME = re.compile(r"^[a-z0-9_.\-]{1,32}$")
TARGET_OK = re.compile(r"^ARGS(?::[a-z0-9_.\-]{1,32})?$")
# RCE: dấu nối lệnh + tên lệnh hệ thống. KHÔNG có '&' đơn (dấu ngăn tham số) — chỉ ; | ` $( && xuống dòng.
RCE_RX = (r"(?:;|\||`|\$\(|&&|[\n\r])\s*(?:/(?:usr/)?s?bin/)?"
          r"(?:cat|ls|id|whoami|uname|nc|wget|curl|bash|sh|ping|dir|type|echo|head|tail|sleep)\b")
RCE_RE = re.compile(RCE_RX)
# Phương án A (người dùng chọn 12/11/2026): với lớp RCE, regex nối-lệnh viết sẵn là MỘT ỨNG VIÊN ĐẶC BIỆT trước G2r.
# Lý do: payload RCE đa dạng (;cat ;wget ;id ...) chỉ chung nhau dấu nối lệnh — bộ sinh ML (token >= 3 ký tự) không
# có ứng viên tổng quát, G2r chỉ chọn được luật hẹp kiểu 'cat / … etc/'.
# Khác RCE_RX của g0: tên lệnh phải ĐỨNG RIÊNG (theo sau là hết chuỗi / khoảng trắng / ký tự shell). RCE_RX khớp
# nhầm lưu lượng thật dạng 'retail;id=797700018', ';cat=bby-s0', ';type=...' (mã theo dõi quảng cáo, đo trên kho
# lành tính openappsec). Không gộp khoảng trắng để còn bắt được nối lệnh bằng xuống dòng (%0a). Không có '"' và '\\'
# ngoài các escape regex -> không phá cú pháp SecRule.
RCE_FIXED_RX = (r"(?:;|\||`|\$\(|&&|[\n\r])\s*(?:/(?:usr/)?s?bin/)?"
                r"(?:cat|ls|id|whoami|uname|nc|wget|curl|bash|sh|ping|dir|type|echo|head|tail|sleep)"
                r"(?=$|[\s;|&<>`)'])")
FIXED_RX = (RCE_FIXED_RX,)                                     # biểu thức viết sẵn được phép trong luật đặc tả
RCE_FIXED_SPEC = {"class": "rce", "target": "ARGS", "transforms": ["urlDecodeUni", "removeNulls", "lowercase"],
                  "op": "rx_fixed", "tokens": [RCE_FIXED_RX]}
def is_specific(g):
    return any(ch in STRONG for ch in g) or bool(GRAMMAR.search(g))

state = load_json(STATE_PATH, {"next_id": BASE_ID, "rules": {}})
if not isinstance(state, dict): state = {}
state.setdefault("next_id", BASE_ID); state.setdefault("rules", {})
es = None
prod = None
status_consumer = None
g2r = None                                                     # rulesel_g2r.Selector, nạp trong main()
_last_cleanup = 0.0

# ------------------------------------------------------------------ dữ liệu
FIELDS = ["target", "body", "label", "status", "@timestamp", "src_ip", "arg_n", "arg_v", "marg_n", "marg_v"]
def fetch(lookback, labels=None, limit=50000):
    """Sự kiện web trong `lookback` giây, MỚI NHẤT trước. Lọc nhãn ngay trong truy vấn."""
    flt = [{"range": {"@timestamp": {"gte": f"now-{int(lookback)}s"}}}, {"term": {"source.keyword": "web"}}]
    if labels: flt.append({"terms": {"label.keyword": list(labels)}})
    q = {"query": {"bool": {"filter": flt}}, "sort": [{"@timestamp": "desc"}]}
    out = []
    for h in helpers.scan(es, index="web-events-*", query=q, size=1000, ignore_unavailable=True,
                          preserve_order=True, _source=FIELDS):
        out.append(h["_source"])
        if len(out) >= limit: break
    return out

def attacker_ips(lookback):
    """IP coi là NGUỒN TẤN CÔNG (cả lưu lượng 'lành tính' của nó bị loại khỏi corpus): có >= ATTACKER_MIN_EVENTS sự
    kiện KHÔNG lành tính VÀ chúng chiếm >= ATTACKER_MIN_SHARE lưu lượng web của IP đó trong khoảng xét.
    Trước 12/11/2026 chỉ cần MỘT sự kiện: một nhãn nhầm của classifier (vd 'order by price' bị tầng 2 gắn sqli)
    làm mất toàn bộ corpus của một người dùng hợp lệ -> rulegen ngừng sinh luật. Kẻ tấn công vẫn không phủ quyết được
    luật bằng request 'lành tính' xen kẽ trừ khi tấn công dưới 10 % lưu lượng của chính nó."""
    r = es.search(index="web-events-*", size=0, ignore_unavailable=True,
                  query={"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{int(lookback)}s"}}},
                                             {"term": {"source.keyword": "web"}}]}},
                  aggs={"ips": {"terms": {"field": "src_ip.keyword", "size": 10000},
                                "aggs": {"bad": {"filter": {"bool": {"must_not": [
                                    {"term": {"label.keyword": "benign"}}]}}}}}})
    out = set()
    for b in (r.get("aggregations") or {}).get("ips", {}).get("buckets", []):
        bad = (b.get("bad") or {}).get("doc_count", 0)
        if bad >= ATTACKER_MIN_EVENTS and bad >= ATTACKER_MIN_SHARE * b.get("doc_count", bad):
            out.add(b["key"])
    return out

def _split(raw):
    out = []
    for part in (raw or "").split("&"):
        if not part: continue
        n, sep, v = part.partition("=")
        out.append((n, v) if sep else ("", part))
    return out

def args_of(e):
    """[(tên, giá trị)] của một sự kiện. Bản ghi mới có arg_n/arg_v; bản ghi cũ thì tách từ target/body."""
    n, v = e.get("arg_n"), e.get("arg_v")
    if isinstance(v, str): n, v = [n], [v]            # ES trả mảng một phần tử... vẫn là mảng, nhưng phòng hờ
    if isinstance(n, list) and isinstance(v, list) and len(n) == len(v):
        return [(str(a), str(b)) for a, b in zip(n, v) if b]
    t = e.get("target") or ""
    return [(a, b) for a, b in _split(t.split("?", 1)[1] if "?" in t else "") + _split(e.get("body") or "") if b]

def margs_of(e):
    """[(tên, giá trị)] theo góc nhìn ARGS của ModSecurity (giải mã MỘT lần, giữ hoa thường) — luật đặc tả được
    sinh và kiểm chứng trên góc nhìn này. Bản ghi cũ không có marg_* -> rỗng."""
    n, v = e.get("marg_n"), e.get("marg_v")
    if isinstance(v, str): n, v = [n], [v]
    if isinstance(n, list) and isinstance(v, list) and len(n) == len(v):
        return [(str(a), str(b)) for a, b in zip(n, v) if b]
    return []

def sample_of(e):
    return {"arg": args_of(e), "marg": margs_of(e)}

class Corpus:
    """Tập giá trị tham số lành tính (từ nguồn sạch) + hạt giống. `hits(pred)` = số sự kiện có giá trị thoả pred."""
    def __init__(self):
        self.values = Counter(); self.events = 0; self.blob = ""
    def add(self, vals):
        self.events += 1
        for v in set(vals): self.values[v] += 1
    def seal(self): self.blob = "\x00".join(self.values)
    def count(self, token=None, rx=None):
        if token is not None:
            if token not in self.blob: return 0
            return sum(c for v, c in self.values.items() if token in v)
        if not rx.search(self.blob): return 0
        return sum(c for v, c in self.values.items() if rx.search(v))
    def rejects(self, token=None, rx=None):
        """True nếu ứng viên xuất hiện trong lưu lượng lành tính quá tỷ lệ ε."""
        n = self.count(token, rx)
        return n > EPSILON * max(self.events, 1)

def benign_corpus():
    """-> (Corpus góc nhìn arg_v cho luật g0, số sự kiện thật, rulegen_ml.Benign góc nhìn marg_v cho luật đặc tả)."""
    bad = attacker_ips(BENIGN_LOOKBACK)
    corp = Corpus(); live = []
    for e in fetch(BENIGN_LOOKBACK, labels=["benign"]):
        if e.get("src_ip") in bad: continue            # nguồn từng tấn công -> không đáng tin làm 'lành tính'
        corp.add([v for _, v in args_of(e)])
        live += [v for _, v in margs_of(e)]
    n_real = corp.events
    try:
        with open(SEED, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip().lower()
                if ln:
                    vals = [v for _, v in _split(ln.split("?", 1)[1] if "?" in ln else "")] or [ln]
                    corp.add(vals); live += vals
    except FileNotFoundError: pass
    corp.seal()
    return corp, n_real, M.Benign(live)

# ------------------------------------------------------------------ trích bất biến
def candidates(values, digit_free):
    out = set()
    for base in values:
        base = base[:256]
        for i in range(len(base)):
            for j in range(i + MIN_TOK, min(len(base), i + MAX_TOK) + 1):
                c = base[i:j]
                if c.strip() != c or not SAFE.match(c) or "${" in c: continue
                if digit_free and any(ch.isdigit() for ch in c): continue
                if IP_OR_NUM.match(c) or not is_specific(c): continue
                out.add(c)
    return out

def covers(token, sample):   # sample = [(tên, giá trị)]
    return any(token in v for _, v in sample)

def invariant(samples, corpus):
    """Chọn token phủ NHIỀU mẫu nhất (>= MIN_CLUSTER); hoà thì lấy token dài hơn, rồi theo thứ tự chữ
    (tất định). Ưu tiên token không chứa chữ số (chữ số = phần biến thiên của payload).
    Trả (token, [chỉ số mẫu được phủ]) hoặc (None, [])."""
    bases = sorted({v for s in sorted(samples, key=lambda s: sum(len(v) for _, v in s))[:5] for _, v in s})
    for digit_free in (True, False):
        ranked = []
        for c in candidates(bases, digit_free):
            n = sum(1 for s in samples if covers(c, s))
            if n >= MIN_CLUSTER: ranked.append((n, len(c), c))
        ranked.sort(reverse=True)
        for _, _, c in ranked[:400]:                  # theo độ ưu tiên; bỏ ứng viên dính lưu lượng lành tính
            if corpus.rejects(token=c): continue
            return c, [i for i, s in enumerate(samples) if covers(c, s)]
    return None, []

def narrow_target(match, samples, idx):
    """ARGS:<tên> nếu >= 80% mẫu được phủ có payload ở cùng một tham số tên hợp lệ; ngược lại ARGS."""
    names = Counter()
    for i in idx:
        for n in {n for n, v in samples[i] if match(v)}: names[n] += 1
    if names:
        n, c = names.most_common(1)[0]
        if n and ARG_NAME.match(n) and c >= 0.8 * len(idx): return f"ARGS:{n}"
    return "ARGS"

# ------------------------------------------------------------------ luật
# Hai loại luật cùng tồn tại trong state: luật g0 (token/op/target, so trên arg_v) và luật ĐẶC TẢ (kind="spec",
# r["spec"] theo secrule — so trên marg_v bằng đúng phép biến đổi + toán tử mà ModSecurity sẽ chạy).
def is_spec(r):
    return r.get("kind") == "spec" and isinstance(r.get("spec"), dict)

def matcher(r):
    if r.get("op") == "rx": return lambda v: bool(RCE_RE.search(v))
    tok = r["token"]; return lambda v: tok in v

def rule_hits(r, sample):
    """sample = {"arg": [(tên, giá trị)] góc nhìn classifier, "marg": [...] góc nhìn ModSecurity}."""
    if is_spec(r):
        return S.matches(r["spec"], sample["marg"])
    m = matcher(r); want = r.get("target", "ARGS")
    name = want.split(":", 1)[1] if ":" in want else None
    return any(m(v) for n, v in sample["arg"] if name is None or n == name)

def static_check(r):
    if r["state"] not in ("shadow", "active"): return False
    if not (BASE_ID <= r["id"] < BASE_ID + 100000): return False
    if is_spec(r):
        return S.static_check(r["spec"], fixed_rx=FIXED_RX)[0] and r["spec"].get("target") == r.get("target")
    if not TARGET_OK.match(r.get("target", "")): return False
    if r.get("op") == "rx": return r["token"] == RCE_RX          # chỉ cho phép regex cố định đã kiểm (không ReDoS)
    t = r["token"]
    return MIN_TOK <= len(t) <= MAX_TOK and bool(SAFE.match(t)) and "${" not in t and t.strip() == t

def spec_benign_rejects(spec, live):
    """Luật đặc tả khớp lưu lượng lành tính sống quá tỷ lệ ε (ε = 0: một giá trị khớp là loại).
    Benign.hit_idx bỏ qua tên tham số -> khắt khe hơn chính luật (luật ARGS:<tên> chỉ soi một tham số)."""
    return len(live.hit_idx(spec)) > EPSILON * max(len(live), 1)

def render(r):
    if is_spec(r):
        return S.render(r["spec"], r["id"], r["state"])
    action = "deny,status:403" if r["state"] == "active" else "pass"
    operator = ("@rx " if r.get("op") == "rx" else "@contains ") + r["token"]
    return (f'SecRule {r["target"]} "{operator}" '
            f'"id:{r["id"]},phase:2,t:none,t:urlDecodeUni,t:lowercase,{action},log,'
            f'msg:\'autogen {r["class"]} {r["state"]}\',tag:\'autogen/{r["state"]}\'"')

def live_rules():
    return sorted((r for r in state["rules"].values() if r["state"] in ("shadow", "active")), key=lambda r: r["id"])

def build_conf():
    return "# generated by rulegen — do not edit\n" + "".join(render(r) + "\n" for r in live_rules() if static_check(r))

def publish(conf):
    """Gửi tệp luật qua Kafka, chờ enforcer báo kết quả apachectl -t qua enforce.status."""
    sha = hashlib.sha256(conf.encode()).hexdigest()[:16]
    # key cố định -> cùng partition -> enforcer áp đúng thứ tự
    prod.produce("enforce.rules", key=b"rules", value=json.dumps({"conf": conf, "sha": sha, "ts": time.time()}).encode())
    prod.flush(5)
    deadline = time.time() + 45
    while time.time() < deadline:
        msg = status_consumer.poll(1.0)
        if msg is None or msg.error(): continue
        try: st = json.loads(msg.value())
        except Exception: continue
        if st.get("kind") == "rules" and st.get("sha", "")[:16] == sha:
            L.info("apache configtest sha=%s ok=%s", sha, st.get("ok"))
            return sha, st.get("ok")
    L.warning("không nhận được enforce.status cho sha=%s", sha)
    return sha, None

def set_state(r, new, reason):
    r.update(state=new, reason=reason, changed=time.time())
    es.index(index="rule-status", id=str(r["id"]), document={**r, "@timestamp": iso(), "changed_at": iso(r["changed"])})
    L.info("rule %s [%s] %s %r → %s (%s)", r["id"], r["class"], r.get("target"), r["token"], new, reason)

def cleanup_indices():
    """Xoá chỉ mục sự kiện/kiểm toán theo ngày cũ hơn RETENTION_DAYS (không để ES đầy dần)."""
    global _last_cleanup
    if RETENTION_DAYS <= 0 or time.time() - _last_cleanup < 3600: return
    _last_cleanup = time.time()
    keep_s = max(RETENTION_DAYS * 86400, BENIGN_LOOKBACK + 86400)
    for prefix in ("web-events", "audit-decisions"):
        try: names = list(es.indices.get(index=f"{prefix}-*", ignore_unavailable=True))
        except Exception as e:
            L.warning("không liệt kê được chỉ mục %s: %s", prefix, e); continue
        for name in names:
            try: day = datetime.strptime(name[len(prefix) + 1:], "%Y.%m.%d").replace(tzinfo=timezone.utc)
            except ValueError: continue
            if time.time() - day.timestamp() > keep_s + 86400:
                es.indices.delete(index=name, ignore_unavailable=True); L.info("đã xoá chỉ mục cũ %s", name)

def longest_marg(s):
    v = max((v for _, v in s["marg"]), key=len, default="")
    return v if len(v) <= RULESEL_MAX_LEN else ""

def fixed_rce_pick(samples, live_benign):
    """Ứng viên đặc biệt của lớp RCE (phương án A): regex nối-lệnh viết sẵn. Chọn nếu nó phủ >= MIN_CLUSTER mẫu của
    cụm và không khớp giá trị lành tính nào (lưu lượng sống + kho nền đóng băng của G2r). -> (None, đặc tả, idx) | None."""
    spec = dict(RCE_FIXED_SPEC)
    idx = [i for i, s in enumerate(samples) if S.matches(spec, s["marg"])]
    if len(idx) < MIN_CLUSTER:
        return None
    spec = dict(spec, target=M._target(spec, [{"args": s["marg"]} for s in samples], idx))
    if not S.static_check(spec, fixed_rx=FIXED_RX)[0]:
        spec = dict(spec, target="ARGS")
    if spec_benign_rejects(spec, live_benign) or (g2r is not None and g2r.benign.hit_idx(spec)):
        L.info("regex RCE viết sẵn khớp lưu lượng lành tính — nhường G2r")
        return None
    return None, spec, idx

def gen_g2r(cls, samples, live_benign, now):
    """Phủ tập tham lam như g0, nhưng mỗi vòng: liệt kê ứng viên trên tối đa RULESEL_SUBSAMPLE payload mới nhất
    (mỗi mẫu một giá trị dài nhất — đúng dạng dữ liệu huấn luyện), G2r chấm điểm, rồi lấy ứng viên điểm cao nhất
    qua đủ: điểm >= RULESEL_MIN_SCORE, kiểm tra tĩnh, phủ >= MIN_CLUSTER mẫu của CẢ cụm, không khớp lành tính sống.
    Trả danh sách luật mới (trạng thái shadow)."""
    out = []
    if cls not in S.PROFILE:                                   # chỉ 4 lớp có bộ biến đổi (sqli/xss/lfi/rce)
        return out
    while len(out) < MAX_RULES_PER_CLASS:
        vals = list(dict.fromkeys(v for v in (longest_marg(s) for s in samples) if v))
        if len(vals) < MIN_CLUSTER:
            break
        pick = fixed_rce_pick(samples, live_benign) if cls == "rce" else None
        for score, cand, spec in ([] if pick else g2r.rank(cls, vals[:RULESEL_SUBSAMPLE])):
            if score < RULESEL_MIN_SCORE:
                break                                          # đã sắp giảm dần: các ứng viên sau còn thấp hơn
            if not S.static_check(spec)[0]:
                continue
            idx = [i for i, s in enumerate(samples) if S.matches(spec, s["marg"])]
            if len(idx) < MIN_CLUSTER:
                continue
            tgt = M._target(spec, [{"args": s["marg"]} for s in samples], idx)
            spec = dict(spec, target=tgt)                      # dict MỚI: secrule.matches cache theo id(spec)
            if not S.static_check(spec)[0]:
                spec = dict(spec, target="ARGS")
            if spec_benign_rejects(spec, live_benign):
                continue
            pick = (score, spec, idx)
            break
        if pick is None:
            L.info("cluster %s (%d mẫu): G2r không có ứng viên an toàn đủ điểm (nhường tầng khác)", cls, len(samples))
            break
        score, spec, idx = pick
        rid = state["next_id"]; state["next_id"] += 1
        r = {"id": rid, "class": cls, "kind": "spec", "spec": spec, "token": S.describe(spec), "op": spec["op"],
             "target": spec["target"], "selector": "fixed_rx" if spec["op"] == "rx_fixed" else "g2r",
             "score": None if score is None else round(score, 4),
             "since": now, "last_hit": now, "cluster_size": len(idx), "state": "new"}
        state["rules"][str(rid)] = r
        set_state(r, "shadow", "new_cluster"); out.append(r)
        covered = set(idx)
        samples = [s for i, s in enumerate(samples) if i not in covered]
    return out

def cycle():
    now = time.time()
    # Mọi truy vấn ES ở ĐẦU chu kỳ: ES lỗi -> ngoại lệ -> không đổi gì, không phát gì (E3: an toàn khi hỏng).
    attacks = fetch(LOOKBACK, labels=ATTACK_LABELS)
    corpus, n_benign, live_benign = benign_corpus()
    corpus_ok = n_benign >= MIN_BENIGN
    if not corpus_ok:
        L.warning("corpus lành tính mới có %d/%d sự kiện từ nguồn sạch — tạm KHÔNG sinh và KHÔNG ban hành luật",
                  n_benign, MIN_BENIGN)
    att_samples = [sample_of(e) for e in attacks]

    for r in list(state["rules"].values()):                  # luật từ phiên bản cũ (đích URI|ARGS|UA) -> thu hồi
        if r["state"] in ("shadow", "active") and "target" not in r:
            set_state(r, "revoked", "upgrade_v2")

    for r in live_rules():
        if not static_check(r):
            set_state(r, "rejected", "static_check"); continue
        if any(rule_hits(r, s) for s in att_samples): r["last_hit"] = now
        if is_spec(r):
            bad = spec_benign_rejects(r["spec"], live_benign)
        else:
            rx = RCE_RE if r.get("op") == "rx" else None
            bad = corpus.rejects(token=None if rx else r["token"], rx=rx)
        if bad:
            set_state(r, "rejected", "benign_hit")
        elif r["state"] == "shadow" and now - r["since"] >= SHADOW and corpus_ok:
            r["expires"] = now + RULE_TTL; set_state(r, "active", "shadow_passed")
        elif r["state"] == "active" and now >= r["expires"]:
            set_state(r, "expired", "ttl")
        elif r["state"] == "active" and now - r.get("last_hit", r["since"]) > REVOKE:
            set_state(r, "revoked", "no_match")

    # Gom cụm: theo lớp tấn công, chỉ mẫu LỌT cổng 2 (khác 403); khử trùng (IP, payload) để một nguồn
    # lặp lại một request không tự tạo được cụm.
    # Bộ g2r gom và khử trùng theo góc nhìn ModSecurity (marg), bộ g0 theo góc nhìn classifier (arg).
    view = "marg" if SELECTOR == "g2r" else "arg"
    clusters = defaultdict(dict)
    for e, s in zip(attacks, att_samples):
        if e.get("status") == 403 or not s[view]: continue
        clusters[e.get("label")].setdefault((e.get("src_ip"), tuple(sorted(v for _, v in s[view]))), s)
    new = []
    if corpus_ok and SELECTOR == "g2r":
        if g2r is None:
            L.warning("bộ chọn g2r chưa nạp được model/kho nền — KHÔNG sinh luật mới chu kỳ này")
        else:
            for cls, uniq in clusters.items():
                live = live_rules()                           # mẫu đã có luật phủ thì không sinh luật nữa
                samples = [s for s in uniq.values() if not any(rule_hits(r, s) for r in live)][:300]
                new += gen_g2r(cls, samples, live_benign, now)
    elif corpus_ok and SELECTOR == "g0":
        for cls, uniq in clusters.items():
            live = live_rules()                               # mẫu đã có luật phủ thì không sinh luật nữa
            samples = [s["arg"] for s in uniq.values() if not any(rule_hits(r, s) for r in live)][:300]
            made = 0
            while len(samples) >= MIN_CLUSTER and made < MAX_RULES_PER_CLASS:
                tok, op, idx = None, "contains", []
                if cls == "rce":                               # rce ưu tiên @rx neo dấu nối lệnh
                    idx = [i for i, s in enumerate(samples) if any(RCE_RE.search(v) for _, v in s)]
                    if len(idx) >= MIN_CLUSTER and not corpus.rejects(rx=RCE_RE): tok, op = RCE_RX, "rx"
                if tok is None:
                    tok, idx = invariant(samples, corpus)
                if not tok:
                    L.info("cluster %s (%d mẫu): không có bất biến ĐẶC HIỆU an toàn (nhường tầng khác)", cls, len(samples))
                    break
                m = (lambda v: bool(RCE_RE.search(v))) if op == "rx" else (lambda v, t=tok: t in v)
                rid = state["next_id"]; state["next_id"] += 1
                r = {"id": rid, "class": cls, "token": tok, "op": op, "target": narrow_target(m, samples, idx),
                     "since": now, "last_hit": now, "cluster_size": len(idx), "state": "new"}
                state["rules"][str(rid)] = r
                set_state(r, "shadow", "new_cluster"); new.append(r); made += 1
                covered = set(idx)
                samples = [s for i, s in enumerate(samples) if i not in covered]

    conf = build_conf()
    sha = hashlib.sha256(conf.encode()).hexdigest()[:16]
    if sha != state.get("published_sha"):                      # chỉ phát khi tệp luật THAY ĐỔI
        _, ok = publish(conf)
        if ok is False:
            for r in new: set_state(r, "rejected", "apache_configtest")
            conf = build_conf(); sha = hashlib.sha256(conf.encode()).hexdigest()[:16]
            _, ok = publish(conf)
        if ok: state["published_sha"] = sha                   # chưa được xác nhận -> chu kỳ sau phát lại
    for r in live_rules():                                     # 'nhịp tim' để bảng Grafana luôn thấy luật đang sống
        es.index(index="rule-status", id=str(r["id"]),
                 document={**r, "@timestamp": iso(), "changed_at": iso(r.get("changed", now))})
    atomic_write(STATE_PATH, json.dumps(state))
    cleanup_indices()

def load_selector():
    """Nạp G2r. Lỗi -> None: rulegen vẫn quản lý luật đang có nhưng KHÔNG sinh luật mới (an toàn khi hỏng)."""
    if SELECTOR != "g2r":
        return None
    try:
        import rulesel_g2r
        t0 = time.time()
        sel = rulesel_g2r.Selector(RULESEL_MODEL, RULESEL_PRIOR)
        L.info("bộ chọn G2r đã nạp (%s, %s) trong %.1f s", RULESEL_MODEL, RULESEL_PRIOR, time.time() - t0)
        return sel
    except Exception:
        L.exception("KHÔNG nạp được bộ chọn G2r — sẽ không sinh luật mới (đặt RULEGEN_SELECTOR=g0 để dùng bộ cũ)")
        return None

def main():
    global es, prod, status_consumer, g2r
    install_stop()
    if SELECTOR not in ("g2r", "g0"):
        raise SystemExit(f"RULEGEN_SELECTOR={SELECTOR!r} không hợp lệ (g2r | g0)")
    g2r = load_selector()
    es = es_client(); prod = producer()
    status_consumer = consumer("rulegen-status", ["enforce.status"])
    os.makedirs("/state", exist_ok=True)
    state.pop("published_sha", None)                           # khởi động lại -> phát lại một lần để đồng bộ enforcer
    L.info("rulegen started: bộ chọn %s, chu kỳ %ss, shadow %ss, corpus tối thiểu %d, ε=%s",
           SELECTOR, INTERVAL, SHADOW, MIN_BENIGN, EPSILON)
    hb = Heartbeat("rulegen"); failed = 0
    while running():
        try: cycle(); hb.inc()
        except Exception:
            failed += 1; L.exception("cycle failed — giữ nguyên tập luật hiện có")
        end = time.time() + INTERVAL
        while running() and time.time() < end:
            time.sleep(1)
            d = hb.tick(cycles_failed=failed, live_rules=len(live_rules()))     # nhịp tim -> nsm-health-*
            if d:
                try: es.index(index=day_index("nsm-health"), document=d)
                except Exception: pass

if __name__ == "__main__":
    main()
