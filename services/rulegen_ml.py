"""rulegen_ml: hai bộ sinh luật mới, dùng chung một bộ tìm kiếm, khác nhau ở cách GOM CỤM và ở CỔNG
quyết định "token này có phải dấu hiệu tấn công không".

  G1 — thuật toán cải tiến, KHÔNG học:
       cụm = nhãn lớp của classifier; cổng = token phải chứa ký tự/cụm cú pháp tấn công (viết tay).
  G2 — học máy:
       cụm = DBSCAN trên TF-IDF n-gram ký tự (gom theo nội dung, mẫu lẻ loi bị bỏ);
       cổng = mô hình Naive Bayes trên token: tỷ số khả năng tấn công/lành tính học từ dữ liệu,
       kèm ước lượng tỷ lệ chặn nhầm của tổ hợp token (tích xác suất lành tính của từng token).

Cả hai đều: biến đổi giá trị theo lớp (secrule.PROFILE) TRƯỚC khi trích token, cho phép luật 1–2
token có thứ tự, và chỉ trả về ĐẶC TẢ luật (xem secrule.py). Việc kiểm chứng trên corpus lành tính
là điều kiện cứng với mọi bộ sinh.
"""
import math, re
from collections import Counter

import secrule as S

MIN_CLUSTER = 5
MAX_RULES = 3                 # số luật tối đa cho một cụm (phủ tập tham lam)
TOP_ATOMS = 40                # số token ứng viên được xét ghép cặp
MAX_SPAN, ATOM_MIN, ATOM_MAX = 7, 3, 32
# đơn vị: từ | số | khoảng trắng | một dấu lặp lại ('..', '--', '((') — không gộp '../' thành một khối
_TOK = re.compile(r"[a-z_]+|\d+|\s+|([^\sa-z0-9_])*")
_STRONG = set("'\"<>;|(){}$`")
_GRAMMAR = re.compile(r"\.\./|\.\.\\|/\*|\*/|--|/etc/|php://|file://|\bon[a-z]+=")


def is_specific(tok):
    """Cổng viết tay của rulegen hiện tại: token có ký tự/cụm cú pháp tấn công."""
    return any(c in _STRONG for c in tok) or bool(_GRAMMAR.search(tok))


def atoms_of(value):
    """Mọi token ứng viên của một giá trị ĐÃ biến đổi: chuỗi gồm 1..MAX_SPAN đơn vị liền nhau
    (từ, số, dấu, khoảng trắng), dài 3..32 ký tự, không bắt đầu/kết thúc bằng khoảng trắng,
    không chứa chữ số (chữ số là phần biến thiên của payload)."""
    toks = [m.group(0) for m in _TOK.finditer(value[:256])]
    out = set()
    for i, t in enumerate(toks):
        if t.isspace():
            continue
        span = ""
        for j in range(i, min(len(toks), i + MAX_SPAN)):
            span += toks[j]
            if len(span) > ATOM_MAX:
                break
            if toks[j].isspace() or len(span) < ATOM_MIN:
                continue
            if any(c.isdigit() for c in span) or not S.TOKEN_OK.match(span) or "${" in span:
                continue
            out.add(span)
    return out


# ------------------------------------------------------------------ dữ liệu lành tính
class Benign:
    """Tập giá trị lành tính; đếm số giá trị mà một luật khớp, theo đúng cách ModSecurity sẽ khớp."""

    def __init__(self, values, vocab_blob="", n_vocab=0):
        """values: giá trị tham số lành tính đã quan sát. vocab_blob: vốn từ nền (mỗi dòng một từ thuần
        chữ thường, không đổi qua mọi phép biến đổi) — để một từ thông dụng không bao giờ thành luật."""
        self.values = list(dict.fromkeys(values))
        self.vocab_blob, self.n_vocab = vocab_blob, n_vocab
        self._tv = {}

    def __len__(self):
        return len(self.values) + self.n_vocab

    def transformed(self, transforms):
        key = tuple(transforms)
        if key not in self._tv:
            vals = [S.apply(key, v).replace("\n", " ") for v in self.values]
            self._tv[key] = (vals, "\n".join(vals))
        return self._tv[key]

    def hit_idx(self, spec):
        """Tập chỉ số các giá trị lành tính mà luật khớp (-1 = khớp một từ trong vốn từ nền)."""
        vals, blob = self.transformed(spec["transforms"])
        p = S.pattern(spec)
        out = set()
        if spec.get("op") == "rx_fixed":
            # biểu thức viết sẵn: KHÔNG lọc nhanh bằng "token in blob" (token là chính biểu thức) -> quét thật
            rx = re.compile(p, re.ASCII)
            out = {i for i, v in enumerate(vals) if rx.search(v)}
            # vốn từ nối bằng '\n': quét TỪNG từ, nếu không '\n' giữa hai từ sẽ bị coi là một phần của payload
            if self.vocab_blob and any(rx.search(w) for w in self.vocab_blob.split("\n")):
                out.add(-1)
            return out
        if p is None:
            tok = spec["tokens"][0]
            if tok in blob:
                out = {i for i, v in enumerate(vals) if tok in v}
            if tok in self.vocab_blob:
                out.add(-1)
            return out
        line = re.compile(p.replace(".{0,", "[^\\n]{0,"), re.ASCII)      # không cho khoảng trống vượt sang dòng khác
        if all(t in blob for t in spec["tokens"]) and line.search(blob):
            rx = re.compile(p, re.ASCII)
            out = {i for i, v in enumerate(vals) if rx.search(v)}
        if all(t in self.vocab_blob for t in spec["tokens"]) and line.search(self.vocab_blob):
            out.add(-1)
        return out

    def hits(self, spec):
        return len(self.hit_idx(spec))

    def df(self, transforms, atom):
        """Số giá trị chứa token (xấp xỉ bằng số lần xuất hiện trong khối văn bản)."""
        return self.transformed(transforms)[1].count(atom) + self.vocab_blob.count(atom)


# ------------------------------------------------------------------ mô hình Naive Bayes trên token (G2)
class TokenPrior:
    """P(token | tấn công lớp c) và P(token | lành tính), làm trơn Laplace.
    Học từ: payload tấn công đã biết theo lớp + văn bản lành tính nền. Không có tham số nào chỉnh tay."""

    def __init__(self, attacks_by_class, benign):
        self.benign = benign                                   # Benign
        self.att = {}
        for cls, values in attacks_by_class.items():
            tv = [S.apply(S.PROFILE[cls], v).replace("\n", " ") for v in dict.fromkeys(values)]
            self.att[cls] = (len(tv), "\n".join(tv))

    def p_attack(self, cls, atom):
        n, blob = self.att.get(cls, (0, ""))
        return (min(blob.count(atom), n) + 1.0) / (n + 2.0)

    def p_benign(self, cls, atom):
        n = len(self.benign)
        return (min(self.benign.df(S.PROFILE[cls], atom), n) + 1.0) / (n + 2.0)

    def llr(self, cls, atom):
        return math.log(self.p_attack(cls, atom) / self.p_benign(cls, atom))

    def seen(self, cls, atom):
        return self.att.get(cls, (0, ""))[1].count(atom)


# ------------------------------------------------------------------ gom cụm
def cluster_by_label(samples):
    """G0/G1: mỗi nhãn lớp một cụm."""
    out = {}
    for s in samples:
        out.setdefault(s["cls"], []).append(s)
    return [(c, xs) for c, xs in out.items() if len(xs) >= MIN_CLUSTER]


def _mask(v):
    return re.sub(r"\d+", "0", v)


def cluster_by_content(samples, eps=0.8):
    """G2: DBSCAN (khoảng cách cosine) trên TF-IDF n-gram ký tự 2–4 của giá trị đã biến đổi, chữ số
    được che. eps = 0,8 chọn trên phần dữ liệu nền (cụm thuần ~93 %, ~25 % mẫu bị coi là nhiễu khi n = 30). Mẫu không thuộc vùng đủ dày bị coi là nhiễu và bỏ qua. Nhãn của cụm = nhãn đa số."""
    from sklearn.cluster import DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer
    if len(samples) < MIN_CLUSTER:
        return []
    texts = [_mask(" ".join(S.apply(S.PROFILE[s["cls"]], v) for _, v in s["args"])) for s in samples]
    X = TfidfVectorizer(analyzer="char", ngram_range=(2, 4), sublinear_tf=True).fit_transform(texts)
    labels = DBSCAN(eps=eps, min_samples=MIN_CLUSTER, metric="cosine").fit_predict(X)
    groups = {}
    for lab, s in zip(labels, samples):
        if lab >= 0:
            groups.setdefault(int(lab), []).append(s)
    out = []
    for xs in groups.values():
        cls = Counter(s["cls"] for s in xs).most_common(1)[0][0]
        out.append((cls, xs))
    return out


# ------------------------------------------------------------------ tìm luật cho một cụm
def _target(spec, samples, idx):
    """ARGS:<tên> nếu >= 80 % mẫu được phủ có payload ở cùng một tham số, ngược lại ARGS."""
    m, tr = S.matcher(spec), spec["transforms"]
    names = Counter()
    for i in idx:
        for n, v in samples[i]["args"]:
            if m(S.apply(tr, v)):
                names[n.lower()] += 1
                break
    if names:
        n, c = names.most_common(1)[0]
        if n and re.match(r"^[a-z0-9_.\-]{1,32}$", n) and c >= 0.8 * len(idx):
            return f"ARGS:{n}"
    return "ARGS"


def search_rules(cls, samples, benign, gate, prior=None, max_rules=MAX_RULES, min_cluster=MIN_CLUSTER):
    """Phủ tập tham lam: mỗi vòng chọn luật (1 hoặc 2 token có thứ tự) phủ nhiều mẫu nhất trong số
    các luật qua được cổng `gate` ('struct' | 'nb') và KHÔNG khớp giá trị lành tính nào.
    Trả [(đặc tả, số mẫu phủ, thông tin cổng)]."""
    tr = list(S.PROFILE[cls])
    tvals = [[S.apply(tr, v) for _, v in s["args"]] for s in samples]
    remaining = list(range(len(samples)))
    rules = []
    while len(remaining) >= min_cluster and len(rules) < max_rules:
        best = _best_rule(cls, tr, [tvals[i] for i in remaining], benign, gate, prior, min_cluster)
        if best is None:
            break
        spec, cov_local, info = best
        idx = [remaining[k] for k in cov_local]
        spec["target"] = _target(spec, samples, idx)
        rules.append((spec, len(idx), info))
        covered = set(idx)
        remaining = [i for i in remaining if i not in covered]
    return rules


def _best_rule(cls, tr, tvals, benign, gate, prior, min_cluster):
    n = len(tvals)
    df = Counter()
    for vals in tvals:
        seen = set()
        for v in vals:
            seen |= atoms_of(v)
        df.update(seen)
    atoms = [a for a, c in df.items() if c >= min_cluster]
    if not atoms:
        return None

    def spec_of(tokens):
        # một token không có mép chữ/số -> @contains là đủ; còn lại dùng @rx (có \b và khoảng trống giới hạn)
        plain = len(tokens) == 1 and S.atom_rx(tokens[0]) == S.rx_escape(tokens[0])
        return {"class": cls, "target": "ARGS", "transforms": tr, "op": "contains" if plain else "seq",
                "tokens": list(tokens), "max_gap": 40}

    def cover(spec):
        m = S.matcher(spec)
        return [i for i, vals in enumerate(tvals) if any(m(v) for v in vals)]

    # thông tin cổng cho từng token
    info = {}
    for a in atoms:
        d = {"specific": is_specific(a)}
        if prior is not None:
            d["llr"] = prior.llr(cls, a)
            d["pb"] = prior.p_benign(cls, a)
            d["seen"] = prior.seen(cls, a)
        info[a] = d
    eps_fp = 2.0 / (len(prior.benign) + 2.0) if prior is not None else None
    tau = math.log(20.0)

    def passes(tokens):
        if gate == "struct":
            return any(info[t]["specific"] for t in tokens)
        # 'nb': ít nhất một token đã từng thấy trong tấn công (>= 3 lần), tổng log tỷ số khả năng đủ lớn,
        # và tỷ lệ chặn nhầm ước lượng (các token độc lập) không vượt mức đo được của dữ liệu nền
        if not any(info[t]["seen"] >= 3 for t in tokens):
            return False
        if sum(info[t]["llr"] for t in tokens) < tau:
            return False
        return math.prod(info[t]["pb"] for t in tokens) <= eps_fp

    def strength(tokens):
        return sum(info[t].get("llr", 0.0) for t in tokens) if prior is not None else sum(len(t) for t in tokens)

    cands = []                                            # (số mẫu phủ, -số token, độ mạnh, tokens, cov)
    single_cov, bh = {}, {}
    for a in atoms:
        sp = spec_of([a])
        cov = cover(sp)
        single_cov[a] = cov
        if len(cov) >= min_cluster:
            bh[a] = benign.hit_idx(sp)                    # giá trị lành tính mà token này (đứng một mình) khớp
            if passes([a]):
                cands.append((len(cov), -1, strength([a]), [a], cov))
    # ghép cặp có thứ tự trong số TOP_ATOMS token phủ rộng nhất
    top = sorted(atoms, key=lambda a: (-len(single_cov[a]), -len(a), a))[:TOP_ATOMS]
    sets = {a: set(single_cov[a]) for a in top}
    for a in top:
        for b in top:
            if a == b or a in b or b in a or len(sets[a] & sets[b]) < min_cluster:
                continue
            if not passes([a, b]):
                continue
            sp = spec_of([a, b])
            cov = cover(sp)
            if len(cov) >= min_cluster:
                cands.append((len(cov), -2, strength([a, b]), [a, b], cov))
    cands.sort(key=lambda c: (-c[0], -c[1], -c[2], c[3]))
    for ncov, _, st, tokens, cov in cands:
        sp = spec_of(tokens)
        # luật nhiều token chỉ có thể khớp giá trị lành tính mà MỌI token của nó đều khớp
        if len(tokens) == 1:
            clean = not bh[tokens[0]]
        else:
            clean = any(not bh.get(t, {0}) for t in tokens) or not benign.hit_idx(sp)
        if clean:
            return sp, cov, {"cover": ncov, "of": n, "strength": round(st, 2),
                             "tokens": {t: {k: (round(v, 6) if isinstance(v, float) else v) for k, v in info[t].items()}
                                        for t in tokens}}
    return None


# ------------------------------------------------------------------ hai bộ sinh
def generate_g1(samples, benign, **kw):
    out = []
    for cls, xs in cluster_by_label(samples):
        out += search_rules(cls, xs, benign, "struct", **kw)
    return out


def generate_g2(samples, benign, prior, cluster="content", **kw):
    groups = cluster_by_content(samples) if cluster == "content" else cluster_by_label(samples)
    out, seen = [], {}
    for cls, xs in groups:
        for spec, cov, info in search_rules(cls, xs, benign, "nb", prior=prior, **kw):
            key = (spec["class"], spec["target"], spec["op"], tuple(spec["tokens"]))
            if key in seen:                               # hai cụm cho ra cùng một luật -> gộp
                out[seen[key]] = (out[seen[key]][0], out[seen[key]][1] + cov, out[seen[key]][2])
            else:
                seen[key] = len(out)
                out.append((spec, cov, info))
    return out
