"""rulesel_g2r: bộ CHỌN LUẬT học máy G2r cho rulegen.

Với một cụm payload cùng lớp, bộ sinh ML (rulegen_ml) liệt kê tối đa 20 luật ứng viên 1–2 token đã lọc an toàn;
model HistGradientBoosting (huấn luyện ở train/notebooks_src/02, chọn trên valid) dự đoán "điểm" của từng ứng
viên = recall trên tấn công tương lai nếu không chặn nhầm, −1 nếu chặn nhầm; ứng viên điểm cao nhất được chọn.
Kết quả độc lập (Huan-luyen-Colab-tier2-va-chon-luat-NSM.md, mục 8): SR-BH +0,144 và 0 % cụm chặn nhầm, so với
bộ G2n −0,030 / 13,6 %.

KHỚP HUẤN LUYỆN: mọi hàm dưới đây chép đúng train/build_rulesel_dataset.py (liệt kê ứng viên, cổng NB) và
notebook 02 (đặc trưng). Đặc trưng llr / seen / pb được tính trên KHO NỀN ĐÓNG BĂNG của lúc huấn luyện
(models/rulesel_prior.json.gz, xuất bằng train/export_rulesel_prior.py) — không tính trên dữ liệu sống, nếu không
điểm của model sẽ lệch thang. Kiểm chứng an toàn trên lưu lượng lành tính SỐNG do rulegen làm thêm sau khi chọn.
"""
import gzip, json, math, re

import numpy as np

import rulegen_ml as M
import secrule as S

MAX_CAND = 20
CLS = ["sqli", "xss", "lfi", "rce"]
FEAT_NAMES = ["cov_frac", "cov", "m", "n_tok", "len", "len_max", "len_min", "llr_sum", "llr_min", "seen_max", "seen_min",
              "log_pb", "struct_gate", "nb_gate", "op_seq", "alpha_frac", "punct_frac", "word_only", "quote", "angle",
              "paren", "slash", "dotdot", "space", "cmdsep", "rank_cov", "n_cands"] + [f"cls_{k}" for k in CLS]


# ------------------------------------------------------------------ liệt kê ứng viên (= build_rulesel_dataset.candidates)
def spec_of(cls, toks):
    plain = len(toks) == 1 and S.atom_rx(toks[0]) == S.rx_escape(toks[0])
    return {"class": cls, "target": "ARGS", "transforms": list(S.PROFILE[cls]),
            "op": "contains" if plain else "seq", "tokens": list(toks), "max_gap": 40}


def quick_match(spec, toks, tv):
    m = S.matcher(spec)
    return [i for i, v in enumerate(tv) if all(t in v for t in toks) and m(v)]


def enumerate_candidates(cls, values, prior, benign, max_cand=MAX_CAND):
    """values = giá trị tham số (góc nhìn ModSecurity, CHƯA biến đổi), mỗi mẫu một giá trị (giá trị dài nhất)."""
    tr = S.PROFILE[cls]
    tv = [S.apply(tr, v) for v in values]
    m = len(values)
    need = max(2, math.ceil(0.3 * m))
    df = {}
    for v in tv:
        for a in M.atoms_of(v):
            df[a] = df.get(a, 0) + 1
    atoms = [a for a, c in df.items() if c >= need]
    if not atoms:
        return []
    top = sorted(atoms, key=lambda a: (-df[a], -len(a), a))[:25]
    cand_toks = [(a,) for a in atoms]
    for a in top:
        for b in top:
            if a != b and a not in b and b not in a:
                cand_toks.append((a, b))
    out = []
    for toks in cand_toks:
        sp = spec_of(cls, toks)
        cov = quick_match(sp, toks, tv)
        if len(cov) < need:
            continue
        if benign.hit_idx(sp):                       # không khớp giá trị lành tính nào của kho nền
            continue
        info = [{"llr": prior.llr(cls, t), "pb": prior.p_benign(cls, t), "seen": prior.seen(cls, t),
                 "spec": M.is_specific(t)} for t in toks]
        out.append({"tokens": list(toks), "op": sp["op"], "cov": len(cov), "m": m,
                    "llr_sum": round(sum(i["llr"] for i in info), 4), "llr_min": round(min(i["llr"] for i in info), 4),
                    "seen_max": max(i["seen"] for i in info), "seen_min": min(i["seen"] for i in info),
                    "log_pb": round(sum(math.log(i["pb"]) for i in info), 4),
                    "struct_gate": any(i["spec"] for i in info)})
    eps = 2.0 / (len(benign) + 2.0)
    for c in out:
        c["nb_gate"] = bool(c["seen_max"] >= 3 and c["llr_sum"] >= math.log(20.0) and math.exp(c["log_pb"]) <= eps)
    out.sort(key=lambda c: (-c["cov"], len(c["tokens"]), -c["llr_sum"], c["tokens"]))
    return out[:max_cand]


# ------------------------------------------------------------------ đặc trưng (= notebook 02, cand_feats)
def cand_feats(cls, cands, c):
    toks = c["tokens"]; s = "".join(toks)
    f = [c["cov"] / c["m"], c["cov"], c["m"], len(toks), len(s), max(len(t) for t in toks), min(len(t) for t in toks),
         c["llr_sum"], c["llr_min"], c["seen_max"], c["seen_min"], c["log_pb"], int(c["struct_gate"]), int(c["nb_gate"]),
         int(c["op"] == "seq"), sum(ch.isalpha() for ch in s) / len(s), sum(not ch.isalnum() for ch in s) / len(s),
         int(bool(re.fullmatch(r"[a-z_]+", s))), int("'" in s or '"' in s), int("<" in s or ">" in s),
         int("(" in s or ")" in s), int("/" in s), int(".." in s), int(" " in s), int(";" in s or "|" in s or "`" in s)]
    # lúc huấn luyện ứng viên bị xáo thứ tự nên vị trí giữa các ứng viên CÙNG độ phủ là ngẫu nhiên; ở đây là thứ tự
    # tất định của enumerate_candidates — chỉ khác nhau trong nhóm đồng hạng
    rank_cov = sorted(cands, key=lambda x: -x["cov"]).index(c)
    f += [rank_cov, len(cands)] + [int(cls == k) for k in CLS]
    return f


class Selector:
    """Nạp model + kho nền đóng băng một lần; rank() trả [(điểm dự đoán, ứng viên, đặc tả luật)] giảm dần."""

    def __init__(self, model_path, prior_path):
        import joblib
        d = joblib.load(model_path)
        if list(d.get("features", [])) != FEAT_NAMES:
            raise ValueError("model G2r được huấn luyện với bộ đặc trưng khác bộ đặc trưng của rulesel_g2r.py")
        self.model = d["model"]
        with gzip.open(prior_path, "rt", encoding="utf-8") as f:
            p = json.load(f)
        vocab = p["vocab"]
        self.benign = M.Benign(p["benign"], "\n".join(vocab), len(vocab))
        self.prior = M.TokenPrior(p["attacks"], self.benign)
        for c in CLS:                                  # biến đổi trước kho lành tính cho cả 4 lớp (tốn vài giây)
            self.benign.transformed(S.PROFILE[c])

    def rank(self, cls, values):
        cands = enumerate_candidates(cls, values, self.prior, self.benign)
        if not cands:
            return []
        X = np.array([cand_feats(cls, cands, c) for c in cands], dtype=float)
        scores = self.model.predict(X)
        order = sorted(range(len(cands)), key=lambda i: -scores[i])
        return [(float(scores[i]), cands[i], spec_of(cls, cands[i]["tokens"])) for i in order]
