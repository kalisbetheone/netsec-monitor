#!/usr/bin/env python3
"""train/build_rulesel_dataset.py — dựng dữ liệu CHỌN LUẬT cho bộ xếp hạng ML (G2r) và LLM (G3).

    python -I -X utf8 -B train/build_rulesel_dataset.py          (chạy từ thư mục nsm; ~10–20 phút)

Một mẫu = một "đợt tấn công": cụm 8–24 payload cùng lớp, cùng nguồn. Bộ sinh ML (services/rulegen_ml.py) liệt kê
tối đa 20 luật ứng viên (1–2 token, phép biến đổi theo lớp), CHỈ giữ ứng viên phủ đủ cụm và không khớp giá trị lành
tính nào đã biết — đúng bộ lọc an toàn của hệ thống. Mỗi ứng viên được chấm trên:
    - P: payload cùng lớp KHÔNG nằm trong cụm (tấn công "tương lai"), lấy từ tập tương ứng;
    - B: giá trị tham số lành tính THẬT của tập tương ứng (website chưa thấy với tập kiểm tra).
Điểm (eval/PROTOCOL.md mục 4): recall trên P nếu không chặn nhầm giá trị nào trong B; ngược lại -(số chặn nhầm).
Nhãn = ứng viên điểm cao nhất (hoà: ít token hơn, rồi thứ tự chữ).

Tập: train / valid (từ phần train / valid của SecLists + openappsec Malicious, lành tính của website train / valid);
test_srbh (tấn công THẬT SR-BH 2020) và test_httpparams — lành tính lấy từ website test_sites + phần lành tính của
chính dataset đó. Đầu ra: train/data/rulesel_<tập>.jsonl.gz
"""
import gzip, json, math, os, random, re, sys, time
from collections import Counter, defaultdict
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services"))
import secrule as S            # noqa: E402
import rulegen_ml as M         # noqa: E402

NORM = os.path.join(ROOT, "eval", "data", "normalized")
VOCAB = os.path.join(ROOT, "eval", "data", "seclists", "Miscellaneous_lang-english.words3-10.txt")
OUT = os.path.join(ROOT, "train", "data")
CLASSES = ("sqli", "xss", "lfi", "rce")
N_CLUSTERS = {"train": 1600, "valid": 300, "test_srbh": 300, "test_httpparams": 240}
MAX_CAND, P_EVAL, B_EVAL, B_SAFE = 20, 400, 15000, 30000
SEED = 20261112

G = {}       # dữ liệu dùng chung cho tiến trình con (nạp bằng init)


def rows(src):
    with gzip.open(os.path.join(NORM, f"{src}.jsonl.gz"), "rt", encoding="utf-8") as f:
        for ln in f:
            yield json.loads(ln)


def longest(r):
    v = r.get("marg_v") or []
    return max(v, key=len) if v else ""


def reservoir(it, k, rng):
    out, n = [], 0
    for x in it:
        n += 1
        if len(out) < k:
            out.append(x)
        else:
            j = rng.randrange(n)
            if j < k:
                out[j] = x
    return out


# ------------------------------------------------------------------ ứng viên
def spec_of(cls, toks):
    plain = len(toks) == 1 and S.atom_rx(toks[0]) == S.rx_escape(toks[0])
    return {"class": cls, "target": "ARGS", "transforms": list(S.PROFILE[cls]),
            "op": "contains" if plain else "seq", "tokens": list(toks), "max_gap": 40}


def quick_match(spec, toks, tv):
    """tv = giá trị ĐÃ biến đổi. Lọc nhanh bằng 'in' trước khi chạy regex."""
    m = S.matcher(spec)
    return [i for i, v in enumerate(tv) if all(t in v for t in toks) and m(v)]


def candidates(cls, values):
    """Liệt kê ứng viên cho một cụm; trả danh sách dict có đặc trưng."""
    prior, benign = G["prior"], G["benign"]
    tr = S.PROFILE[cls]
    tv = [S.apply(tr, v) for v in values]
    m = len(values)
    need = max(2, math.ceil(0.3 * m))
    df = Counter()
    for v in tv:
        df.update(M.atoms_of(v))
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
        if benign.hit_idx(sp):                       # bộ lọc an toàn của hệ thống: không khớp lành tính đã biết
            continue
        info = [{"llr": prior.llr(cls, t), "pb": prior.p_benign(cls, t), "seen": prior.seen(cls, t),
                 "spec": M.is_specific(t)} for t in toks]
        out.append({"tokens": list(toks), "op": sp["op"], "cov": len(cov), "m": m,
                    "llr_sum": round(sum(i["llr"] for i in info), 4), "llr_min": round(min(i["llr"] for i in info), 4),
                    "seen_max": max(i["seen"] for i in info), "seen_min": min(i["seen"] for i in info),
                    "log_pb": round(sum(math.log(i["pb"]) for i in info), 4),
                    "struct_gate": any(i["spec"] for i in info)})
    eps = 2.0 / (len(benign) + 2.0)
    for c in out:                                      # cổng Naive Bayes của G2n (rulegen_ml.search_rules)
        c["nb_gate"] = bool(c["seen_max"] >= 3 and c["llr_sum"] >= math.log(20.0) and math.exp(c["log_pb"]) <= eps)
    out.sort(key=lambda c: (-c["cov"], len(c["tokens"]), -c["llr_sum"], c["tokens"]))
    return out[:MAX_CAND]


def score(cls, cand, P, B):
    sp = spec_of(cls, cand["tokens"])
    tr = S.PROFILE[cls]
    p_hit = len(quick_match(sp, cand["tokens"], [S.apply(tr, v) for v in P])) if P else 0
    b_hit = len(quick_match(sp, cand["tokens"], G["B_tv"][cls]))
    rec = p_hit / max(len(P), 1)
    return {"recall": round(rec, 4), "fp": b_hit, "util": round(rec if b_hit == 0 else -b_hit, 4)}


def _init(prior_src, benign_vals, vocab_blob, n_vocab, b_eval):
    G["benign"] = M.Benign(benign_vals, vocab_blob, n_vocab)
    G["prior"] = M.TokenPrior(prior_src, G["benign"])
    G["B_tv"] = {c: [S.apply(S.PROFILE[c], v) for v in b_eval] for c in CLASSES}


def _job(task):
    cid, split, cls, group, values, P = task
    cands = candidates(cls, values)
    if len(cands) < 2:
        return None
    for c in cands:
        c.update(score(cls, c, P, None))
    best = max(range(len(cands)), key=lambda i: (cands[i]["util"], -len(cands[i]["tokens"]), [-ord(x) for x in "".join(cands[i]["tokens"])[:8]]))
    order = list(range(len(cands)))
    random.Random(cid).shuffle(order)                # thứ tự trình bày ngẫu nhiên: tránh LLM/ranker học vị trí
    cands = [cands[i] for i in order]
    best = order.index(best)
    g2n = next((i for i, c in sorted(enumerate(cands), key=lambda x: (-x[1]["cov"], len(x[1]["tokens"]), -x[1]["llr_sum"])) if c["nb_gate"]), None)
    g1 = next((i for i, c in sorted(enumerate(cands), key=lambda x: (-x[1]["cov"], -len("".join(x[1]["tokens"])))) if c["struct_gate"]), None)
    return {"id": cid, "split": split, "class": cls, "group": group, "payloads": values, "cands": cands,
            "best": best, "g2n": g2n, "g1": g1, "n_eval_pos": len(P)}


def main():
    t0 = time.time()
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(SEED)
    # ---- nhóm payload theo (tập, lớp, nguồn)
    pools = defaultdict(lambda: defaultdict(list))        # split -> (cls, group) -> [value]
    for src in ("seclists", "openappsec_mal"):
        for r in rows(src):
            if r["ds_class"] in CLASSES and r["split"] in ("train", "valid"):
                v = longest(r)
                if v and len(v) <= 400:
                    pools[r["split"]][(r["ds_class"], r["sub"])].append(v)
    for name, src in (("test_srbh", "srbh2020"), ("test_httpparams", "httpparams")):
        for r in rows(src):
            if r["ds_class"] in CLASSES and r.get("marg_v"):
                v = longest(r)
                if v and len(v) <= 400:
                    pools[name][(r["ds_class"], r["sub"] if src == "srbh2020" else "all")].append(v)
    # ---- lành tính: giá trị tham số thật theo tập
    def bvals(split_set, extra=()):
        it = (v for r in rows("openappsec_legit") if r["split"] in split_set for v in (r.get("marg_v") or []) if v)
        vals = list(dict.fromkeys(reservoir(it, B_SAFE, rng)))
        for src in extra:
            vals += list(dict.fromkeys(v for r in rows(src) if r["ds_class"] == "benign" for v in (r.get("marg_v") or []) if v))[:5000]
        return vals
    benign_train = bvals({"train"})
    benign_eval = {"train": bvals({"train"})[:B_EVAL], "valid": bvals({"valid"})[:B_EVAL],
                   # KHÔNG dùng phần "bình thường" của SR-BH: ~10 % là tấn công bị gắn nhầm nhãn (WAMM, arXiv 2512.23610),
                   # làm mọi luật tốt bị tính là chặn nhầm. Lành tính = website openappsec chưa thấy (test_sites).
                   "test_srbh": bvals({"test_sites"})[:B_EVAL],
                   "test_httpparams": bvals({"test_sites"}, ("httpparams",))[:B_EVAL + 5000]}
    vocab = [w for w in open(VOCAB, encoding="utf-8").read().split() if w]
    prior_src = {c: [] for c in CLASSES}
    for (c, g), vs in pools["train"].items():
        prior_src[c] += vs
    print(f"   payload theo tập: { {s: sum(len(v) for v in p.values()) for s, p in pools.items()} }; "
          f"lành tính: train {len(benign_train)}", file=sys.stderr, flush=True)
    # ---- sinh cụm
    tasks = defaultdict(list)
    cid = 0
    for split, n in N_CLUSTERS.items():
        groups = [(k, v) for k, v in pools[split].items() if len(v) >= 12]
        by_cls = defaultdict(list)
        for (c, g), vs in groups:
            by_cls[c].append((g, vs))
        clss = [c for c in CLASSES if by_cls[c]]
        for k in range(n):
            c = clss[k % len(clss)]
            g, vs = rng.choice(by_cls[c])
            m = rng.randint(8, min(24, len(vs) - 4))
            idx = rng.sample(range(len(vs)), m)
            values = [vs[i] for i in idx]
            chosen = set(idx)
            rest = [v for (cc, gg), pool in pools[split].items() if cc == c for v in pool]
            rest = [v for v in rest if v not in values]
            P = rng.sample(rest, min(P_EVAL, len(rest)))
            tasks[split].append((cid, split, c, g, values, P))
            cid += 1
    summary = {}
    for split in N_CLUSTERS:
        args = (prior_src, benign_train, "\n".join(vocab), len(vocab), benign_eval[split])
        out = []
        with Pool(6, initializer=_init, initargs=args) as pool:
            for r in pool.imap_unordered(_job, tasks[split], chunksize=8):
                if r:
                    out.append(r)
        out.sort(key=lambda r: r["id"])
        with gzip.open(os.path.join(OUT, f"rulesel_{split}.jsonl.gz"), "wt", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r, ensure_ascii=True) + "\n")
        util = lambda r, i: r["cands"][i]["util"] if i is not None else 0.0      # noqa: E731
        summary[split] = {"clusters": len(out), "by_class": dict(Counter(r["class"] for r in out)),
                          "mean_cands": round(sum(len(r["cands"]) for r in out) / max(len(out), 1), 1),
                          "oracle_util": round(sum(util(r, r["best"]) for r in out) / max(len(out), 1), 4),
                          "g2n_util": round(sum(util(r, r["g2n"]) for r in out) / max(len(out), 1), 4),
                          "g1_util": round(sum(util(r, r["g1"]) for r in out) / max(len(out), 1), 4)}
        print(f"   {split}: {summary[split]}", file=sys.stderr, flush=True)
    with open(os.path.join(OUT, "rulesel_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "seed": SEED, "max_cand": MAX_CAND, "p_eval": P_EVAL, "b_eval": B_EVAL,
                   "seconds": round(time.time() - t0)}, f, ensure_ascii=False, indent=1)
    print(f"   xong sau {time.time() - t0:.0f} s", file=sys.stderr)


if __name__ == "__main__":
    main()
