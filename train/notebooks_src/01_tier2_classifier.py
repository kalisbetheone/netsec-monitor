# %% [markdown]
# # 01 — Huấn luyện lại tầng 2 của classifier NSM
#
# **Mục tiêu:** thay `models/tier2.joblib` (đang báo nhầm ~40 % lưu lượng lành tính thật, bỏ sót ~50 % SQLi của SR-BH) bằng
# một model **thay vào được ngay**, không phải sửa mã classifier: cùng dạng tệp `{"vectorizer", "clf", "num_cols"}`, `clf` có
# `predict_proba`, `classes_` và `coef_`, đặc trưng tính bằng **đúng** `feats.py` của hệ thống.
#
# **Dữ liệu** (`data/tier2_*.jsonl.gz`, dựng bằng `train/build_tier2_dataset.py`):
#
# | Tập | Lành tính | Tấn công | Dùng để |
# |---|---|---|---|
# | train | 285.802 request thật của 253 website | 60.000 payload **cấy** vào request lành tính thật | huấn luyện |
# | valid | 70.507 (63 website khác) | 12.000 cấy (họ payload khác) | chọn model, chọn ngưỡng |
# | test_sites | 390.309 (322 website chưa thấy) | — | báo nhầm trên website lạ |
# | test_srbh | 90.893 | 203.173 tấn công THẬT từ Internet (79 % chỉ nằm ở đường dẫn — tầng 2 không đọc đường dẫn, xem cột `_args`) | kiểm tra độc lập 1 |
# | test_httpparams | 19.304 | 11.763 | kiểm tra độc lập 2 |
#
# **Tiêu chí chọn (chốt trước khi chạy):** trên **valid**, model tốt nhất là model phát hiện được nhiều tấn công nhất trong
# khi tầng 2 chỉ được thêm tối đa **0,1 %** báo nhầm trên lành tính. Tập test chỉ dùng để báo cáo, không dùng để chọn.
#
# **Runtime:** CPU là đủ (nên bật *High-RAM*). Khoảng 2–3 giờ.

# %%
# ---- 0. Cấu hình và đường dẫn ----
import os, sys, json, time, math, gzip, copy, random
IN_COLAB = "google.colab" in sys.modules
SMOKE = os.environ.get("NSM_SMOKE") == "1"          # chạy thử nhanh trên máy cục bộ với một phần dữ liệu
FAST = os.environ.get("NSM_FAST") == "1"            # đủ dữ liệu nhưng chỉ M2 (C=1) + M3, bỏ M1 và XGBoost (chạy trên máy)
if IN_COLAB:
    from google.colab import drive
    drive.mount("/content/drive")
    BASE = "/content/drive/MyDrive/NSM-train"
else:
    BASE = os.environ.get("NSM_TRAIN_BASE", os.path.abspath("."))
DATA, CODE = f"{BASE}/data", f"{BASE}/code"
OUTD = f"{BASE}/output/tier2" + ("_smoke" if SMOKE else "")
os.makedirs(OUTD, exist_ok=True)
sys.path.insert(0, CODE)
print("BASE =", BASE, "| SMOKE =", SMOKE)

# ---- Chia việc cho nhiều phiên Colab chạy cùng lúc (thêm 15/11/2026) ----
# "0"        : một phiên làm hết, như trước.
# "1".."N"   : phiên song song thứ mấy trong N_SHARDS phiên. Mỗi phiên học phần ứng viên của mình rồi ghi model và số đo
#              vào output/tier2/parts/<tên ứng viên>.joblib + .json (mỗi ứng viên một tệp riêng nên các phiên không ghi đè nhau).
# "gop"      : không học gì; đọc mọi tệp trong parts/, chọn model theo ĐÚNG quy tắc của một phiên, rồi lưu kết quả như trước.
# Các notebook 01_tier2_classifier_phien<i>.ipynb do make_notebooks.py sinh ra chỉ khác đúng dòng SHARD dưới đây.
SHARD = os.environ.get("NSM_SHARD", "0")
N_SHARDS = int(os.environ.get("NSM_N_SHARDS", "3"))
MERGE = SHARD == "gop"
FINAL = SHARD == "0" or MERGE                       # phiên này có chọn model và lưu kết quả cuối không
PARTS = f"{OUTD}/parts"
os.makedirs(PARTS, exist_ok=True)
print("SHARD =", SHARD, "/", N_SHARDS, "| số CPU:", os.cpu_count())

# %% [markdown]
# ## 1. Phiên bản thư viện
# Model sẽ được nạp trong container classifier với **scikit-learn 1.6.1, numpy 2.0.2, scipy 1.13.1**
# (`services/requirements.txt`). Tệp joblib tạo bằng phiên bản khác có thể không nạp được.
# Trên Colab: chạy ô cài đặt dưới, rồi **Runtime → Restart session**, rồi chạy lại từ ô 0.

# %%
if IN_COLAB:
    import sklearn
    if sklearn.__version__ != "1.6.1":
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "-q", "install", "scikit-learn==1.6.1", "numpy==2.0.2", "scipy==1.13.1"],
                       check=True)
        print(">> ĐÃ CÀI. Hãy Runtime → Restart session rồi chạy lại từ ô 0.")

# %%
import numpy as np, scipy, sklearn, joblib
from scipy.sparse import hstack, csr_matrix
print("scikit-learn", sklearn.__version__, "| numpy", np.__version__, "| scipy", scipy.__version__)
assert sklearn.__version__ == "1.6.1", "Cần scikit-learn 1.6.1 để classifier nạp được model (xem ô trên)."
from feats import make_text, make_feats, NUM          # ĐÚNG mã đặc trưng của hệ thống (services/feats.py)
import re
META = re.compile(r"""['"<>()=;|`$*\\{}#&%!^~\[\]]|\.\.|--|/\*""")   # = classifier.META (cổng cú pháp)
CLASSES = ["benign", "lfi", "rce", "sqli", "xss"]
RNG = np.random.default_rng(20261112)

# %%
# ---- 2. Nạp dữ liệu (chép từ Drive sang ổ cục bộ của máy Colab cho nhanh) ----
LOCAL = "/content/nsm-data" if IN_COLAB else DATA
if IN_COLAB and not os.path.exists(LOCAL):
    os.system(f'cp -r "{DATA}" "{LOCAL}"')

def load(name, limit=None):
    out = []
    with gzip.open(f"{LOCAL}/tier2_{name}.jsonl.gz", "rt", encoding="utf-8") as f:
        for i, ln in enumerate(f):
            out.append(json.loads(ln))
    if limit and len(out) > limit:
        idx = RNG.choice(len(out), limit, replace=False)
        out = [out[i] for i in sorted(idx)]
    return out

LIM = {"train": 30000, "valid": 10000, "test_sites": 10000, "test_srbh": 10000, "test_httpparams": 5000} if SMOKE else {}
# test_freetext: câu Tatoeba CHƯA thấy cấy vào website chưa thấy; test_scenario_text: câu tự viết của khung kịch bản
# (chỉ để kiểm tra, không dùng chọn model). Hai tập này có từ 14/11/2026.
# test_hardtext (văn bản hợp lệ "khó") và test_residual (tấn công thật của SR-BH mà Cổng 2 để lọt) có từ đợt cải thiện tầng 2
# 15/11/2026 (train/t2_hard_benign.py, train/t2_pool.py). V2 = dữ liệu có các cờ g2 / hard -> đổi danh sách ứng viên và tiêu chí chọn.
TESTS = [k for k in ("test_sites", "test_srbh", "test_httpparams", "test_freetext", "test_scenario_text", "test_hardtext", "test_residual")
         if os.path.exists(f"{LOCAL}/tier2_{k}.jsonl.gz")]
V2 = "test_hardtext" in TESTS
print("dữ liệu đợt cải thiện tầng 2 (V2):", V2)
D = {k: load(k, LIM.get(k)) for k in (["valid"] if MERGE else ["train", "valid"] + TESTS)}   # gộp: chỉ cần valid để đo độ trễ
for k, v in D.items():
    from collections import Counter
    print(f"{k:16} {len(v):8}", dict(Counter(r["ds_class"] for r in v)))

# %%
# ---- 3. Đặc trưng: ĐÚNG như classifier tính khi chạy thật ----
# classifier gọi make_text(ev["query"], ev["body"]) và make_feats(ev["uri"], ev["query"], ev["body"]), trong đó
# ev["query"] là %q của Apache: CÓ dấu '?' ở đầu khi khác rỗng. Bỏ quên chi tiết này là lệch train/serve.
def featurize(rows):
    texts, nums = [], np.zeros((len(rows), len(NUM)), dtype=np.float64)
    for i, r in enumerate(rows):
        q = ("?" + r["query"]) if r["query"] else ""
        texts.append(make_text(q, r["body"]))
        f = make_feats(r["uri"], q, r["body"])
        nums[i] = [float(f[c]) for c in NUM]
    y = np.array([r["ds_class"] for r in rows])
    t1 = np.array([r["t1"] != "benign" for r in rows])        # tầng 1 (regex) đã bắt -> tầng 2 không chạy
    gate = np.array([bool(r["gate"]) for r in rows])          # cổng cú pháp (TIER2_SYNTAX_GATE=1)
    # vị trí payload: 'args' (có query/thân) hoặc 'path_only' (chỉ đường dẫn — tầng 2 KHÔNG đọc đường dẫn, chỉ
    # regex tầng 1 bắt được). 79 % tấn công của SR-BH là path_only nên phải báo cáo tách riêng.
    loc = np.array([r.get("loc", "args") for r in rows])
    nul = np.array([bool(r.get("nul")) for r in rows])        # thân có byte rỗng (lỗi C7: hệ thống thật cắt thân)
    free = np.array([str(r.get("source", "")).startswith(("inject:tatoeba", "inject:scenario")) for r in rows])
    g2p = np.array([r.get("g2") == "pass" for r in rows])     # payload LỌT Cổng 2 thật: phần duy nhất tầng 2 có giá trị riêng
    hard = np.array([bool(r.get("hard")) for r in rows])      # văn bản hợp lệ "khó" (từ khoá SQL / lệnh shell, ký hiệu)
    return texts, nums, y, t1, gate, loc, nul, free, g2p, hard

t0 = time.time()
F = {} if MERGE else {k: featurize(v) for k, v in D.items()}
print(f"tính đặc trưng: {time.time() - t0:.0f} s")

# %% [markdown]
# ## 4. Đánh giá theo đúng luồng quyết định của classifier
# Một request bị coi là tấn công nếu: tầng 1 bắt được, **hoặc** (cổng cú pháp mở **và** tầng 2 vượt ngưỡng θ).
# Tầng 2 có hai cách quyết định (`TIER2_DECISION`): `argmax` (lớp tấn công có xác suất cao nhất phải là lớp lớn nhất và ≥ θ)
# và `mass` (1 − P(benign) ≥ θ).

# %%
def tier2_scores(proba, classes):
    bi = classes.index("benign")
    att = [i for i in range(len(classes)) if i != bi]
    top = np.array(att)[proba[:, att].argmax(1)]
    p_top = proba[np.arange(len(proba)), top]
    argmax_score = np.where(proba.argmax(1) == top, p_top, 0.0)
    mass_score = 1.0 - proba[:, bi]
    return {"argmax": argmax_score, "mass": mass_score}, np.array(classes)[top]

def system_flags(F_k, scores, decision, theta, use_gate):
    y, t1, gate = F_k[2], F_k[3], F_k[4]
    t2 = scores[decision] >= theta
    if use_gate:
        t2 = t2 & gate
    return t1 | t2, t2 & ~t1

def report(F_k, scores, decision, theta, use_gate):
    y, loc, nul = F_k[2], F_k[5], F_k[6]
    flag, t2only = system_flags(F_k, scores, decision, theta, use_gate)
    ben = y == "benign"
    out = {"n_benign": int(ben.sum()),
           "fpr_system": float(flag[ben].mean()) if ben.any() else None,
           "fpr_tier2_added": float(t2only[ben].mean()) if ben.any() else None}
    for c in ("sqli", "xss", "lfi", "rce"):
        m = y == c
        if m.any():
            out[f"det_{c}"] = float(flag[m].mean())
            out[f"n_{c}"] = int(m.sum())
    att = ~ben
    if att.any():
        out["det_all"] = float(flag[att].mean())
        out["det_tier2_added"] = float(t2only[att].mean())
        # tách theo vị trí payload: chỉ phần 'args' đo được tác dụng của tầng 2
        for L in ("args", "path_only"):
            m = att & (loc == L)
            if m.any() and m.sum() != att.sum():
                out[f"det_all_{L}"] = float(flag[m].mean()); out[f"n_att_{L}"] = int(m.sum())
                ms = m & (y == "sqli")
                if ms.any():
                    out[f"det_sqli_{L}"] = float(flag[ms].mean()); out[f"n_sqli_{L}"] = int(ms.sum())
    g2p, hard = F_k[8], F_k[9]
    if (att & g2p).any():                                     # phát hiện trên payload lọt Cổng 2; tách phần tầng 2 tự bắt
        m = att & g2p
        out["det_residual"] = float(flag[m].mean()); out["det_residual_tier2"] = float(t2only[m].mean()); out["n_residual"] = int(m.sum())
        per = []
        for c in ("sqli", "xss", "lfi", "rce"):
            mc = m & (y == c)
            if mc.any():
                out[f"det_residual_{c}"] = float(flag[mc].mean()); out[f"n_residual_{c}"] = int(mc.sum())
                per.append(out[f"det_residual_{c}"])
        out["det_residual_macro"] = float(np.mean(per))        # trung bình ĐỀU theo lớp: LFI có hàng nghìn payload lọt, lớp khác vài chục
    if (ben & hard).any():                                    # báo nhầm riêng trên văn bản hợp lệ "khó"
        out["fpr_hard_system"] = float(flag[ben & hard].mean()); out["fpr_hard_tier2_added"] = float(t2only[ben & hard].mean())
        out["n_hard"] = int((ben & hard).sum())
    free = F_k[7]
    if (ben & free).any():                                    # báo nhầm riêng trên văn bản tự do (câu người gõ)
        out["fpr_free_system"] = float(flag[ben & free].mean()); out["fpr_free_tier2_added"] = float(t2only[ben & free].mean())
        out["n_free"] = int((ben & free).sum())
    if (ben & nul).any():                                     # báo nhầm riêng trên thân có byte rỗng
        out["fpr_system_nul_body"] = float(flag[ben & nul].mean()); out["n_benign_nul_body"] = int((ben & nul).sum())
    return out

def objective(r):
    """Điều cần tối đa khi chọn: phát hiện trên payload LỌT Cổng 2, trung bình đều theo lớp (nếu dữ liệu có cờ đó), rồi mới
    tới phát hiện chung. Dữ liệu cũ không có cờ -> cả hai phần đều là phát hiện chung, tức đúng tiêu chí trước 15/11."""
    return (r.get("det_residual_macro", r["det_all"]), r["det_all"])

def pick_threshold(F_valid, scores, decision, use_gate, budget=0.001, budget_free=0.002, budget_hard=0.05):
    """θ cho mục tiêu cao nhất mà tầng 2 chỉ thêm <= budget báo nhầm trên lành tính của valid, <= budget_free trên văn bản tự
    do của valid (câu người gõ — thêm 14/11/2026, vì model trước khoá người dùng ở kịch bản 02) VÀ <= budget_hard trên văn
    bản hợp lệ "khó" của valid (thêm 15/11/2026; dữ liệu cũ không có loại này thì ràng buộc không có tác dụng)."""
    best = None
    for theta in np.round(np.concatenate([np.arange(0.50, 0.95, 0.01), np.arange(0.95, 0.9995, 0.001)]), 4):
        r = report(F_valid, scores, decision, theta, use_gate)
        if (r["fpr_tier2_added"] <= budget and r.get("fpr_free_tier2_added", 0.0) <= budget_free
                and r.get("fpr_hard_tier2_added", 0.0) <= budget_hard):
            if best is None or objective(r) > objective(best[1]):
                best = (float(theta), r)
    return best

# %%
# ---- 5. Model hiện tại (baseline) — chạy y như cấu hình trong docker-compose ----
# Dữ liệu V2 (15/11/2026): model 14/11 đang chạy với argmax, θ = 0,67, cổng cú pháp TẮT. Dữ liệu cũ: giữ cấu hình của lần
# huấn luyện trước (argmax, θ = 0,90, cổng bật) để bảng cũ tái lập được.
CUR_DEC, CUR_THETA, CUR_GATE = ("argmax", 0.67, False) if V2 else ("argmax", 0.90, True)
cur = joblib.load(f"{CODE}/tier2_current.joblib")
def proba_of(model, F_k):
    texts, nums = F_k[0], F_k[1]
    X = hstack([model["vectorizer"].transform(texts), csr_matrix(nums[:, [NUM.index(c) for c in model["num_cols"]]])]).tocsr()
    return model["clf"].predict_proba(X)

RESULTS = {}
BASELINE_PATH = f"{PARTS}/_baseline.json"
if SHARD in ("0", "1"):                                 # chia phiên: chỉ phiên 1 đo model hiện tại (mọi phiên sẽ ra cùng số)
    cur_cls = [str(c) for c in cur["clf"].classes_]
    S_cur = {k: tier2_scores(proba_of(cur, F[k]), cur_cls)[0] for k in F}
    RESULTS["M0_hien_tai"] = {k: report(F[k], S_cur[k], CUR_DEC, CUR_THETA, CUR_GATE) for k in F}
    RESULTS["M0_hien_tai"]["_config"] = {"decision": CUR_DEC, "gate": CUR_GATE, "theta": CUR_THETA}
    for k, v in RESULTS["M0_hien_tai"].items():
        print(k, {a: (round(b, 4) if isinstance(b, float) else b) for a, b in v.items()})
    # (tuỳ chọn) model huấn luyện lại LẦN TRƯỚC (12/11, chưa có văn bản tự do): NSM_PREV_MODEL=<đường dẫn joblib>,
    # chạy đúng cấu hình đã triển khai (mass, θ 0,87, cổng tắt) — để thấy tác dụng của dữ liệu văn bản tự do
    if os.environ.get("NSM_PREV_MODEL"):
        prev = joblib.load(os.environ["NSM_PREV_MODEL"])
        S_prev = {k: tier2_scores(proba_of(prev, F[k]), [str(c) for c in prev["clf"].classes_])[0] for k in F}
        RESULTS["M_truoc_12_11"] = {k: report(F[k], S_prev[k], "mass", 0.87, False) for k in F}
        for k in TESTS + ["valid"]:
            print("model 12/11:", k, {a: (round(b, 4) if isinstance(b, float) else b) for a, b in RESULTS["M_truoc_12_11"][k].items()
                                     if a.startswith(("fpr", "det_all", "n_free"))})
    if SHARD == "1":
        with open(BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump(RESULTS, f, ensure_ascii=False, indent=1, default=float)
elif MERGE and os.path.exists(BASELINE_PATH):
    RESULTS.update(json.load(open(BASELINE_PATH, encoding="utf-8")))
    print("đọc số đo của model hiện tại từ", BASELINE_PATH)
else:
    print("phiên", SHARD, ": bỏ qua phần đo model hiện tại (phiên 1 làm)")

# %% [markdown]
# ## 6. Huấn luyện các ứng viên (đều thay vào classifier được ngay)
#
# | Ký hiệu | Đặc trưng văn bản | Bộ phân loại | Ghi chú |
# |---|---|---|---|
# | M1 | như model hiện tại (`char_wb` 2–4, 4.000 đặc trưng) | LogisticRegression C=1 | cùng công thức, chỉ đổi dữ liệu |
# | M2 | `char_wb` 1–5, tới 100.000 đặc trưng, sublinear tf | LogisticRegression, cân bằng lớp, C chọn trên valid | đặc trưng số được chuẩn hoá khi học rồi **gập** hệ số chuẩn hoá vào `coef_` |
# | M3 | như M2 | SGDClassifier (modified Huber, elastic-net) | nhanh, thưa |
#
# Model "gập chuẩn hoá": học trên đặc trưng số đã chia cho giá trị tuyệt đối lớn nhất, sau đó chia hệ số tương ứng
# cho đúng số đó. Kết quả là một `LogisticRegression` bình thường nhận đặc trưng THÔ như classifier đang đưa vào.

# %%
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier

def fit_text(spec, texts):
    vec = TfidfVectorizer(analyzer="char_wb", dtype=np.float64, **spec)
    return vec, vec.fit_transform(texts)

def fold_scaling(clf, scale):
    """clf học trên [tfidf | số/scale] -> trả bản sao nhận [tfidf | số thô]."""
    out = copy.deepcopy(clf)
    out.coef_ = out.coef_.copy()
    out.coef_[:, -len(scale):] = out.coef_[:, -len(scale):] / scale
    return out

def train_model(name, text_spec, make_clf, scale_numeric, weight=1.0):
    """weight > 1: dòng "payload lọt Cổng 2" và dòng "văn bản hợp lệ khó" được tính nặng gấp `weight` lần khi học."""
    t0 = time.time()
    texts, nums, y = F["train"][0], F["train"][1], F["train"][2]
    vec, Xt = fit_text(text_spec, texts)
    scale = np.maximum(np.abs(nums).max(0), 1.0) if scale_numeric else np.ones(len(NUM))
    X = hstack([Xt, csr_matrix(nums / scale)]).tocsr()
    sw = np.where(F["train"][8] | F["train"][9], float(weight), 1.0) if weight != 1.0 else None
    clf = make_clf().fit(X, y, sample_weight=sw)
    clf = fold_scaling(clf, scale) if scale_numeric else clf
    model = {"vectorizer": vec, "clf": clf, "num_cols": list(NUM)}
    print(f"{name}: {X.shape[1]} đặc trưng, học {time.time() - t0:.0f} s")
    return model

# Danh sách ứng viên theo THỨ TỰ CỐ ĐỊNH (thứ tự này quyết định ứng viên nào được chọn khi hoà điểm, và phiên nào học gì)
TEXT_BIG = {"ngram_range": (1, 5), "min_df": 3, "max_features": 100000, "sublinear_tf": True}
def _m2(C=1.0):
    return lambda: LogisticRegression(C=C, class_weight="balanced", max_iter=3000, n_jobs=-1)
def _m3():
    return SGDClassifier(loss="modified_huber", penalty="elasticnet", alpha=2e-6, l1_ratio=0.15,
                         class_weight="balanced", max_iter=30, tol=1e-4, random_state=0)
SPECS = {}
if V2:
    # Đợt cải thiện tầng 2: hai model tuyến tính × trọng số của dòng "lọt Cổng 2" và "hợp lệ khó". 6 ứng viên = 2 ứng viên / phiên
    # khi chia 3 phiên (mỗi phiên một M2 và một M3). Chạy thử nhanh: 3 ứng viên.
    for w, kinds in (((1, "23"), (3, "3")) if (SMOKE or FAST) else ((1, "23"), (3, "23"), (10, "23"))):
        if "2" in kinds:
            SPECS[f"M2_lr_C1.0_w{w}"] = (TEXT_BIG, _m2(1.0), True, float(w))
        if "3" in kinds:
            SPECS[f"M3_sgd_w{w}"] = (TEXT_BIG, _m3, True, float(w))
else:
    if not FAST:
        SPECS["M1_cong_thuc_cu"] = ({"ngram_range": (2, 4), "min_df": 5, "max_features": 4000},
                                    lambda: LogisticRegression(C=1.0, max_iter=2000, n_jobs=-1), False)
    for C in ([1.0] if (SMOKE or FAST) else [0.3, 1.0, 3.0]):
        SPECS[f"M2_lr_C{C}"] = (TEXT_BIG, _m2(C), True)
    SPECS["M3_sgd"] = (TEXT_BIG, _m3, True)
NAMES = list(SPECS)
if SHARD == "0":
    MINE = NAMES
elif MERGE:
    MINE = []
else:
    assert SHARD.isdigit() and 1 <= int(SHARD) <= N_SHARDS, f"SHARD phải là 0, gop hoặc 1..{N_SHARDS}"
    MINE = [n for i, n in enumerate(NAMES) if i % N_SHARDS == int(SHARD) - 1]
print("mọi ứng viên:", NAMES, "\nphiên này học:", MINE)
TRAIN_S = {}
CANDIDATES = {}
for name in MINE:
    t0 = time.time()
    CANDIDATES[name] = train_model(name, *SPECS[name])
    TRAIN_S[name] = round(time.time() - t0)

# %%
# ---- 7. Chọn model và ngưỡng trên VALID (không nhìn tập test) ----
SCORES = {}
SEL = {}            # (ứng viên, cách quyết định, cổng) -> (θ, số đo trên valid)
REPORTS = {}        # (ứng viên, cách quyết định, cổng) -> {tập: số đo} ở đúng θ đã chọn trên valid
OPTIONS = [(d, g) for d in ("argmax", "mass") for g in (True, False)]

def show_sel(name, decision, gate, p):
    r = p[1]
    extra = (f", lọt Cổng 2 (TB theo lớp) {r['det_residual_macro']:.4f}, hợp lệ khó {r.get('fpr_hard_tier2_added', float('nan')):.4f}"
             if "det_residual_macro" in r else "")
    print(f"{name:18} {decision:6} cổng={'bật' if gate else 'tắt'}  θ={p[0]:.3f}  "
          f"valid: phát hiện {r['det_all']:.4f}, tầng 2 thêm báo nhầm {r['fpr_tier2_added']:.5f}{extra}")

for name, model in CANDIDATES.items():
    classes = [str(c) for c in model["clf"].classes_]
    SCORES[name] = {k: tier2_scores(proba_of(model, F[k]), classes)[0] for k in F}
    for decision, gate in OPTIONS:
        p = pick_threshold(F["valid"], SCORES[name]["valid"], decision, gate)
        if p:
            SEL[(name, decision, gate)] = p
            REPORTS[(name, decision, gate)] = {k: report(F[k], SCORES[name][k], decision, p[0], gate) for k in F}
            show_sel(name, decision, gate, p)
    if SHARD != "0":                                    # chia phiên: ghi phần của ứng viên này (tệp .json ghi SAU CÙNG = dấu "đã xong")
        joblib.dump(model, f"{PARTS}/{name}.joblib", compress=3)
        part = {"name": name, "shard": SHARD, "train_seconds": TRAIN_S.get(name), "smoke": SMOKE, "n_train": len(D["train"]),
                "options": [{"decision": d, "gate": g, "theta": SEL[(name, d, g)][0], "valid": SEL[(name, d, g)][1],
                             "report": REPORTS[(name, d, g)]} for d, g in OPTIONS if (name, d, g) in SEL]}
        with open(f"{PARTS}/{name}.json", "w", encoding="utf-8") as f:
            json.dump(part, f, ensure_ascii=False, indent=1, default=float)
        print("   đã ghi", f"{PARTS}/{name}.json")

if MERGE:                                               # đọc phần của mọi phiên, theo đúng thứ tự NAMES
    missing = [n for n in NAMES if not os.path.exists(f"{PARTS}/{n}.json")]
    assert not missing, f"chưa đủ kết quả để gộp — thiếu: {missing} (phiên học các ứng viên này chưa chạy xong)"
    for name in NAMES:
        part = json.load(open(f"{PARTS}/{name}.json", encoding="utf-8"))
        assert part["smoke"] == SMOKE, f"{name}: phần này được học ở chế độ khác (smoke={part['smoke']})"
        TRAIN_S[name] = part.get("train_seconds")
        for o in part["options"]:
            key = (name, o["decision"], bool(o["gate"]))
            SEL[key] = (o["theta"], o["valid"]); REPORTS[key] = o["report"]
            show_sel(name, o["decision"], bool(o["gate"]), SEL[key])

if FINAL:
    best_key = max(SEL, key=lambda k: (*objective(SEL[k][1]), -SEL[k][1]["fpr_system"]))
    BEST_NAME, BEST_DEC, BEST_GATE = best_key
    BEST_THETA = SEL[best_key][0]
    print("\n>> CHỌN:", BEST_NAME, "| TIER2_DECISION =", BEST_DEC, "| TIER2_SYNTAX_GATE =", int(BEST_GATE),
          "| TIER2_THRESHOLD =", BEST_THETA)
else:
    print(f"\nPhiên {SHARD}/{N_SHARDS} xong phần của mình. Khi cả {N_SHARDS} phiên xong: chạy bước gộp (SHARD = 'gop').")

# %%
# ---- 8. Báo cáo trên các tập TEST (chỉ báo cáo; đã chọn xong ở bước 7) ----
def fmt(r):
    return {a: (round(b, 4) if isinstance(b, float) else b) for a, b in r.items()}
if FINAL:
    for name in NAMES:
        RESULTS[name] = {}
        key = (name, BEST_DEC, BEST_GATE)
        if key in SEL:
            RESULTS[name] = dict(REPORTS[key])
            RESULTS[name]["_config"] = {"decision": BEST_DEC, "gate": BEST_GATE, "theta": SEL[key][0]}
    if "M0_hien_tai" in RESULTS:
        print(f"Model hiện tại ({CUR_DEC}, θ={CUR_THETA}, cổng={'bật' if CUR_GATE else 'tắt'}):")
        for k in TESTS:
            print("  ", k, fmt(RESULTS["M0_hien_tai"][k]))
    print(f"\nModel chọn {BEST_NAME} ({BEST_DEC}, θ={BEST_THETA}, cổng={'bật' if BEST_GATE else 'tắt'}):")
    for k in TESTS:
        print("  ", k, fmt(RESULTS[BEST_NAME][k]))

# %% [markdown]
# ## 9. Nghiên cứu thêm (không thay vào hệ thống ngay): gradient boosting
# Đo **trần** có thể đạt được với một model phi tuyến: XGBoost trên [đặc trưng số + 256 chiều SVD của TF-IDF].
# Model này không có `coef_` nên không thay trực tiếp vào classifier; chỉ dùng để biết model tuyến tính còn cách trần bao xa.

# %%
RUN_GBM = not SMOKE and not FAST and SHARD == "0"       # chia phiên: bỏ phần nghiên cứu này (cần model và dữ liệu trong cùng phiên)
if RUN_GBM:
    import xgboost as xgb
    from sklearn.decomposition import TruncatedSVD
    vec = CANDIDATES[BEST_NAME]["vectorizer"]
    svd = TruncatedSVD(256, random_state=0)
    sub = RNG.choice(len(F["train"][0]), min(150000, len(F["train"][0])), replace=False)
    svd.fit(vec.transform([F["train"][0][i] for i in sub]))
    def dense(k):
        return np.hstack([svd.transform(vec.transform(F[k][0])), F[k][1]])
    lab = {c: i for i, c in enumerate(CLASSES)}
    ytr = np.array([lab[c] for c in F["train"][2]])
    cnt = np.bincount(ytr, minlength=len(CLASSES))
    w = len(ytr) / (len(CLASSES) * cnt[ytr])                      # cân bằng lớp như class_weight="balanced"
    gbm = xgb.XGBClassifier(n_estimators=600, max_depth=8, learning_rate=0.08, subsample=0.8, colsample_bytree=0.8,
                            tree_method="hist", device="cuda" if os.environ.get("COLAB_GPU") else "cpu", n_jobs=-1)
    gbm.fit(dense("train"), ytr, sample_weight=w)
    S_gbm = {k: tier2_scores(gbm.predict_proba(dense(k)), CLASSES)[0] for k in F}
    p = pick_threshold(F["valid"], S_gbm["valid"], BEST_DEC, BEST_GATE)
    RESULTS["M4_xgboost_nghien_cuu"] = {k: report(F[k], S_gbm[k], BEST_DEC, p[0], BEST_GATE) for k in F}
    RESULTS["M4_xgboost_nghien_cuu"]["_config"] = {"decision": BEST_DEC, "gate": BEST_GATE, "theta": p[0]}
    for k in TESTS:
        print("XGBoost", k, fmt(RESULTS["M4_xgboost_nghien_cuu"][k]))

# %%
# ---- 10. Độ trễ khi chạy thật: MỘT request một lần, như classifier gọi ----
if FINAL:
    best = joblib.load(f"{PARTS}/{BEST_NAME}.joblib") if MERGE else CANDIDATES[BEST_NAME]
    sample = D["valid"][:2000]
    t0 = time.perf_counter()
    for r in sample:
        q = ("?" + r["query"]) if r["query"] else ""
        xt = best["vectorizer"].transform([make_text(q, r["body"])])
        f = make_feats(r["uri"], q, r["body"])
        X = hstack([xt, csr_matrix([[float(f[c]) for c in best["num_cols"]]])]).tocsr()
        best["clf"].predict_proba(X)
    lat_ms = (time.perf_counter() - t0) / len(sample) * 1000
    print(f"độ trễ trung bình: {lat_ms:.3f} ms/request (model hiện tại cần < ~1 ms để theo kịp ~400 request/giây)")

# %%
# ---- 11. Lưu model và kết quả ----
if FINAL:
    meta = {"trained_at": time.strftime("%Y-%m-%d %H:%M:%S"), "name": BEST_NAME, "sklearn": sklearn.__version__,
            "decision": BEST_DEC, "syntax_gate": BEST_GATE, "threshold": BEST_THETA, "latency_ms": round(lat_ms, 3),
            "smoke": SMOKE, "v2": V2,
            "selection": ("max valid detection on Gate-2-passing payloads (macro average over classes), then overall; tier-2 added FPR <= 0.1% on valid benign, "
                          "<= 0.2% on free text, <= 5% on hard benign text") if V2
                         else "max valid detection with tier-2 added FPR <= 0.1% on valid benign",
            "shards": N_SHARDS if MERGE else 1, "train_seconds": TRAIN_S}
    out_model = {"vectorizer": best["vectorizer"], "clf": best["clf"], "num_cols": best["num_cols"], "meta": meta}
    joblib.dump(out_model, f"{OUTD}/tier2_new.joblib", compress=3)
    with open(f"{OUTD}/metrics.json", "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "results": RESULTS,
                   "selection_table": {f"{n}|{d}|gate={g}": {"theta": t, **r} for (n, d, g), (t, r) in SEL.items()}},
                  f, ensure_ascii=False, indent=1, default=float)
    env = (f"TIER2_THRESHOLD: \"{BEST_THETA}\"\nTIER2_DECISION: \"{BEST_DEC}\"\nTIER2_SYNTAX_GATE: \"{int(BEST_GATE)}\"\n")
    open(f"{OUTD}/docker-compose-env.txt", "w").write(env)
    print("Đã lưu vào", OUTD)
    print(env)
    print("Cách dùng: chép tier2_new.joblib thành nsm/models/tier2.joblib, đặt 3 biến trên cho dịch vụ classifier "
          "trong docker-compose.yml, rồi `docker compose up -d --build classifier`.")
