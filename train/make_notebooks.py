#!/usr/bin/env python3
"""train/make_notebooks.py — chuyển train/notebooks_src/*.py (định dạng ô '# %%') thành .ipynb và dựng thư mục
NSM-train để đẩy lên Google Drive.

    python -X utf8 -B train/make_notebooks.py [thư_mục_đích] [tiền_tố]      (mặc định: train/drive_stage/NSM-train)

`tiền_tố` (vd `01`): chỉ dựng notebook có tên bắt đầu bằng tiền tố đó và chỉ chép dữ liệu `tier2_*` (01) / `rulesel_*` (02, 03).
Tên thư mục đích khác `NSM-train` (vd `NSM-train-v3`): đường dẫn Drive trong notebook được đổi theo tên đó, để mỗi đợt dữ liệu
nằm ở một thư mục Drive riêng và không ghi đè đợt trước.

Thư mục đích:
    notebooks/   01_tier2_classifier.ipynb, 02_rule_selection_ranker_llm.ipynb
    data/        tier2_*.jsonl.gz, rulesel_*.jsonl.gz (+ *_summary.json)
    code/        feats.py, secrule.py, rulegen_ml.py (đúng mã của hệ thống), tier2_current.joblib (model hiện tại)
    README.md
"""
import glob, json, os, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "train", "notebooks_src")


# Notebook chia được cho nhiều phiên Colab chạy cùng lúc: mã nguồn có đúng dòng SHARD_LINE. Với notebook như vậy, ngoài bản
# thường còn sinh <tên>_phien<i>.ipynb (i = 1..N_SESSIONS, đặt sẵn SHARD = "i") và <tên>_gop.ipynb (SHARD = "gop").
# Mỗi phiên mở MỘT tệp riêng: mở chung một tệp ở nhiều phiên thì Colab lưu đè lên nhau.
SHARD_LINE = 'SHARD = os.environ.get("NSM_SHARD", "0")'
N_SESSIONS = 3


def to_ipynb(py_path):
    return to_ipynb_text(open(py_path, encoding="utf-8").read())


def shard_variants(text):
    """[(hậu tố tên tệp, notebook)] cho các phiên song song và bước gộp; rỗng nếu notebook không chia được."""
    if SHARD_LINE not in text:
        return []
    out = []
    for tag, val, note in ([(f"phien{i}", str(i), f"**Bản dành cho PHIÊN {i}/{N_SESSIONS}.** Mỗi phiên Colab mở một tệp "
                             f"`_phien<i>` khác nhau rồi Run all; phiên này chỉ học phần ứng viên của mình và ghi vào "
                             f"`output/tier2/parts/`. Khi cả {N_SESSIONS} phiên xong mới chạy bước gộp.")
                            for i in range(1, N_SESSIONS + 1)]
                           + [("gop", "gop", f"**Bản GỘP.** Chỉ chạy sau khi cả {N_SESSIONS} phiên `_phien<i>` đã xong: đọc "
                               f"`output/tier2/parts/`, chọn model theo đúng quy tắc của một phiên, lưu kết quả. Không cần GPU.")]):
        nb = to_ipynb_text(text.replace(SHARD_LINE, f'SHARD = "{val}"'))
        nb["cells"].insert(0, {"cell_type": "markdown", "metadata": {}, "source": [note]})
        out.append((tag, nb))
    return out


def to_ipynb_text(text):
    cells, cur, kind = [], [], None

    def flush():
        if kind is None:
            return
        lines = cur[:]
        while lines and not lines[-1].strip():
            lines.pop()
        if kind == "markdown":
            lines = [ln[2:] if ln.startswith("# ") else ln.lstrip("#") for ln in lines]
        src = [ln + "\n" for ln in lines]
        if src:
            src[-1] = src[-1].rstrip("\n")
        cell = {"cell_type": kind, "metadata": {}, "source": src}
        if kind == "code":
            cell.update(execution_count=None, outputs=[])
        cells.append(cell)

    for ln in text.splitlines():
        if ln.startswith("# %% [markdown]"):
            flush(); cur, kind = [], "markdown"
        elif ln.startswith("# %%"):
            flush(); cur, kind = [ln[4:].strip() and "# " + ln[4:].strip() or ""], "code"
            cur = [c for c in cur if c]
        else:
            cur.append(ln)
    flush()
    # Notebook dùng torch / Unsloth (02, 03) cần GPU. Notebook 01 chỉ dùng scikit-learn (CPU): KHÔNG xin GPU, để Colab không
    # mở runtime GPU vô ích; xin máy nhiều RAM ("hm" = High-RAM) vì ma trận TF-IDF 100 000 cột của ~430 000 request khá lớn.
    gpu = "import torch" in text or "unsloth" in text
    colab = {"provenance": []} if gpu else {"provenance": [], "machine_shape": "hm"}
    return {"cells": cells, "metadata": {**({"accelerator": "GPU"} if gpu else {}), "colab": colab,
                                         "kernelspec": {"display_name": "Python 3", "name": "python3"},
                                         "language_info": {"name": "python"}},
            "nbformat": 4, "nbformat_minor": 5}


DRIVE_BASE = '"/content/drive/MyDrive/NSM-train"'


def main():
    dst = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "train", "drive_stage", "NSM-train")
    prefix = sys.argv[2] if len(sys.argv) > 2 else ""
    folder = os.path.basename(os.path.normpath(dst))
    for sub in ("notebooks", "data", "code"):
        os.makedirs(os.path.join(dst, sub), exist_ok=True)
    for py in sorted(glob.glob(os.path.join(SRC, "*.py"))):
        if not os.path.basename(py).startswith(prefix):
            continue
        text = open(py, encoding="utf-8").read()
        if folder != "NSM-train":
            assert DRIVE_BASE in text, f"{py}: không thấy đường dẫn Drive để đổi"
            text = text.replace(DRIVE_BASE, f'"/content/drive/MyDrive/{folder}"')
        nb = to_ipynb_text(text)
        out = os.path.join(dst, "notebooks", os.path.basename(py)[:-3] + ".ipynb")
        json.dump(nb, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("notebook:", out, f"({len(nb['cells'])} ô)")
        for tag, nb2 in shard_variants(text):
            out2 = out[:-len(".ipynb")] + f"_{tag}.ipynb"
            json.dump(nb2, open(out2, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print("notebook:", out2, f"({len(nb2['cells'])} ô)")
    data_prefix = {"01": ("tier2_",), "02": ("rulesel_",), "03": ("rulesel_",)}.get(prefix, ("",))
    for f in glob.glob(os.path.join(ROOT, "train", "data", "*")):
        if not os.path.basename(f).startswith(data_prefix):
            continue
        t = os.path.join(dst, "data", os.path.basename(f))
        if not os.path.exists(t) or os.path.getmtime(t) < os.path.getmtime(f) or os.path.getsize(t) != os.path.getsize(f):
            shutil.copy2(f, t)
            print("data:", os.path.basename(f))
    for f in ("feats.py", "secrule.py", "rulegen_ml.py"):
        shutil.copy2(os.path.join(ROOT, "services", f), os.path.join(dst, "code", f))
    shutil.copy2(os.path.join(ROOT, "models", "tier2.joblib"), os.path.join(dst, "code", "tier2_current.joblib"))
    readme = os.path.join(ROOT, "train", "DRIVE_README.md")
    if os.path.exists(readme):
        shutil.copy2(readme, os.path.join(dst, "README.md"))
    print("xong:", dst)


if __name__ == "__main__":
    main()
