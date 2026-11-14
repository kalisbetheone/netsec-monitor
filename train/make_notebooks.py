#!/usr/bin/env python3
"""train/make_notebooks.py — chuyển train/notebooks_src/*.py (định dạng ô '# %%') thành .ipynb và dựng thư mục
NSM-train để đẩy lên Google Drive.

    python -X utf8 -B train/make_notebooks.py [thư_mục_đích]      (mặc định: train/drive_stage/NSM-train)

Thư mục đích:
    notebooks/   01_tier2_classifier.ipynb, 02_rule_selection_ranker_llm.ipynb
    data/        tier2_*.jsonl.gz, rulesel_*.jsonl.gz (+ *_summary.json)
    code/        feats.py, secrule.py, rulegen_ml.py (đúng mã của hệ thống), tier2_current.joblib (model hiện tại)
    README.md
"""
import glob, json, os, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "train", "notebooks_src")


def to_ipynb(py_path):
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

    for ln in open(py_path, encoding="utf-8").read().splitlines():
        if ln.startswith("# %% [markdown]"):
            flush(); cur, kind = [], "markdown"
        elif ln.startswith("# %%"):
            flush(); cur, kind = [ln[4:].strip() and "# " + ln[4:].strip() or ""], "code"
            cur = [c for c in cur if c]
        else:
            cur.append(ln)
    flush()
    return {"cells": cells, "metadata": {"accelerator": "GPU", "colab": {"provenance": []},
                                         "kernelspec": {"display_name": "Python 3", "name": "python3"},
                                         "language_info": {"name": "python"}},
            "nbformat": 4, "nbformat_minor": 5}


def main():
    dst = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "train", "drive_stage", "NSM-train")
    for sub in ("notebooks", "data", "code"):
        os.makedirs(os.path.join(dst, sub), exist_ok=True)
    for py in sorted(glob.glob(os.path.join(SRC, "*.py"))):
        nb = to_ipynb(py)
        out = os.path.join(dst, "notebooks", os.path.basename(py)[:-3] + ".ipynb")
        json.dump(nb, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("notebook:", out, f"({len(nb['cells'])} ô)")
    for f in glob.glob(os.path.join(ROOT, "train", "data", "*")):
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
