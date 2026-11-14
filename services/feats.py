"""Đặc trưng tầng 2 — PHẢI khớp build_dataset_run4.feats() + train_tier2 (text).
Dùng chung cho classifier (serve) để train-serve skew = 0. Không dùng pandas."""
import math, collections, re
from urllib.parse import unquote_plus

# 21 cột numeric (đúng thứ tự NUM trong train_tier2)
NUM = ["f_uri_len", "f_query_len", "f_body_len", "f_path_depth", "f_n_params",
       "f_n_digits", "f_n_alpha", "f_n_special", "f_pct_special", "f_entropy",
       "f_n_nonascii", "f_has_quote", "f_has_dquote", "f_has_angle", "f_has_paren",
       "f_has_semicolon", "f_has_backtick", "f_has_dotdot", "f_has_pct",
       "f_has_pipe", "f_has_space"]

SPECIAL = set("'\"<>(){}[];|&$`=/\\%*:")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_N = re.compile(r"\d+")
_BTN = re.compile(r"\b(?:submit|login|sign|change)\b", re.I)

def values_only(s):
    out = []
    for p in str(s).split("&"):
        if p:
            out.append(p.split("=", 1)[1] if "=" in p else p)
    return " ".join(out)

def normalize(s):
    return _BTN.sub(" ", _N.sub("<N>", _IP.sub(" <IP> ", s)))

def _entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s); n = len(s)
    return round(-sum((v/n) * math.log2(v/n) for v in c.values()), 4)

def make_text(query, body):
    """_text cho TF-IDF: values_only(query_dec) + values_only(unquote(body)) -> normalize."""
    qdec = unquote_plus(query or "")
    b = body or ""; b = "" if b == "-" else b
    return normalize(values_only(qdec) + " " + values_only(unquote_plus(b)))[:2000]

def make_feats(uri, query, body):
    """21 đặc trưng numeric, khớp build_dataset_run4.feats()."""
    q = unquote_plus(query or "")
    b = body or ""; b = "" if b == "-" else b
    bdec = unquote_plus(b); uri = uri or ""; tgt = q + " " + bdec
    nsp = sum(ch in SPECIAL for ch in tgt)
    return {"f_uri_len": len(uri), "f_query_len": len(q), "f_body_len": len(bdec),
            "f_path_depth": uri.count("/"), "f_n_params": (q.count("&")+1) if q else 0,
            "f_n_digits": sum(ch.isdigit() for ch in tgt), "f_n_alpha": sum(ch.isalpha() for ch in tgt),
            "f_n_special": nsp, "f_pct_special": round(nsp/max(len(tgt), 1), 4), "f_entropy": _entropy(tgt),
            "f_n_nonascii": sum(ord(ch) > 127 for ch in tgt), "f_has_quote": "'" in tgt, "f_has_dquote": '"' in tgt,
            "f_has_angle": "<" in tgt or ">" in tgt, "f_has_paren": "(" in tgt or ")" in tgt,
            "f_has_semicolon": ";" in tgt, "f_has_backtick": "`" in tgt, "f_has_dotdot": ".." in tgt,
            "f_has_pct": "%" in (query or ""), "f_has_pipe": "|" in tgt, "f_has_space": " " in q}
