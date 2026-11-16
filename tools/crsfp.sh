#!/usr/bin/env bash
# tools/crsfp.sh — LUẬT CRS NÀO CHẶN NHẦM trong một lượt phát lại lưu lượng hợp lệ? Lớp bọc của tools/crsfp.py. Chạy trên HOST, từ nsm:
#   bash tools/crsfp.sh <thư mục kết quả của scenario.sh> <mã kịch bản> [--tong] [MB cuối nhật ký cần đọc, mặc định 60]
# Ví dụ:  bash tools/crsfp.sh eval/results/crs-20261116-130000 quan-sat
# Đọc phần cuối nhật ký kiểm toán của ModSecurity trong container apache (chỉ đọc), lọc các request của đúng lượt chạy đó.
# Chạy NGAY sau lượt phát lại: nhật ký bị xoay khi lớn, mục cũ có thể không còn trong phần cuối.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
[ $# -ge 2 ] || { sed -n 2,6p "${BASH_SOURCE[0]}"; exit 2; }
rdir="$1"; sid="$2"; shift 2
opt=""; mb=60
for a in "$@"; do case "$a" in --tong) opt="--tong";; *[!0-9]*) ;; *) mb="$a";; esac; done
case "$rdir" in /*|[A-Za-z]:*) ;; *) rdir="$D/$rdir";; esac
docker compose -f "$D/docker-compose.yml" exec -T apache sh -c \
  "for f in /var/log/apache-json/modsec_audit.json.1 /var/log/apache-json/modsec_audit.json; do [ -f \$f ] && tail -c $((mb * 1024 * 1024)) \$f; done" \
  | PYTHONIOENCODING=utf-8 python -X utf8 -B "$D/tools/crsfp.py" "$rdir" "$sid" $opt
