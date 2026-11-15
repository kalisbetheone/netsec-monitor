#!/usr/bin/env bash
# tools/t2test.sh — bộ thử tầng 2 ("CRS và regex tầng 1 đều bỏ lọt"). Chạy trên HOST, từ thư mục nsm. Chỉ đọc dữ liệu.
#   bash tools/t2test.sh fetch <thư mục kết quả>/<kịch bản>   đọc ĐỦ sự kiện web của các IP tác nhân từ Elasticsearch -> web.json
#                                                             (obs.json của scenario.sh dừng ở 10 000 bản ghi mọi nguồn)
#   bash tools/t2test.sh report <thư mục kết quả kịch bản 44>  tính ba số đo (tools/t2test.py) -> t2test.md
set -u
. "$(dirname "${BASH_SOURCE[0]}")/_host.sh"
case "${1:-}" in
  fetch)  docker run --rm -i --network nsm_monitor_net -e ES_URL=http://elasticsearch:9200 -e ES_USER=elastic --env-file "$D/.env" \
            -v "$D/tools:/tools:ro" -v "$D/$2:/r" --entrypoint python "${BENCH_IMAGE:-nsm-classifier}" -B /tools/t2test.py fetch /r ;;
  report) PYTHONIOENCODING=utf-8 python -X utf8 -B "$D/tools/t2test.py" "$D/$2" ;;
  *) sed -n 2,6p "${BASH_SOURCE[0]}"; exit 2 ;;
esac
