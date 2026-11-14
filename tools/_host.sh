# tools/_host.sh — được nạp (source) bởi các script chạy trên HOST: demo.sh, reset.sh, reset-all.sh,
# ruledemo.sh, ruledemo-multi.sh, bench.sh, nsmctl.sh, init-env.sh. KHÔNG chạy trực tiếp tệp này.
#
# Xác định thư mục dự án D từ CHÍNH VỊ TRÍ của tệp này — không có đường dẫn cứng nào:
#   - cách dùng thường gặp: cd vào thư mục nsm rồi gõ  bash tools/<tên>.sh
#   - gọi từ thư mục khác cũng được; đổi tên / chuyển thư mục dự án sang máy khác không cần sửa gì
#   - muốn ép một thư mục khác: đặt biến môi trường NSM_DIR
# Mọi tệp mà script đọc hay ghi trên host đều nằm trong D.
D="${NSM_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*)     # Git Bash trên Windows: Docker cần đường dẫn dạng C:/..., và không để MSYS tự đổi tham số
    export MSYS_NO_PATHCONV=1
    D="$(cd "$D" 2>/dev/null && pwd -W)" ;;
  CYGWIN*)
    D="$(cygpath -m "$D" 2>/dev/null)" ;;
esac
if [ -z "$D" ] || [ ! -f "$D/docker-compose.yml" ]; then
  echo "!! không thấy docker-compose.yml trong '${D:-${NSM_DIR:-?}}' — hãy cd vào thư mục nsm rồi chạy lại." >&2
  exit 1
fi
# Bí mật (mật khẩu Elasticsearch/Kafka/Grafana) nằm trong D/.env do tools/init-env.sh sinh.
if [ -z "${NSM_NO_ENV_CHECK:-}" ] && [ ! -f "$D/.env" ]; then
  echo "!! chưa có tệp .env trong '$D' — chạy trước:  bash tools/init-env.sh" >&2
  exit 1
fi

# ES <tham số curl...> — gọi Elasticsearch TỪ BÊN TRONG container của nó. Mật khẩu lấy từ biến môi trường
# của chính container (ELASTIC_PASSWORD), không đi qua dòng lệnh hay màn hình của host.
ES() {
  docker compose -f "$D/docker-compose.yml" exec -T elasticsearch \
    sh -c 'exec curl -s -u "elastic:$ELASTIC_PASSWORD" "$@"' sh "$@"
}
