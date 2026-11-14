<?php
// lib.php — phần dùng chung của cổng đặt chỗ: kết nối PDO, phiên đăng nhập, hàm thoát ký tự HTML, khung trang và
// các hàm nghiệp vụ mà cả trang HTML lẫn api.php cùng gọi (để hai bên luôn kiểm tra giống nhau).
// Tệp này nằm NGOÀI thư mục public/ nên không thể gọi trực tiếp qua web.

ini_set('display_errors', '0');          // không bao giờ in lỗi PHP ra trang
ini_set('log_errors', '1');
error_reporting(E_ALL);
date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');
ob_start();                               // gom đầu ra: còn đổi được mã trạng thái/tiêu đề cho tới khi kết thúc

const SESSION_NAME          = 'BOOKSESS';
const HOLD_TTL              = 600;        // giữ chỗ tồn tại 10 phút
const MAX_HOLDS_PER_SESSION = 5;
// Chuỗi bcrypt đúng định dạng nhưng không ứng với mật khẩu nào: dùng khi email không tồn tại để thời gian xử lý
// của "sai email" và "sai mật khẩu" gần như nhau.
const DUMMY_HASH            = '$2y$04$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';

header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

// Lỗi không lường trước: ghi vào nhật ký máy chủ, trả 500 với thông báo chung (không lộ chi tiết)
set_exception_handler(function (Throwable $e): void {
    error_log('booking: ' . get_class($e) . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    $api = defined('BOOKING_API');
    if (!headers_sent()) {
        http_response_code(500);
        header('Cache-Control: no-store');
        header('Content-Type: ' . ($api ? 'application/json' : 'text/plain') . '; charset=utf-8');
    }
    echo $api ? "{\"ok\":false,\"error\":\"Lỗi máy chủ.\"}\n" : "Lỗi máy chủ. Vui lòng thử lại sau.\n";
});

// ---------------------------------------------------------------- tiện ích chung

/** Thoát ký tự HTML — MỌI dữ liệu in ra trang đều đi qua hàm này. */
function h($s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

/** Chuẩn hoá một giá trị đầu vào thành chuỗi UTF-8 hợp lệ, bỏ ký tự điều khiển, cắt độ dài. Mảng/giá trị lạ -> ''. */
function clean_str($v, int $max = 200): string
{
    if (!is_string($v) || $v === '' || !mb_check_encoding($v, 'UTF-8')) {
        return '';
    }
    $v = preg_replace('/[\x00-\x1F\x7F]/', '', $v);
    if (!is_string($v)) {
        return '';
    }
    return mb_substr(trim($v), 0, $max, 'UTF-8');
}

function param(array $src, string $key, int $max = 200): string
{
    return clean_str($src[$key] ?? '', $max);
}

/** Mật khẩu: giữ nguyên từng byte (không cắt gọt), chỉ chặn kiểu dữ liệu lạ và độ dài bất thường. */
function password_param(array $src, string $key): string
{
    $v = $src[$key] ?? '';
    return (is_string($v) && strlen($v) <= 200) ? $v : '';
}

function lower(string $s): string
{
    return mb_strtolower($s, 'UTF-8');
}

function valid_date(string $d): bool
{
    return preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $d, $m) === 1 && checkdate((int) $m[2], (int) $m[3], (int) $m[1]);
}

function fmt_price($v): string
{
    return number_format((float) $v, 0, ',', '.') . ' ₫';
}

function status_label(string $s): string
{
    $map = ['confirmed' => 'Đã xác nhận', 'checked_in' => 'Đã làm thủ tục', 'cancelled' => 'Đã huỷ'];
    return $map[$s] ?? $s;
}

/** Danh sách sân bay (mã -> tên thành phố). Bảng flights chỉ lưu mã. */
function airports(): array
{
    return [
        'HAN' => 'Hà Nội', 'SGN' => 'TP. Hồ Chí Minh', 'DAD' => 'Đà Nẵng', 'CXR' => 'Nha Trang', 'PQC' => 'Phú Quốc',
        'HPH' => 'Hải Phòng', 'VCA' => 'Cần Thơ', 'HUI' => 'Huế', 'DLI' => 'Đà Lạt', 'VII' => 'Vinh',
    ];
}

function airport_label(string $code): string
{
    $ap = airports();
    return isset($ap[$code]) ? $ap[$code] . ' (' . $code . ')' : $code;
}

// ---------------------------------------------------------------- che bớt dữ liệu cá nhân

function mask_email(string $e): string
{
    $at = strrpos($e, '@');
    if ($at === false || $at === 0) {
        return '***';
    }
    return mb_substr($e, 0, 1, 'UTF-8') . '***' . substr($e, $at);
}

/** Che phần giữa, chỉ giữ $head ký tự đầu và $tail ký tự cuối. */
function mask_middle(string $s, int $head, int $tail): string
{
    $n = mb_strlen($s, 'UTF-8');
    if ($n <= $head + $tail) {
        return str_repeat('*', $n);
    }
    return mb_substr($s, 0, $head, 'UTF-8') . str_repeat('*', $n - $head - $tail) . mb_substr($s, $n - $tail, $tail, 'UTF-8');
}

// ---------------------------------------------------------------- CSDL

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        // Apache: SetEnv BOOKING_DB ... trong vhost; CLI/máy chủ thử: biến môi trường
        $path = $_SERVER['BOOKING_DB'] ?? getenv('BOOKING_DB');
        if (!is_string($path) || $path === '') {
            $path = '/var/lib/booking/booking.db';
        }
        if (!is_file($path)) {
            throw new RuntimeException('không tìm thấy tệp CSDL (chưa chạy seed.php?)');
        }
        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_TIMEOUT            => 3,       // chờ khoá tối đa 3 giây khi có tiến trình khác đang ghi
        ]);
        $pdo->exec('PRAGMA foreign_keys = ON');
    }
    return $pdo;
}

// ---------------------------------------------------------------- phiên đăng nhập

function is_https(): bool
{
    $https = $_SERVER['HTTPS'] ?? '';
    $xfp   = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    return (is_string($https) && $https !== '' && strtolower($https) !== 'off') || $xfp === 'https';
}

/**
 * Mở phiên. Khách vãng lai chưa có cookie thì KHÔNG tạo phiên (trừ khi $force) để không rải cookie/tệp phiên thừa.
 * Cookie phiên sai định dạng bị bỏ qua thay vì để session_start() phát cảnh báo.
 */
function session_boot(bool $force = false): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $sid   = $_COOKIE[SESSION_NAME] ?? null;
    $valid = is_string($sid) && preg_match('/^[A-Za-z0-9,-]{22,128}$/', $sid) === 1;
    if (!$valid && !$force) {
        return;
    }
    ini_set('session.use_strict_mode', '1');      // không nhận mã phiên do phía khách tự đặt
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    session_name(SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    if (!$valid && $sid !== null) {
        session_id(session_create_id());          // không dùng giá trị cookie hỏng
    }
    session_start();
}

function current_customer_id(): ?int
{
    session_boot();
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return null;
    }
    $cid = $_SESSION['cid'] ?? null;
    return (is_int($cid) && $cid > 0) ? $cid : null;
}

function end_session(): void
{
    session_boot();
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }
    $_SESSION = [];
    $p = session_get_cookie_params();
    setcookie(SESSION_NAME, '', [
        'expires'  => time() - 86400,
        'path'     => $p['path'],
        'secure'   => $p['secure'],
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_destroy();
}

/**
 * Chống giả mạo yêu cầu từ trang khác (CSRF) cho các yêu cầu POST: nếu trình duyệt gửi tiêu đề Origin thì tên máy
 * trong Origin phải trùng với Host. (Cookie phiên còn đặt SameSite=Lax.) curl/ứng dụng di động không gửi Origin.
 */
function require_same_origin(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (!is_string($origin) || $origin === '') {
        return;
    }
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $host = strtolower((string) preg_replace('/:\d+$/', '', is_string($host) ? $host : ''));
    $oh   = parse_url($origin, PHP_URL_HOST);
    if (!is_string($oh) || $host === '' || strtolower($oh) !== $host) {
        fail(403, 'Yêu cầu bị từ chối', 'Yêu cầu đến từ một trang không hợp lệ.');
    }
}

function require_method(array $allowed): void
{
    $m = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($m, $allowed, true)) {
        header('Allow: ' . implode(', ', $allowed));
        fail(405, 'Phương thức không được hỗ trợ', 'Phương thức không được hỗ trợ.');
    }
}

// ---------------------------------------------------------------- nghiệp vụ (dùng chung cho HTML và JSON)

/** Kiểm tra đăng nhập. Thành công: mở phiên mới (đổi mã phiên) và trả thông tin tối thiểu; thất bại: null. */
function attempt_login(string $email, string $password): ?array
{
    $row = false;
    if ($email !== '' && strlen($email) <= 254) {
        $st = db()->prepare('SELECT id, full_name, password_hash, points FROM customers WHERE email = ?');
        $st->execute([lower($email)]);
        $row = $st->fetch();
    }
    $hash = ($row !== false) ? (string) $row['password_hash'] : DUMMY_HASH;
    $ok   = password_verify($password, $hash);
    if ($row === false || !$ok) {
        return null;
    }
    session_boot(true);
    session_regenerate_id(true);                  // chống cố định phiên
    $_SESSION = ['cid' => (int) $row['id'], 'since' => time()];
    return ['id' => (int) $row['id'], 'full_name' => (string) $row['full_name'], 'points' => (int) $row['points']];
}

/** Tìm chuyến bay. Mọi giá trị người dùng nhập đều là tham số ràng buộc; tối đa 50 dòng. */
function search_flights(string $from, string $to, string $date, string $q): array
{
    $ap    = airports();
    $where = [];
    $args  = [];
    if (isset($ap[$from])) {
        $where[] = 'origin = ?';
        $args[]  = $from;
    }
    if (isset($ap[$to])) {
        $where[] = 'dest = ?';
        $args[]  = $to;
    }
    if (valid_date($date)) {
        $where[] = 'depart_date = ?';
        $args[]  = $date;
    }
    if ($q !== '') {
        // Từ khoá tự do: khớp mã chuyến bay hoặc điểm đến (mã sân bay hay tên thành phố). Thoát ký tự đại diện của LIKE.
        $like   = '%' . strtr($q, ['!' => '!!', '%' => '!%', '_' => '!_']) . '%';
        $or     = ["code LIKE ? ESCAPE '!'", "dest LIKE ? ESCAPE '!'"];
        $args[] = $like;
        $args[] = $like;
        $needle = lower($q);
        foreach ($ap as $code => $city) {
            if (mb_strpos(lower($city), $needle, 0, 'UTF-8') !== false) {
                $or[]   = 'dest = ?';
                $args[] = $code;
            }
        }
        $where[] = '(' . implode(' OR ', $or) . ')';
    }
    $sql = 'SELECT id, code, origin, dest, depart_date, price, seats_left FROM flights'
         . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
         . ' ORDER BY depart_date, price, id LIMIT 50';
    $st = db()->prepare($sql);
    $st->execute($args);
    return $st->fetchAll();
}

/** Từ cuối cùng của họ tên (ô "Tên" trên biểu mẫu tra cứu). */
function last_name(string $full): string
{
    $parts = preg_split('/\s+/u', trim($full));
    if (!is_array($parts) || $parts === []) {
        return '';
    }
    return (string) $parts[count($parts) - 1];
}

/** Chuẩn hoá để so sánh tên: không phân biệt hoa thường, coi các kiểu dấu nháy là một. */
function norm_name(string $s): string
{
    return lower(trim(strtr($s, ['’' => "'", '‘' => "'", 'ʼ' => "'", '`' => "'"])));
}

/**
 * Tra đặt chỗ theo mã + tên. Chỉ trả kết quả khi CẢ HAI cùng khớp; khi không khớp, bên gọi luôn trả cùng một câu
 * "không tìm thấy" (không cho biết mã có tồn tại hay không). Kết quả đã che email/điện thoại, không có số giấy tờ.
 */
function find_booking(string $code, string $last): ?array
{
    $code = strtoupper($code);
    if ($last === '' || preg_match('/^[A-Z0-9]{6}$/', $code) !== 1) {
        return null;
    }
    $st = db()->prepare(
        'SELECT b.code, b.seat, b.status, b.created_at, c.full_name, c.email, c.phone,
                f.code AS flight_code, f.origin, f.dest, f.depart_date
           FROM bookings b
           JOIN customers c ON c.id = b.customer_id
           JOIN flights f ON f.id = b.flight_id
          WHERE b.code = ?'
    );
    $st->execute([$code]);
    $row = $st->fetch();
    if ($row === false) {
        return null;
    }
    if (!hash_equals(norm_name(last_name((string) $row['full_name'])), norm_name($last))) {
        return null;
    }
    return [
        'code'        => (string) $row['code'],
        'status'      => (string) $row['status'],
        'seat'        => (string) $row['seat'],
        'created_at'  => (string) $row['created_at'],
        'passenger'   => (string) $row['full_name'],
        'email'       => mask_email((string) $row['email']),
        'phone'       => mask_middle((string) $row['phone'], 2, 2),
        'flight_code' => (string) $row['flight_code'],
        'origin'      => (string) $row['origin'],
        'dest'        => (string) $row['dest'],
        'depart_date' => (string) $row['depart_date'],
    ];
}

/** Hồ sơ + các đặt chỗ của ĐÚNG khách hàng $cid (mã khách lấy từ phiên, không bao giờ từ tham số yêu cầu). */
function load_profile(int $cid): ?array
{
    $st = db()->prepare('SELECT id, full_name, email, phone, id_number, points FROM customers WHERE id = ?');
    $st->execute([$cid]);
    $c = $st->fetch();
    if ($c === false) {
        return null;
    }
    $st = db()->prepare(
        'SELECT b.code, b.seat, b.status, b.created_at, f.code AS flight_code, f.origin, f.dest, f.depart_date
           FROM bookings b
           JOIN flights f ON f.id = b.flight_id
          WHERE b.customer_id = ?
          ORDER BY f.depart_date, b.id
          LIMIT 100'
    );
    $st->execute([$cid]);
    return [
        'customer' => [
            'id'        => (int) $c['id'],
            'full_name' => (string) $c['full_name'],
            'email'     => (string) $c['email'],
            'phone'     => (string) $c['phone'],
            'id_number' => mask_middle((string) $c['id_number'], 0, 3),   // số giấy tờ: chỉ hiện 3 ký tự cuối
            'points'    => (int) $c['points'],
        ],
        'bookings' => $st->fetchAll(),
    ];
}

// ---------------------------------------------------------------- đầu ra

function json_out(int $status, array $data): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_HEX_TAG | JSON_HEX_AMP), "\n";
    exit;
}

function page_header(string $title, int $status = 200): void
{
    $cid = current_customer_id();
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    echo "<!doctype html>\n<html lang=\"vi\">\n<head>\n<meta charset=\"utf-8\">\n",
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
         '<title>', h($title), " — Cổng đặt chỗ trực tuyến</title>\n",
         "<link rel=\"stylesheet\" href=\"style.css\">\n</head>\n<body>\n",
         "<header class=\"top\">\n<a class=\"brand\" href=\"index.php\">Cổng đặt chỗ trực tuyến</a>\n<nav>\n",
         "<a href=\"index.php\">Trang chủ</a>\n<a href=\"search.php\">Tìm chuyến bay</a>\n",
         "<a href=\"index.php#tra-ma\">Tra mã đặt chỗ</a>\n";
    if ($cid !== null) {
        echo "<a href=\"profile.php\">Hồ sơ của tôi</a>\n",
             "<form class=\"inline\" method=\"post\" action=\"logout.php\"><button type=\"submit\">Đăng xuất</button></form>\n";
    } else {
        echo "<a href=\"login.php\">Đăng nhập</a>\n";
    }
    echo "</nav>\n</header>\n<main>\n";
}

function page_footer(): void
{
    echo "</main>\n<footer>Dữ liệu trên trang này là dữ liệu giả lập phục vụ phòng thí nghiệm — không có thông tin của người thật.</footer>\n",
         "</body>\n</html>\n";
}

/** Kết thúc yêu cầu bằng một trang lỗi (HTML) hoặc JSON lỗi (khi được gọi từ api.php). */
function fail(int $status, string $title, string $message): never
{
    if (defined('BOOKING_API')) {
        json_out($status, ['ok' => false, 'error' => $message]);
    }
    page_header($title, $status);
    echo '<h1>', h($title), "</h1>\n<p class=\"error\">", h($message), "</p>\n",
         "<p><a href=\"index.php\">Về trang chủ</a></p>\n";
    page_footer();
    exit;
}

function redirect(string $to): never
{
    http_response_code(302);
    header('Location: ' . $to);
    header('Cache-Control: no-store');
    exit;
}

function render_search_form(string $from = '', string $to = '', string $date = '', string $q = ''): void
{
    $options = function (string $selected): string {
        $out = '<option value="">— Tất cả —</option>';
        foreach (airports() as $code => $city) {
            $out .= '<option value="' . h($code) . '"' . ($code === $selected ? ' selected' : '') . '>'
                  . h($city . ' (' . $code . ')') . '</option>';
        }
        return $out;
    };
    echo "<form class=\"card\" method=\"get\" action=\"search.php\">\n<h2>Tìm chuyến bay</h2>\n",
         '<label>Điểm đi <select name="from">', $options($from), "</select></label>\n",
         '<label>Điểm đến <select name="to">', $options($to), "</select></label>\n",
         '<label>Ngày bay <input type="date" name="date" value="', h($date), "\"></label>\n",
         '<label>Từ khoá (mã chuyến bay hoặc điểm đến) <input type="text" name="q" maxlength="60" value="', h($q), "\"></label>\n",
         "<button type=\"submit\">Tìm chuyến bay</button>\n</form>\n";
}

function render_lookup_form(string $code = '', string $last = ''): void
{
    echo "<form class=\"card\" id=\"tra-ma\" method=\"get\" action=\"booking.php\">\n<h2>Tra mã đặt chỗ</h2>\n",
         '<label>Mã đặt chỗ (6 ký tự) <input type="text" name="code" maxlength="6" required value="', h($code), "\"></label>\n",
         '<label>Tên hành khách (từ cuối cùng trong họ tên, ví dụ: An, Smith, O\'Neil) <input type="text" name="last" maxlength="60" required value="',
         h($last), "\"></label>\n",
         "<button type=\"submit\">Tra cứu</button>\n</form>\n";
}
