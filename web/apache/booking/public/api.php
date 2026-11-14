<?php
// api.php — API JSON cho "ứng dụng di động": POST, Content-Type: application/json,
// thân {"action": "login" | "search" | "booking" | "profile", ...}. Dùng đúng các hàm nghiệp vụ của trang HTML
// (lib.php) nên mọi kiểm tra giống hệt; phiên đăng nhập dùng chung cookie phiên PHP.
// 400: JSON hỏng/thiếu action; 401: đăng nhập sai hoặc chưa đăng nhập; 404: không tìm thấy; 405/413/415: sai cách gọi.
define('BOOKING_API', true);
require __DIR__ . '/../lib.php';
require_method(['POST']);
require_same_origin();

$raw = file_get_contents('php://input', false, null, 0, 8193);
if (!is_string($raw)) {
    $raw = '';
}
if (strlen($raw) > 8192) {
    json_out(413, ['ok' => false, 'error' => 'Thân yêu cầu quá lớn.']);
}
$in = json_decode($raw, true, 8);
if (!is_array($in) || !isset($in['action']) || !is_string($in['action'])) {
    json_out(400, ['ok' => false, 'error' => 'JSON không hợp lệ hoặc thiếu trường action.']);
}
$ct = $_SERVER['CONTENT_TYPE'] ?? '';
if (!is_string($ct) || stripos($ct, 'application/json') !== 0) {
    json_out(415, ['ok' => false, 'error' => 'Content-Type phải là application/json.']);
}

switch ($in['action']) {
    case 'login':
        $c = attempt_login(param($in, 'email', 254), password_param($in, 'password'));
        if ($c === null) {
            json_out(401, ['ok' => false, 'error' => 'Email hoặc mật khẩu không đúng.']);
        }
        json_out(200, ['ok' => true, 'customer' => $c]);

    case 'search':
        $date = param($in, 'date', 10);
        $rows = search_flights(
            strtoupper(param($in, 'from', 3)),
            strtoupper(param($in, 'to', 3)),
            valid_date($date) ? $date : '',
            param($in, 'q', 60)
        );
        json_out(200, ['ok' => true, 'count' => count($rows), 'flights' => $rows]);

    case 'booking':
        $b = find_booking(param($in, 'code', 6), param($in, 'last', 60));
        if ($b === null) {
            json_out(404, ['ok' => false, 'error' => 'Không tìm thấy đặt chỗ.']);
        }
        json_out(200, ['ok' => true, 'booking' => $b]);

    case 'profile':
        $cid = current_customer_id();
        $p   = ($cid !== null) ? load_profile($cid) : null;
        if ($p === null) {
            json_out(401, ['ok' => false, 'error' => 'Chưa đăng nhập.']);
        }
        json_out(200, ['ok' => true] + $p);

    default:
        json_out(400, ['ok' => false, 'error' => 'Hành động không được hỗ trợ.']);
}
