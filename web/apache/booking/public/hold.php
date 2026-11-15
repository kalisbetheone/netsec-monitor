<?php
// hold.php — giữ chỗ tạm cho phiên hiện tại: POST flight_id. Mỗi lần gọi đều xoá các lượt giữ chỗ quá 10 phút.
// 200: đã giữ chỗ; 400: flight_id sai định dạng; 404: không có chuyến bay; 409: hết chỗ; 429: phiên giữ quá nhiều chỗ.
require __DIR__ . '/../lib.php';
require_method(['POST']);
require_same_origin();
header('Cache-Control: no-store');

$raw = param($_POST, 'flight_id', 12);
if ($raw === '' || !ctype_digit($raw) || strlen($raw) > 9) {
    fail(400, 'Yêu cầu không hợp lệ', 'Mã chuyến bay không hợp lệ.');
}
$flightId = (int) $raw;

session_boot(true);
// Bảng holds chỉ lưu mã băm của mã phiên, không lưu mã phiên thật
$sid = hash('sha256', session_id());
$now = time();
$db  = db();

$outcome = 'ok';
$flight  = false;
$db->exec('BEGIN IMMEDIATE');
try {
    $st = $db->prepare('DELETE FROM holds WHERE created_at < ?');
    $st->execute([gmdate('Y-m-d H:i:s', $now - HOLD_TTL)]);

    $st = $db->prepare('SELECT id, code, origin, dest, depart_date, price, seats_left FROM flights WHERE id = ?');
    $st->execute([$flightId]);
    $flight = $st->fetch();

    if ($flight === false) {
        $outcome = 'notfound';
    } else {
        $st = $db->prepare('SELECT id FROM holds WHERE flight_id = ? AND session_id = ?');
        $st->execute([$flightId, $sid]);
        $mine = $st->fetchColumn();
        $ts   = gmdate('Y-m-d H:i:s', $now);
        if ($mine !== false) {
            // Phiên này đang giữ chỗ trên chuyến bay này: gia hạn thay vì tạo dòng mới
            $st = $db->prepare('UPDATE holds SET created_at = ? WHERE id = ?');
            $st->execute([$ts, (int) $mine]);
        } else {
            $st = $db->prepare('SELECT COUNT(*) FROM holds WHERE flight_id = ?');
            $st->execute([$flightId]);
            $held = (int) $st->fetchColumn();
            $st = $db->prepare('SELECT COUNT(*) FROM holds WHERE session_id = ?');
            $st->execute([$sid]);
            $own = (int) $st->fetchColumn();
            if ((int) $flight['seats_left'] - $held <= 0) {
                $outcome = 'full';
            } elseif ($own >= MAX_HOLDS_PER_SESSION) {
                $outcome = 'limit';
            } else {
                $st = $db->prepare('INSERT INTO holds (flight_id, session_id, created_at) VALUES (?, ?, ?)');
                $st->execute([$flightId, $sid, $ts]);
            }
        }
    }
    $db->exec('COMMIT');
} catch (Throwable $e) {
    try {
        $db->exec('ROLLBACK');
    } catch (Throwable $ignored) {
        // giao dịch đã đóng
    }
    throw $e;
}

if ($outcome === 'notfound') {
    fail(404, 'Không tìm thấy', 'Không tìm thấy chuyến bay.');
}
if ($outcome === 'full') {
    fail(409, 'Hết chỗ', 'Chuyến bay này tạm thời đã hết chỗ.');
}
if ($outcome === 'limit') {
    fail(429, 'Quá nhiều lượt giữ chỗ', 'Mỗi phiên chỉ được giữ tối đa ' . MAX_HOLDS_PER_SESSION . ' chỗ cùng lúc.');
}

page_header('Đã giữ chỗ');
echo "<h1>Đã giữ chỗ</h1>\n",
     '<p>Đã giữ một chỗ trên chuyến bay <strong>', h($flight['code']), '</strong> (',
     h(airport_label((string) $flight['origin'])), ' → ', h(airport_label((string) $flight['dest'])), ', ngày ',
     h($flight['depart_date']), ', giá ', h(fmt_price($flight['price'])), ").</p>\n",
     "<p>Chỗ được giữ trong 10 phút kể từ bây giờ.</p>\n",
     "<p><a href=\"search.php\">Tìm chuyến bay khác</a></p>\n";
page_footer();
