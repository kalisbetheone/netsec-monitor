<?php
// health.php — kiểm tra sống: "ok" kèm số dòng của từng bảng; CSDL lỗi -> 503
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD']);
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

try {
    $parts = [];
    // Tên bảng là danh sách cố định trong mã nguồn, không lấy từ yêu cầu
    foreach (['customers', 'flights', 'bookings', 'holds'] as $t) {
        $parts[] = $t . '=' . (int) db()->query('SELECT COUNT(*) FROM ' . $t)->fetchColumn();
    }
    echo 'ok ', implode(' ', $parts), "\n";
} catch (Throwable $e) {
    error_log('booking health: ' . $e->getMessage());
    http_response_code(503);
    echo "fail\n";
}
