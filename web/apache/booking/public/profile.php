<?php
// profile.php — hồ sơ của khách đang đăng nhập và các đặt chỗ của chính khách đó. Chưa đăng nhập -> 302 tới login.php.
// Mã khách hàng chỉ lấy từ phiên; trang không nhận tham số nào để xem hồ sơ người khác.
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD']);
header('Cache-Control: no-store');

$cid = current_customer_id();
if ($cid === null) {
    redirect('login.php');
}
$p = load_profile($cid);
if ($p === null) {            // tài khoản không còn tồn tại: huỷ phiên
    end_session();
    redirect('login.php');
}
$c = $p['customer'];

page_header('Hồ sơ của tôi');
echo "<h1>Hồ sơ của tôi</h1>\n<table class=\"kv\">\n",
     '<tr><th>Họ tên</th><td>', h($c['full_name']), "</td></tr>\n",
     '<tr><th>Email</th><td>', h($c['email']), "</td></tr>\n",
     '<tr><th>Điện thoại</th><td>', h($c['phone']), "</td></tr>\n",
     '<tr><th>Số giấy tờ</th><td>', h($c['id_number']), "</td></tr>\n",
     '<tr><th>Điểm thưởng</th><td>', h(number_format((float) $c['points'], 0, ',', '.')), "</td></tr>\n",
     "</table>\n<h2>Đặt chỗ của tôi</h2>\n";
if ($p['bookings'] === []) {
    echo "<p>Bạn chưa có đặt chỗ nào.</p>\n";
} else {
    echo "<table>\n<thead><tr><th>Mã đặt chỗ</th><th>Chuyến bay</th><th>Hành trình</th><th>Ngày bay</th>",
         "<th>Ghế</th><th>Trạng thái</th></tr></thead>\n<tbody>\n";
    foreach ($p['bookings'] as $b) {
        echo '<tr><td>', h($b['code']), '</td><td>', h($b['flight_code']), '</td><td>',
             h(airport_label((string) $b['origin'])), ' → ', h(airport_label((string) $b['dest'])), '</td><td>',
             h($b['depart_date']), '</td><td>', h($b['seat']), '</td><td>', h(status_label((string) $b['status'])),
             "</td></tr>\n";
    }
    echo "</tbody>\n</table>\n";
}
page_footer();
