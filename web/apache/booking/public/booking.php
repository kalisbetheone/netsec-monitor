<?php
// booking.php — tra đặt chỗ: GET code (mã đặt chỗ) + last (tên hành khách). Chỉ hiện khi CẢ HAI cùng khớp;
// mọi trường hợp khác trả 404 với cùng một thông báo. Email/điện thoại luôn được che bớt.
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD']);
header('Cache-Control: no-store');

$code = strtoupper(param($_GET, 'code', 6));
$last = param($_GET, 'last', 60);

$b = find_booking($code, $last);
if ($b === null) {
    page_header('Không tìm thấy', 404);
    echo "<h1>Không tìm thấy</h1>\n",
         "<p class=\"error\">Không tìm thấy đặt chỗ ứng với mã và tên đã nhập. Vui lòng kiểm tra lại.</p>\n";
    render_lookup_form($code, $last);
    page_footer();
    exit;
}

page_header('Đặt chỗ ' . $b['code']);
echo '<h1>Đặt chỗ ', h($b['code']), "</h1>\n<table class=\"kv\">\n",
     '<tr><th>Hành khách</th><td>', h($b['passenger']), "</td></tr>\n",
     '<tr><th>Email</th><td>', h($b['email']), "</td></tr>\n",
     '<tr><th>Điện thoại</th><td>', h($b['phone']), "</td></tr>\n",
     '<tr><th>Chuyến bay</th><td>', h($b['flight_code']), "</td></tr>\n",
     '<tr><th>Hành trình</th><td>', h(airport_label($b['origin'])), ' → ', h(airport_label($b['dest'])), "</td></tr>\n",
     '<tr><th>Ngày bay</th><td>', h($b['depart_date']), "</td></tr>\n",
     '<tr><th>Ghế</th><td>', h($b['seat']), "</td></tr>\n",
     '<tr><th>Trạng thái</th><td>', h(status_label($b['status'])), "</td></tr>\n",
     '<tr><th>Ngày đặt</th><td>', h($b['created_at']), " (UTC)</td></tr>\n",
     "</table>\n";
page_footer();
