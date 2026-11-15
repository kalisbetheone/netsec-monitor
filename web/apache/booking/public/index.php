<?php
// index.php — trang chủ: biểu mẫu tìm chuyến bay và biểu mẫu tra mã đặt chỗ
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD']);

page_header('Trang chủ');
echo "<h1>Đặt chỗ trực tuyến</h1>\n",
     "<p>Tìm chuyến bay giữa 10 sân bay trong nước, giữ chỗ trong 10 phút, hoặc tra lại đặt chỗ bằng mã đặt chỗ và tên hành khách.</p>\n";
render_search_form();
render_lookup_form();
page_footer();
