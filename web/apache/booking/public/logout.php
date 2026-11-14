<?php
// logout.php — huỷ phiên đăng nhập rồi chuyển về trang chủ (302)
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD', 'POST']);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_same_origin();
}
end_session();
redirect('index.php');
