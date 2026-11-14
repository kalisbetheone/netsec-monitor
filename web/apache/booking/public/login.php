<?php
// login.php — GET: biểu mẫu đăng nhập; POST email + password: đúng -> 302 tới profile.php, sai -> 401 kèm biểu mẫu
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD', 'POST']);
header('Cache-Control: no-store');

$email  = '';
$error  = '';
$status = 200;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_same_origin();
    $email = param($_POST, 'email', 254);
    if (attempt_login($email, password_param($_POST, 'password')) !== null) {
        redirect('profile.php');
    }
    // Cùng một thông báo cho "sai email" và "sai mật khẩu"
    $error  = 'Email hoặc mật khẩu không đúng.';
    $status = 401;
} elseif (current_customer_id() !== null) {
    redirect('profile.php');
}

page_header('Đăng nhập', $status);
echo "<h1>Đăng nhập</h1>\n";
if ($error !== '') {
    echo '<p class="error">', h($error), "</p>\n";
}
echo "<form class=\"card\" method=\"post\" action=\"login.php\">\n",
     '<label>Email <input type="email" name="email" maxlength="254" required autocomplete="username" value="', h($email), "\"></label>\n",
     "<label>Mật khẩu <input type=\"password\" name=\"password\" maxlength=\"200\" required autocomplete=\"current-password\"></label>\n",
     "<button type=\"submit\">Đăng nhập</button>\n</form>\n";
page_footer();
