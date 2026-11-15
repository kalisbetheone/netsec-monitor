<?php
// search.php — tìm chuyến bay: GET from, to, date và từ khoá tự do q (tuỳ chọn). Tối đa 50 kết quả.
require __DIR__ . '/../lib.php';
require_method(['GET', 'HEAD']);

$from = strtoupper(param($_GET, 'from', 3));
$to   = strtoupper(param($_GET, 'to', 3));
$date = param($_GET, 'date', 10);
$q    = param($_GET, 'q', 60);

// Bộ lọc không hợp lệ (mã sân bay lạ, ngày sai định dạng) bị bỏ qua và báo cho người dùng biết
$notes = [];
$ap = airports();
if ($from !== '' && !isset($ap[$from])) {
    $notes[] = 'Điểm đi không hợp lệ nên đã được bỏ qua.';
    $from = '';
}
if ($to !== '' && !isset($ap[$to])) {
    $notes[] = 'Điểm đến không hợp lệ nên đã được bỏ qua.';
    $to = '';
}
if ($date !== '' && !valid_date($date)) {
    $notes[] = 'Ngày bay không hợp lệ nên đã được bỏ qua.';
    $date = '';
}

$flights = search_flights($from, $to, $date, $q);

page_header('Tìm chuyến bay');
echo "<h1>Tìm chuyến bay</h1>\n";
render_search_form($from, $to, $date, $q);
foreach ($notes as $n) {
    echo '<p class="note">', h($n), "</p>\n";
}
if ($q !== '') {
    echo '<p>Từ khoá: <strong>', h($q), "</strong></p>\n";
}
if ($flights === []) {
    echo "<p>Không có chuyến bay phù hợp.</p>\n";
} else {
    echo '<p>Có ', h(count($flights)), " chuyến bay phù hợp (hiển thị tối đa 50).</p>\n",
         "<table>\n<thead><tr><th>Chuyến bay</th><th>Điểm đi</th><th>Điểm đến</th><th>Ngày bay</th>",
         "<th>Giá vé</th><th>Còn chỗ</th><th></th></tr></thead>\n<tbody>\n";
    foreach ($flights as $f) {
        echo '<tr><td>', h($f['code']), '</td><td>', h(airport_label((string) $f['origin'])), '</td><td>',
             h(airport_label((string) $f['dest'])), '</td><td>', h($f['depart_date']), '</td><td class="num">',
             h(fmt_price($f['price'])), '</td><td class="num">', h($f['seats_left']), '</td><td>',
             '<form class="inline" method="post" action="hold.php"><input type="hidden" name="flight_id" value="',
             h($f['id']), '"><button type="submit">Giữ chỗ</button></form></td></tr>', "\n";
    }
    echo "</tbody>\n</table>\n";
}
page_footer();
