<?php
// seed.php — tạo CSDL SQLite GIẢ LẬP cho cổng đặt chỗ. Chỉ chạy bằng dòng lệnh (CLI):
//     BOOKING_DB=/var/lib/booking/booking.db php seed.php
// Mọi dữ liệu đều là dữ liệu tổng hợp, sinh tất định từ một hạt giống cố định (mt_srand): chạy lại cho ra cùng họ tên,
// chuyến bay, mã đặt chỗ. (Riêng password_hash khác nhau giữa các lần chạy vì bcrypt tự sinh muối ngẫu nhiên.)
// Không có thông tin của người thật hay doanh nghiệp thật.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

error_reporting(E_ALL);
ini_set('display_errors', 'stderr');
date_default_timezone_set('UTC');

const SEED_VALUE    = 20261115;
const N_CUSTOMERS   = 10000;
const N_FLIGHTS     = 2000;
const N_BOOKINGS    = 50000;
const N_TEST        = 20;            // user1..user20@example.test
const N_CANARY      = 5;             // khách hàng "đánh dấu" CANARY-
const TEST_PASSWORD = 'Passw0rd!1';
const BASE_DATE     = '2026-11-15';
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // chữ hoa + số, bỏ ký tự dễ nhầm (I, O, 0, 1)

// Các cặp CỐ ĐỊNH (mã đặt chỗ, họ tên) dành cho lưu lượng người dùng bình thường: tools/benign_booking.sh và
// benign_pairs.txt lấy từ đúng danh sách này. Đổi danh sách thì phải cập nhật cả hai tệp kia.
$FIXED_PAIRS = [
    ['VB8LYM', "Liam O'Neil"],
    ['6NGCRM', "Nguyễn Văn An"],
    ['KF9LXX', "Emma Smith"],
    ['JZ7ZMC', "Sofia D'Angelo"],
    ['5AZVWY', "Trần Thị Bình"],
    ['2WFPGC', "Noah Johnson"],
    ['4G66YH', "Aidan O'Brien"],
    ['RHHVSY', "Lê Minh Châu"],
    ['ABSJVU', "Olivia Brown"],
    ['KKWKLX', "Awa N'Dour"],
    ['ZH7ZUH', "Phạm Quốc Dũng"],
    ['2HD46M', "Lucas Miller"],
    ['KPNS4B', "Nora O'Connor"],
    ['5HTN3B', "Hoàng Thu Giang"],
    ['GEPRBS', "Mia Garcia"],
    ['J56Z5G', "Ravi D'Souza"],
    ['L39BXR', "Huỳnh Ngọc Hà"],
    ['HBH9ZQ', "Hugo Martin"],
    ['Y9AR4S', "Kate O'Hara"],
    ['A9XG6S', "Phan Thanh Hải"],
    ['NDRRTF', "Lea Dubois"],
    ['TYVLMF', "Omar M'Baye"],
    ['YLUE9P', "Vũ Thị Hạnh"],
    ['8D748K', "Luca Rossi"],
    ['LX6XDD', "Sean O'Donnell"],
    ['XQKZ7V', "Võ Đức Hiếu"],
    ['VGCR7E', "Anna Schmidt"],
    ['6XEURL', "Claire L'Heureux"],
    ['F3YCFR', "Đặng Thị Hoa"],
    ['LYCQPW', "Jan Novak"],
    ['DJPK67', "Marco D'Amico"],
    ['GPUPGG', "Bùi Hữu Hùng"],
    ['T23KZY', "Ana Silva"],
    ['9NWGJR', "Fiona O'Reilly"],
    ['64K4HU', "Đỗ Gia Khánh"],
    ['FVH698', "Piotr Kowalski"],
    ['ZRPYBM', "Ama N'Guessan"],
    ['AG57DY', "Hồ Thị Lan"],
    ['LZYKKY', "Ella Nilsson"],
    ['C8SECJ', "Rory O'Sullivan"],
    ['F9DRL4', "Ngô Bảo Linh"],
    ['LH4JVL', "Tom Baker"],
    ['6HBVM9', "Dương Văn Long"],
    ['FMT6ZX', "Ines Moreau"],
    ['584NJB', "Lý Thị Mai"],
    ['H96GQ3', "Paul Weber"],
    ['QKPS6J', "Nguyễn Hoài Nam"],
    ['G7YUBQ', "Trần Thị Yến"],
];

// ---- Nguồn họ tên tổng hợp ----
$VI_HO  = ['Nguyễn', 'Trần', 'Lê', 'Phạm', 'Hoàng', 'Huỳnh', 'Phan', 'Vũ', 'Võ', 'Đặng', 'Bùi', 'Đỗ', 'Hồ', 'Ngô', 'Dương', 'Lý'];
$VI_DEM = ['Văn', 'Thị', 'Hữu', 'Minh', 'Ngọc', 'Thanh', 'Đức', 'Quốc', 'Thu', 'Hoài', 'Gia', 'Bảo'];
$VI_TEN = ['An', 'Bình', 'Châu', 'Dũng', 'Giang', 'Hà', 'Hải', 'Hạnh', 'Hiếu', 'Hoa', 'Hùng', 'Khánh', 'Lan', 'Linh',
           'Long', 'Mai', 'Nam', 'Nga', 'Phúc', 'Quân', 'Sơn', 'Tâm', 'Thảo', 'Trang', 'Tuấn', 'Vy', 'Yến'];
$EN_FIRST = ['Liam', 'Emma', 'Noah', 'Olivia', 'Lucas', 'Mia', 'Hugo', 'Lea', 'Luca', 'Anna', 'Jan', 'Ana', 'Piotr',
             'Ella', 'Tom', 'Ines', 'Paul', 'Sofia', 'Aidan', 'Nora', 'Ravi', 'Kate', 'Omar', 'Sean', 'Claire', 'Marco',
             'Fiona', 'Ama', 'Rory', 'Awa'];
$EN_LAST  = ['Smith', 'Johnson', 'Brown', 'Miller', 'Garcia', 'Martin', 'Dubois', 'Rossi', 'Schmidt', 'Novak', 'Silva',
             'Kowalski', 'Nilsson', 'Baker', 'Moreau', 'Weber', 'Taylor', 'Clark', 'Lopez', 'Fischer'];
// Họ có dấu nháy đơn: tên hợp lệ mà ứng dụng (và hệ thống giám sát) phải xử lý như dữ liệu bình thường.
$APOS_LAST = ["O'Neil", "D'Angelo", "O'Brien", "N'Dour", "O'Connor", "D'Souza", "O'Hara", "M'Baye", "O'Donnell",
              "L'Heureux", "D'Amico", "O'Reilly", "N'Guessan", "O'Sullivan"];
$AIRPORTS  = ['HAN', 'SGN', 'DAD', 'CXR', 'PQC', 'HPH', 'VCA', 'HUI', 'DLI', 'VII'];

function pick(array $a)
{
    return $a[mt_rand(0, count($a) - 1)];
}

$t0 = microtime(true);
$dbPath = getenv('BOOKING_DB');
if (!is_string($dbPath) || $dbPath === '') {
    $dbPath = '/var/lib/booking/booking.db';
}
$dir = dirname($dbPath);

try {
    if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
        throw new RuntimeException("không tạo được thư mục $dir");
    }
    // Luôn tạo mới từ đầu để kết quả tất định
    foreach ([$dbPath, $dbPath . '-journal', $dbPath . '-wal', $dbPath . '-shm'] as $old) {
        if (file_exists($old) && !unlink($old)) {
            throw new RuntimeException("không xoá được tệp cũ $old");
        }
    }

    mt_srand(SEED_VALUE);

    $db = new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    $db->exec('PRAGMA journal_mode = MEMORY');
    $db->exec('PRAGMA synchronous = OFF');

    $db->exec('CREATE TABLE customers (
        id            INTEGER PRIMARY KEY,
        full_name     TEXT NOT NULL,
        email         TEXT NOT NULL UNIQUE,
        phone         TEXT NOT NULL,
        id_number     TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        points        INTEGER NOT NULL DEFAULT 0
    )');
    $db->exec('CREATE TABLE flights (
        id          INTEGER PRIMARY KEY,
        code        TEXT NOT NULL UNIQUE,
        origin      TEXT NOT NULL,
        dest        TEXT NOT NULL,
        depart_date TEXT NOT NULL,
        price       INTEGER NOT NULL,
        seats_left  INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE bookings (
        id          INTEGER PRIMARY KEY,
        code        TEXT NOT NULL UNIQUE,
        customer_id INTEGER NOT NULL REFERENCES customers(id),
        flight_id   INTEGER NOT NULL REFERENCES flights(id),
        seat        TEXT NOT NULL,
        status      TEXT NOT NULL,
        created_at  TEXT NOT NULL
    )');
    $db->exec('CREATE TABLE holds (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        flight_id  INTEGER NOT NULL REFERENCES flights(id),
        session_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    )');

    $db->beginTransaction();

    // ---------- customers ----------
    // id 1..20: tài khoản thử; 21..68: khách của các cặp cố định; 9996..10000: khách đánh dấu CANARY; còn lại ngẫu nhiên.
    $nFixed      = count($FIXED_PAIRS);
    $firstCanary = N_CUSTOMERS - N_CANARY + 1;
    $insC = $db->prepare('INSERT INTO customers (id, full_name, email, phone, id_number, password_hash, points)
                          VALUES (?, ?, ?, ?, ?, ?, ?)');
    for ($id = 1; $id <= N_CUSTOMERS; $id++) {
        // Số điện thoại và số giấy tờ có tiền tố không tồn tại ngoài đời (0000..., 9990...) để không trùng người thật
        $phone = sprintf('0000%06d', ($id * 7919) % 1000000);
        $idNo  = sprintf('9990%08d', ($id * 48271) % 100000000);
        $email = sprintf('kh%05d@example.test', $id);

        if ($id >= $firstCanary) {
            // Khách "đánh dấu": chỉ để hệ thống giám sát kiểm tra rằng chuỗi CANARY không lọt ra cho khách vãng lai
            $k     = $id - $firstCanary + 1;
            $name  = sprintf('CANARY-%04d Marker', $k);
            $idNo  = sprintf('CANARY-ID-%04d', $k);
            $email = sprintf('canary%04d@example.test', $k);
        } elseif ($id > N_TEST && $id <= N_TEST + $nFixed) {
            $name = $FIXED_PAIRS[$id - N_TEST - 1][1];
        } elseif ($id > N_TEST && $id % 25 === 0) {
            $name = pick($EN_FIRST) . ' ' . pick($APOS_LAST);
        } elseif (mt_rand(1, 100) <= 60) {
            $name = pick($VI_HO) . ' ' . pick($VI_DEM) . ' ' . pick($VI_TEN);
        } else {
            $name = pick($EN_FIRST) . ' ' . pick($EN_LAST);
        }

        if ($id <= N_TEST) {
            // Tài khoản thử cho bộ sinh lưu lượng bình thường: cùng một mật khẩu, mỗi tài khoản một muối riêng
            $email = sprintf('user%d@example.test', $id);
            $hash  = password_hash(TEST_PASSWORD, PASSWORD_BCRYPT, ['cost' => 4]);
        } else {
            // Các khách còn lại: mật khẩu ngẫu nhiên không ai biết (không lấy từ mt_rand để không tính lại được từ hạt giống)
            $hash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT, ['cost' => 4]);
        }
        $insC->execute([$id, $name, $email, $phone, $idNo, $hash, mt_rand(0, 50000)]);
    }

    // ---------- flights ----------
    $base = new DateTimeImmutable(BASE_DATE, new DateTimeZone('UTC'));
    $insF = $db->prepare('INSERT INTO flights (id, code, origin, dest, depart_date, price, seats_left)
                          VALUES (?, ?, ?, ?, ?, ?, ?)');
    for ($i = 1; $i <= N_FLIGHTS; $i++) {
        $o = pick($AIRPORTS);
        do {
            $d = pick($AIRPORTS);
        } while ($d === $o);
        $date = $base->modify('+' . mt_rand(1, 60) . ' days')->format('Y-m-d');
        $insF->execute([$i, sprintf('NS%04d', 1000 + $i), $o, $d, $date, mt_rand(590, 3900) * 1000, mt_rand(5, 180)]);
    }

    // ---------- bookings ----------
    $baseTs = $base->getTimestamp();
    $used   = [];
    foreach ($FIXED_PAIRS as $p) {
        if (!preg_match('/^[A-Z0-9]{6}$/', $p[0]) || isset($used[$p[0]])) {
            throw new RuntimeException('cặp cố định không hợp lệ: ' . $p[0]);
        }
        $used[$p[0]] = true;
    }
    $alphaMax = strlen(CODE_ALPHABET) - 1;
    $newCode = function () use (&$used, $alphaMax): string {
        do {
            $c = '';
            for ($k = 0; $k < 6; $k++) {
                $c .= CODE_ALPHABET[mt_rand(0, $alphaMax)];
            }
        } while (isset($used[$c]));
        $used[$c] = true;
        return $c;
    };
    $seatLetters = 'ABCDEF';
    $insB = $db->prepare('INSERT INTO bookings (id, code, customer_id, flight_id, seat, status, created_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)');
    for ($i = 1; $i <= N_BOOKINGS; $i++) {
        if ($i <= $nFixed) {                                   // 1..48: cặp cố định
            $code = $FIXED_PAIRS[$i - 1][0];
            $cid  = N_TEST + $i;
        } elseif ($i <= $nFixed + N_CANARY) {                  // mỗi khách CANARY đúng một đặt chỗ
            $code = $newCode();
            $cid  = $firstCanary + ($i - $nFixed - 1);
        } elseif ($i <= $nFixed + N_CANARY + 2 * N_TEST) {     // mỗi tài khoản thử ít nhất hai đặt chỗ
            $code = $newCode();
            $cid  = intdiv($i - $nFixed - N_CANARY - 1, 2) + 1;
        } else {                                               // còn lại: khách ngẫu nhiên (không gồm CANARY)
            $code = $newCode();
            $cid  = mt_rand(1, $firstCanary - 1);
        }
        $r      = mt_rand(1, 100);
        $status = $r <= 80 ? 'confirmed' : ($r <= 92 ? 'checked_in' : 'cancelled');
        if ($i <= $nFixed) {
            $status = 'confirmed';
        }
        $seat    = mt_rand(1, 30) . $seatLetters[mt_rand(0, 5)];
        $created = gmdate('Y-m-d H:i:s', $baseTs - mt_rand(0, 90 * 86400));
        $insB->execute([$i, (string) $code, $cid, mt_rand(1, N_FLIGHTS), $seat, $status, $created]);
    }

    $db->exec('CREATE INDEX idx_flights_route ON flights (origin, dest, depart_date)');
    $db->exec('CREATE INDEX idx_flights_dest ON flights (dest, depart_date)');
    $db->exec('CREATE INDEX idx_bookings_customer ON bookings (customer_id)');
    $db->exec('CREATE INDEX idx_holds_created ON holds (created_at)');
    $db->exec('CREATE INDEX idx_holds_session ON holds (session_id)');
    $db->commit();
    $db->exec('PRAGMA journal_mode = DELETE');
    $db->exec('PRAGMA synchronous = FULL');

    // ---------- benign_pairs.txt: "MÃ<TAB>từ cuối của họ tên", đọc lại từ chính CSDL ----------
    $st = $db->prepare('SELECT b.code, c.full_name FROM bookings b JOIN customers c ON c.id = b.customer_id
                        WHERE b.id <= ? ORDER BY b.id');
    $st->execute([$nFixed]);
    $lines  = '';
    $nPairs = 0;
    foreach ($st->fetchAll() as $row) {
        $parts = explode(' ', trim((string) $row['full_name']));
        $lines .= $row['code'] . "\t" . $parts[count($parts) - 1] . "\n";
        $nPairs++;
    }
    if ($nPairs < 40 || file_put_contents($dir . '/benign_pairs.txt', $lines) === false) {
        throw new RuntimeException('không ghi được benign_pairs.txt');
    }

    // ---------- tự kiểm tra ----------
    $count = function (string $sql) use ($db): int {
        return (int) $db->query($sql)->fetchColumn();
    };
    $nC     = $count('SELECT COUNT(*) FROM customers');
    $nF     = $count('SELECT COUNT(*) FROM flights');
    $nB     = $count('SELECT COUNT(*) FROM bookings');
    $nH     = $count('SELECT COUNT(*) FROM holds');
    $nCodes = $count('SELECT COUNT(DISTINCT code) FROM bookings');
    $nCan   = $count("SELECT COUNT(*) FROM customers WHERE full_name LIKE 'CANARY-%' AND id_number LIKE 'CANARY-ID-%'");
    $nCanB  = $count("SELECT COUNT(*) FROM bookings b JOIN customers c ON c.id = b.customer_id WHERE c.full_name LIKE 'CANARY-%'");
    $nApo   = $count("SELECT COUNT(*) FROM customers WHERE full_name LIKE '%''%'");
    $h1     = (string) $db->query("SELECT password_hash FROM customers WHERE email = 'user1@example.test'")->fetchColumn();
    if ($nC !== N_CUSTOMERS || $nF !== N_FLIGHTS || $nB !== N_BOOKINGS || $nCodes !== N_BOOKINGS
        || $nCan !== N_CANARY || $nCanB !== N_CANARY || $nApo < 300 || !password_verify(TEST_PASSWORD, $h1)) {
        throw new RuntimeException("tự kiểm tra thất bại: customers=$nC flights=$nF bookings=$nB codes=$nCodes canary=$nCan/$nCanB apostrophe=$nApo");
    }

    printf(
        "seed ok: customers=%d flights=%d bookings=%d holds=%d canary=%d apostrophe_names=%d test_accounts=%d pairs=%d db=%s time=%.1fs\n",
        $nC, $nF, $nB, $nH, $nCan, $nApo, N_TEST, $nPairs, $dbPath, microtime(true) - $t0
    );
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, 'seed FAILED: ' . $e->getMessage() . "\n");
    exit(1);
}
