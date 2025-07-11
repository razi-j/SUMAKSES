
<?php
$host = 'localhost'; // e.g., localhost or an IP address
$db   = 'user_auth';
$user = 'root';
$pass = '';
//$port = '3306'; // Default MariaDB port (only used for checking by ja)
$charset = 'utf8mb4'; // Or another suitable charset

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
    echo "Connected successfully";
} catch (PDOException $e) {
    throw new PDOException($e->getMessage(), (int)$e->getCode());
}
?>
