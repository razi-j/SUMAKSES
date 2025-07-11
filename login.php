<?php
require_once 'config/database.php';
require_once 'includes/session.php';
require_once 'includes/cookies.php';

// Check if already logged in
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

// Check remember me cookie
$remembered_user = checkRememberMeCookie();
if ($remembered_user) {
    // Auto-login from cookie
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$remembered_user['user_id']]);
    $user = $stmt->fetch();

    if ($user) {
        loginUser($user);
        header('Location: dashboard.php');
        exit;
    }
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $remember_me = isset($_POST['remember_me']);

    if (empty($username) || empty($password)) {
        $error = 'Username and password are required';
    } else {
        try {
            // Find user by username or email
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password'])) {
                // Login successful
                loginUser($user);

                // Set remember me cookie if requested
                if ($remember_me) {
                    setRememberMeCookie($user['id'], $user['username']);
                }

                header('Location: dashboard.php');
                exit;
            } else {
                $error = 'Invalid username or password';
            }
        } catch (PDOException $e) {
            $error = 'Login failed: ' . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>Login - PHP MySQL Auth</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <div class="container">
        <div class="form-container">
            <h2>Login</h2>

            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label>Username or Email:</label>
                    <input type="text" name="username" required>
                </div>

                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>

                <div class="form-group">
                    <label>
                        <input type="checkbox" name="remember_me"> Remember me for 30 days
                    </label>
                </div>

                <button type="submit">Login</button>
            </form>

            <p><a href="register.php">Don't have an account? Register here</a></p>
        </div>
    </div>
</body>

</html>
