# PHP MySQL Authentication System - Beginner Tutorial

## Learning Objectives
By the end of this activity, you will:
- Connect PHP to MySQL database
- Create user registration and login functionality
- Implement PHP sessions for user state management
- Use cookies for "Remember Me" functionality
- Understand basic security practices

## Prerequisites
- XAMPP/WAMP/MAMP installed (includes Apache, PHP, MySQL)
- Basic knowledge of HTML, PHP, and SQL

## Project Structure
```
project-folder/
├── config/
│   └── database.php
├── includes/
│   ├── session.php
│   └── cookies.php
├── register.php
├── login.php
├── dashboard.php
├── logout.php
└── style.css
```

## Step 1: Database Setup

First, create a MySQL database and table. Open phpMyAdmin and run this SQL:

```sql
CREATE DATABASE user_auth;
USE user_auth;

CREATE TABLE users (
    id INT AUTO_INCREMENT [A_I checkbox] PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
## Another way to create database:
1.	Setup Database
To create database:
o	Open xampp > start Apache and MySql
o	MySql > Admin > redirected to php database dashboard
o	Click new > type database name > click create
To create a table
o	Type table name > select number of columns > click create


## Step 2: Database Connection (config/database.php)

```php
<?php
// Database configuration
$host = 'localhost';
$dbname = 'user_auth';
$username = 'root';  // Default XAMPP username
$password = '';      // Default XAMPP password (empty)

try {
    // Create PDO connection
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    
    // Set error mode to exception
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    echo "<!-- Database connected successfully -->";
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>
```

## Step 3: Session Management (includes/session.php)

```php
<?php
// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Function to check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

// Function to get current user info
function getCurrentUser() {
    if (isLoggedIn()) {
        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'email' => $_SESSION['email']
        ];
    }
    return null;
}

// Function to login user (set session variables)
function loginUser($user_data) {
    $_SESSION['user_id'] = $user_data['id'];
    $_SESSION['username'] = $user_data['username'];
    $_SESSION['email'] = $user_data['email'];
    $_SESSION['login_time'] = time();
}

// Function to logout user
function logoutUser() {
    // Unset all session variables
    $_SESSION = array();
    
    // Destroy the session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Destroy the session
    session_destroy();
}

// Function to require login (redirect if not logged in)
function requireLogin($redirect_to = 'login.php') {
    if (!isLoggedIn()) {
        header("Location: $redirect_to");
        exit;
    }
}
?>
```

## Step 4: Cookie Management (includes/cookies.php)

```php
<?php
// Function to set remember me cookie
function setRememberMeCookie($user_id, $username) {
    // Create a secure token
    $token = bin2hex(random_bytes(32));
    
    // Store token in cookie (30 days)
    $expire = time() + (30 * 24 * 60 * 60); // 30 days
    setcookie('remember_me', $token, $expire, '/', '', false, true);
    
    // In a real application, you'd store this token in database
    // For this tutorial, we'll store it in a simple file
    $remember_data = [
        'user_id' => $user_id,
        'username' => $username,
        'token' => $token,
        'expires' => $expire
    ];
    
    file_put_contents('remember_tokens.json', json_encode($remember_data));
}

// Function to check remember me cookie
function checkRememberMeCookie() {
    if (isset($_COOKIE['remember_me'])) {
        $token = $_COOKIE['remember_me'];
        
        // Check if token file exists
        if (file_exists('remember_tokens.json')) {
            $remember_data = json_decode(file_get_contents('remember_tokens.json'), true);
            
            // Verify token and check if not expired
            if ($remember_data['token'] === $token && time() < $remember_data['expires']) {
                return [
                    'user_id' => $remember_data['user_id'],
                    'username' => $remember_data['username']
                ];
            }
        }
    }
    return false;
}

// Function to clear remember me cookie
function clearRememberMeCookie() {
    setcookie('remember_me', '', time() - 3600, '/');
    if (file_exists('remember_tokens.json')) {
        unlink('remember_tokens.json');
    }
}
?>
```

## Step 5: User Registration (register.php)

```php
<?php
require_once 'config/database.php';
require_once 'includes/session.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Basic validation
    if (empty($username) || empty($email) || empty($password)) {
        $error = 'All fields are required';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters';
    } else {
        try {
            // Check if username or email already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            
            if ($stmt->rowCount() > 0) {
                $error = 'Username or email already exists';
            } else {
                // Hash password
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                
                // Insert new user
                $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                $stmt->execute([$username, $email, $hashed_password]);
                
                $success = 'Registration successful! You can now login.';
            }
        } catch(PDOException $e) {
            $error = 'Registration failed: ' . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register - PHP MySQL Auth</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="form-container">
            <h2>Register</h2>
            
            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo $success; ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" required>
                </div>
                
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
                
                <div class="form-group">
                    <label>Confirm Password:</label>
                    <input type="password" name="confirm_password" required>
                </div>
                
                <button type="submit">Register</button>
            </form>
            
            <p><a href="login.php">Already have an account? Login here</a></p>
        </div>
    </div>
</body>
</html>
```

## Step 6: User Login (login.php)

```php
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
        } catch(PDOException $e) {
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
```

## Step 7: Dashboard (dashboard.php)

```php
<?php
require_once 'config/database.php';
require_once 'includes/session.php';

// Require user to be logged in
requireLogin();

$current_user = getCurrentUser();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - PHP MySQL Auth</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="dashboard">
            <h2>Welcome to Your Dashboard</h2>
            
            <div class="user-info">
                <h3>User Information</h3>
                <p><strong>User ID:</strong> <?php echo $current_user['id']; ?></p>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($current_user['username']); ?></p>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($current_user['email']); ?></p>
                <p><strong>Login Time:</strong> <?php echo date('Y-m-d H:i:s', $_SESSION['login_time']); ?></p>
            </div>
            
            <div class="actions">
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
    </div>
</body>
</html>
```

## Step 8: Logout (logout.php)

```php
<?php
require_once 'includes/session.php';
require_once 'includes/cookies.php';

// Clear remember me cookie
clearRememberMeCookie();

// Logout user
logoutUser();

// Redirect to login page
header('Location: login.php');
exit;
?>
```

## Step 9: Basic Styling (style.css)

```css
body {
    font-family: Arial, sans-serif;
    background-color: #f4f4f4;
    margin: 0;
    padding: 20px;
}

.container {
    max-width: 600px;
    margin: 0 auto;
    background: white;
    padding: 30px;
    border-radius: 10px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
}

.form-container h2 {
    text-align: center;
    color: #333;
    margin-bottom: 30px;
}

.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 5px;
    color: #555;
    font-weight: bold;
}

.form-group input[type="text"],
.form-group input[type="email"],
.form-group input[type="password"] {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 5px;
    font-size: 16px;
    box-sizing: border-box;
}

button {
    width: 100%;
    padding: 12px;
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 5px;
    font-size: 16px;
    cursor: pointer;
}

button:hover {
    background-color: #0056b3;
}

.error {
    background-color: #f8d7da;
    color: #721c24;
    padding: 10px;
    border-radius: 5px;
    margin-bottom: 20px;
    border: 1px solid #f5c6cb;
}

.success {
    background-color: #d4edda;
    color: #155724;
    padding: 10px;
    border-radius: 5px;
    margin-bottom: 20px;
    border: 1px solid #c3e6cb;
}

.dashboard {
    text-align: center;
}

.user-info {
    background-color: #f8f9fa;
    padding: 20px;
    border-radius: 5px;
    margin: 20px 0;
    text-align: left;
}

.logout-btn {
    display: inline-block;
    padding: 10px 20px;
    background-color: #dc3545;
    color: white;
    text-decoration: none;
    border-radius: 5px;
    margin-top: 20px;
}

.logout-btn:hover {
    background-color: #c82333;
}

p {
    text-align: center;
    margin-top: 20px;
}

a {
    color: #007bff;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}
```

## Testing Instructions

1. **Setup Environment:**
   - Start XAMPP/WAMP/MAMP
   - Create the database using the SQL provided
   - Place all files in your web server directory (htdocs for XAMPP)

2. **Test Registration:**
   - Go to `http://localhost/your-project/register.php`
   - Create a new user account
   - Verify success message appears

3. **Test Login:**
   - Go to `http://localhost/your-project/login.php`
   - Login with your credentials
   - Try the "Remember Me" feature

4. **Test Sessions:**
   - After logging in, navigate to dashboard
   - Open a new tab and go directly to dashboard - you should stay logged in
   - Close browser and reopen - if you checked "Remember Me", you should auto-login

5. **Test Logout:**
   - Click logout and verify you're redirected to login page
   - Try accessing dashboard directly - you should be redirected to login

## Key Learning Points

1. **Database Connection:** Using PDO for secure database connections
2. **Password Security:** Using `password_hash()` and `password_verify()`
3. **Sessions:** Managing user state across pages
4. **Cookies:** Implementing "Remember Me" functionality
5. **Security:** Basic input validation and XSS prevention with `htmlspecialchars()`
6. **Error Handling:** Using try-catch blocks for database operations

## Next Steps for Enhancement

- Add email verification
- Implement password reset functionality
- Add CSRF protection
- Use prepared statements for all database queries
- Store remember tokens in database instead of files
- Add input sanitization
- Implement rate limiting for login attempts

This tutorial provides a solid foundation for understanding PHP-MySQL integration with user authentication!