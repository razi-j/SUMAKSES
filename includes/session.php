<?php
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

function isloggedIn()
{
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

function getCurrentUser()
{
    if (isloggedIn()) {
        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'email' => $_SESSION['email']
        ];
    }
    return null;
}

function loginUser($user_data) //array of user's data.
{
    $_SESSION['user_id'] = $user_data['id'];
    $_SESSION['username'] = $user_data['username'];
    $_SESSION['email'] = $user_data['email'];
    $_SESSION['login_time'] = time();
}

function logoutUser()
{
    $_SESSION = array(); // clear session Array   

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
}

function requireLogin()
{
    if (!isloggedIn()) {
        header("Location: ./login.php");
    }
}
