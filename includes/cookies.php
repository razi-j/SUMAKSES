<?php
function setRememberMe($user_id, $username)
{
    $token = bin2hex(random_bytes(32));
    $expire = time() + (30 * 24 * 60 * 60);
    setcookie(
        'remember_me',
        $token,
        [
            $expire,
            '/',
            '',
            false,
            true
        ]
    );

    $remember_data = [
        'user_id' => $user_id,
        'username' => $username,
        'token' => $token,
        'expire' => $expire,
    ];

    require 'database.php'; //require database to access pd-object

    try {
        $stmt_delete = $pdo->prepare("DELETE FROM remember_me_tokens WHERE user_id = :user_id");
        $stmt_delete->execute([':user_id' => $user_id]);
        $stmt = $pdo->prepare("INSERT INTO remember_me_tokens (username, user_id, token_hash, expire)
        values (:username,:user_id, :token,:expire)");
        $stmt->execute(
            [
                ':username' => $username,
                ':user_id' => $user_id,
                ':token_id' => $token,
                ':expire' => date('Y-m-d H:i:s', $expire),
            ]
        );
        echo "Successfully Saved Cookies.<br>";
    } catch (PDOException $e) {
        error_log("Error saving remember me token: " . $e->getMessage());
        echo "Error occured while saving login session.<br>";
    }
}

function checkRememberMe()
{
    require 'database.php'; //require database to access pd-object
    if (isset($_COOKIE['remember_me']) && !empty($_COOKIE['remember_me'])) {
        $token = $_COOKIE['remember_me'];
        try {
            $stmt = $pdo->prepare("SELECT username, user_id FROM remember_me_tokens where token_hash = :token");
            $stmt->execute([':token' => $token]);
            $data = $stmt->fetch();
            if ($data) {
                if (time() < strtotime($data['expires_at'])) {
                    $new_token = bin2hex(random_bytes(32));
                    $new_expire_timestamp = time() + (30 * 24 * 60 * 60);
                    $update_stmt = $pdo->prepare("UPDATE remember_me_tokens SET token_hash = :new_token, expires_at = :new_expires_at WHERE user_id = :user_id");
                    $update_stmt->execute([
                        ':new_token' => $new_token,
                        ':new_expires_at' => date('Y-m-d H:i:s', $new_expire_timestamp),
                        ':user_id' => $data['user_id']
                    ]);
                    setcookie(
                        'remember_me',
                        $new_token,
                        [
                            'expires' => $new_expire_timestamp,
                            'path' => '/',
                            'domain' => '',
                            'secure' => false, // <-- IMPORTANT: Set to true in production with HTTPS
                            'httponly' => true,
                        ]
                    );
                }
            }
        } catch (PDOException $e) {

            echo "Error " . $e->getMessage();
        }
    }
}
function clearRememberMe($user_id = null)
{
    setcookie('remember_me', '', time() - 3600, '/', '', false, true);
    require 'database.php';
    try {
        if ($user_id) {
            $stmt = $pdo->prepare("DELETE FROM remember_me_tokens WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);
        } else if (isset($_COOKIE['remember_me'])) {

            $cookie_token = $_COOKIE['remember_me'];
            $stmt = $pdo->prepare("DELETE FROM remember_me_tokens WHERE token_hash = :token_hash");
            $stmt->execute([':token_hash' => $cookie_token]);
        }
        echo "Cookies Cleared Successfully.<br>";
    } catch (PDOException $e) {
        error_log("Error clearing remember me token from DB: " . $e->getMessage());
        echo "An error occurred while clearing your login session.<br>";
    }
}
