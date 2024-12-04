<?php
include 'db.php';

if (isset($_GET['token'])) {
    $token = $_GET['token'];
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE token = ? AND used = FALSE");
    $stmt->execute([$token]);
    $reset = $stmt->fetch();

    if ($reset && $reset['expires'] > date('U')) {
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $password = trim($_POST['password']);
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Update user password
            $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE username = ?");
            $stmt->execute([$hashedPassword, $reset['username']]);

            // Mark the token as used
            $stmt = $pdo->prepare("UPDATE password_resets SET used = TRUE WHERE token = ?");
            $stmt->execute([$token]);

            echo "Password has been reset successfully!";
        }
    } else {
        echo "Invalid or expired token!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h2>Reset Password</h2>
        <form action="reset_password.php?token=<?php echo htmlspecialchars($token); ?>" method="POST">
            <label for="password">New Password:</label>
            <input type="password" name="password" required><br>
            <button type="submit">Reset Password</button>
        </form>
    </div>
</body>
</html>
