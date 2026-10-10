<?php
session_start();
if (isset($_GET["logout"])) {
    $_SESSION = [];
    session_destroy();
    header("Location: index.php");
    exit;
}
if (!isset($_SESSION["user_id"]) || !isset($_SESSION["role"])) {
    header("Location: index.php");
    exit;
}
if ($_SESSION["role"] !== "user") {
    header("Location: home2.php");
    exit;
}
$username = htmlspecialchars(
    $_SESSION["username"] ?? "",
    ENT_QUOTES,
    "UTF-8"
);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Homepage</title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="dashboard">
    <main class="main">
        <header class="header">
            <div>
                <h1> User Dashboard</h1>
            </div>
        </header>
        <section class="welcome_user">
            <div>
                <h2>Welcome, <?php echo $username; ?>!</h2>
                <p>You are logged in as a regular user.</p>
            </div>
        </section>
        <section class="info">
            <h2>Account Information</h2>
            <p class="muted">Your current login details.</p>

            <div class="info-row">
                <span>Username</span>
                <strong><?php echo $username; ?></strong>
            </div>

            <div class="info-row">
                <span>Role</span>
                <strong><span class="role_user">User</span></strong>
            </div>

            <div class="info-row">
                <span>Account Status</span>
                <strong class="status">● Logged In</strong>
            </div>   
        </section>
        <div class="main-bottom">
                <p>Logged in as</p>
                <strong><?php echo $username; ?></strong>
                <a href="home.php?logout=1">Log Out</a>
        </div>
    </main>
</body>
</html>
