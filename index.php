<?php
session_start();
require_once "db.php";
if (isset($_SESSION["user_id"], $_SESSION["role"])) {
    header(
        "Location: " .
        ($_SESSION["role"] === "admin" ? "home2.php" : "home.php")
    );
    exit;
}
$error = "";
$success = "";
$page = $_GET["page"] ?? "login";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $action = $_POST["action"] ?? "";
        // REGISTRATION
    if ($action === "register") {
        $username = trim($_POST["username"] ?? "");
        $password = $_POST["password"] ?? "";
        $confirm = $_POST["confirm_password"] ?? "";
        $role = "user";
        $page = "register";
        if ($username === "" || $password === "" || $confirm === "") {
            $error = "All fields are required.";
        } elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
            $error = "Username must be 3-50 characters using letters, numbers, or underscores.";
        } elseif (strlen($password) < 8) {
            $error = "Password must be at least 8 characters.";
        } elseif ($password !== $confirm) {
            $error = "Passwords do not match.";
        } else {
            $check = $conn->prepare(
                "SELECT id FROM users WHERE username = ? LIMIT 1"
            );
            $check->bind_param("s", $username);
            $check->execute();
            $check->store_result();
            if ($check->num_rows > 0) {
                $error = "Username already exists.";
            } else {
                $hashedPassword = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );
                $stmt = $conn->prepare(
                    "INSERT INTO users (username, password, role)
                     VALUES (?, ?, ?)"
                );
                $stmt->bind_param("sss", $username, $hashedPassword, $role);

                if ($stmt->execute()) {
                    $success = "Registration successful. You can now log in.";
                    $page = "login";
                } else {
                    $error = "Registration failed. Please try again.";
                }
                $stmt->close();
            }
            $check->close();
        }
        // LOGIN
    } elseif ($action === "login") {
        $username = trim($_POST["username"] ?? "");
        $password = $_POST["password"] ?? "";
        $page = "login";
        if ($username === "" || $password === "") {
            $error = "Please fill in all fields.";
        } else {
            $stmt = $conn->prepare(
                "SELECT id, username, password, role
                 FROM users
                 WHERE username = ?
                 LIMIT 1"
            );
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            if ($user && password_verify($password, $user["password"])) {
                session_regenerate_id(true);
                $_SESSION["user_id"] = $user["id"];
                $_SESSION["username"] = $user["username"];
                $_SESSION["role"] = $user["role"];
                header(
                    "Location: " .
                    ($user["role"] === "admin" ? "home2.php" : "home.php")
                );
                exit;
            } else {
                $error = "Invalid username or password.";
            }
            $stmt->close();
        }
    } else {
        $error = "Invalid request.";
    }
}
if ($page !== "register") {
    $page = "login";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $page === "register" ? "Create Account" : "Login" ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body class="auth-page">
    <main class="auth-card">
        <div class="auth-heading">
            <h1><?= $page === "register" ? "Create Account" : "Welcome Back" ?></h1>
            <p>
                <?= $page === "register"
                    ? "Register to create your account."
                    : "Log in to continue to your account." ?>
            </p>
        </div>
        <?php if ($error !== ""): ?>
            <div class="message error-message">
                <?= htmlspecialchars($error, ENT_QUOTES, "UTF-8") ?>
            </div>
        <?php endif; ?>
        <?php if ($success !== ""): ?>
            <div class="message success-message">
                <?= htmlspecialchars($success, ENT_QUOTES, "UTF-8") ?>
            </div>
        <?php endif; ?>
        <?php if ($page === "register"): ?>
            <form method="POST" action="index.php?page=register">
                <input type="hidden" name="action" value="register">
                <div class="form-group">
                    <label for="register-username">Username</label>
                    <input
                        type="text"
                        id="register-username"
                        name="username"
                        placeholder="Choose a username"
                        minlength="3"
                        maxlength="50"
                        pattern="[a-zA-Z0-9_]+"
                        autocomplete="username"
                        required
                    >
                </div>
                <div class="form-group">
                    <label for="register-password">Password</label>
                    <input
                        type="password"
                        id="register-password"
                        name="password"
                        placeholder="At least 8 characters"
                        minlength="8"
                        autocomplete="new-password"
                        required
                    >
                </div>
                <div class="form-group">
                    <label for="confirm-password">Confirm Password</label>
                    <input
                        type="password"
                        id="confirm-password"
                        name="confirm_password"
                        placeholder="Enter your password again"
                        minlength="8"
                        autocomplete="new-password"
                        required
                    >
                </div>
                <button class="primary-button" type="submit">
                    Create Account
                </button>
            </form>
            <p class="form-footer">
                Already have an account?
                <a href="index.php">Log in</a>
            </p>
        <?php else: ?>
            <form method="POST" action="index.php">
                <input type="hidden" name="action" value="login">
                <div class="form-group">
                    <label for="login-username">Username</label>
                    <input
                        type="text"
                        id="login-username"
                        name="username"
                        placeholder="Enter your username"
                        maxlength="50"
                        autocomplete="username"
                        required
                    >
                </div>
                <div class="form-group">
                    <label for="login-password">Password</label>
                    <input
                        type="password"
                        id="login-password"
                        name="password"
                        placeholder="Enter your password"
                        autocomplete="current-password"
                        required
                    >
                </div>
                <button class="primary-button" type="submit">
                    Log In
                </button>
            </form>
            <p class="form-footer">
                Don't have an account?
                <a href="index.php?page=register">Create one</a>
            </p>
        <?php endif; ?>
    </main>
</body>
</html>