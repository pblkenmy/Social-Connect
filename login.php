<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $conn = new mysqli('localhost', 'root', '', 'capstone');

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT username, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row['password'])) {
            $_SESSION['username'] = $row['username'];
            echo json_encode(array("success" => true, "message" => "Login successful!"));
        } else {
            echo json_encode(array("success" => false, "message" => "Invalid username or password."));
        }
    } else {
        echo json_encode(array("success" => false, "message" => "Invalid username or password."));
    }

    $stmt->close();
    $conn->close();
}
?>
