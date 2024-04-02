<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['new-username'];
    $password = $_POST['new-password'];

    $conn = new mysqli('localhost', 'root', '', 'capstone');

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $hashed_password);

    if ($stmt->execute()) {
        echo json_encode(array("success" => true, "message" => "Account created successfully!"));
    } else {
        echo json_encode(array("success" => false, "message" => "Error creating account."));
    }

    $stmt->close();
    $conn->close();
}
?>
