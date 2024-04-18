<?php
// Check if the request method is POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve the new username and password from the POST data
    $username = $_POST['new-username'];
    $password = $_POST['new-password'];

    // Establish a connection to the MySQL database
    $conn = new mysqli('localhost', 'root', '', 'capstone');

    // Check if the connection was successful
    if ($conn->connect_error) {
        // If connection fails, terminate script and output an error message
        die("Connection failed: " . $conn->connect_error);
    }

    // Hash the password using the PASSWORD_DEFAULT algorithm
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepare an SQL statement to insert username and hashed password into the users table
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    // Bind the parameters to the prepared statement
    $stmt->bind_param("ss", $username, $hashed_password);

    // Execute the prepared statement
    if ($stmt->execute()) {
        // If execution is successful, echo a JSON-encoded success message
        echo json_encode(array("success" => true, "message" => "Account created successfully!"));
    } else {
        // If execution fails, echo a JSON-encoded error message
        echo json_encode(array("success" => false, "message" => "Error creating account."));
    }

    // Close the prepared statement
    $stmt->close();
    // Close the database connection
    $conn->close();
}
?>
