<?php
// Start a new session or resume the existing session
session_start();

// Check if the request method is POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve the username and password from the POST data
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Establish a connection to the MySQL database
    $conn = new mysqli('localhost', 'root', '', 'capstone');

    // Check if the connection was successful
    if ($conn->connect_error) {
        // If connection fails, terminate script and output an error message
        die("Connection failed: " . $conn->connect_error);
    }

    // Prepare an SQL statement to select username and password from users table
    $stmt = $conn->prepare("SELECT username, password FROM users WHERE username = ?");
    // Bind the username parameter to the prepared statement
    $stmt->bind_param("s", $username);
    // Execute the prepared statement
    $stmt->execute();
    // Get the result of the executed statement
    $result = $stmt->get_result();

    // Check if there is exactly one row returned
    if ($result->num_rows == 1) {
        // Fetch the row as an associative array
        $row = $result->fetch_assoc();
        // Verify the password using the stored hashed password
        if (password_verify($password, $row['password'])) {
            // If password is verified, set the username in the session
            $_SESSION['username'] = $row['username'];
            // Echo a JSON-encoded success message
            echo json_encode(array("success" => true, "message" => "Login successful!"));
        } else {
            // If password verification fails, echo a JSON-encoded error message
            echo json_encode(array("success" => false, "message" => "Invalid username or password."));
        }
    } else {
        // If no rows are returned, echo a JSON-encoded error message
        echo json_encode(array("success" => false, "message" => "Invalid username or password."));
    }

    // Close the prepared statement
    $stmt->close();
    // Close the database connection
    $conn->close();
}
?>
