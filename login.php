<?php
require 'db_connection.php';
header('Content-Type: application/json');

$data = json_decode(file_get_contents("php://input"));

if (isset($data->username) && isset($data->password)) {
    $username = $data->username;
    $password = $data->password;

    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $hashed_password);
        $stmt->fetch();

        if (password_verify($password, $hashed_password)) {
            $session_token = bin2hex(random_bytes(32));
            $stmt = $conn->prepare("INSERT INTO sessions (user_id, session_token) VALUES (?, ?)");
            $stmt->bind_param("is", $id, $session_token);

            if ($stmt->execute()) {
                echo json_encode(["status" => "success", "message" => "Login successful", "token" => $session_token]);
            } else {
                echo json_encode(["status" => "error", "message" => "Failed to create session"]);
            }
        } else {
            echo json_encode(["status" => "error", "message" => "Invalid username or password"]);
        }
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid username or password"]);
    }

    $stmt->close();
} else {
    echo json_encode(["status" => "error", "message" => "Please fill in both fields"]);
}

$conn->close();
?>
