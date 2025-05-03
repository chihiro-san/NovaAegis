<?php
    include("connection.php");
    // function to log
    function logXSSAttempts($payload, $origin) {
        include("connection.php");
        $user_ip = $_SERVER['REMOTE_ADDR'];
        $stmt = $conn->prepare("INSERT INTO logs (payload, origin, ip) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $payload, $origin, $user_ip);
        $stmt->execute();
    }
    session_start();

    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['message'])) {
        // Get the username and message from POST data
        $username = $_SESSION["username"];
        $message = $_POST['message'];
        logXSSAttempts($message, "Internal chat app");
        // Insert the message into the database
        $sql = "INSERT INTO messages (username, message) VALUES (?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $username, $message);

        // Execute the statement
        if ($stmt->execute()) {
            echo "Message sent!";
        } else {
            echo "Error: " . $stmt->error;
        }

        $stmt->close();
        $conn->close();
    }
?>
