<?php
    include("connection.php");

    // Query to fetch all messages ordered by the creation time
    $sql = "SELECT username, message, created_at FROM messages ORDER BY created_at ASC";
    $result = $conn->query($sql);

    // Check if there are messages
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo "<p><strong>" . $row['username'] . ":</strong> " . $row['message'] . " <em>[" . $row['created_at'] . "]</em></p>";
        }
    } else {
        echo "<p>No messages yet!</p>";
    }

    $conn->close();
?>
