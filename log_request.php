<?php
    include("connection.php");
    $sql = "SELECT origin, payload, ip, created_at FROM logs";
    $result = mysqli_query($conn, $sql);
    $data = [];

    if (mysqli_num_rows($result) > 0) {
        while ($row = mysqli_fetch_assoc($result)) {
            $row['payload'] = htmlspecialchars($row['payload'], ENT_QUOTES, 'UTF-8');
            $data[] = $row;
        }
        echo json_encode($data);
    } else {
        echo json_encode(["message" => "No records found"]);
    }


?>