<?php
    include("connection.php");
    
    
    // function to log 
    function logLoginAttempts($payload, $origin) {
        $user_ip = $_SERVER['REMOTE_ADDR'];
        include("connection.php");
        $stmt = $conn->prepare("INSERT INTO logs (payload, origin, ip) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $payload, $origin, $user_ip);
        $stmt->execute();
    }

    if(isset($_POST['login'])){
        $username = $_POST["username"];
        $password = $_POST["password"];

        // log the username
        logLoginAttempts($username, 'login');
        $sql = "select * from users where username = '$username' and password = '$password'";

        $result = mysqli_query($conn,  $sql);
        $count = mysqli_num_rows($result);


        
        if($count==1){
            session_start();
            $_SESSION['username'] = $username;
            setcookie("user", "$username", time() + 3600, "/"); 
            header("Location:homepage.html");
            exit;
        }
        else{
            echo '<script>
            window.location.href = "login.html";
            alert("Login failed. Invalid username or password")
            </script>';
            }
            exit;
    }

   
    if (isset($_POST['signup'])){
        $username = $_POST['username'];
        $password = $_POST['password'];

        $sql = "INSERT INTO users (username, password) VALUES('$username', '$password')";
        $result = mysqli_query($conn, $sql);
        
        if($result){
            header("Location:login.html");
            exit;
        }
        else{
            echo '<script>
            alert("Unable to create the user")
            </script>';
            exit;
        }
    }
    echo '1';
    if(isset($_POST['change'])){
        $password = $_POST['password']; 
        $confirm_password = $_POST['confirm_password'];
        echo '2';
        //validate input
        if(empty($password) || empty($confirm_password)) {
            echo "Both fields are required";
            exit;
        }

        if ($password !== $confirm_password) {
            echo "passwords do not match.";
            exit;
        }

        session_start();
        $username = $_SESSION['username'];
        $query = "UPDATE users SET password = '$password' where username = '$username'";
        $result = mysqli_query($conn,  $query);
        header("Location:login.html");
        exit;

    }   
    echo '3';

?>