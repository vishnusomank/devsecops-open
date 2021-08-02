<?php
$XVWA_WEBROOT = "";
$host = "devsecops-db.ck7kirzv4mdo.us-east-2.rds.amazonaws.com";
$dbname = 'xvwa';
$user = "app";
$pass = "apppass@1";
$conn = new mysqli($host,$user,$pass,$dbname);
$conn1 = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);
$conn1->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
?>
