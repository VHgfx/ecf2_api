<?php
try {
    $database = new PDO('mysql:host=localhost;dbname=api_ecf;charset=utf8', 'root', '');

    $database->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

} catch (Exception $e) {
    die('Erreur : ' . $e->getMessage());
}