<?php
header('Content-Type: application/json');

// Kunci rahasia ini HARUS SAMA PERSIS dengan yang ada di validate-id.php
define('HMAC_SECRET_KEY', 'DeveloperNPSnpspro34521');

// Buat nonce yang aman secara kriptografis
$nonce = bin2hex(random_bytes(16));

// Buat tanda tangan HMAC untuk nonce tersebut
$signature = hash_hmac('sha256', $nonce, HMAC_SECRET_KEY);

// Kirim nonce dan tanda tangannya ke aplikasi
echo json_encode(['status' => 'success', 'nonce' => $nonce, 'signature' => $signature]);
?>