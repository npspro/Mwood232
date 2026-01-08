<?php
header('Content-Type: application/json');

define('API_KEY', 'NPSproDeveloper12341234');

$data = json_decode(file_get_contents('php://input'), true);
$devices_file = __DIR__ . '/../../private_data_masterwood231/devices.json';

if ($data === null || !isset($data['api_key']) || $data['api_key'] !== API_KEY) {
    http_response_code(401);
    echo json_encode(['status' => 'failed', 'message' => 'Akses ditolak. API Key salah.']);
    exit();
}

$devices_content = file_get_contents($devices_file);
$devices = $devices_content ? json_decode($devices_content, true) : [];
if ($devices === null) $devices = [];

if (!isset($data['action'])) {
    http_response_code(400);
    echo json_encode(['status' => 'failed', 'message' => 'Aksi tidak ditemukan.']);
    exit();
}

$action = $data['action'];

if ($action === 'add_update') {
    if (!isset($data['alias']) || !isset($data['device_data'])) {
        http_response_code(400);
        echo json_encode(['status' => 'failed', 'message' => 'Alias atau data perangkat tidak ditemukan.']);
        exit();
    }

    // Validasi field-field wajib (Pastikan field utama tetap ada)
    // Field 'apk_sha256_update' tidak diwajibkan di sini agar tidak error jika Anda menambah perangkat lama
    if (!isset($data['device_data']['expiry_date']) || !isset($data['device_data']['signature_hash'])) {
        http_response_code(400);
        echo json_encode(['status' => 'failed', 'message' => 'Tanggal expired dan Signature Hash wajib diisi.']);
        exit();
    }

    $alias = $data['alias'];

    /** * PENJELASAN: 
     * Karena $data['device_data'] mengambil seluruh objek dari Android, 
     * maka field baru 'apk_sha256_update' yang Anda tambahkan di Java 
     * akan otomatis ikut tersimpan ke dalam file JSON tanpa perlu menulis kodenya satu per satu di sini.
     */
    $devices[$alias] = $data['device_data'];

    // Simpan ke file JSON
    file_put_contents($devices_file, json_encode($devices, JSON_PRETTY_PRINT | JSON_FORCE_OBJECT), LOCK_EX);
    
    echo json_encode([
        'status' => 'success', 
        'message' => "Perangkat '$alias' berhasil ditambahkan/diperbarui dengan dukungan Multi-Hash."
    ]);
} elseif ($action === 'delete') {
    if (!isset($data['alias'])) {
        http_response_code(400);
        echo json_encode(['status' => 'failed', 'message' => 'Alias tidak ditemukan.']);
        exit();
    }
    $alias = $data['alias'];
    if (isset($devices[$alias])) {
        unset($devices[$alias]);
        file_put_contents($devices_file, json_encode($devices, JSON_PRETTY_PRINT | JSON_FORCE_OBJECT), LOCK_EX);
        echo json_encode(['status' => 'success', 'message' => "Perangkat '$alias' berhasil dihapus."]);
    } else {
        http_response_code(404);
        echo json_encode(['status' => 'failed', 'message' => "Perangkat dengan alias '$alias' tidak ditemukan."]);
    }

} elseif ($action === 'get_all') {
    echo json_encode(['status' => 'success', 'devices' => (object)$devices]);
    
} else {
    http_response_code(400);
    echo json_encode(['status' => 'failed', 'message' => 'Aksi tidak dikenal.']);
}
?>