<?php
header('Content-Type: application/json');

// Mulai sesi jika Anda masih menggunakan get-nonce.php versi lama,
// atau hapus jika sudah beralih sepenuhnya ke HMAC.
// Untuk amannya, kita sertakan.
session_start();

// Kunci rahasia ini HARUS SAMA PERSIS dengan yang ada di get-nonce.php
define('HMAC_SECRET_KEY', 'DeveloperNPSnpspro34521');

$common_app_rules = [
    'app_name' => 'Master Wood',
   // 'version_name' => '2.1.8',
   // 'version_code' => 218,
    'package_name' => 'com.npsprostudio.masterwood',
];

$devices_file_path = __DIR__ . '/../../private_data_masterwood231/devices.json';
$devices_json = @file_get_contents($devices_file_path); // Gunakan @ untuk menekan warning jika file belum ada
$allowed_devices = $devices_json ? json_decode($devices_json, true) : [];
if ($allowed_devices === null) $allowed_devices = [];

$data = json_decode(file_get_contents('php://input'), true);

if ($data === null) {
    echo json_encode(['status' => 'failed', 'message' => 'Invalid JSON received.']);
    exit();
}

// --- BAGIAN YANG HILANG: VALIDASI KEAMANAN AWAL ---

// 1. Validasi Nonce & Signature
$sent_nonce = isset($data['nonce']) ? $data['nonce'] : null;
$sent_signature = isset($data['signature']) ? $data['signature'] : null;

if ($sent_nonce === null || $sent_signature === null) {
    echo json_encode(['status' => 'failed', 'message' => 'Sesi tidak valid atau terdeteksi adanya replay attack.']);
    exit();
}

$expected_signature = hash_hmac('sha256', $sent_nonce, HMAC_SECRET_KEY);
if (!hash_equals($expected_signature, $sent_signature)) {
    echo json_encode(['status' => 'failed', 'message' => 'Tanda tangan sesi tidak valid.']);
    exit();
}

// 2. Validasi Laporan Deteksi Klien
if (isset($data['is_rooted']) && $data['is_rooted']) {
    echo json_encode(['status' => 'failed', 'message' => 'Akses ditolak. Perangkat terdeteksi di-root.']);
    exit();
}
if (isset($data['is_hooked']) && $data['is_hooked']) {
    echo json_encode(['status' => 'failed', 'message' => 'Akses ditolak. Framework hooking terdeteksi.']);
    exit();
}
if (isset($data['is_emulator']) && $data['is_emulator']) {
    echo json_encode(['status' => 'failed', 'message' => 'Akses ditolak. Aplikasi tidak dapat berjalan di emulator.']);
    exit();
}

// --- BAGIAN YANG HILANG: VALIDASI METADATA & PENCARIAN ALIAS ---

// Validasi Aturan Umum Aplikasi //versi, nama, versi kode, packaged
foreach ($common_app_rules as $key => $value) {
    if (!isset($data[$key]) || $data[$key] != $value) {
        echo json_encode(['status' => 'failed', 'message' => "Metadata aplikasi tidak valid (gagal di '$key')."]);
        exit();
    }
}

// Ambil android_id yang dikirim
$sent_android_id = isset($data['android_id']) ? $data['android_id'] : null;
if (!$sent_android_id) {
    echo json_encode(['status' => 'failed', 'message' => 'Aplikasi tidak mengirimkan android_id.']);
    exit();
}

// Cari perangkat berdasarkan android_id
$found_alias = null;
foreach ($allowed_devices as $alias => $device_rules) {
    if (isset($device_rules['android_id']) && $device_rules['android_id'] === $sent_android_id) {
        $found_alias = $alias;
        break;
    }
}

// --- Sisa Kode (Sudah Benar di File Anda) ---
if ($found_alias) {
    $device_to_check = $allowed_devices[$found_alias];
    
    // Validasi penuh semua properti
        // Validasi penuh semua properti
    foreach ($device_to_check as $key => $value) {
        if ($key === 'expiry_date') {
            continue;
        }

        // --- TAMBAHAN LOGIKA DUAL HASH (LAMA & UPDATE) ---
        if ($key === 'apk_sha256') {
            // Ambil nilai hash update dari JSON jika ada (jika tidak ada, anggap string kosong)
            $hash_update = isset($device_to_check['apk_sha256_update']) ? $device_to_check['apk_sha256_update'] : '';
            
            // Cek: Apakah hash dari HP ($data['apk_sha256']) tidak cocok dengan KEDUANYA?
            if ($data['apk_sha256'] !== $value && $data['apk_sha256'] !== $hash_update) {
                $error_detail = "Gagal untuk '$found_alias': Hash APK tidak terdaftar (Versi Lama maupun Update tidak cocok).";
                echo json_encode(['status' => 'failed', 'message' => 'Server validation failed: ' . $error_detail]);
                exit();
            }
            continue; // Hash cocok dengan salah satu, lanjut ke properti berikutnya
        }

        // Abaikan kolom apk_sha256_update agar tidak dicek ulang secara general
        if ($key === 'apk_sha256_update') {
            continue;
        }
        // -------------------------------------------------

        if ($key === 'signature_hash') {
            if (!isset($data['signature_hash']) || !hash_equals((string)$value, (string)$data['signature_hash'])) {
                $error_detail = "Gagal untuk '$found_alias': Signature Hash aplikasi tidak cocok dengan yang terdaftar di server.";
                echo json_encode(['status' => 'failed', 'message' => 'Server validation failed: ' . $error_detail]);
                exit();
            }
            continue;
        }

        if (!isset($data[$key]) || $data[$key] != $value) {
            $error_detail = "Gagal untuk '$found_alias': Properti '$key' tidak cocok.";
            echo json_encode(['status' => 'failed', 'message' => 'Server validation failed: ' . $error_detail]);
            exit();
        }
    }


    // Pengecekan Expired Date
    $expiry_date_str = $device_to_check['expiry_date'];
    $expiry_timestamp = strtotime($expiry_date_str . ' 23:59:59');
    $current_timestamp = time();

    if ($current_timestamp > $expiry_timestamp) {
        echo json_encode(['status' => 'failed', 'message' => 'Aplikasi expired, silakan hubungi pengembang aplikasi untuk pembaruan.']);
    } else {
        echo json_encode(['status' => 'success', 'message' => 'Validasi berhasil untuk: ' . $found_alias]);
    }

} else {
    // KASUS PERANGKAT BARU
    $final_message = "Validasi gagal. Perangkat tidak diizinkan. Detail: Nilai 'android_id' tidak cocok ('{$sent_android_id}' vs 'belum terdaftar').";
    echo json_encode(['status' => 'failed', 'message' => $final_message]);
}
?>