const express = require("express");
const path = require("path");
const crypto = require("crypto");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs"); // Untuk hash password
const jwt = require("jsonwebtoken"); // Untuk auth admin

const app = express();
const port = 3000;
const JWT_SECRET = "SIMPAN PASSWORD KAMU ULAH DI BERE KASASAHA"; // Ganti dengan secret acak Anda

// --- 1. KONFIGURASI DATABASE ---
// Pastikan detail ini sesuai dengan MySQL Workbench Anda
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  port: 3308, // Port Anda
  password: "MySqlaku123", // Password Anda
  database: "apikeyprojectpertemuan8", // Nama DB Anda yang baru
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Tes koneksi pool saat server start
(async () => {
  try {
    await pool.query("SELECT 1");
    console.log(
      "Successfully connected to MySQL database (apikeyprojectpertemuan8)."
    );
  } catch (err) {
    console.error("Error connecting to MySQL:", err);
  }
})();

// --- 2. MIDDLEWARE ---
app.use(express.json()); // Untuk membaca body JSON
app.use(express.static(path.join(__dirname, "public"))); // Melayani file HTML/CSS/JS

// --- 3. ENDPOINT PUBLIK (Tidak Perlu Login) ---

// Route utama untuk menyajikan halaman HTML
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Endpoint untuk Validasi Key (Publik)
// Memeriksa apakah sebuah API key ada di tabel 'users'
app.post("/check", async (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) {
    return res.status(400).json({ error: "API key tidak ada di body" });
  }
  try {
    const sqlQuery = "SELECT COUNT(*) AS count FROM users WHERE api_key = ?";
    const [results] = await pool.query(sqlQuery, [apiKey]);
    const isFound = results[0].count > 0;

    if (isFound) {
      res.status(200).json({ valid: true, message: "API key valid" });
    } else {
      res.status(401).json({ valid: false, message: "API key tidak valid" });
    }
  } catch (error) {
    console.error("Gagal mengecek key:", error);
    res.status(500).json({ error: "Gagal memvalidasi key di server" });
  }
});

// Endpoint Generate Key (Sesuai C2)
// Ini hanya menghasilkan string key, tidak menyimpannya
app.get("/generate_key", (req, res) => {
  try {
    const randomBytes = crypto.randomBytes(32);
    const token = randomBytes.toString("base64url");
    const stamp = Date.now().toString();
    const apiKey = `apipi_${token}_${stamp}`;
    res.status(200).json({ apiKey: apiKey });
  } catch (error) {
    console.error("Gagal generate key:", error);
    res.status(500).json({ error: "Gagal generate key string" });
  }
});

// --- 4. ENDPOINT AUTH ADMIN (Sesuai C5) ---

// Register Admin
app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email dan password diperlukan" });
  }

  try {
    // Hash password sebelum disimpan
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO admins (email, password) VALUES (?, ?)";
    await pool.query(sql, [email, hashedPassword]);
    res.status(201).json({ message: "Admin berhasil terdaftar" });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Email admin sudah terdaftar" });
    }
    console.error("Gagal register admin:", error);
    res.status(500).json({ error: "Gagal mendaftarkan admin" });
  }
});

// Login Admin
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email dan password diperlukan" });
  }

  try {
    // 1. Cari admin berdasarkan email
    const sql = "SELECT * FROM admins WHERE email = ?";
    const [admins] = await pool.query(sql, [email]);
    if (admins.length === 0) {
      return res.status(401).json({ error: "Email atau password salah" });
    }

    const admin = admins[0];

    // 2. Bandingkan password yang diinput dengan hash di DB
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Email atau password salah" });
    }

    // 3. Buat token JWT jika password cocok
    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, {
      expiresIn: "1h", // Token berlaku 1 jam
    });

    res.status(200).json({ message: "Login berhasil", token: token });
  } catch (error) {
    console.error("Gagal login:", error);
    res.status(500).json({ error: "Gagal login" });
  }
});

// --- 5. MIDDLEWARE OTENTIKASI (Pengecek Admin) ---
// Fungsi ini akan dipakai untuk melindungi endpoint admin
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Format: "Bearer TOKEN"

  if (token == null) {
    return res.status(401).json({ error: "Akses ditolak: Tidak ada token" });
  }

  jwt.verify(token, JWT_SECRET, (err, admin) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Akses ditolak: Token tidak valid" });
    }
    // Jika valid, simpan data admin di request untuk dipakai nanti
    req.admin = admin;
    next(); // Lanjutkan ke endpoint yang dituju
  });
}

// --- 6. ENDPOINT ADMIN (CRU[D] - Dilindungi Auth) ---

// Create User (Sesuai C4)
// Endpoint ini dilindungi oleh middleware 'authenticateToken'
app.post("/users", async (req, res) => {
  // Ambil data user dari body
  const { firstName, lastName, email, apiKey } = req.body;

  // Validasi (Sesuai C4: "kolo apikeynya harus diisi")
  if (!firstName || !lastName || !email || !apiKey) {
    return res.status(400).json({
      error: "Semua field (firstName, lastName, email, apiKey) harus diisi",
    });
  }

  try {
    // Masukkan user baru ke tabel 'users'
    const sql =
      "INSERT INTO users (first_name, last_name, email, api_key) VALUES (?, ?, ?, ?)";
    await pool.query(sql, [firstName, lastName, email, apiKey]);
    res.status(201).json({ message: `User ${email} berhasil dibuat` });
  } catch (error) {
    // Tangani jika email atau API key sudah ada (karena keduanya UNIQUE)
    if (error.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ error: "Email atau API key sudah terdaftar." });
    }
    console.error("Gagal create user:", error);
    res.status(500).json({ error: "Gagal membuat user" });
  }
});

// Read Users (Sesuai C3)
// Endpoint ini juga dilindungi
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, first_name, last_name, email, api_key, status, created_at FROM users"
    );
    res.status(200).json(users); // Kirim daftar user sebagai JSON
  } catch (error) {
    console.error("Gagal list user:", error);
    res.status(500).json({ error: "Gagal mengambil list user" });
  }
});

// --- 7. MENJALANKAN SERVER ---
app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
