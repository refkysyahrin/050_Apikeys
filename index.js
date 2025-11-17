const express = require("express");
const path = require("path");
const crypto = require("crypto");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = 3000;
const JWT_SECRET = "RAHASIA_ANDA_JANGAN_BAGIKAN_INI";

// --- 1. KONFIGURASI DATABASE ---
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  port: 3308,
  password: "MySqlaku123",
  database: "apikeyprojectpertemuan8",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

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
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --- 3. ENDPOINT PUBLIK ---

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Endpoint Validasi Key
app.post("/check", async (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) {
    return res.status(400).json({ error: "API key tidak ada di body" });
  }
  try {
    const sqlQuery =
      "SELECT COUNT(*) AS count FROM apikeys WHERE key_value = ? AND status = 'active'";
    const [results] = await pool.query(sqlQuery, [apiKey]);
    const isFound = results[0].count > 0;

    if (isFound) {
      res.status(200).json({ valid: true, message: "API key valid" });
    } else {
      res.status(401).json({ valid: false, message: "API key tidak valid" });
    }
  } catch (error) {
    res.status(500).json({ error: "Gagal memvalidasi key di server" });
  }
});

// Endpoint Generate Key
app.get("/generate_key", (req, res) => {
  try {
    const randomBytes = crypto.randomBytes(32);
    const token = randomBytes.toString("base64url");
    const stamp = Date.now().toString();
    const apiKey = `apipi_${token}_${stamp}`;
    res.status(200).json({ apiKey: apiKey });
  } catch (error) {
    res.status(500).json({ error: "Gagal generate key string" });
  }
});

// Endpoint Create User (Registrasi)
app.post("/users", async (req, res) => {
  const { firstName, lastName, email, apiKey } = req.body;

  if (!firstName || !lastName || !email || !apiKey) {
    return res.status(400).json({ error: "Semua field harus diisi" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const userSql =
      "INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)";
    const [userResult] = await connection.query(userSql, [
      firstName,
      lastName,
      email,
    ]);
    const newUserId = userResult.insertId;

    const keySql = "INSERT INTO apikeys (key_value, user_id) VALUES (?, ?)";
    await connection.query(keySql, [apiKey, newUserId]);

    await connection.commit();

    res.status(201).json({ message: `User ${email} berhasil dibuat` });
  } catch (error) {
    if (connection) await connection.rollback();

    if (error.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ error: "Email atau API key sudah terdaftar." });
    }
    console.error("Gagal create user:", error);
    res.status(500).json({ error: "Gagal membuat user" });
  } finally {
    if (connection) connection.release();
  }
});

// --- 4. ENDPOINT AUTH ADMIN ---

// (Blok duplikat yang kosong sudah dihapus)

app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email dan password diperlukan" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO admins (email, password) VALUES (?, ?)";
    await pool.query(sql, [email, hashedPassword]);
    res.status(201).json({ message: "Admin berhasil terdaftar" });
  } catch (error) {
    // Tambahkan penanganan error duplikat untuk admin juga
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Email admin sudah terdaftar." });
    }
    console.error("Gagal register admin:", error);
    res.status(500).json({ error: "Gagal mendaftarkan admin" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const sql = "SELECT * FROM admins WHERE email = ?";
    const [admins] = await pool.query(sql, [email]);
    if (admins.length === 0) {
      return res.status(401).json({ error: "Email atau password salah" });
    }
    const admin = admins[0];
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Email atau password salah" });
    }
    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ message: "Login berhasil", token: token });
  } catch (error) {
    console.error("Gagal login:", error);
    res.status(500).json({ error: "Gagal login" });
  }
});

// --- 5. MIDDLEWARE OTENTIKASI ---

// (Blok duplikat yang kosong sudah dihapus)

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401); // Tidak ada token

  jwt.verify(token, JWT_SECRET, (err, admin) => {
    if (err) return res.sendStatus(403); // Token salah/expired
    req.admin = admin;
    next();
  });
}

// --- 6. ENDPOINT ADMIN (Dilindungi Auth) ---

app.get("/users", authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, first_name, last_name, email, created_at FROM users"
    );
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ error: "Gagal mengambil list user" });
  }
});

app.get("/apikeys", authenticateToken, async (req, res) => {
  try {
    const sql = `
            SELECT 
                apikeys.id, 
                apikeys.key_value, 
                apikeys.status, 
                apikeys.created_at, 
                users.email AS owner_email
            FROM apikeys
            JOIN users ON apikeys.user_id = users.id
            ORDER BY apikeys.created_at DESC
        `;
    const [keys] = await pool.query(sql);
    res.status(200).json(keys);
  } catch (error) {
    console.error("Gagal list apikeys:", error);
    res.status(500).json({ error: "Gagal mengambil list API keys" });
  }
});

// --- 7. MENJALANKAN SERVER ---
app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
