import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

const pool = mysql.createPool({
  host:               process.env.DB_HOST     || "localhost",
  user:               process.env.DB_USER     || "root",
  password:           process.env.DB_PASSWORD || "",
  database:           process.env.DB_NAME     || "inventory",
  connectionLimit:    20,    // ✅ Giảm từ 40 → 20
                             //    Sau khi dùng query() đúng cách, 20 là thừa cho 200 user
  queueLimit:         200,
  waitForConnections: true,
  connectTimeout:     10_000,
  idleTimeout:        30_000,
  enableKeepAlive:    true,
  keepAliveInitialDelay: 0,
  charset:  "utf8mb4",
  timezone: "+07:00",
});

// ✅ FIX CHÍNH: mỗi connection mới tạo ra sẽ tự bị MySQL kill
// sau 5 phút Sleep — đây là nguyên nhân gây Sleep 6000+ giây
pool.on("connection", (conn) => {
  conn.query("SET SESSION wait_timeout = 300, interactive_timeout = 300");
});

pool.getConnection()
  .then(conn => {
    console.log("✅ MySQL pool connected (limit=20, queue=200)");
    conn.release();
  })
  .catch(err => {
    console.error("❌ MySQL pool error:", err.message);
  });

// Ping giữ connection sống
setInterval(async () => {
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.ping();
  } catch (e) {
    console.warn("⚠️ Pool ping failed:", e.message);
  } finally {
    if (conn) conn.release();
  }
}, 5 * 60_000);

// Monitor
setInterval(() => {
  const used   = pool.pool._allConnections.length;
  const free   = pool.pool._freeConnections.length;
  const queued = pool.pool._connectionQueue.length;
  const limit  = pool.pool.config.connectionLimit;
  const pct    = Math.round((used / limit) * 100);
  console.log(`📊 [Pool] ${used}/${limit} (${pct}%) | Free: ${free} | Queued: ${queued}`);
  if (queued > 0) console.warn(`⚠️ [Pool] Queued: ${queued}`);
  if (pct >= 80)  console.warn(`⚠️ [Pool] High: ${pct}%`);
}, 30_000);

/**
 * Query đơn — tự động lấy và release connection ngay sau khi xong.
 * Dùng hàm này cho mọi query SELECT, INSERT, UPDATE, DELETE đơn lẻ.
 */
export async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/**
 * Transaction — tự động commit / rollback / release.
 * Dùng khi nhiều query phải chạy cùng nhau (all-or-nothing).
 */
export async function transaction(callback) {
  const conn = await pool.getConnection();
  await conn.beginTransaction();
  try {
    const result = await callback(conn);
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * Dùng khi cần nhiều query trên cùng 1 connection NHƯNG không phải transaction.
 * Tự động release sau khi callback xong.
 */
export async function withConnection(callback) {
  const conn = await pool.getConnection();
  try {
    return await callback(conn);
  } finally {
    conn.release();
  }
}

export { pool };