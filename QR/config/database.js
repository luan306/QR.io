import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

// ══════════════════════════════════════════════════════════
//  POOL CONFIG
//  200 thiết bị đồng thời scan:
//  - Mỗi scan chỉ giữ connection ~5-10ms
//  - Với 30 connection, throughput = 30 / 0.01s = 3000 req/s → thừa
//  - queueLimit 500: request xếp hàng thay vì bị reject
// ══════════════════════════════════════════════════════════
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || "localhost",
  user:               process.env.DB_USER     || "root",
  password:           process.env.DB_PASSWORD || "",
  database:           process.env.DB_NAME     || "inventory",
  port:               process.env.DB_PORT     || 3306,
  connectionLimit:    30,     // tăng từ 20 → 30 cho 200 user đồng thời
  queueLimit:         500,    // tăng từ 200 → 500 để không reject lúc spike
  waitForConnections: true,
  connectTimeout:     10_000,
  idleTimeout:        60_000, // tăng từ 30s → 60s: giảm tạo lại connection liên tục
  enableKeepAlive:    true,
  keepAliveInitialDelay: 10_000,
  charset:  "utf8mb4",
  timezone: "+07:00",
});

// Set timeout cho mỗi connection mới
pool.on("connection", (conn) => {
  conn.query("SET SESSION wait_timeout = 300, interactive_timeout = 300");
});

pool.getConnection()
  .then(conn => {
    console.log("✅ MySQL pool connected (limit=30, queue=500)");
    conn.release();
  })
  .catch(err => {
    console.error("❌ MySQL pool error:", err.message);
  });

// ── Ping giữ ít nhất 1 connection sống — KHÔNG dùng getConnection
// pool.execute() tự lấy connection từ pool mà không chiếm slot cho lâu
setInterval(async () => {
  try {
    await pool.execute("SELECT 1");
  } catch (e) {
    console.warn("⚠️ Pool keepalive failed:", e.message);
  }
}, 4 * 60_000); // mỗi 4 phút (< wait_timeout 5 phút)

// ── Monitor — dùng pool.pool.config thay vì private _allConnections
setInterval(() => {
  try {
    const p      = pool.pool;
    const used   = p._allConnections?.length   ?? 0;
    const free   = p._freeConnections?.length  ?? 0;
    const queued = p._connectionQueue?.length  ?? 0;
    const limit  = p.config?.connectionLimit   ?? 30;
    const pct    = limit > 0 ? Math.round((used / limit) * 100) : 0;
    console.log(`📊 [Pool] ${used}/${limit} (${pct}%) | Free: ${free} | Queued: ${queued}`);
    if (queued > 10) console.warn(`⚠️ [Pool] High queue: ${queued}`);
    if (pct >= 90)   console.warn(`⚠️ [Pool] Critical: ${pct}%`);
  } catch { /* mysql2 version không có private API — bỏ qua */ }
}, 30_000);

/**
 * Query đơn — pool.execute() tự lấy + release connection.
 * KHÔNG dùng getConnection() cho query đơn lẻ.
 */
export async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/**
 * Transaction — commit / rollback / release tự động.
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
 * Nhiều query cùng connection, không phải transaction.
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