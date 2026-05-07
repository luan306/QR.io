import express from "express";
import { query, transaction, withConnection } from "../config/database.js";

const router = express.Router();

/* ============================================================
   GET /api/scans  — danh sách scans (có pagination)
   ============================================================ */
router.get("/", async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit  || 200), 500);
    const offset = parseInt(req.query.offset || 0);

    // ✅ query() tự lấy + release connection ngay sau khi xong
    const rows = await query(`
      SELECT
        s.id,
        d.qr_code,
        d.name          AS device_name,
        dep_d.name      AS device_department,
        dep_s.name      AS scan_department,
        u.full_name     AS user_name,
        s.scanned_at,
        CASE
          WHEN d.department_id = s.scan_department THEN 'Đúng bộ phận'
          ELSE CONCAT('Chuyển từ ', dep_d.name, ' → ', dep_s.name)
        END             AS status
      FROM scans s
      JOIN  devices     d     ON d.id    = s.device_id
      JOIN  users       u     ON u.id    = s.user_id
      LEFT JOIN departments dep_d ON dep_d.id = d.department_id
      LEFT JOIN departments dep_s ON dep_s.id = s.scan_department
      ORDER BY s.scanned_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `);
    return res.json(rows);
  } catch (err) {
    console.error("GET SCANS ERROR:", err);
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   DELETE /api/scans — xóa toàn bộ scans
   ============================================================ */
router.delete("/", async (req, res) => {
  try {
    await query(`DELETE FROM scans`);
    return res.json({ success: true, message: "Đã xóa toàn bộ lịch sử quét" });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

/* ============================================================
   GET /api/scans/export — xuất Excel
   ============================================================ */
router.get("/export", async (req, res) => {
  try {
    const rows = await query(`
      SELECT
        d.qr_code,
        d.name          AS device_name,
        dep_d.name      AS device_department,
        dep_s.name      AS scan_department,
        u.full_name     AS user_name,
        s.scanned_at
      FROM scans s
      JOIN  devices     d     ON d.id    = s.device_id
      JOIN  users       u     ON u.id    = s.user_id
      LEFT JOIN departments dep_d ON dep_d.id = d.department_id
      LEFT JOIN departments dep_s ON dep_s.id = s.scan_department
      ORDER BY s.scanned_at DESC
      LIMIT 5000
    `);
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   GET /api/scan/user-scans/:dept_id
   ============================================================ */
router.get("/user-scans/:dept_id", async (req, res) => {
  try {
    const rows = await query(`
      SELECT
        s.id,
        d.qr_code,
        d.name      AS device_name,
        d.id        AS device_id,
        u.full_name AS scanned_by,
        s.scanned_at
      FROM scans s
      JOIN devices d ON d.id = s.device_id
      JOIN users   u ON u.id = s.user_id
      WHERE s.session_id IS NULL
        AND d.department_id = ?
      ORDER BY s.scanned_at DESC
      LIMIT 500
    `, [req.params.dept_id]);
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   GET /api/scan/session/:session_id
   ============================================================ */
router.get("/session/:session_id", async (req, res) => {
  try {
    const rows = await query(`
      SELECT
        s.id,
        d.qr_code,
        d.name       AS device_name,
        d.id         AS device_id,
        u.full_name  AS scanned_by,
        s.scanned_at
      FROM scans s
      JOIN devices d ON d.id = s.device_id
      JOIN users   u ON u.id = s.user_id
      WHERE s.session_id = ?
      ORDER BY s.scanned_at DESC
    `, [req.params.session_id]);
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   POST /api/scan  — quét thiết bị
   
   Tối ưu connection:
   - Mỗi SELECT dùng query() riêng → release ngay sau mỗi query
   - INSERT + UPDATE dùng transaction() → atomic, release sau khi xong
   - Tổng connection time giảm ~70% so với giữ 1 conn cho toàn bộ request
   ============================================================ */
router.post("/", async (req, res) => {
  try {
    const { qr_code, session_id } = req.body;
    const user_id = req.session?.user?.id;  // lấy từ session, không tin client

    if (!user_id || !qr_code) {
      return res.json({ success: false, message: "Thiếu dữ liệu hoặc chưa đăng nhập" });
    }

    // Chuẩn hoá QR (Zebra đôi khi thêm $ ở cuối)
    const serial = (qr_code.includes("$") ? qr_code.split("$")[0] : qr_code).trim();

    // ── 1. Tìm thiết bị — query() tự release ngay ───────────────
    const [device] = await query(
      `SELECT d.id, d.name, d.qr_code, d.department_id, d.is_new,
              dt.name  AS device_type_name,
              dep.name AS department_name
       FROM devices d
       LEFT JOIN device_types  dt  ON dt.id  = d.device_type_id
       LEFT JOIN departments   dep ON dep.id = d.department_id
       WHERE d.qr_code = ?
       LIMIT 1`,
      [serial]
    );
    if (!device) {
      return res.json({ success: false, message: "Không tìm thấy thiết bị" });
    }

    // ── 2. Tìm user — query() tự release ngay ───────────────────
    const [user] = await query(
      `SELECT u.id, u.full_name, u.department_id,
              dep.name AS dept_name
       FROM users u
       LEFT JOIN departments dep ON dep.id = u.department_id
       WHERE u.id = ?
       LIMIT 1`,
      [user_id]
    );
    if (!user) {
      return res.json({ success: false, message: "Không tìm thấy user" });
    }

    // ── 3. Xác định bộ phận quét ─────────────────────────────────
    let scanDeptId   = user.department_id;
    let scanDeptName = user.dept_name || "-";

    if (session_id) {
      // query() tự release ngay sau khi lấy session
      const [sess] = await query(
        `SELECT as2.department_id, dep.name AS dept_name
         FROM audit_sessions as2
         LEFT JOIN departments dep ON dep.id = as2.department_id
         WHERE as2.id = ?
         LIMIT 1`,
        [session_id]
      );
      if (sess) {
        scanDeptId   = sess.department_id;
        scanDeptName = sess.dept_name || "-";
      }
    }

    const deviceDeptName = device.department_name || "-";
    const statusText     = String(device.department_id) !== String(scanDeptId)
      ? `Chuyển từ ${deviceDeptName} → ${scanDeptName}`
      : `Đang ở ${scanDeptName}`;

    // ── 4a. CHẾ ĐỘ AUDIT ─────────────────────────────────────────
    if (session_id) {

      // Thiết bị phải thuộc bộ phận đang audit
      if (String(device.department_id) !== String(scanDeptId)) {
        return res.json({
          success:           false,
          not_in_list:       true,
          message:           "❌ Thiết bị không thuộc bộ phận đang audit",
          device_name:       device.name,
          device_department: deviceDeptName,
          scan_department:   scanDeptName,
          status:            `Thuộc ${deviceDeptName}, không phải ${scanDeptName}`,
        });
      }

      // Chặn quét trùng trong cùng session — query() tự release
      const [dupScan] = await query(
        `SELECT id FROM scans WHERE device_id = ? AND session_id = ? LIMIT 1`,
        [device.id, session_id]
      );
      if (dupScan) {
        return res.json({
          success:      false,
          message:      "⚠️ Thiết bị này đã quét trong phiên audit này rồi",
          device_name:  device.name,
          is_duplicate: true,
        });
      }

      // ✅ INSERT + UPDATE dùng transaction — atomic, release sau khi xong
      await transaction(async (conn) => {
        await conn.execute(
          `INSERT INTO scans (device_id, user_id, session_id, scan_department) VALUES (?, ?, ?, ?)`,
          [device.id, user_id, session_id, scanDeptId]
        );
        if (device.is_new) {
          await conn.execute(`UPDATE devices SET is_new = 0 WHERE id = ?`, [device.id]);
        }
      });

      return res.json({
        success:           true,
        device_name:       device.name,
        device_department: deviceDeptName,
        scan_department:   scanDeptName,
        status:            statusText,
        message:           `✅ Quét: ${device.name}`,
      });
    }

    // ── 4b. CHẾ ĐỘ QUÉT THƯỜNG ───────────────────────────────────
    const [prevScan] = await query(
      `SELECT s.id, u2.full_name AS prev_user, dep_s.name AS prev_scan_dept
       FROM scans s
       JOIN users u2 ON u2.id = s.user_id
       LEFT JOIN departments dep_s ON dep_s.id = s.scan_department
       WHERE s.device_id = ?
       ORDER BY s.scanned_at DESC
       LIMIT 1`,
      [device.id]
    );

    // Đã quét rồi → trả về NGAY, không insert thêm
    if (prevScan) {
      return res.json({
        success:           false,
        already:           true,
        device_name:       device.name,
        device_department: deviceDeptName,
        scan_department:   prevScan.prev_scan_dept || scanDeptName,
        message:           "⚠️ Thiết bị đã quét rồi",
      });
    }

    // ✅ INSERT + UPDATE dùng transaction — atomic
    await transaction(async (conn) => {
      await conn.execute(
        `INSERT INTO scans (device_id, user_id, scan_department) VALUES (?, ?, ?)`,
        [device.id, user_id, scanDeptId]
      );
      if (device.is_new) {
        await conn.execute(`UPDATE devices SET is_new = 0 WHERE id = ?`, [device.id]);
      }
    });

    return res.json({
      success:           true,
      already:           false,
      device_name:       device.name,
      device_department: deviceDeptName,
      scan_department:   scanDeptName,
      status:            statusText,
      message:           `✅ Quét: ${device.name}`,
    });

  } catch (err) {
    console.error("SCAN ERROR:", err.message);
    return res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

/* ============================================================
   POST /api/scan/start-audit
   ============================================================ */
router.post("/start-audit", async (req, res) => {
  try {
    const { user_id, department_id, force_new } = req.body;

    if (!user_id || !department_id) {
      return res.json({ success: false, message: "Thiếu user_id hoặc department_id" });
    }

    // ✅ withConnection — nhiều query liên tiếp trên cùng 1 connection,
    // release tự động sau khi callback xong
    return await withConnection(async (conn) => {
      const [[active]] = await conn.execute(
        `SELECT a.id, a.user_id, a.started_at, u.full_name, u.id AS auditor_id
         FROM audit_sessions a
         JOIN users u ON u.id = a.user_id
         WHERE a.department_id = ? AND a.ended_at IS NULL
         ORDER BY a.started_at DESC
         LIMIT 1`,
        [department_id]
      );

      if (active && !force_new) {
        const [[scannedData]] = await conn.execute(
          `SELECT COUNT(*) AS count FROM scans WHERE session_id = ?`,
          [active.id]
        );
        return res.json({
          has_existing:  true,
          success:       false,
          session_id:    active.id,
          scanned_count: scannedData?.count || 0,
          started_at:    active.started_at,
          auditor_name:  active.full_name,
          auditor_id:    active.auditor_id,
          message:       `${active.full_name} đang audit bộ phận này`,
        });
      }

      const [result] = await conn.execute(
        `INSERT INTO audit_sessions (user_id, department_id) VALUES (?, ?)`,
        [user_id, department_id]
      );

      return res.json({
        has_existing: false,
        success:      true,
        session_id:   result.insertId,
        message:      "Phiên audit mới tạo",
      });
    });

  } catch (err) {
    console.error("START-AUDIT ERROR:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

/* ============================================================
   POST /api/scan/stop-audit
   ============================================================ */
router.post("/stop-audit", async (req, res) => {
  try {
    await query(
      `UPDATE audit_sessions SET ended_at = NOW() WHERE id = ?`,
      [req.body.session_id]
    );
    return res.json({ success: true });
  } catch (err) {
    console.error("STOP-AUDIT ERROR:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

/* ============================================================
   GET /api/scan/audit-sessions?from=&to=&dept=
   ============================================================ */
router.get("/audit-sessions", async (req, res) => {
  try {
    const { from, to, dept } = req.query;
    const params = [];
    let where = "WHERE 1=1";

    if (from) { where += " AND DATE(a.started_at) >= ?"; params.push(from); }
    if (to)   { where += " AND DATE(a.started_at) <= ?"; params.push(to); }
    if (dept) { where += " AND a.department_id = ?";     params.push(dept); }

    const rows = await query(`
      SELECT
        a.id,
        u.full_name                                                     AS auditor_name,
        d.name                                                          AS dept_name,
        a.started_at,
        a.ended_at,
        COUNT(s.id)                                                     AS total_scanned,
        TIMESTAMPDIFF(MINUTE, a.started_at, IFNULL(a.ended_at, NOW())) AS duration_min
      FROM audit_sessions a
      JOIN  users       u ON u.id = a.user_id
      JOIN  departments d ON d.id = a.department_id
      LEFT JOIN scans   s ON s.session_id = a.id
      ${where}
      GROUP BY a.id, u.full_name, d.name, a.started_at, a.ended_at
      ORDER BY a.started_at DESC
      LIMIT 50
    `, params);

    return res.json(rows);
  } catch (err) {
    console.error("AUDIT-SESSIONS ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   GET /api/scan/audit-compare/:session_id
   ============================================================ */
router.get("/audit-compare/:session_id", async (req, res) => {
  try {
    const { session_id } = req.params;

    // query 1: lấy dept của session
    const [sess] = await query(
      `SELECT department_id FROM audit_sessions WHERE id = ?`,
      [session_id]
    );
    if (!sess) return res.status(404).json({ error: "Session không tồn tại" });

    // query 2: lấy devices + scans
    const rows = await query(`
      SELECT
        d.id         AS device_id,
        d.name       AS device_name,
        d.qr_code,
        d.location,
        s.device_id  IS NOT NULL AS audited,
        u.full_name  AS scanned_by,
        s.scanned_at
      FROM devices d
      LEFT JOIN scans s ON s.device_id = d.id AND s.session_id = ?
      LEFT JOIN users u ON u.id = s.user_id
      WHERE d.department_id = ? AND d.is_new = 0
      ORDER BY audited ASC
    `, [session_id, sess.department_id]);

    return res.json(rows);
  } catch (err) {
    console.error("AUDIT-COMPARE ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   GET /api/scan/audit-summary/:session_id
   ============================================================ */
router.get("/audit-summary/:session_id", async (req, res) => {
  try {
    const [row] = await query(`
      SELECT
        COUNT(*)                                                              AS total,
        SUM(CASE WHEN d.department_id = s.scan_department THEN 1 ELSE 0 END) AS correct,
        SUM(CASE WHEN d.department_id != s.scan_department THEN 1 ELSE 0 END) AS wrong
      FROM scans s
      JOIN devices d ON d.id = s.device_id
      WHERE s.session_id = ?
    `, [req.params.session_id]);
    return res.json(row);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   DELETE /api/scan/audit-session/:id
   ============================================================ */
router.delete("/audit-session/:id", async (req, res) => {
  try {
    const { id } = req.params;
    // ✅ transaction — 2 query phải chạy cùng nhau, atomic
    await transaction(async (conn) => {
      await conn.execute(`UPDATE scans SET session_id = NULL WHERE session_id = ?`, [id]);
      await conn.execute(`DELETE FROM audit_sessions WHERE id = ?`, [id]);
    });
    return res.json({ success: true, message: "Đã xóa phiên audit" });
  } catch (err) {
    console.error("DELETE-AUDIT-SESSION ERROR:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

/* ============================================================
   POST /api/scan/force-stop/:id
   ============================================================ */
router.post("/force-stop/:id", async (req, res) => {
  try {
    await query(
      `UPDATE audit_sessions SET ended_at = NOW() WHERE id = ? AND ended_at IS NULL`,
      [req.params.id]
    );
    return res.json({ success: true, message: "Đã dừng phiên audit" });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

export default router;