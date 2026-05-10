import express from "express";
import { query } from "../config/database.js";

const router = express.Router();

// ─────────────────────────────────────────────────────────────
// DEPARTMENTS
// ─────────────────────────────────────────────────────────────

router.get("/", async (req, res) => {
  try {
    const rows = await query("SELECT * FROM departments ORDER BY name");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/", async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ success: false, message: "Thiếu tên bộ phận" });
  try {
    const result = await query("INSERT INTO departments (name) VALUES (?)", [name.trim()]);
    res.json({ success: true, id: result.insertId, name: name.trim() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

router.put("/:id", async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ success: false, message: "Thiếu tên" });
  try {
    await query("UPDATE departments SET name=? WHERE id=?", [name.trim(), req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

router.delete("/:id", async (req, res) => {
  try {
    await query("DELETE FROM departments WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Xóa bộ phận thành công" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// ─────────────────────────────────────────────────────────────
// SECTIONS
// ─────────────────────────────────────────────────────────────

router.get("/:id/sections", async (req, res) => {
  try {
    const rows = await query(
      "SELECT * FROM sections WHERE department_id=? ORDER BY name",
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/:id/sections", async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ success: false, message: "Thiếu tên section" });
  try {
    const result = await query(
      "INSERT INTO sections (name, department_id) VALUES (?, ?)",
      [name.trim(), req.params.id]
    );
    res.json({ success: true, id: result.insertId, name: name.trim() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// ─────────────────────────────────────────────────────────────
// GROUPS
// ─────────────────────────────────────────────────────────────

router.get("/:id/groups", async (req, res) => {
  try {
    const rows = await query(
      "SELECT * FROM `groups` WHERE section_id=? ORDER BY name",
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ─────────────────────────────────────────────────────────────
// DEVICES của department
// ─────────────────────────────────────────────────────────────

router.get("/:deptId/devices", async (req, res) => {
  try {
    const { deptId } = req.params;
    const rows = await query(`
      SELECT
        d.id, d.name, d.qr_code, d.location,
        d.section_id, d.group_id, d.cost_center_id,
        dep.name      AS device_department,
        dep_scan.name AS current_department,
        dt.name       AS device_type_name,
        sec.name      AS section_name,
        grp.name      AS group_name,
        cc.name       AS cost_center,
        u.username    AS user_name,
        s.scanned_at,
        CASE
          WHEN s.id IS NULL THEN 'Chưa quét'
          WHEN d.department_id = s.scan_department THEN CONCAT('Đang ở ', dep_scan.name)
          WHEN d.department_id != s.scan_department AND s.scan_department = ? THEN CONCAT('Chuyển từ ', dep.name)
          WHEN d.department_id != s.scan_department AND d.department_id = ? THEN CONCAT('Đã chuyển đến ', dep_scan.name)
          ELSE '-'
        END AS status
      FROM devices d
      LEFT JOIN device_types dt    ON dt.id    = d.device_type_id
      LEFT JOIN departments  dep   ON dep.id   = d.department_id
      LEFT JOIN sections     sec   ON sec.id   = d.section_id
      LEFT JOIN \`groups\`    grp   ON grp.id   = d.group_id
      LEFT JOIN cost_centers cc    ON cc.id    = d.cost_center_id
      LEFT JOIN (
        SELECT s1.* FROM scans s1
        INNER JOIN (
          SELECT device_id, MAX(scanned_at) AS max_time FROM scans GROUP BY device_id
        ) latest ON s1.device_id=latest.device_id AND s1.scanned_at=latest.max_time
      ) s ON s.device_id = d.id
      LEFT JOIN departments dep_scan ON dep_scan.id = s.scan_department
      LEFT JOIN users       u        ON u.id        = s.user_id
      WHERE d.department_id=? OR s.scan_department=?
    `, [deptId, deptId, deptId, deptId]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

export default router;