import express from "express";
import bcrypt from "bcrypt";
import { query, transaction } from "../config/database.js";
import { checkAdmin } from "../middleware/admin.js";

const router = express.Router();

/* GET /api/users */
router.get("/", checkAdmin, async (req, res) => {
  try {
    const rows = await query(`
      SELECT
        u.id,
        u.username,
        u.full_name,
        u.role,
        u.department_id,
        u.section_id,
        u.group_id,
        u.cost_center_id,
        dep.name AS department_name,
        sec.name AS section_name,
        grp.name AS group_name,
        cc.name  AS cost_center
      FROM users u
      LEFT JOIN departments dep ON dep.id = u.department_id
      LEFT JOIN sections    sec ON sec.id = u.section_id
      LEFT JOIN \`groups\`   grp ON grp.id = u.group_id
      LEFT JOIN cost_centers cc  ON cc.id  = u.cost_center_id
      ORDER BY u.id DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

/* POST /api/users — tạo user mới */
router.post("/", checkAdmin, async (req, res) => {
  try {
    const {
      username, password, full_name,
      department_id, section_id, group_id, cost_center_id, role
    } = req.body;

    if (!username || !password) {
      return res.json({ success: false, message: "Thiếu username hoặc password" });
    }

    const exist = await query("SELECT id FROM users WHERE username = ?", [username]);
    if (exist.length > 0) {
      return res.json({ success: false, message: "Username đã tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await query(
      `INSERT INTO users (username, password, full_name, department_id, section_id, group_id, cost_center_id, role)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        hashedPassword,
        full_name      || "",
        department_id  || null,
        section_id     || null,
        group_id       || null,
        cost_center_id || null,
        role           || "user",
      ]
    );

    res.json({ success: true, message: "Tạo user thành công" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

/* PUT /api/users/:id */
router.put("/:id", checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      full_name, department_id, section_id,
      group_id, cost_center_id, role, password
    } = req.body;

    let sql = "UPDATE users SET full_name=?, department_id=?, section_id=?, group_id=?, cost_center_id=?, role=?";
    let params = [
      full_name      || "",
      department_id  || null,
      section_id     || null,
      group_id       || null,
      cost_center_id || null,
      role           || "user",
    ];

    if (password && password.trim() !== "") {
      const hashedPassword = await bcrypt.hash(password, 12);
      sql += ", password=?";
      params.push(hashedPassword);
    }

    sql += " WHERE id=?";
    params.push(id);

    const result = await query(sql, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User không tồn tại" });
    }
    res.json({ success: true, message: "Cập nhật user thành công" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* DELETE /api/users/:id */
router.delete("/:id", checkAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await query("DELETE FROM users WHERE id=?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User không tồn tại" });
    }
    res.json({ success: true, message: "Đã xóa tài khoản" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

export default router;