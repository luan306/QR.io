import express from "express";
import { query } from "../config/database.js";

const router = express.Router();

// GET /api/groups/:id/cost-centers
router.get("/:id/cost-centers", async (req, res) => {
  try {
    const rows = await query(
      "SELECT * FROM cost_centers WHERE group_id=? ORDER BY name",
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST /api/groups  { name, section_id }
router.post("/", async (req, res) => {
  const { name, section_id } = req.body;
  if (!name || !section_id)
    return res.status(400).json({ success: false, message: "Thiếu thông tin" });
  try {
    const result = await query(
      "INSERT INTO `groups` (name, section_id) VALUES (?, ?)",
      [name.trim(), section_id]
    );
    res.json({ success: true, id: result.insertId, name: name.trim() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// DELETE /api/groups/:id
router.delete("/:id", async (req, res) => {
  try {
    await query("DELETE FROM `groups` WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Đã xóa group" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

export default router;