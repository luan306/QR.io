import express from "express";
import { query } from "../config/database.js";

const router = express.Router();

// GET /api/sections/:id/groups
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

// DELETE /api/sections/:id
router.delete("/:id", async (req, res) => {
  try {
    await query("DELETE FROM sections WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Đã xóa section" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

export default router;