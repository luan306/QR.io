import express from "express";
import { query } from "../config/database.js";

const router = express.Router();

// POST /api/cost-centers  { name, group_id }
router.post("/", async (req, res) => {
  const { name, group_id } = req.body;
  if (!name || !group_id)
    return res.status(400).json({ success: false, message: "Thiếu thông tin" });
  try {
    const result = await query(
      "INSERT INTO cost_centers (name, group_id) VALUES (?, ?)",
      [name.trim(), group_id]
    );
    res.json({ success: true, id: result.insertId, name: name.trim() });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// DELETE /api/cost-centers/:id
router.delete("/:id", async (req, res) => {
  try {
    await query("DELETE FROM cost_centers WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Đã xóa cost center" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

export default router;