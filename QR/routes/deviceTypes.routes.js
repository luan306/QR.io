import express from "express";
import { query } from "../config/database.js";

const router = express.Router();

/* =========================
   GET /api/device-types
========================= */
router.get("/", async (req, res) => {
  try {
    const rows = await query("SELECT * FROM device_types ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* =========================
   POST /api/device-types
========================= */
router.post("/", async (req, res) => {
  try {
    const { name } = req.body;
    await query("INSERT INTO device_types(name) VALUES(?)", [name]);
    res.json({ success: true, message: "Thêm loại thiết bị thành công" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* =========================
   PUT /api/device-types/:id
========================= */
router.put("/:id", async (req, res) => {
  try {
    const { name } = req.body;
    await query("UPDATE device_types SET name=? WHERE id=?", [name, req.params.id]);
    res.json({ success: true, message: "Cập nhật thành công" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* =========================
   DELETE /api/device-types/:id
========================= */
router.delete("/:id", async (req, res) => {
  try {
    await query("DELETE FROM device_types WHERE id=?", [req.params.id]);
    res.json({ success: true, message: "Đã xóa loại thiết bị" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

export default router;