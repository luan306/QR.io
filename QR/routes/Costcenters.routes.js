import express from "express";
import { query } from "../config/database.js";

const router = express.Router();

// POST /api/cost-centers  { name, group_id } hoặc { name, section_id } hoặc { name, department_id }
router.post("/", async (req, res) => {
  const { name, group_id, section_id, department_id } = req.body;
  if (!name?.trim())
    return res.status(400).json({ success: false, message: "Thiếu tên" });
  if (!group_id && !section_id && !department_id)
    return res.status(400).json({ success: false, message: "Cần group_id, section_id hoặc department_id" });
  try {
    const result = await query(
      "INSERT INTO cost_centers (name, group_id, section_id, department_id) VALUES (?, ?, ?, ?)",
      [name.trim(), group_id || null, section_id || null, department_id || null]
    );
    res.json({ success: true, id: result.insertId, name: name.trim() });
  } catch (err) {
    console.error("POST cost-centers error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/cost-centers/:id
router.put("/:id", async (req, res) => {
  const { name } = req.body;
  if (!name?.trim())
    return res.status(400).json({ success: false, message: "Thiếu tên" });
  try {
    await query("UPDATE cost_centers SET name = ? WHERE id = ?", [name.trim(), req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/cost-centers/:id
router.delete("/:id", async (req, res) => {
  try {
    await query("DELETE FROM cost_centers WHERE id = ?", [req.params.id]);
    res.json({ success: true, message: "Đã xóa cost center" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/groups/:groupId/cost-centers  (đã có trong groupRoutes, giữ nguyên)
// GET /api/sections/:sectionId/cost-centers
router.get("/by-section/:sectionId", async (req, res) => {
  try {
    const rows = await query("SELECT * FROM cost_centers WHERE section_id = ? ORDER BY name", [req.params.sectionId]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/departments/:deptId/cost-centers
router.get("/by-department/:deptId", async (req, res) => {
  try {
    const rows = await query("SELECT * FROM cost_centers WHERE department_id = ? ORDER BY name", [req.params.deptId]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

export default router;