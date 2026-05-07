import express from "express";
import { query, transaction } from "../config/database.js";

const router = express.Router();

// ======================================================
// GET ALL INVENTORY ROUNDS
// ======================================================
router.get("/inventory-rounds", async (req, res) => {
  try {

    const rows = await query(`
      SELECT *
      FROM v_round_summary
      ORDER BY
        status = 'active' DESC,
        created_at DESC
    `);

    res.json(rows);

  } catch (e) {

    console.error("GET inventory rounds error:", e);

    res.status(500).json({
      message: e.message,
    });
  }
});

// ======================================================
// CREATE INVENTORY ROUND
// ======================================================
router.post("/inventory-rounds", async (req, res) => {

  const { name, description } = req.body;

  if (!name) {
    return res.status(400).json({
      message: "Thiếu tên đợt kiểm kê",
    });
  }

  try {

    const roundId = await transaction(async (conn) => {

      // =================================================
      // CREATE ROUND
      // =================================================
      const [roundResult] = await conn.query(
        `
        INSERT INTO inventory_rounds (
          name,
          description,
          status,
          started_at
        )
        VALUES (?, ?, 'draft', NOW())
        `,
        [
          name,
          description || null,
        ]
      );

      const newRoundId = roundResult.insertId;

      // =================================================
      // SNAPSHOT DEVICES
      // =================================================
      await conn.query(
        `
        INSERT INTO inventory_round_items (

          round_id,

          device_id,

          qr_code,
          device_name,

          location,

          department_id,
          department_name,

          section_name,
          group_name,

          cost_center_name,

          floor,

          audited

        )

        SELECT

          ?,

          d.id,

          -- ======================================
          -- QR CODE
          -- ======================================
          COALESCE(
            d.qr_code,
            '—'
          ),

          -- ======================================
          -- DEVICE NAME
          -- ======================================
          COALESCE(
            d.name,
            '—'
          ),

          -- ======================================
          -- LOCATION
          -- ======================================
          COALESCE(
            d.location,
            CONCAT('Tầng ', COALESCE(d.floor, 1)),
            '—'
          ),

          -- ======================================
          -- DEPARTMENT
          -- ======================================
          dep.id,

          COALESCE(
            dep.name,
            '—'
          ),

          -- ======================================
          -- SECTION
          -- ======================================
          COALESCE(
            sec.name,
            '—'
          ),

          -- ======================================
          -- GROUP
          -- ======================================
          COALESCE(
            gr.name,
            '—'
          ),

          -- ======================================
          -- COST CENTER
          -- ======================================
          COALESCE(
            cc.name,
            '—'
          ),

          -- ======================================
          -- FLOOR
          -- ======================================
          d.floor,

          -- ======================================
          -- AUDITED
          -- ======================================
          0

        FROM devices d

        -- ======================================
        -- DEPARTMENT
        -- ======================================
        LEFT JOIN departments dep
          ON dep.id = d.department_id

        -- ======================================
        -- SECTION
        -- ======================================
        LEFT JOIN sections sec
          ON sec.id = d.section_id

        -- ======================================
        -- GROUP
        -- ======================================
        LEFT JOIN \`groups\` gr
          ON gr.id = d.group_id

        -- ======================================
        -- COST CENTER
        -- ======================================
        LEFT JOIN cost_centers cc
          ON cc.id = d.cost_center_id
        `,
        [newRoundId]
      );

      return newRoundId;
    });

    res.json({
      success: true,
      id: roundId,
    });

  } catch (e) {

    console.error("CREATE inventory round error:", e);

    res.status(500).json({
      message: e.message,
    });
  }
});

// ======================================================
// GET ROUND ITEMS
// ======================================================
router.get("/inventory-rounds/:id/items", async (req, res) => {

  try {

    const rows = await query(
      `
      SELECT

        ri.id,
        ri.round_id,

        ri.device_id,

        ri.qr_code,
        ri.device_name,

        ri.location,

        ri.department_id,
        ri.department_name,

        ri.section_name,
        ri.group_name,

        ri.cost_center_name,

        ri.floor,

        ri.audited,
        ri.audited_by,
        ri.audited_by_name,
        ri.audited_at,

        ri.scanned_dept_id,
        ri.scanned_dept_name,

        ri.is_mismatch,

        ri.note,

        ri.snapshotted_at

      FROM inventory_round_items ri

      WHERE ri.round_id = ?

      ORDER BY ri.id ASC
      `,
      [req.params.id]
    );

    res.json(rows);

  } catch (e) {

    console.error("GET round items error:", e);

    res.status(500).json({
      message: e.message,
    });
  }
});

// ======================================================
// UPDATE AUDIT STATUS
// ======================================================
router.put(
  "/inventory-rounds/:roundId/items/:itemId/audit",
  async (req, res) => {

    try {

      const {
        audited,
        note,
        audited_by_name,
      } = req.body;

      await query(
        `
        UPDATE inventory_round_items
        SET
          audited = ?,
          audited_at = ?,
          audited_by_name = ?,
          note = ?
        WHERE
          id = ?
          AND round_id = ?
        `,
        [
          audited ? 1 : 0,
          audited ? new Date() : null,
          audited_by_name || null,
          note || null,
          req.params.itemId,
          req.params.roundId,
        ]
      );

      res.json({
        success: true,
      });

    } catch (e) {

      console.error("UPDATE audit error:", e);

      res.status(500).json({
        message: e.message,
      });
    }
  }
);

// ======================================================
// DELETE ONE ITEM
// ======================================================
router.delete(
  "/inventory-rounds/:roundId/items/:itemId",
  async (req, res) => {

    try {

      await query(
        `
        DELETE FROM inventory_round_items
        WHERE
          id = ?
          AND round_id = ?
        `,
        [
          req.params.itemId,
          req.params.roundId,
        ]
      );

      res.json({
        success: true,
      });

    } catch (e) {

      console.error("DELETE item error:", e);

      res.status(500).json({
        message: e.message,
      });
    }
  }
);

// ======================================================
// DELETE ROUND
// ======================================================
router.delete("/inventory-rounds/:id", async (req, res) => {

  try {

    await query(
      `
      DELETE FROM inventory_rounds
      WHERE id = ?
      `,
      [req.params.id]
    );

    res.json({
      success: true,
    });

  } catch (e) {

    console.error("DELETE round error:", e);

    res.status(500).json({
      message: e.message,
    });
  }
});

export default router;