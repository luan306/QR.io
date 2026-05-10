import express from "express";
import bcrypt  from "bcrypt";
import { query } from "../config/database.js";

const router = express.Router();

const MAX_ATTEMPTS = 5;

/* POST /api/login */
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: "Thiếu username hoặc password" });

  try {
    const rows = await query(
      "SELECT id, username, full_name, password, role, department_id, section_id, group_id, cost_center_id, login_attempts, locked_at FROM users WHERE username = ? LIMIT 1",
      [username]
    );

    if (!rows.length)
      return res.status(401).json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });

    const user = rows[0];

    // ── Kiểm tra khoá ────────────────────────────────────────
    if (user.locked_at)
      return res.status(403).json({
        success: false,
        locked:  true,
        message: "Tài khoản đã bị khoá do đăng nhập sai quá nhiều lần. Vui lòng liên hệ admin để mở lại.",
      });

    // ── Kiểm tra mật khẩu ────────────────────────────────────
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      const attempts = (user.login_attempts || 0) + 1;
      if (attempts >= MAX_ATTEMPTS) {
        // Khoá tài khoản
        await query(
          "UPDATE users SET login_attempts = ?, locked_at = NOW() WHERE id = ?",
          [attempts, user.id]
        );
        return res.status(403).json({
          success: false,
          locked:  true,
          message: "Tài khoản đã bị khoá do đăng nhập sai 5 lần. Vui lòng liên hệ admin để mở lại.",
        });
      }
      // Tăng số lần sai
      await query("UPDATE users SET login_attempts = ? WHERE id = ?", [attempts, user.id]);
      return res.status(401).json({
        success:      false,
        message:      `Sai mật khẩu. Còn ${MAX_ATTEMPTS - attempts} lần thử.`,
        attemptsLeft: MAX_ATTEMPTS - attempts,
      });
    }

    // ── Đăng nhập thành công — reset attempts ─────────────────
    await query("UPDATE users SET login_attempts = 0, locked_at = NULL WHERE id = ?", [user.id]);

    req.session.userId = user.id;
    req.session.user   = {
      id:             user.id,
      username:       user.username,
      full_name:      user.full_name,
      role:           user.role,
      department_id:  user.department_id,
      section_id:     user.section_id,
      group_id:       user.group_id,
      cost_center_id: user.cost_center_id,
    };

    res.json({ success: true, user: req.session.user });

  } catch (err) {
    console.error("[Login] error:", err.message);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

/* POST /api/logout */
router.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

/* GET /api/current-user — luôn lấy từ DB để có role mới nhất */
router.get("/current-user", async (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ user: null });
  try {
    const rows = await query(
      `SELECT id, username, full_name, role, department_id, section_id, group_id, cost_center_id
       FROM users WHERE id = ? LIMIT 1`,
      [req.session.userId]
    );
    if (!rows.length) return res.status(401).json({ user: null });
    const user = rows[0];
    // Sync lại session
    req.session.user = user;
    res.json({ user });
  } catch (err) {
    // Fallback về session nếu DB lỗi
    if (req.session?.user) return res.json({ user: req.session.user });
    res.status(500).json({ user: null });
  }
});

export default router;