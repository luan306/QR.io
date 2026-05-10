import express from "express";
import cors from "cors";
import session from "express-session";
import dotenv from "dotenv";
import https from "https";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Server as SocketIO } from "socket.io";
import { rateLimit } from "express-rate-limit";
import compression from "compression";
import helmet from "helmet";
import { createClient } from "redis";
import { RedisStore } from "connect-redis";

import authRoutes           from "./routes/auth.routes.js";
import userRoutes           from "./routes/users.routes.js";
import departmentRoutes     from "./routes/departments.routes.js";
import deviceRoutes         from "./routes/devices.routes.js";
import scanRoutes           from "./routes/scans.routes.js";
import statsRoutes          from "./routes/stats.routes.js";
import deviceTypeRoutes     from "./routes/deviceTypes.routes.js";
import templateRoutes       from "./routes/template.routes.js";
import pageRoutes           from "./routes/pages.routes.js";
import uploadRoutes         from "./routes/upload.routes.js";
import auditRoutes          from "./routes/audit.routes.js";
import mapRoutes            from "./routes/map.routes.js";
import sectionRoutes        from "./routes/sections.routes.js";
import groupRoutes          from "./routes/groups.routes.js";
import costCenterRoutes     from "./routes/costCenters.routes.js";
import inventoryRoundRoutes from "./routes/inventoryRounds.js";
dotenv.config();

if (!process.env.SESSION_SECRET) {
  throw new Error("❌ SESSION_SECRET is required in .env");
}

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const isDev      = process.env.NODE_ENV !== "production";
console.log(`🚀 Mode: ${isDev ? "development" : "production"}`);

// ══════════════════════════════════════════════════════════════
//  REDIS
// ══════════════════════════════════════════════════════════════
const redisClient = createClient({
  socket: {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: process.env.REDIS_PORT || 6379,
    reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
  },
});
redisClient.on("error",   (err) => console.error("❌ Redis error:", err.message));
redisClient.on("connect", ()    => console.log("✅ Redis connected"));
await redisClient.connect();

// ══════════════════════════════════════════════════════════════
//  VIEW ENGINE
// ══════════════════════════════════════════════════════════════
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ══════════════════════════════════════════════════════════════
//  SECURITY & PERFORMANCE
// ══════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy:      false,
  crossOriginEmbedderPolicy:  false,
}));

app.use(compression({
  level:     6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers["accept"] === "text/event-stream") return false;
    return compression.filter(req, res);
  },
}));

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ limit: "20mb", extended: true }));

// ── CORS ─────────────────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map(s => s.trim())
  : ["https://localhost:3000"];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true,
}));

// ── Static files ─────────────────────────────────────────────
const staticOptions = { maxAge: "1d", etag: true, lastModified: true };
app.use(express.static(path.join(__dirname, "public"), staticOptions));
app.use("/layouts", express.static(path.join(__dirname, "public", "layouts"), staticOptions));

// ══════════════════════════════════════════════════════════════
//  RATE LIMITER
//  LAN 200 thiết bị: tất cả có thể qua cùng 1 IP (NAT/proxy)
//  → rate limit theo IP sẽ block toàn bộ LAN
//  → tăng max, và trong môi trường LAN nội bộ thường bỏ qua luôn
// ══════════════════════════════════════════════════════════════
const isLocalNetwork = (req) => {
  const ip = req.ip || req.socket?.remoteAddress || "";
  return (
    ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" ||
    // LAN ranges: 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    /^(::ffff:)?(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)
  );
};

const limiter = rateLimit({
  windowMs:        60 * 1000,
  max:             600,          // tăng từ 300 → 600 cho 200 user LAN
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { success: false, message: "Quá nhiều request, thử lại sau." },
  skip: (req) => {
    if (req.path.startsWith("/api/scan")) return true; // scan có limiter riêng
    if (isDev || isLocalNetwork(req))     return true; // bỏ qua LAN nội bộ
    return false;
  },
});
app.use("/api", limiter);

// Scan: 200 lần/phút — 200 user mỗi người 1 lần/phút là vừa đủ
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      200,
  message:  { success: false, message: "Quét quá nhanh, thử lại sau." },
  skip: (req) => isDev || isLocalNetwork(req), // LAN không bị limit
});
app.use("/api/scan", scanLimiter);

// ══════════════════════════════════════════════════════════════
//  SESSION
// ══════════════════════════════════════════════════════════════
const sessionMiddleware = session({
  store: new RedisStore({
    client: redisClient,
    ttl:    8 * 60 * 60, // 8 tiếng (giây)
  }),
  secret:            process.env.SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  name:              "sid",
  cookie: {
    secure:   process.env.NODE_ENV === "production", // false khi dev/LAN HTTP
    httpOnly: true,
    sameSite: "lax",   // "strict" gây lỗi trên một số mobile browser
    maxAge:   8 * 60 * 60 * 1000,
  },
});
app.use(sessionMiddleware);

// ══════════════════════════════════════════════════════════════
//  IN-MEMORY CACHE
// ══════════════════════════════════════════════════════════════
export const memCache = new Map();

export function cacheMiddleware(ttlSeconds = 30) {
  return (req, res, next) => {
    const key    = `cache:${req.originalUrl}`;
    const cached = memCache.get(key);
    if (cached && cached.expireAt > Date.now()) {
      res.setHeader("X-Cache", "HIT");
      return res.json(cached.data);
    }
    const originalJson = res.json.bind(res);
    res.json = (data) => {
      if (res.statusCode === 200) {
        memCache.set(key, { data, expireAt: Date.now() + ttlSeconds * 1000 });
      }
      res.setHeader("X-Cache", "MISS");
      return originalJson(data);
    };
    next();
  };
}

setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, val] of memCache.entries()) {
    if (val.expireAt <= now) { memCache.delete(key); cleaned++; }
  }
  if (cleaned > 0) console.log(`🧹 [Cache] Cleaned ${cleaned} expired entries`);
}, 5 * 60 * 1000);

// ══════════════════════════════════════════════════════════════
//  API ROUTES
// ══════════════════════════════════════════════════════════════
app.use("/api",                  authRoutes);
app.use("/api/users",            userRoutes);
app.use("/api/departments",      departmentRoutes);
app.use("/api/sections",         sectionRoutes);
app.use("/api/groups",           groupRoutes);
app.use("/api/cost-centers",     costCenterRoutes);
app.use("/api/devices/template", templateRoutes);
app.use("/api/devices/upload",   uploadRoutes);
app.use("/api/devices",          deviceRoutes);
app.use("/api/scan",             scanRoutes);
app.use("/api/scans",            scanRoutes);
app.use("/api/stats",            statsRoutes);
app.use("/api/device-types",     deviceTypeRoutes);
app.use("/api",                  inventoryRoundRoutes);
app.use("/api",                  mapRoutes);
app.use("/admin",                auditRoutes);
app.use("/",                     authRoutes);
app.use("/",                     pageRoutes);

// ══════════════════════════════════════════════════════════════
//  GLOBAL ERROR HANDLER
// ══════════════════════════════════════════════════════════════
app.use((err, req, res, _next) => {
  console.error("❌ [Error]", err.message, req.method, req.originalUrl);
  res.status(err.status || 500).json({
    success: false,
    message: isDev ? err.message : "Lỗi server",
  });
});

// ══════════════════════════════════════════════════════════════
//  HTTPS SERVER
// ══════════════════════════════════════════════════════════════
const options = {
  key:  fs.readFileSync("./certs/key.pem"),
  cert: fs.readFileSync("./certs/cert.pem"),
};

const httpsServer = https.createServer(options, app);

// Timeout tăng: 200 user đồng thời, server có thể bận → không disconnect sớm
httpsServer.keepAliveTimeout = 65_000;
httpsServer.headersTimeout   = 66_000;
httpsServer.maxHeadersCount  = 200;     // tăng từ 100 → 200

// ── Graceful shutdown — không drop request đang xử lý ───────
let isShuttingDown = false;
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

async function shutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\n🛑 [${signal}] Shutting down gracefully...`);
  httpsServer.close(() => {
    console.log("✅ HTTP server closed");
    redisClient.quit().then(() => {
      console.log("✅ Redis disconnected");
      process.exit(0);
    });
  });
  // Force exit sau 10s nếu còn request treo
  setTimeout(() => { console.error("⚠️ Forced exit"); process.exit(1); }, 10_000);
}

// ══════════════════════════════════════════════════════════════
//  SOCKET.IO
// ══════════════════════════════════════════════════════════════
const io = new SocketIO(httpsServer, {
  cors: {
    origin:      allowedOrigins,
    methods:     ["GET", "POST"],
    credentials: true,
  },
  allowEIO3: true,
  pingTimeout:    20_000,
  pingInterval:   25_000,
  upgradeTimeout: 10_000,
  maxHttpBufferSize: 1e6,

  // Tăng concurrency cho 200 kết nối đồng thời
  transports: ["websocket", "polling"], // websocket trước, polling fallback
});

io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

const roomUsers = {};

io.on("connection", (socket) => {
  console.log(`🔌 [Socket] Connected: ${socket.id} | Total: ${io.engine.clientsCount}`);

  socket.on("join_audit", ({ deptId, userId, userName }) => {
    const room = `audit:${deptId}`;
    socket.join(room);
    if (!roomUsers[room]) roomUsers[room] = {};
    roomUsers[room][socket.id] = { userId, userName };
    io.to(room).emit("room_users", Object.values(roomUsers[room]));
    console.log(`✅ [Socket] ${userName} joined ${room}`);
  });

  socket.on("leave_audit", ({ deptId }) => {
    _leaveRoom(socket, `audit:${deptId}`);
  });

  socket.on("device_scanned", ({ deptId, qr_code, device_name, scanned_by, scanned_at }) => {
    const room = `audit:${deptId}`;
    io.to(room).emit("device_scanned", { qr_code, device_name, scanned_by, scanned_at });
  });

  socket.on("disconnect", () => {
    for (const room of Object.keys(roomUsers)) _leaveRoom(socket, room);
  });

  // Bắt lỗi socket để không crash server
  socket.on("error", (err) => {
    console.error(`❌ [Socket] Error ${socket.id}:`, err.message);
  });
});

function _leaveRoom(socket, room) {
  if (!roomUsers[room]?.[socket.id]) return;
  socket.leave(room);
  delete roomUsers[room][socket.id];
  if (Object.keys(roomUsers[room]).length === 0) delete roomUsers[room];
  else io.to(room).emit("room_users", Object.values(roomUsers[room]));
}

export { io };

// ══════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

httpsServer.listen(PORT, HOST, () => {
  console.log(`✅ HTTPS + Socket.io → https://${HOST}:${PORT}`);
  console.log(`   Mode: ${process.env.NODE_ENV || "development"}`);
  console.log(`   Session store: Redis`);
  console.log(`   DB pool: 30 connections, queue: 500`);
});