import fs from "fs";
import path from "path";
import http from "http";
import { fileURLToPath } from "url";
import {
  initDatabase,
  checkRateLimit,
  resetRateLimit,
  hashPassword,
  verifyPassword,
  findUserByEmail,
  createUser,
  createSession,
  findSession,
  deleteSession,
  parseCookies,
  serializeSessionCookie,
  serializeClearedCookie,
} from "./server-auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT && process.env.PORT !== "8080" ? Number(process.env.PORT) : 3000;
const HOST = "0.0.0.0";
const staticDir = path.join(__dirname, "ciphercheck");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

async function startServer() {
  await initDatabase();

  let expressApp = null;
  try {
    const { default: express } = await import("express");
    const app = express();

    app.use(express.json());

    // Health check
    app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

    // Auth: Register
    app.post("/api/auth/register", async (req, res) => {
      const { email, password } = req.body || {};
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Please enter a valid email address." });
      }
      if (typeof password !== "string" || password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long." });
      }

      const existing = await findUserByEmail(email);
      if (existing) {
        return res.status(409).json({ error: "An account with this email already exists." });
      }

      try {
        const passwordHash = await hashPassword(password);
        const user = await createUser(email, passwordHash);
        const { sessionId, expiresAt } = await createSession(user.id);

        res.setHeader("Set-Cookie", serializeSessionCookie(sessionId, expiresAt));
        return res.status(201).json({ user });
      } catch (err) {
        console.error("[Auth] Registration error:", err);
        return res.status(500).json({ error: "An unexpected error occurred during registration." });
      }
    });

    // Auth: Login
    app.post("/api/auth/login", async (req, res) => {
      const clientIp = req.ip || req.socket.remoteAddress || "127.0.0.1";
      const rate = checkRateLimit(clientIp);
      if (!rate.allowed) {
        return res.status(429).json({
          error: `Too many login attempts. Please wait ${rate.resetInSeconds} seconds before trying again.`,
        });
      }

      const { email, password } = req.body || {};
      if (!isValidEmail(email) || typeof password !== "string") {
        return res.status(400).json({ error: "Please provide a valid email and password." });
      }

      const user = await findUserByEmail(email);
      if (!user) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      const isMatch = await verifyPassword(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      resetRateLimit(clientIp);
      const { sessionId, expiresAt } = await createSession(user.id);
      res.setHeader("Set-Cookie", serializeSessionCookie(sessionId, expiresAt));

      return res.json({
        user: {
          id: user.id,
          email: user.email,
          isVerified: user.isVerified,
          createdAt: user.createdAt,
        },
      });
    });

    // Auth: Logout
    app.post("/api/auth/logout", async (req, res) => {
      const cookies = parseCookies(req.headers.cookie);
      if (cookies.session_id) {
        await deleteSession(cookies.session_id);
      }
      res.setHeader("Set-Cookie", serializeClearedCookie());
      return res.json({ success: true });
    });

    // Auth: Current Session (Me)
    app.get("/api/auth/me", async (req, res) => {
      const cookies = parseCookies(req.headers.cookie);
      if (!cookies.session_id) {
        return res.json({ user: null });
      }
      const sessionData = await findSession(cookies.session_id);
      if (!sessionData) {
        res.setHeader("Set-Cookie", serializeClearedCookie());
        return res.json({ user: null });
      }
      return res.json({ user: sessionData.user });
    });

    // Auth: Honest SMTP handling for email verification & password recovery
    app.post("/api/auth/verify-email", (_req, res) => {
      return res.status(503).json({
        error: "SMTP email delivery service is not configured. Email verification is currently unavailable in this environment.",
      });
    });

    app.post("/api/auth/forgot-password", (_req, res) => {
      return res.status(503).json({
        error: "SMTP email delivery service is not configured. Password recovery is currently unavailable in this environment.",
      });
    });

    app.post("/api/auth/reset-password", (_req, res) => {
      return res.status(503).json({
        error: "SMTP email delivery service is not configured. Password recovery is currently unavailable in this environment.",
      });
    });

    // Serve static files
    app.use(express.static(staticDir));
    app.use("/ciphercheck", express.static(staticDir));
    app.get("*", (_req, res) => res.sendFile(path.join(staticDir, "index.html")));

    expressApp = app;
  } catch (err) {
    console.warn("Express not loaded, using built-in http server:", err.message);
  }

  if (expressApp) {
    expressApp.listen(PORT, HOST, () => {
      console.log(`CipherCheck Express server running at http://${HOST}:${PORT}`);
    });
  } else {
    const server = http.createServer((req, res) => {
      if (req.url === "/api/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ status: "ok" }));
      }

      let filePath = req.url ? req.url.split("?")[0] : "/";
      if (filePath.startsWith("/ciphercheck")) {
        filePath = filePath.replace(/^\/ciphercheck/, "") || "/";
      }
      if (filePath === "/") {
        filePath = "/index.html";
      }

      let resolvedPath = path.join(staticDir, filePath);
      if (!fs.existsSync(resolvedPath) || fs.statSync(resolvedPath).isDirectory()) {
        resolvedPath = path.join(staticDir, "index.html");
      }

      const ext = path.extname(resolvedPath).toLowerCase();
      const contentType = MIME_TYPES[ext] || "application/octet-stream";

      fs.readFile(resolvedPath, (err, data) => {
        if (err) {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("Server Error");
        } else {
          res.writeHead(200, { "Content-Type": contentType });
          res.end(data);
        }
      });
    });

    server.listen(PORT, HOST, () => {
      console.log(`CipherCheck built-in HTTP server running at http://${HOST}:${PORT}`);
    });
  }
}

startServer();
