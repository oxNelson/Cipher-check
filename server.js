import fs from "fs";
import path from "path";
import http from "http";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
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

async function startServer() {
  let expressApp = null;
  try {
    const { default: express } = await import("express");
    const app = express();
    app.get("/api/health", (req, res) => res.json({ status: "ok" }));
    app.use(express.static(staticDir));
    app.use("/ciphercheck", express.static(staticDir));
    app.get("*", (req, res) => res.sendFile(path.join(staticDir, "index.html")));
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
