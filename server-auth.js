import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Rate limiter for authentication attempts (IP-based)
const loginAttempts = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;

export function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record || record.resetAt <= now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, remaining: MAX_ATTEMPTS - 1 };
  }
  if (record.count >= MAX_ATTEMPTS) {
    return { allowed: false, remaining: 0, resetInSeconds: Math.ceil((record.resetAt - now) / 1000) };
  }
  record.count += 1;
  return { allowed: true, remaining: MAX_ATTEMPTS - record.count };
}

export function resetRateLimit(ip) {
  loginAttempts.delete(ip);
}

// Secure Password Hashing using crypto.scrypt
export async function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt:${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

export async function verifyPassword(password, storedHash) {
  return new Promise((resolve) => {
    if (!storedHash || !storedHash.startsWith("scrypt:")) {
      return resolve(false);
    }
    const [, salt, originalKeyHex] = storedHash.split(":");
    if (!salt || !originalKeyHex) {
      return resolve(false);
    }
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return resolve(false);
      const originalKey = Buffer.from(originalKeyHex, "hex");
      if (originalKey.length !== derivedKey.length) return resolve(false);
      resolve(crypto.timingSafeEqual(originalKey, derivedKey));
    });
  });
}

// In-Memory Data Store (used when DATABASE_URL is not set or unavailable)
const memoryUsers = new Map(); // id -> user
const memoryUsersByEmail = new Map(); // lowercase email -> user
const memorySessions = new Map(); // sessionId -> { userId, expiresAt }
let memoryUserIdCounter = 1;

let pgPool = null;
let isPostgresReady = false;

export async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log("[CipherCheck Auth] DATABASE_URL is not configured. Running with in-memory persistence.");
    return { type: "in-memory", ready: true };
  }

  try {
    const { default: pg } = await import("pg");
    const { Pool } = pg;
    pgPool = new Pool({ connectionString: process.env.DATABASE_URL });

    // Test connection
    const client = await pgPool.connect();
    try {
      // Run initial migrations if tables do not exist
      const migrationPath = path.join(__dirname, "lib", "db", "migrations", "0000_initial_users_and_sessions.sql");
      if (fs.existsSync(migrationPath)) {
        const sql = fs.readFileSync(migrationPath, "utf-8");
        await client.query(sql);
      }
      isPostgresReady = true;
      console.log("[CipherCheck Auth] Connected to PostgreSQL database and verified schema.");
      return { type: "postgres", ready: true };
    } finally {
      client.release();
    }
  } catch (err) {
    console.warn("[CipherCheck Auth] Failed to connect to PostgreSQL:", err.message);
    console.warn("[CipherCheck Auth] Falling back to secure in-memory store for session/user storage.");
    pgPool = null;
    isPostgresReady = false;
    return { type: "in-memory-fallback", ready: true, error: err.message };
  }
}

export async function findUserByEmail(email) {
  const normalizedEmail = email.trim().toLowerCase();
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT id, email, password_hash as \"passwordHash\", is_verified as \"isVerified\", created_at as \"createdAt\" FROM users WHERE email = $1 LIMIT 1",
      [normalizedEmail]
    );
    return res.rows[0] || null;
  }
  return memoryUsersByEmail.get(normalizedEmail) || null;
}

export async function findUserById(id) {
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT id, email, is_verified as \"isVerified\", created_at as \"createdAt\" FROM users WHERE id = $1 LIMIT 1",
      [id]
    );
    return res.rows[0] || null;
  }
  const user = memoryUsers.get(Number(id));
  if (!user) return null;
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

export async function createUser(email, passwordHash) {
  const normalizedEmail = email.trim().toLowerCase();
  const now = new Date();

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "INSERT INTO users (email, password_hash, is_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $4) RETURNING id, email, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [normalizedEmail, passwordHash, false, now]
    );
    return res.rows[0];
  }

  const user = {
    id: memoryUserIdCounter++,
    email: normalizedEmail,
    passwordHash,
    isVerified: false,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };

  memoryUsers.set(user.id, user);
  memoryUsersByEmail.set(normalizedEmail, user);
  const { passwordHash: _, ...safeUser } = user;
  return safeUser;
}

export async function createSession(userId) {
  const sessionId = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  if (isPostgresReady && pgPool) {
    await pgPool.query(
      "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES ($1, $2, NOW(), $3)",
      [sessionId, userId, expiresAt]
    );
  } else {
    memorySessions.set(sessionId, { userId, expiresAt });
  }

  return { sessionId, expiresAt };
}

export async function findSession(sessionId) {
  if (!sessionId) return null;

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT s.id, s.user_id as \"userId\", s.expires_at as \"expiresAt\", u.email, u.is_verified as \"isVerified\", u.created_at as \"createdAt\" FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = $1 AND s.expires_at > NOW() LIMIT 1",
      [sessionId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      session: { id: row.id, userId: row.userId, expiresAt: row.expiresAt },
      user: { id: row.userId, email: row.email, isVerified: row.isVerified, createdAt: row.createdAt },
    };
  }

  const record = memorySessions.get(sessionId);
  if (!record) return null;
  if (new Date(record.expiresAt) <= new Date()) {
    memorySessions.delete(sessionId);
    return null;
  }
  const user = await findUserById(record.userId);
  if (!user) return null;
  return {
    session: { id: sessionId, userId: record.userId, expiresAt: record.expiresAt },
    user,
  };
}

export async function deleteSession(sessionId) {
  if (!sessionId) return;
  if (isPostgresReady && pgPool) {
    await pgPool.query("DELETE FROM sessions WHERE id = $1", [sessionId]);
  } else {
    memorySessions.delete(sessionId);
  }
}

export function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const pair of cookieHeader.split(";")) {
    const [name, ...val] = pair.trim().split("=");
    if (name) {
      cookies[name] = decodeURIComponent(val.join("="));
    }
  }
  return cookies;
}

export function serializeSessionCookie(sessionId, expiresAt) {
  const maxAge = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
  return `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

export function serializeClearedCookie() {
  return "session_id=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
}
