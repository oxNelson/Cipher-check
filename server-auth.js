try {
  process.loadEnvFile();
} catch (_) {}

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

// Secure Password Hashing: uses bcryptjs (matching existing database accounts) or scrypt
export async function hashPassword(password) {
  try {
    const { default: bcrypt } = await import("bcryptjs");
    return await bcrypt.hash(password, 12);
  } catch (_) {
    return new Promise((resolve, reject) => {
      const salt = crypto.randomBytes(16).toString("hex");
      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) return reject(err);
        resolve(`scrypt:${salt}:${derivedKey.toString("hex")}`);
      });
    });
  }
}

export async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;

  // Support bcrypt hashes ($2a$, $2b$, $2y$)
  if (storedHash.startsWith("$2")) {
    try {
      const { default: bcrypt } = await import("bcryptjs");
      return await bcrypt.compare(password, storedHash);
    } catch (_) {
      return false;
    }
  }

  // Support scrypt hashes
  if (storedHash.startsWith("scrypt:")) {
    return new Promise((resolve) => {
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

  return false;
}

// In-Memory Data Store (used when DATABASE_URL is not set or unavailable)
const memoryUsers = new Map(); // id -> user
const memoryUsersByEmail = new Map(); // lowercase email -> user
const memorySessions = new Map(); // sessionId -> { userId, expiresAt }

let pgPool = null;
let isPostgresReady = false;

export async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log("[CipherCheck Auth] DATABASE_URL is not configured. Running with in-memory persistence.");
    return { type: "in-memory", ready: true };
  }

  try {
    const pgModule = await import("pg");
    const Pool = pgModule.default?.Pool || pgModule.Pool;
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      connectionTimeoutMillis: 5000,
    });

    // Test connection
    const client = await pgPool.connect();
    try {
      // Run migrations in lib/db/migrations
      const migrationsDir = path.join(__dirname, "lib", "db", "migrations");
      if (fs.existsSync(migrationsDir)) {
        const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith(".sql")).sort();
        for (const file of files) {
          const sql = fs.readFileSync(path.join(migrationsDir, file), "utf-8");
          await client.query(sql);
        }
      }
      // Ensure nickname column exists
      await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname VARCHAR(30);");
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
      "SELECT id, email, nickname, password_hash as \"passwordHash\", is_verified as \"isVerified\", created_at as \"createdAt\" FROM users WHERE LOWER(email) = $1 LIMIT 1",
      [normalizedEmail]
    );
    return res.rows[0] || null;
  }
  return memoryUsersByEmail.get(normalizedEmail) || null;
}

export async function findUserById(id) {
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\" FROM users WHERE id = $1 LIMIT 1",
      [String(id)]
    );
    return res.rows[0] || null;
  }
  const user = memoryUsers.get(String(id));
  if (!user) return null;
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

export async function createUser(email, passwordHash, nickname = null) {
  const normalizedEmail = email.trim().toLowerCase();
  const now = new Date();
  const id = crypto.randomUUID();
  const cleanNickname =
    typeof nickname === "string" && nickname.trim().length >= 2 && nickname.trim().length <= 30
      ? nickname.trim()
      : null;

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "INSERT INTO users (id, email, password_hash, nickname, is_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [id, normalizedEmail, passwordHash, cleanNickname, false, now]
    );
    return res.rows[0];
  }

  const user = {
    id,
    email: normalizedEmail,
    passwordHash,
    nickname: cleanNickname,
    isVerified: false,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };

  memoryUsers.set(id, user);
  memoryUsersByEmail.set(normalizedEmail, user);
  const { passwordHash: _, ...safeUser } = user;
  return safeUser;
}

export async function updateUserNickname(userId, nickname) {
  if (!userId) return null;
  const cleanNickname = typeof nickname === "string" ? nickname.trim() : "";
  if (cleanNickname.length < 2 || cleanNickname.length > 30) {
    throw new Error("Nickname must be between 2 and 30 characters long.");
  }
  if (/[\r\n\t\0]/.test(cleanNickname) || /<[^>]*>/.test(cleanNickname)) {
    throw new Error("Nickname cannot contain HTML tags or control characters.");
  }

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "UPDATE users SET nickname = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [cleanNickname, String(userId)]
    );
    return res.rows[0] || null;
  }

  const user = memoryUsers.get(String(userId));
  if (!user) return null;
  user.nickname = cleanNickname;
  user.updatedAt = new Date().toISOString();
  const { passwordHash: _, ...safeUser } = user;
  return safeUser;
}

export async function setVerificationToken(userId, token, expiresAt) {
  if (isPostgresReady && pgPool) {
    await pgPool.query(
      "UPDATE users SET email_verification_token = $1, email_verification_expires = $2 WHERE id = $3",
      [token, expiresAt, String(userId)]
    );
  } else {
    const user = memoryUsers.get(String(userId));
    if (user) {
      user.emailVerificationToken = token;
      user.emailVerificationExpires = expiresAt;
    }
  }
}

export async function verifyEmailToken(token) {
  if (!token) return null;
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "UPDATE users SET is_verified = true, email_verification_token = NULL, email_verification_expires = NULL WHERE email_verification_token = $1 AND email_verification_expires > NOW() RETURNING id, email, nickname, is_verified as \"isVerified\", created_at as \"createdAt\"",
      [token]
    );
    return res.rows[0] || null;
  }
  for (const user of memoryUsers.values()) {
    if (user.emailVerificationToken === token && new Date(user.emailVerificationExpires) > new Date()) {
      user.isVerified = true;
      user.emailVerificationToken = null;
      user.emailVerificationExpires = null;
      const { passwordHash: _, ...safeUser } = user;
      return safeUser;
    }
  }
  return null;
}

export async function setPasswordResetToken(identifier, token, expiresAt) {
  if (!identifier) return false;
  const str = String(identifier).trim();
  const isEmail = str.includes("@");
  if (isPostgresReady && pgPool) {
    const query = isEmail
      ? "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE LOWER(email) = LOWER($3) RETURNING id"
      : "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3 RETURNING id";
    const res = await pgPool.query(query, [token, expiresAt, str]);
    return Boolean(res.rows.length);
  }
  const user = isEmail
    ? memoryUsersByEmail.get(str.toLowerCase())
    : memoryUsers.get(str);
  if (user) {
    user.passwordResetToken = token;
    user.passwordResetExpires = expiresAt;
    return true;
  }
  return false;
}

export async function resetPasswordWithToken(token, newPasswordHash) {
  if (!token) return null;
  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL, updated_at = NOW() WHERE password_reset_token = $2 AND password_reset_expires > NOW() RETURNING id, email",
      [newPasswordHash, token]
    );
    if (!res.rows.length) return null;
    const user = res.rows[0];
    await pgPool.query("DELETE FROM sessions WHERE user_id = $1", [user.id]);
    return user;
  }
  for (const user of memoryUsers.values()) {
    if (user.passwordResetToken === token && new Date(user.passwordResetExpires) > new Date()) {
      user.passwordHash = newPasswordHash;
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      for (const [sId, s] of memorySessions.entries()) {
        if (s.userId === user.id) {
          memorySessions.delete(sId);
        }
      }
      return { id: user.id, email: user.email };
    }
  }
  return null;
}

export async function createSession(userId) {
  const sessionId = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  if (isPostgresReady && pgPool) {
    await pgPool.query(
      "INSERT INTO sessions (id, user_id, created_at, last_active_at, expires_at) VALUES ($1, $2, NOW(), NOW(), $3)",
      [sessionId, String(userId), expiresAt]
    );
  } else {
    memorySessions.set(sessionId, { userId: String(userId), expiresAt });
  }

  return { sessionId, expiresAt };
}

export async function findSession(sessionId) {
  if (!sessionId) return null;

  if (isPostgresReady && pgPool) {
    const res = await pgPool.query(
      "SELECT s.id, s.user_id as \"userId\", s.expires_at as \"expiresAt\", u.email, u.nickname, u.is_verified as \"isVerified\", u.created_at as \"createdAt\" FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = $1 AND s.expires_at > NOW() LIMIT 1",
      [sessionId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      session: { id: row.id, userId: row.userId, expiresAt: row.expiresAt },
      user: {
        id: row.userId,
        email: row.email,
        nickname: row.nickname || null,
        isVerified: row.isVerified,
        createdAt: row.createdAt,
      },
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

export function serializeSessionCookie(sessionId, expiresAt, isSecure = false) {
  const maxAge = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
  const secureFlag = isSecure || process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;
}

export function serializeClearedCookie(isSecure = false) {
  const secureFlag = isSecure || process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `session_id=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureFlag}`;
}

