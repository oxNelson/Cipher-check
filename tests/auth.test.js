import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  hashPassword,
  verifyPassword,
  checkRateLimit,
  resetRateLimit,
  createUser,
  findUserByEmail,
  createSession,
  findSession,
  deleteSession,
  parseCookies,
  serializeSessionCookie,
} from "../server-auth.js";

describe("Phase 2: Authentication & Security Foundation", () => {
  test("Password hashing creates scrypt salt and verifies correctly", async () => {
    const rawPassword = "CorrectHorseBatteryStaple!";
    const hash = await hashPassword(rawPassword);

    assert.ok(hash.startsWith("scrypt:"));
    const isCorrect = await verifyPassword(rawPassword, hash);
    assert.equal(isCorrect, true);

    const isWrong = await verifyPassword("WrongPassword!", hash);
    assert.equal(isWrong, false);
  });

  test("Rate limiter blocks brute force after 5 attempts", () => {
    const testIp = "192.0.2.42";
    resetRateLimit(testIp);

    for (let i = 0; i < 5; i++) {
      const res = checkRateLimit(testIp);
      assert.equal(res.allowed, true);
    }

    const blocked = checkRateLimit(testIp);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.resetInSeconds > 0);

    resetRateLimit(testIp);
    const unblocked = checkRateLimit(testIp);
    assert.equal(unblocked.allowed, true);
  });

  test("User registration and email lookup", async () => {
    const email = `audit-test-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    assert.ok(user.id);
    assert.equal(user.email, email.toLowerCase());
    assert.equal(user.isVerified, false);
    assert.equal(user.passwordHash, undefined); // Ensure passwordHash is omitted

    const found = await findUserByEmail(email);
    assert.ok(found);
    assert.equal(found.id, user.id);
  });

  test("Session lifecycle: create, find, and delete", async () => {
    const email = `session-test-${Date.now()}@example.com`;
    const hash = await hashPassword("AuditPass123!");
    const user = await createUser(email, hash);

    const { sessionId, expiresAt } = await createSession(user.id);
    assert.equal(typeof sessionId, "string");
    assert.equal(sessionId.length, 64); // 32 bytes hex
    assert.ok(expiresAt > new Date());

    const sessionData = await findSession(sessionId);
    assert.ok(sessionData);
    assert.equal(sessionData.user.id, user.id);
    assert.equal(sessionData.user.email, email);

    await deleteSession(sessionId);
    const invalidated = await findSession(sessionId);
    assert.equal(invalidated, null);
  });

  test("Cookie serialization enforces HttpOnly and SameSite=Lax", () => {
    const sessionId = "abcdef0123456789abcdef0123456789";
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    const serialized = serializeSessionCookie(sessionId, expiresAt);

    assert.ok(serialized.includes(`session_id=${sessionId}`));
    assert.ok(serialized.includes("HttpOnly"));
    assert.ok(serialized.includes("SameSite=Lax"));
    assert.ok(serialized.includes("Path=/"));
  });

  test("Cookie parser extracts cookies accurately", () => {
    const header = "theme=dark; session_id=abc123xyz; other=val";
    const parsed = parseCookies(header);
    assert.equal(parsed.theme, "dark");
    assert.equal(parsed.session_id, "abc123xyz");
    assert.equal(parsed.other, "val");
  });
});
