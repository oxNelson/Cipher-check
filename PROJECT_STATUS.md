# CipherCheck Project Status

**Last Updated:** October 27, 2026  
**Version:** 1.2.0 (Phase 1 Complete + Phase 2 PostgreSQL Auth & Real SMTP Integration Live)

---

## 1. Executive Summary

CipherCheck is a privacy-first password security auditor, secure generator, and authentication platform.
- **Phase 1 (Core Capabilities):** 100% verified. All password analysis, heuristic scoring, weakness detection, and secure password generation run strictly client-side using vanilla HTML5/CSS3/JavaScript and the browser Web Crypto API. Passwords entered in the workbench are never transmitted or stored.
- **Theme Toggle:** Fully implemented with Light/Dark mode, accessible sun/moon icons, keyboard support, `localStorage` persistence, device `prefers-color-scheme` detection, and zero-flash inline loading.
- **Phase 2 (Database & PostgreSQL Authentication):** Fully connected to PostgreSQL database with version-controlled migrations (`users` and `sessions` tables with verification and password reset columns). Secure password hashing with bcrypt, session invalidation, and rate limiting.
- **Phase 3 (SMTP & Email Delivery):** Live and active. SMTP configuration verified via TLS connection to mail server. Registration automatically dispatches real email verification links, and password recovery dispatches reset links.

---

## 2. Issues Diagnosed & Resolved

### 2.1 Issue 1: Registration "Connection error. Please try again."
- **Root Cause:** In the AI Studio preview environment, the web application runs inside an iframe (`https://aistudio.google.com` or `*.googleusercontent.com`) addressing a Cloud Run container (`*.run.app`). The previous CSRF middleware rejected requests with `Sec-Fetch-Site: cross-site` and compared `Origin` strictly against internal host `localhost:3000`. This resulted in HTTP 403 Forbidden without CORS response headers, causing the browser's `fetch()` call to fail with a `TypeError: Failed to fetch`, which was caught and displayed as `"Connection error. Please try again."`
- **Resolution:**
  1. Configured Express `trust proxy` to honor proxy headers (`x-forwarded-host`, `x-forwarded-proto`).
  2. Implemented CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Headers`) allowing preview environments (`.googleusercontent.com`, `.google.com`, `.run.app`, `localhost`).
  3. Added dual session token transmission: sessions are managed via both `HttpOnly` cookies and `Authorization: Bearer <token>` in `sessionStorage` to maintain seamless sessions across browsers that partition third-party iframe cookies.

### 2.2 Issue 2: Account Modal Reporting "SMTP is not configured in this environment"
- **Root Cause:** 
  1. The server code previously had hardcoded 503 stubs for email endpoints and no dynamic status endpoint.
  2. `nodemailer` package was not installed.
  3. `index.html` contained hardcoded static warning text.
- **Resolution:**
  1. Installed `nodemailer` and built `server-smtp.js`.
  2. Verified SMTP credentials live against `process.env.SMTP_HOST` on port 587 (`transporter.verify()` succeeded).
  3. Created `GET /api/auth/status` endpoint to dynamically report `{ smtpConfigured: true, databaseConnected: true }`.
  4. Updated UI in `ciphercheck/index.html` and `ciphercheck/script.js` to dynamically query status and display active green banner: `✓ SMTP email service is active. Email verification and password recovery are enabled.`
  5. Implemented live verification token generation, expiration tracking, and email delivery for registration (`/api/auth/register`), resending (`/api/auth/resend-verification`), verification (`/api/auth/verify-email`), and password recovery (`/api/auth/forgot-password`, `/api/auth/reset-password`).

### 2.3 Issue 3: Verification & Password Reset URLs Contained "localhost:3000"
- **Root Cause:** 
  1. `getBaseUrl` in `server.js` was reading `req.headers["x-forwarded-host"] || req.headers.host || "localhost:3000"`. In this containerized environment, internal proxy forwards requests with internal `host: localhost:3000` and no forwarded host header.
  2. The function ignored `process.env.APP_URL` (`https://ais-dev-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app`), `PUBLIC_URL`, and `BASE_URL`.
  3. The function did not check the browser request's validated `req.headers.origin` or `req.headers.referer` (which carries the exact reachable preview or custom domain the user is interacting with).
  4. The client application had no dedicated Reset Password panel in `index.html` or handler for `?resetToken=...` in `script.js`.
- **Resolution:**
  1. Implemented hierarchical `getBaseUrl(req)` in `server-smtp.js`:
     - Priority 1: Validated public `Origin` / `Referer` from incoming browser request (e.g., active preview URL `https://ais-dev-...run.app` or shared preview `https://ais-pre-...run.app`).
     - Priority 2: Configured public base URL environment variable (`APP_URL`, `PUBLIC_URL`, or `BASE_URL`).
     - Priority 3: Non-localhost `Host` / `X-Forwarded-Host` reverse proxy headers.
     - Priority 4: Development fallback (`http://localhost:${PORT || 3000}`).
  2. Stripped trailing slashes to prevent malformed double-slash links.
  3. Added `#panelReset` in `index.html` with New Password & Confirm Password inputs, validation, and submission to `POST /api/auth/reset-password`.
  4. Handled URL parameters (`?verifyToken=...` and `?resetToken=...`) on load in `script.js`:
     - Cleaned tokens from URL via `history.replaceState` immediately.
     - Automatically called `/api/auth/verify-email`, issuing an authenticated session and displaying verification success or clear error messages for expired/invalid tokens.
     - Displayed the dedicated password reset panel for `resetToken`, validating input, updating the password, and redirecting to sign in.

### 2.4 Issue 4: Password-Reset Link HTTP 403 Forbidden on aistudio.google.com
- **Observed Behavior:** Clicking the "Reset Password" button in delivered emails opened `Error 403 (Forbidden)` on `aistudio.google.com`.
- **Root Cause:**
  1. In the AI Studio editor, preview iframes make frontend API requests with `Origin: https://aistudio.google.com` or `*.googleusercontent.com`.
  2. In `server-smtp.js`, `getBaseUrl(req)` previously evaluated `isOriginAllowed(origin, req)` which allowed `*.google.com` for CORS/iframe compatibility.
  3. Consequently, `getBaseUrl(req)` selected `https://aistudio.google.com`, constructing reset and verification URLs such as `https://aistudio.google.com/?resetToken=...`.
  4. When clicked in an external browser or email client, direct requests to `aistudio.google.com` bypassed the applet and reached Google's platform servers, which returned HTTP 403 Forbidden.
- **Resolution:**
  1. **Strict Application Host Filtering (`isApplicationHost`):** Added hostname validation in `server-smtp.js` that strictly rejects `localhost`, `127.0.0.1`, `*.google.com`, `*.googleusercontent.com`, and `*.googletagmanager.com`. Only permits valid application deployment hosts (such as `*.run.app` or configured `APP_URL`/`PUBLIC_URL`/`BASE_URL`).
  2. **Canonical Origin Resolution (`getBaseUrl`):** If the incoming request has a valid application host in `origin` or `referer`, it is used; otherwise it resolves to `process.env.APP_URL` (`https://ais-dev-ok6xmxuezsad5ybcofshmt-220908265023.europe-west2.run.app`). This guarantees `aistudio.google.com` is never used for email links.
  3. **Identical Link Targets:** Verified that both the "Reset Password" button `href` and the fallback text URL use the exact same `${resetUrl}` variable, with `target="_blank" rel="noopener noreferrer"`.
  4. **Manual Token Entry Fallback:** In addition to the 1-click link, emails now also display the raw 64-character token code. Added an "Already have a reset code?" button (`#haveResetTokenBtn`) and token input field (`#resetTokenInput`) to `index.html` so users can paste the reset code directly into the UI if desired.
  5. **Live Verification:** Verified end-to-end against PostgreSQL: user registration, reset email generation, invalid token rejection (400), valid token submission (200), token replay rejection (400), old password login failure (401), and new password login success (200).

---

## 3. Database Schema & Migration Status

Database: PostgreSQL (Neon) via `pg.Pool`  
Tables:
- `users`:
  - `id`: varchar (UUID) primary key
  - `email`: varchar unique, indexed
  - `password_hash`: varchar (bcrypt cost factor 12)
  - `is_verified`: boolean (default false)
  - `email_verification_token`: varchar (hex)
  - `email_verification_expires`: timestamptz
  - `password_reset_token`: varchar (hex)
  - `password_reset_expires`: timestamptz
  - `created_at`, `updated_at`: timestamptz
- `sessions`:
  - `id`: varchar (64-char hex) primary key
  - `user_id`: varchar foreign key references `users(id)` ON DELETE CASCADE
  - `created_at`, `last_active_at`, `expires_at`: timestamptz

---

## 4. Automated Test Results

Command: `npm test` (`node --test tests/*.test.js`)

```
TAP version 13
# Subtest: Phase 2: Authentication & Security Foundation
    ok 1 - Password hashing creates secure hash and verifies correctly
    ok 2 - Rate limiter blocks brute force after 5 attempts
    ok 3 - User registration and email lookup
    ok 4 - Session lifecycle: create, find, and delete
    ok 5 - Cookie serialization enforces HttpOnly and SameSite=Lax
    ok 6 - Cookie serialization enforces Secure flag when HTTPS / isSecure is true
    ok 7 - User isolation: authenticated session strictly isolates user data
    ok 8 - SQL parameterization safely handles SQL injection payloads without syntax errors
    ok 9 - Cookie parser extracts cookies accurately
    ok 10 - SMTP configuration detection reflects configured environment
    ok 11 - Email verification token lifecycle: set, verify, and invalidate
    ok 12 - Password reset token lifecycle: set, reset password, verify login
    ok 13 - Expired email verification token is strictly rejected
    ok 14 - Expired password reset token is strictly rejected
    ok 15 - getBaseUrl resolves request origin when originating from an allowed preview domain
    ok 16 - getBaseUrl resolves APP_URL environment variable when request origin is absent
    ok 17 - getBaseUrl strips trailing slashes to avoid double-slash URLs
    ok 18 - getBaseUrl strictly rejects aistudio.google.com origin and resolves to APP_URL
    ok 19 - getBaseUrl strictly rejects googleusercontent.com iframe origin
ok 1 - Phase 2: Authentication & Security Foundation (19/19 passed)

# Subtest: CipherCheck Core Password Analyzer
    ok 1 - Length scoring follows documented rules
    ok 2 - Score bands match classification requirements
    ok 3 - Detects predictable numeric sequences
    ok 4 - Detects common password patterns
    ok 5 - Detects excessive character repetition
    ok 6 - Detects repeated sequences
    ok 7 - Detects predictable construction (word followed by digits)
    ok 8 - High entropy, long password earns Very Strong without weakness findings
ok 2 - CipherCheck Core Password Analyzer (8/8 passed)

# Subtest: CipherCheck Secure Password Generator
    ok 1 - Generates password with exact requested length
    ok 2 - Generated password contains all selected categories
    ok 3 - Rejects invalid configuration where length is smaller than selected categories
    ok 4 - Rejects empty categories
ok 3 - CipherCheck Secure Password Generator (4/4 passed)

# Subtest: Theme Toggle & Persistence
    ok 1 - Applies theme and updates DOM attributes and localStorage
ok 4 - Theme Toggle & Persistence (1/1 passed)

1..4
# tests 32
# suites 4
# pass 32
# fail 0
# cancelled 0
# skipped 0
# todo 0
```

---

## 5. Security Audit Findings & Matrix

| # | Security Control | Status | Evidence / Verification |
|---|---|---|---|
| 1 | Password Hashing & Plaintext Secrecy | **PASS** | Hashed with `bcryptjs` (cost factor 12); never logged or exposed in responses. |
| 2 | Session Generation & Invalidation | **PASS** | 256-bit cryptographically secure token; old sessions destroyed on login to prevent fixation; deleted on logout. |
| 3 | Cookie & Token Security | **PASS** | `HttpOnly; SameSite=Lax; Path=/`; dynamically appends `; Secure` on HTTPS and in production. Bearer tokens supported for partitioned iframe storage. |
| 4 | Rate Limiting & Input Validation | **PASS** | 5 failed attempts per 60s per IP (HTTP 429); strict email and password validation (HTTP 400). |
| 5 | User Isolation | **PASS** | Authenticated endpoints strictly scope data to session user ID; unauthenticated requests reject with 401/403. |
| 6 | CSRF & Origin Defense | **PASS** | Origin validation allows preview and production domains while blocking unauthorized origins on state-changing requests. |
| 7 | SQL Injection Defense & Secret Protection | **PASS** | 100% parameterized queries ($1, $2, ...); credentials never transmitted to client or committed. |
| 8 | SMTP Integration & Integrity | **PASS** | Real SMTP transport over TLS with `nodemailer`; verified server authentication; active verification and reset tokens. |
| 9 | Client-Side Password Processing | **PASS** | Analyzer workbench and generator run purely synchronously in-browser with zero outbound network calls. |
| 10 | Production Readiness Documentation | **PASS** | Required environment variables (`DATABASE_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`) and migrations documented. |
