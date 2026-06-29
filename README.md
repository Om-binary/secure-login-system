# Secure Login System
**Cybersecurity Internship — Task 4 (Thiranex)**

A secure authentication web app built with Node.js + Express, demonstrating
industry-standard login security practices.

## Features Implemented

1. **Password Hashing** — Passwords are never stored in plain text. Each
   password is hashed with **bcrypt** (12 salt rounds) before being saved.
2. **Input Validation & Injection Protection** — All user input is checked
   against a strict allow-pattern before touching the data layer, and no
   query is ever built by concatenating raw user input into a command
   string (the root cause of SQL injection).
3. **Session Management** — Uses `express-session` with `httpOnly` cookies
   and a 30-minute expiry. Dashboard route is protected by middleware that
   redirects unauthenticated users back to `/login`.
4. **Logout** — Destroys the session server-side, not just the cookie, so a
   reused cookie after logout is rejected.
5. **Optional Two-Factor Authentication (2FA)** — TOTP-based 2FA using
   `speakeasy` + a QR code (`qrcode`) compatible with Google Authenticator
   or Authy. Users can enable it right after registering or skip it.

## How to Run

```bash
npm install
node server.js
```

Then open **http://localhost:3000** in your browser.

## Project Structure

```
secure-login-system/
├── server.js          # Main Express app & all routes
├── db.js              # Data layer (JSON-file store) + input sanitization
├── views/             # EJS templates (login, register, 2FA, dashboard)
├── public/style.css    # Styling
├── data/users.json    # Auto-created on first run (stores hashed users)
├── .env               # Session secret & port config
└── package.json
```

## Why a JSON file instead of MySQL/SQLite?

This keeps the project dependency-free and instantly runnable on any
machine (no DB server or native build tools needed) while still
demonstrating the actual security principle the task is testing: **never
build a query by concatenating raw user input.** All lookups use safe,
typed JavaScript operations instead of string-built queries. If you want
to swap in MySQL or PostgreSQL, only `db.js` needs to change — replace its
functions with **parameterized queries**, e.g.:

```js
db.query('SELECT * FROM users WHERE username = ?', [username]);
```

Never use template literals / string concatenation to build the query
itself — that's what reopens the SQL injection hole.

## Security Test Checklist (all verified working)

- [x] Registering stores a bcrypt hash, never the raw password
- [x] Login with correct credentials succeeds
- [x] Login with wrong password is rejected
- [x] Malicious input like `admin' OR '1'='1` is rejected by input validation
- [x] `/dashboard` is inaccessible without a valid session (redirects to `/login`)
- [x] Logout destroys the session; old cookie no longer grants access
- [x] Optional 2FA via TOTP works end-to-end with QR code setup

## Screenshots to include in your submission

1. Registration page
2. 2FA QR code setup page
3. Login page
4. Dashboard after successful login
5. `data/users.json` showing the hashed password (proves passwords aren't stored in plain text)
