/**
 * server.js
 * ------------------------------------------------------------------
 * Secure Login System — Cyber Security Internship Task 4 (Thiranex)
 *
 * Features implemented:
 *  1. User registration & login using hashed passwords (bcrypt)
 *  2. Input validation + protection from injection attacks
 *  3. Session management with logout
 *  4. Optional Two-Factor Authentication (TOTP via speakeasy)
 * ------------------------------------------------------------------
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
require('dotenv').config();

const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change_this_secret_in_production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,        // JS on the page can't read the cookie (XSS protection)
      secure: false,         // set true when served over HTTPS
      maxAge: 1000 * 60 * 30 // 30 minute session
    }
  })
);

// ---------- Middleware ----------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// ---------- Routes ----------

app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

// ---- Registration ----
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (!username || !password || !confirmPassword) {
    return res.render('register', { error: 'All fields are required.' });
  }
  if (!db.isSafeInput(username)) {
    return res.render('register', { error: 'Username contains invalid characters.' });
  }
  if (username.length < 3 || username.length > 20) {
    return res.render('register', { error: 'Username must be 3-20 characters.' });
  }
  if (password.length < 8) {
    return res.render('register', { error: 'Password must be at least 8 characters.' });
  }
  if (password !== confirmPassword) {
    return res.render('register', { error: 'Passwords do not match.' });
  }
  if (db.findUserByUsername(username)) {
    return res.render('register', { error: 'Username already taken.' });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const twoFactorSecret = speakeasy.generateSecret({
    name: `SecureLoginApp (${username})`
  });

  db.createUser({
    username,
    passwordHash,
    twoFactorEnabled: false,
    twoFactorSecret: twoFactorSecret.base32
  });

  // Show the user their 2FA QR code so they can set it up (optional step)
  qrcode.toDataURL(twoFactorSecret.otpauth_url, (err, qrImage) => {
    res.render('setup2fa', {
      username,
      qrImage: err ? null : qrImage,
      secret: twoFactorSecret.base32
    });
  });
});

// ---- Enable 2FA confirmation ----
app.post('/enable-2fa', (req, res) => {
  const { username, token } = req.body;
  const user = db.findUserByUsername(username);
  if (!user) return res.redirect('/login');

  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (verified) {
    db.updateUser(username, { twoFactorEnabled: true });
    return res.redirect('/login');
  }
  res.render('setup2fa', {
    username,
    qrImage: null,
    secret: user.twoFactorSecret,
    error: 'Invalid code. Please try again or skip for now.'
  });
});

app.get('/skip-2fa', (req, res) => res.redirect('/login'));

// ---- Login ----
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || !db.isSafeInput(username)) {
    return res.render('login', { error: 'Invalid username or password.' });
  }

  const user = db.findUserByUsername(username);
  if (!user) {
    return res.render('login', { error: 'Invalid username or password.' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.render('login', { error: 'Invalid username or password.' });
  }

  if (user.twoFactorEnabled) {
    req.session.pending2faUser = username;
    return res.redirect('/verify-2fa');
  }

  req.session.user = username;
  res.redirect('/dashboard');
});

// ---- 2FA verification at login ----
app.get('/verify-2fa', (req, res) => {
  if (!req.session.pending2faUser) return res.redirect('/login');
  res.render('verify2fa', { error: null });
});

app.post('/verify-2fa', (req, res) => {
  const username = req.session.pending2faUser;
  if (!username) return res.redirect('/login');

  const user = db.findUserByUsername(username);
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: req.body.token,
    window: 1
  });

  if (!verified) {
    return res.render('verify2fa', { error: 'Invalid authentication code.' });
  }

  delete req.session.pending2faUser;
  req.session.user = username;
  res.redirect('/dashboard');
});

// ---- Dashboard (protected) ----
app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', { username: req.session.user });
});

// ---- Logout ----
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.listen(PORT, () => {
  console.log(`Secure Login System running at http://localhost:${PORT}`);
});
