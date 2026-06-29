/**
 * db.js
 * ------------------------------------------------------------------
 * Lightweight embedded data layer for the Secure Login System.
 *
 * NOTE ON SQL INJECTION:
 * This project stores users in a local JSON file rather than a SQL
 * database, so there is no SQL query string to inject into in the
 * first place. The same security principle the task asks for —
 * "never build queries by concatenating raw user input" — is honored
 * here because every lookup uses safe, typed JS operations (.find(),
 * strict equality) instead of string-built queries. If you swap this
 * for MySQL/Postgres later, replace the methods below with
 * parameterized queries (e.g. `db.query('SELECT * FROM users WHERE
 * username = ?', [username])`) — never use template literals to
 * build SQL.
 * ------------------------------------------------------------------
 */

const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'data', 'users.json');

function ensureDb() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify([]));
}

function readUsers() {
  ensureDb();
  const raw = fs.readFileSync(DB_FILE, 'utf-8');
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function writeUsers(users) {
  ensureDb();
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// Basic input validation/sanitization helper.
// Rejects anything containing classic SQL-injection / script-injection
// characters, even though we don't use SQL — this also protects
// against stored-XSS if the username is ever rendered back to the page.
function isSafeInput(str) {
  if (typeof str !== 'string') return false;
  const dangerousPattern = /['";`<>{}]|(--)|(\/\*)|(\*\/)/;
  return !dangerousPattern.test(str);
}

function findUserByUsername(username) {
  const users = readUsers();
  return users.find((u) => u.username === username) || null;
}

function createUser(user) {
  const users = readUsers();
  users.push(user);
  writeUsers(users);
  return user;
}

function updateUser(username, updates) {
  const users = readUsers();
  const idx = users.findIndex((u) => u.username === username);
  if (idx === -1) return null;
  users[idx] = { ...users[idx], ...updates };
  writeUsers(users);
  return users[idx];
}

module.exports = {
  isSafeInput,
  findUserByUsername,
  createUser,
  updateUser,
};
