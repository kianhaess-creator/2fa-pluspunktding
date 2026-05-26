const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const config = require('../config');
const store = require('../services/store');
const { sendVerificationEmail } = require('../services/email');
const { pool } = require('../services/db');

const SALT_ROUNDS = 12;
const DUMMY_HASH = '$2a$12$invalidhashinvalidhashinvalidhashinvalidhashinvalid';

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Zu viele Versuche. Bitte warte eine Minute.' },
});

const codeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Zu viele Versuche. Bitte warte eine Minute.' },
});

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeCompare(a, b) {
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

function storeKey(type, email) {
  return `biz:${type}:${email.toLowerCase().trim()}`;
}

function signToken(payload) {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: '7d' });
}

function verifyToken(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) throw Object.assign(new Error('Unauthorized'), { status: 401 });
  try {
    return jwt.verify(auth.slice(7), config.jwtSecret);
  } catch {
    throw Object.assign(new Error('Token invalid or expired'), { status: 401 });
  }
}

// POST /api/auth/business/login
router.post('/auth/business/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    const normalized = email.toLowerCase().trim();
    const result = await pool.query(
      'SELECT email, password_hash, name FROM users WHERE email = $1',
      [normalized]
    );
    const business = result.rows[0];

    const hash = business ? business.password_hash : DUMMY_HASH;
    const matches = await bcrypt.compare(password, hash);

    if (!business || !matches) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    // Businesses always require 2FA
    const code = crypto.randomInt(100000, 1000000).toString();
    store.set(storeKey('code', normalized), sha256(code), config.code.ttlSeconds);
    store.del(storeKey('code-attempts', normalized));
    await sendVerificationEmail(normalized, business.name, code);
    return res.json({ requires2fa: true });
  } catch (err) { next(err); }
});

// POST /api/auth/business/verify-2fa
router.post('/auth/business/verify-2fa', codeLimiter, async (req, res, next) => {
  try {
    const { email, code } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (!code || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Code must be a 6-digit number' });
    }

    const normalized = email.toLowerCase().trim();
    const codeKey = storeKey('code', normalized);
    const attemptsKey = storeKey('code-attempts', normalized);

    const attempts = store.incr(attemptsKey);
    if (attempts === 1) store.expire(attemptsKey, config.code.sendWindowSeconds);

    if (attempts > config.code.maxVerifyAttempts) {
      return res.status(429).json({ success: false, error: 'Too many failed attempts. Request a new code.' });
    }

    const stored = store.get(codeKey);
    if (!stored) {
      return res.status(404).json({ success: false, error: 'No active code found. Please request a new one.' });
    }

    if (!safeCompare(sha256(code), stored)) {
      const remaining = config.code.maxVerifyAttempts - attempts;
      return res.json({ success: false, attemptsRemaining: remaining });
    }

    store.del(codeKey, attemptsKey);

    const businessResult = await pool.query('SELECT name FROM users WHERE email = $1', [normalized]);
    if (businessResult.rows.length === 0) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    res.json({ success: true, token: signToken({ email: normalized, type: 'business' }) });
  } catch (err) { next(err); }
});

// POST /api/auth/employee/login
router.post('/auth/employee/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    const normalized = email.toLowerCase().trim();
    const result = await pool.query(
      'SELECT id, email, password_hash, is_first_login, business_email FROM business_employees WHERE email = $1',
      [normalized]
    );
    const employee = result.rows[0];

    const hash = employee ? employee.password_hash : DUMMY_HASH;
    const matches = await bcrypt.compare(password, hash);

    if (!employee || !matches) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    const token = signToken({
      email: normalized,
      type: 'employee',
      business_email: employee.business_email,
      employee_id: employee.id,
    });

    res.json({
      success: true,
      token,
      is_first_login: employee.is_first_login,
      business_email: employee.business_email,
      employee_id: employee.id,
    });
  } catch (err) { next(err); }
});

// POST /api/auth/employee/update-email
router.post('/auth/employee/update-email', codeLimiter, async (req, res, next) => {
  try {
    let user;
    try { user = verifyToken(req); } catch (e) { return res.status(e.status).json({ error: e.message }); }
    if (user.type !== 'employee') return res.status(403).json({ error: 'Forbidden' });

    const { new_email } = req.body;
    if (!new_email || typeof new_email !== 'string' || !new_email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const normalized = new_email.toLowerCase().trim();
    const existing = await pool.query('SELECT id FROM business_employees WHERE email = $1', [normalized]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email_taken' });

    const code = crypto.randomInt(100000, 1000000).toString();
    store.set(
      storeKey('email-change', user.email),
      JSON.stringify({ hash: sha256(code), new_email: normalized, attempts: 0 }),
      config.code.ttlSeconds
    );

    await sendVerificationEmail(normalized, null, code);
    res.json({ success: true });
  } catch (err) { next(err); }
});

// POST /api/auth/employee/verify-email
router.post('/auth/employee/verify-email', async (req, res, next) => {
  try {
    let user;
    try { user = verifyToken(req); } catch (e) { return res.status(e.status).json({ error: e.message }); }
    if (user.type !== 'employee') return res.status(403).json({ error: 'Forbidden' });

    const { code, new_email } = req.body;
    if (!code || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Invalid code' });

    const codeKey = storeKey('email-change', user.email);
    const stored = store.get(codeKey);
    if (!stored) return res.status(404).json({ error: 'No active code. Request a new one.' });

    const entry = JSON.parse(stored);
    entry.attempts = (entry.attempts || 0) + 1;

    if (entry.attempts > config.code.maxVerifyAttempts) {
      store.del(codeKey);
      return res.status(429).json({ error: 'Too many failed attempts. Request a new code.' });
    }

    store.set(codeKey, JSON.stringify(entry), store.ttl(codeKey));

    if (!safeCompare(sha256(code), entry.hash) || entry.new_email !== new_email?.toLowerCase().trim()) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    store.del(codeKey);

    await pool.query(
      'UPDATE business_employees SET email = $1, is_first_login = false WHERE id = $2',
      [entry.new_email, user.employee_id]
    );

    res.json({
      success: true,
      token: signToken({
        email: entry.new_email,
        type: 'employee',
        business_email: user.business_email,
        employee_id: user.employee_id,
      }),
    });
  } catch (err) { next(err); }
});

// POST /api/auth/business/register-employee
router.post('/auth/business/register-employee', async (req, res, next) => {
  try {
    let user;
    try { user = verifyToken(req); } catch (e) { return res.status(e.status).json({ error: e.message }); }
    if (user.type !== 'business') return res.status(403).json({ error: 'Forbidden' });

    const { first_name, last_name, email, password, role, workdays, shift_from, shift_to, permissions, photo_url } = req.body;
    if (!email || !password || !first_name || !last_name || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'invalid_data' });
    }

    const normalized = email.toLowerCase().trim();
    const existing = await pool.query('SELECT id FROM business_employees WHERE email = $1', [normalized]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email_taken' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      `INSERT INTO business_employees
       (email, password_hash, first_name, last_name, role, business_email,
        workdays, shift_from, shift_to, permissions, photo_url, is_first_login)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true)
       RETURNING id`,
      [
        normalized, passwordHash, first_name, last_name,
        role || null, user.email,
        workdays || null, shift_from || null, shift_to || null,
        permissions ? JSON.stringify(permissions) : null,
        photo_url || null,
      ]
    );

    res.json({ success: true, employee_id: result.rows[0].id });
  } catch (err) { next(err); }
});

router.post('/auth/business/change-password', async (req, res, next) => {
  try {
    let user;
    try { user = verifyToken(req); } catch (e) { return res.status(e.status).json({ error: e.message }); }
    if (user.type !== 'business') return res.status(403).json({ error: 'Forbidden' });

    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ success: false, message: 'Pflichtfelder fehlen.' });
    }
    if (typeof new_password !== 'string' || new_password.length < 8) {
      return res.status(400).json({ success: false, message: 'Neues Passwort muss mindestens 8 Zeichen lang sein.' });
    }

    const result = await pool.query('SELECT password_hash FROM users WHERE email = $1', [user.email]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Business nicht gefunden.' });

    const match = await bcrypt.compare(current_password, result.rows[0].password_hash);
    if (!match) return res.status(400).json({ success: false, message: 'Aktuelles Passwort ist falsch.' });

    const newHash = await bcrypt.hash(new_password, SALT_ROUNDS);
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [newHash, user.email]);

    res.json({ success: true });
  } catch (err) { next(err); }
});

module.exports = router;
