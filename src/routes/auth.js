const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const router = express.Router();
const config = require('../config');
const store = require('../services/store');
const { sendVerificationEmail } = require('../services/email');
const { pool } = require('../services/db');

const SALT_ROUNDS = 12;

function hashCode(code) {
  return crypto
    .createHmac('sha256', config.hashPepper)
    .update(code)
    .digest('hex');
}

function storeKey(type, email) {
  return `2fa:${type}:${email.toLowerCase().trim()}`;
}

// POST /api/send-code
// Body: { email, name? }
router.post('/send-code', async (req, res, next) => {
  try {
    const { email, name } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const sendKey = storeKey('sends', email);
    const sends = store.incr(sendKey);
    if (sends === 1) store.expire(sendKey, config.code.sendWindowSeconds);

    if (sends > config.code.maxSendAttempts) {
      const remaining = store.ttl(sendKey);
      return res.status(429).json({
        error: 'Too many code requests. Please wait before requesting a new code.',
        retryAfterSeconds: remaining,
      });
    }

    const code = crypto.randomInt(100000, 1000000).toString();
    const hashed = hashCode(code);

    const codeKey = storeKey('code', email);
    const attemptsKey = storeKey('attempts', email);

    store.set(codeKey, hashed, config.code.ttlSeconds);
    store.del(attemptsKey);

    await sendVerificationEmail(email, name, code);

    res.json({ success: true, message: 'Verification code sent.' });
  } catch (err) {
    next(err);
  }
});

// POST /api/verify-code
// Body: { email, code }
router.post('/verify-code', async (req, res, next) => {
  try {
    const { email, code } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Code must be a 6-digit number' });
    }

    const codeKey = storeKey('code', email);
    const attemptsKey = storeKey('attempts', email);

    const attempts = store.incr(attemptsKey);
    if (attempts === 1) store.expire(attemptsKey, config.code.sendWindowSeconds);

    if (attempts > config.code.maxVerifyAttempts) {
      return res.status(429).json({
        error: 'Too many failed attempts. Request a new code.',
        valid: false,
      });
    }

    const stored = store.get(codeKey);

    if (!stored) {
      return res.status(404).json({ valid: false, error: 'No active code found. Please request a new one.' });
    }

    const inputHash = hashCode(code);
    const isValid = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(stored));

    if (!isValid) {
      const remaining = config.code.maxVerifyAttempts - attempts;
      return res.status(200).json({ valid: false, attemptsRemaining: remaining });
    }

    store.del(codeKey, attemptsKey);

    res.json({ valid: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/register
router.post('/auth/register', async (req, res, next) => {
  try {
    const { email, password, name, postalCode, city, birthDate } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@') ||
        !password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'invalid_data' });
    }
    const normalized = email.toLowerCase().trim();
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email_taken' });
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query(
      `INSERT INTO users (email, password_hash, name, postal_code, city, birth_date)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [normalized, passwordHash, name || null, postalCode || null, city || null, birthDate || null]
    );
    res.json({ success: true });
  } catch (err) { next(err); }
});

// POST /api/auth/login
router.post('/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      return res.status(200).json({ success: false });
    }
    const normalized = email.toLowerCase().trim();
    const result = await pool.query('SELECT password_hash FROM users WHERE email = $1', [normalized]);
    const user = result.rows[0];
    const hash = user ? user.password_hash : '$2a$12$invalidhashinvalidhashinvalidhashinvalidhashinvalid';
    const match = await bcrypt.compare(password, hash);
    if (!match || !user) return res.status(200).json({ success: false });
    res.json({ success: true });
  } catch (err) { next(err); }
});

// POST /api/auth/profile
router.post('/auth/profile', async (req, res, next) => {
  try {
    const { email, name, postalCode, city, birthDate, loginCount, lastLoginAt, loginMethod } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'invalid_data' });
    }
    const normalized = email.toLowerCase().trim();
    await pool.query(
      `UPDATE users SET
        name = COALESCE($2, name),
        postal_code = COALESCE($3, postal_code),
        city = COALESCE($4, city),
        birth_date = COALESCE($5, birth_date),
        login_count = COALESCE($6, login_count),
        last_login_at = COALESCE($7, last_login_at),
        login_method = COALESCE($8, login_method)
       WHERE email = $1`,
      [normalized, name ?? null, postalCode ?? null, city ?? null, birthDate ?? null,
       loginCount ?? null, lastLoginAt ?? null, loginMethod ?? null]
    );
    res.json({ success: true });
  } catch (err) { next(err); }
});

// GET /api/auth/profile?email=...
router.get('/auth/profile', async (req, res, next) => {
  try {
    const email = req.query.email;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'invalid_data' });
    }
    const normalized = email.toLowerCase().trim();
    const result = await pool.query(
      `SELECT name, postal_code, city, birth_date, login_count, last_login_at, login_method
       FROM users WHERE email = $1`,
      [normalized]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'not_found' });
    const r = result.rows[0];
    res.json({
      name: r.name,
      postalCode: r.postal_code,
      city: r.city,
      birthDate: r.birth_date,
      loginCount: r.login_count,
      lastLoginAt: r.last_login_at,
      loginMethod: r.login_method,
    });
  } catch (err) { next(err); }
});

// POST /api/auth/reset-password
router.post('/auth/reset-password', async (req, res, next) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@') ||
        !newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ error: 'invalid_data' });
    }
    const normalized = email.toLowerCase().trim();
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'not_found' });
    const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [passwordHash, normalized]);
    res.json({ success: true });
  } catch (err) { next(err); }
});

module.exports = router;
