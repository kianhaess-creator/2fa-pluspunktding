const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();
const config = require('../config');
const store = require('../services/store');
const { sendVerificationEmail } = require('../services/email');
const { pool } = require('../services/db');
const requireJwt = require('../middleware/jwt');

const SALT_ROUNDS = 12;

const MAX_EMAIL_LEN    = 254;  // RFC 5321
const MAX_PASSWORD_LEN = 72;   // bcrypt verarbeitet max. 72 Bytes
const MAX_NAME_LEN     = 100;

function validEmail(e) {
  return e && typeof e === 'string' && e.includes('@') && e.length <= MAX_EMAIL_LEN;
}
function validPassword(p) {
  return p && typeof p === 'string' && p.length >= 6 && p.length <= MAX_PASSWORD_LEN;
}

function hashCode(code) {
  return crypto
    .createHmac('sha256', config.hashPepper)
    .update(code)
    .digest('hex');
}

function storeKey(type, email) {
  return `2fa:${type}:${email.toLowerCase().trim()}`;
}

router.post('/send-code', async (req, res, next) => {
  try {
    const { email, name } = req.body;

    if (!validEmail(email)) {
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

    const token = jwt.sign(
      { email: email.toLowerCase().trim(), type: 'customer' },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );

    res.json({ valid: true, token });
  } catch (err) {
    next(err);
  }
});

router.post('/auth/register', async (req, res, next) => {
  try {
    const { email, password, name, postalCode, city, birthDate } = req.body;
    if (!validEmail(email) || !validPassword(password)) {
      return res.status(400).json({ error: 'invalid_data' });
    }
    const normalized = email.toLowerCase().trim();
    const safeName = name ? String(name).slice(0, MAX_NAME_LEN) : null;
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [normalized]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email_taken' });
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query(
      `INSERT INTO users (email, password_hash, name, postal_code, city, birth_date)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [normalized, passwordHash, safeName, postalCode || null, city || null, birthDate || null]
    );
    res.json({ success: true });
  } catch (err) { next(err); }
});

router.post('/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!validEmail(email) || !validPassword(password)) {
      return res.status(200).json({ success: false });
    }
    const normalized = email.toLowerCase().trim();
    const result = await pool.query('SELECT password_hash FROM users WHERE email = $1', [normalized]);
    const user = result.rows[0];
    const hash = user ? user.password_hash : '$2a$12$invalidhashinvalidhashinvalidhashinvalidhashinvalid';
    const match = await bcrypt.compare(password, hash);
    if (!match || !user) return res.status(200).json({ success: false });
    const token = jwt.sign(
      { email: normalized, type: 'customer' },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );
    res.json({ success: true, token });
  } catch (err) { next(err); }
});

router.post('/auth/profile', requireJwt, async (req, res, next) => {
  try {
    const email = req.user.email;
    const { name, postalCode, city, birthDate, loginCount, lastLoginAt, loginMethod, street, plz } = req.body;
    await pool.query(
      `UPDATE users SET
        name = COALESCE($2, name),
        postal_code = COALESCE($3, postal_code),
        city = COALESCE($4, city),
        birth_date = COALESCE($5, birth_date),
        login_count = COALESCE($6, login_count),
        last_login_at = COALESCE($7, last_login_at),
        login_method = COALESCE($8, login_method),
        street = COALESCE($9, street),
        plz = COALESCE($10, plz)
       WHERE email = $1`,
      [email, name ?? null, postalCode ?? null, city ?? null, birthDate ?? null,
       loginCount ?? null, lastLoginAt ?? null, loginMethod ?? null, street ?? null, plz ?? null]
    );
    res.json({ success: true });
  } catch (err) { next(err); }
});

router.get('/auth/profile', requireJwt, async (req, res, next) => {
  try {
    const normalized = req.user.email;
    const result = await pool.query(
      `SELECT name, postal_code, city, birth_date, login_count, last_login_at, login_method, street, plz
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
      street: r.street,
      plz: r.plz,
    });
  } catch (err) { next(err); }
});

router.post('/auth/refresh', requireJwt, async (req, res, next) => {
  try {
    // Nur customer-Tokens dürfen refresht werden (business/employee erfordern Re-Login)
    if (req.user.type !== 'customer') {
      return res.status(403).json({ error: 'Refresh nur für Kunden-Accounts.' });
    }
    // Token darf nicht älter als 30 Tage sein (iat-Check)
    const iat = req.user.iat || 0;
    if (Math.floor(Date.now() / 1000) - iat > 30 * 24 * 60 * 60) {
      return res.status(401).json({ error: 'Token zu alt. Bitte neu einloggen.' });
    }
    const token = jwt.sign(
      { email: req.user.email, type: 'customer' },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );
    res.json({ success: true, token });
  } catch (err) { next(err); }
});

router.post('/auth/reset-password', async (req, res, next) => {
  try {
    const { email, newPassword } = req.body;
    if (!validEmail(email) || !validPassword(newPassword)) {
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
