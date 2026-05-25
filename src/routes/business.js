const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const config = require('../config');
const store = require('../services/store');
const { sendVerificationEmail } = require('../services/email');
const { pool } = require('../services/db');

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Zu viele Versuche. Bitte warte eine Minute.' },
});

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
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

router.post('/business/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    const normalized = email.toLowerCase().trim();
    const result = await pool.query(
      'SELECT email, password_hash, two_fa_enabled, name FROM businesses WHERE email = $1',
      [normalized]
    );
    const business = result.rows[0];

    const hash = business ? business.password_hash : '0'.repeat(64);
    const inputHash = sha256(password);
    const matches = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(hash));

    if (!business || !matches) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    if (business.two_fa_enabled) {
      const code = crypto.randomInt(100000, 1000000).toString();
      store.set(storeKey('code', normalized), sha256(code), config.code.ttlSeconds);
      await sendVerificationEmail(normalized, business.name, code);
      return res.json({ success: false, requires2fa: true });
    }

    res.json({ success: true, token: signToken({ email: normalized, type: 'business' }) });
  } catch (err) { next(err); }
});

router.post('/employee/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, message: 'Ungültige Zugangsdaten' });

    const normalized = email.toLowerCase().trim();
    const result = await pool.query(
      'SELECT id, email, password_hash, is_first_login, business_email FROM business_employees WHERE email = $1',
      [normalized]
    );
    const employee = result.rows[0];

    const hash = employee ? employee.password_hash : '0'.repeat(64);
    const inputHash = sha256(password);
    const matches = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(hash));

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

router.post('/employee/update-email', async (req, res, next) => {
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
      JSON.stringify({ hash: sha256(code), new_email: normalized }),
      config.code.ttlSeconds
    );

    await sendVerificationEmail(normalized, null, code);
    res.json({ success: true });
  } catch (err) { next(err); }
});

router.post('/employee/verify-email', async (req, res, next) => {
  try {
    let user;
    try { user = verifyToken(req); } catch (e) { return res.status(e.status).json({ error: e.message }); }
    if (user.type !== 'employee') return res.status(403).json({ error: 'Forbidden' });

    const { code, new_email } = req.body;
    if (!code || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Invalid code' });

    const codeKey = storeKey('email-change', user.email);
    const stored = store.get(codeKey);
    if (!stored) return res.status(404).json({ error: 'No active code. Request a new one.' });

    const { hash, new_email: storedEmail } = JSON.parse(stored);
    const inputHash = sha256(code);
    const matches = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(hash));

    if (!matches || storedEmail !== new_email?.toLowerCase().trim()) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    store.del(codeKey);

    await pool.query(
      'UPDATE business_employees SET email = $1, is_first_login = false WHERE id = $2',
      [storedEmail, user.employee_id]
    );

    const token = signToken({
      email: storedEmail,
      type: 'employee',
      business_email: user.business_email,
      employee_id: user.employee_id,
    });

    res.json({ success: true, token });
  } catch (err) { next(err); }
});

router.post('/business/register-employee', async (req, res, next) => {
  try {
    let user;
    try { user = verifyToken(req); } catch (e) { return res.status(e.status).json({ error: e.message }); }
    if (user.type !== 'business') return res.status(403).json({ error: 'Forbidden' });

    const { first_name, last_name, email, password, role, workdays, shift_from, shift_to, permissions, photo_url } = req.body;
    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({ error: 'invalid_data' });
    }

    const normalized = email.toLowerCase().trim();
    const existing = await pool.query('SELECT id FROM business_employees WHERE email = $1', [normalized]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email_taken' });

    const result = await pool.query(
      `INSERT INTO business_employees
       (email, password_hash, first_name, last_name, role, business_email,
        workdays, shift_from, shift_to, permissions, photo_url, is_first_login)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true)
       RETURNING id`,
      [
        normalized, sha256(password), first_name, last_name,
        role || null, user.email,
        workdays || null, shift_from || null, shift_to || null,
        permissions ? JSON.stringify(permissions) : null,
        photo_url || null,
      ]
    );

    res.json({ success: true, employee_id: result.rows[0].id });
  } catch (err) { next(err); }
});

module.exports = router;
