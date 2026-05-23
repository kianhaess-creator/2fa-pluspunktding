const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const { pool } = require('../services/db');

const SALT_ROUNDS = 12;

// POST /api/auth/register
router.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@') ||
        !password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'invalid_data' });
    }

    const normalized = email.toLowerCase().trim();
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [normalized]);

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'email_taken' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
      [normalized, passwordHash]
    );

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      return res.status(200).json({ success: false });
    }

    const normalized = email.toLowerCase().trim();
    const result = await pool.query('SELECT password_hash FROM users WHERE email = $1', [normalized]);
    const user = result.rows[0];

    // Dummy hash if user not found — prevents timing attacks
    const hash = user ? user.password_hash : '$2a$12$invalidhashinvalidhashinvalidhashinvalidhashinvalid';
    const match = await bcrypt.compare(password, hash);

    if (!match || !user) {
      return res.status(200).json({ success: false });
    }

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/reset-password
router.post('/reset-password', async (req, res, next) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@') ||
        !newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ error: 'invalid_data' });
    }

    const normalized = email.toLowerCase().trim();
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [normalized]);

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'not_found' });
    }

    const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [passwordHash, normalized]);

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
