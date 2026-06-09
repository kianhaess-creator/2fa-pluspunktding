const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();
const { pool } = require('../services/db');

const ADMIN_PASSWORD_HASH = 'f447452c05ab45f6b009c1f5d5c0989e13aade1ffb332ffeeaa2daf31acaedb7';

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || sha256(key) !== ADMIN_PASSWORD_HASH) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// GET /api/admin/stats — Gesamtzahlen
router.get('/admin/stats', requireAdmin, async (req, res, next) => {
  try {
    const [users, employees, transactions, points] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM business_employees'),
      pool.query('SELECT COUNT(*) FROM point_transactions'),
      pool.query('SELECT COALESCE(SUM(points),0) FROM user_business_points'),
    ]);
    res.json({
      totalUsers:        parseInt(users.rows[0].count),
      totalEmployees:    parseInt(employees.rows[0].count),
      totalTransactions: parseInt(transactions.rows[0].count),
      totalPointsActive: parseInt(points.rows[0].coalesce),
    });
  } catch (err) { next(err); }
});

// GET /api/admin/registrations?days=30 — Registrierungen pro Tag
router.get('/admin/registrations', requireAdmin, async (req, res, next) => {
  try {
    const days = Math.min(parseInt(req.query.days) || 30, 365);
    const result = await pool.query(`
      SELECT DATE(created_at) AS day, COUNT(*) AS count
      FROM users
      WHERE created_at >= NOW() - INTERVAL '${days} days'
      GROUP BY day ORDER BY day ASC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) { next(err); }
});

// GET /api/admin/transactions?days=30 — Transaktionen pro Tag
router.get('/admin/transactions', requireAdmin, async (req, res, next) => {
  try {
    const days = Math.min(parseInt(req.query.days) || 30, 365);
    const result = await pool.query(`
      SELECT DATE(created_at) AS day,
             COUNT(*) FILTER (WHERE type='earn')   AS earn,
             COUNT(*) FILTER (WHERE type='redeem') AS redeem
      FROM point_transactions
      WHERE created_at >= NOW() - INTERVAL '${days} days'
      GROUP BY day ORDER BY day ASC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) { next(err); }
});

// GET /api/admin/users?limit=50&offset=0 — Nutzerliste
router.get('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
    const offset = parseInt(req.query.offset) || 0;
    const search = req.query.search ? `%${req.query.search}%` : null;
    const result = await pool.query(
      `SELECT email, name, city, login_count, last_login_at, login_method, created_at
       FROM users
       WHERE ($1::text IS NULL OR email ILIKE $1 OR name ILIKE $1)
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [search, limit, offset]
    );
    const total = await pool.query(
      `SELECT COUNT(*) FROM users WHERE ($1::text IS NULL OR email ILIKE $1 OR name ILIKE $1)`,
      [search]
    );
    res.json({ success: true, users: result.rows, total: parseInt(total.rows[0].count) });
  } catch (err) { next(err); }
});

// GET /api/admin/activity — Letzte 20 Aktivitäten
router.get('/admin/activity', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT user_email, business_email, points, type, created_at
      FROM point_transactions
      ORDER BY created_at DESC LIMIT 20
    `);
    res.json({ success: true, activity: result.rows });
  } catch (err) { next(err); }
});

module.exports = router;
