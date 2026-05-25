const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS postal_code TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS city TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS birth_date TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login_method TEXT DEFAULT 'email'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS street TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS plz TEXT`);
}

module.exports = { pool, init };
