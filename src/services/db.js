const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function init() {
  // ── Bestehende Tabellen (unverändert) ──────────────────────────────────────

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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS business_employees (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      role TEXT,
      business_email TEXT NOT NULL,
      workdays TEXT[],
      shift_from TEXT,
      shift_to TEXT,
      permissions JSONB,
      photo_url TEXT,
      is_first_login BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // ── Neu: user_business_points ──────────────────────────────────────────────
  // Verknüpft Kunden mit Unternehmen über business_email (TEXT).
  // Die businesses-Tabelle liegt in Supabase und hat keinen UUID-PK.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_business_points (
      id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_email     TEXT NOT NULL,
      business_email TEXT NOT NULL,
      points         INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
      updated_at     TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_email, business_email)
    )
  `);

  // ── Neu: point_transactions ────────────────────────────────────────────────
  // Unveränderliches Transaktionslog für Audit-Trail und Betrugsschutz.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS point_transactions (
      id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_email     TEXT NOT NULL,
      business_email TEXT NOT NULL,
      points         INTEGER NOT NULL,
      type           TEXT NOT NULL CHECK (type IN ('earn','redeem')),
      reward_id      uuid,
      nonce          TEXT UNIQUE NOT NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_user_email     ON point_transactions (user_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_business_email ON point_transactions (business_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_nonce          ON point_transactions (nonce)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ubp_user_email    ON user_business_points (user_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ubp_business_email ON user_business_points (business_email)`);
}

module.exports = { pool, init };
