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

  await pool.query(`ALTER TABLE point_transactions ADD COLUMN IF NOT EXISTS employee_id uuid`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_user_email     ON point_transactions (user_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_business_email ON point_transactions (business_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_nonce          ON point_transactions (nonce)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_employee_id    ON point_transactions (employee_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ubp_user_email    ON user_business_points (user_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ubp_business_email ON user_business_points (business_email)`);

  // ── qr_tokens: temporäre QR-Code-Tokens (15 Min. gültig) ─────────────────
  // Speichert jeden generierten QR-Token mit Betrag, Shop und Ablaufzeit.
  // Nach erfolgreichem Scan oder Ablauf wird der Eintrag gelöscht.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS qr_tokens (
      token          TEXT        PRIMARY KEY,
      business_email TEXT        NOT NULL,
      points         INTEGER     NOT NULL CHECK (points > 0),
      expires_at     TIMESTAMPTZ NOT NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE qr_tokens ADD COLUMN IF NOT EXISTS employee_id uuid`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_qrt_business_email ON qr_tokens (business_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_qrt_expires_at     ON qr_tokens (expires_at)`);

  // ── coupon_tokens: persistente Coupon-QR-Sessions ─────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS coupon_tokens (
      nonce           TEXT        PRIMARY KEY,
      customer_email  TEXT        NOT NULL,
      business_email  TEXT        NOT NULL,
      reward_id       uuid        NOT NULL,
      points_cost     INTEGER     NOT NULL CHECK (points_cost > 0),
      expires_at      TIMESTAMPTZ NOT NULL,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_business_email ON coupon_tokens (business_email)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_ct_expires_at     ON coupon_tokens (expires_at)`);

  // ── notifications ─────────────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
      recipient_email TEXT       NOT NULL,
      recipient_type  TEXT       NOT NULL CHECK (recipient_type IN ('customer', 'business', 'employee')),
      type            TEXT       NOT NULL,
      title           TEXT       NOT NULL,
      message         TEXT       NOT NULL,
      reason          TEXT,
      read            BOOLEAN    DEFAULT FALSE,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      expires_at      TIMESTAMPTZ DEFAULT NOW() + INTERVAL '7 days'
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notif_recipient ON notifications (recipient_email, created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_notif_expires   ON notifications (expires_at)`);
}

module.exports = { pool, init };
