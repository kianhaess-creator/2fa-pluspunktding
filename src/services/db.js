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

  // ── Neu: businesses-Tabelle ────────────────────────────────────────────────
  // Zentrale Unternehmenstabelle — Business-Login-E-Mail ist Fremdschlüssel.
  // Existiert die Tabelle schon (aus Supabase-Migration), werden nur fehlende
  // Spalten ergänzt.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email         TEXT UNIQUE NOT NULL,
      name          TEXT NOT NULL,
      category      TEXT,
      logo_url      TEXT,
      banner_url    TEXT,
      color         TEXT DEFAULT '#5b8cff',
      address       TEXT,
      city          TEXT,
      plz           TEXT,
      points_per_euro NUMERIC(5,2) DEFAULT 1,
      two_fa_enabled BOOLEAN DEFAULT false,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Falls Spalte noch nicht existiert (ältere Instanz)
  await pool.query(`ALTER TABLE businesses ADD COLUMN IF NOT EXISTS points_per_euro NUMERIC(5,2) DEFAULT 1`);

  // ── Neu: user_business_points ──────────────────────────────────────────────
  // Ersetzt / ergänzt die Supabase-seitige user_business_points.
  // Primärschlüssel ist (user_email, business_id) → kein doppelter Eintrag.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_business_points (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_email   TEXT NOT NULL,
      business_id  uuid NOT NULL,
      points       INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
      updated_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_email, business_id)
    )
  `);

  // ── Neu: business_rewards ─────────────────────────────────────────────────
  // Coupons / Belohnungen eines Unternehmens.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS business_rewards (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      business_id   uuid NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
      business_email TEXT NOT NULL,
      title         TEXT NOT NULL,
      description   TEXT,
      points_cost   INTEGER NOT NULL CHECK (points_cost > 0),
      stock         INTEGER NOT NULL DEFAULT 0,
      redeemed      INTEGER DEFAULT 0,
      start_date    DATE,
      end_date      DATE,
      image_url     TEXT,
      status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','planned','expired')),
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE business_rewards ADD COLUMN IF NOT EXISTS business_email TEXT`);

  // ── Neu: point_transactions ────────────────────────────────────────────────
  // Unveränderliches Transaktionslog für Audit-Trail und Betrugsschutz.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS point_transactions (
      id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_email     TEXT NOT NULL,
      business_id    uuid NOT NULL,
      business_email TEXT NOT NULL,
      points         INTEGER NOT NULL,
      type           TEXT NOT NULL CHECK (type IN ('earn','redeem')),
      reward_id      uuid,
      nonce          TEXT UNIQUE NOT NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Index für schnelle Abfragen nach Nutzer / Unternehmen
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_pt_user_email   ON point_transactions (user_email);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_pt_business_id  ON point_transactions (business_id);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_ubp_user_email  ON user_business_points (user_email);
  `);
}

module.exports = { pool, init };
