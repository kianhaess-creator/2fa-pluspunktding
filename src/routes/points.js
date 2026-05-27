/**
 * POINTS & COUPON ROUTES
 *
 * Alle sicherheitskritischen Operationen für Punkte und Coupons.
 * Läuft ausschließlich serverseitig — kein Secret verlässt diesen Service.
 *
 * Endpunkte:
 *   POST /api/points/generate-qr     → Business/Employee erzeugt signierten QR-Payload
 *   POST /api/points/redeem-qr       → Kunde löst QR-Code ein (Punkte gutschreiben)
 *   POST /api/coupon/generate-qr     → Kunde erzeugt signierten Coupon-QR-Payload
 *   POST /api/coupon/redeem-qr       → Employee/Business scannt Coupon-QR (Punkte abziehen)
 */

const express  = require('express');
const crypto   = require('crypto');
const jwt      = require('jsonwebtoken');
const router   = express.Router();
const rateLimit = require('express-rate-limit');

const config       = require('../config');
const store        = require('../services/store');
const { pool }     = require('../services/db');
const requireJwt   = require('../middleware/jwt');

// ─── Hilfsfunktionen ──────────────────────────────────────────────────────────

/**
 * Erstellt eine HMAC-SHA256-Signatur über die kanonische JSON-Darstellung
 * des Payloads. Verhindert Manipulation einzelner Felder.
 */
function signPayload(payload) {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return crypto
    .createHmac('sha256', config.qrSecret)
    .update(canonical)
    .digest('hex');
}

function verifySignature(payload, signature) {
  const expected = signPayload(payload);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(signature,  'hex')
    );
  } catch {
    return false;
  }
}

/** Erzeuge eine kryptografisch zufällige Nonce (24 Byte → 48 Hex-Zeichen). */
function generateNonce() {
  return crypto.randomBytes(24).toString('hex');
}

/**
 * Prüft, ob eine Nonce bereits verwendet wurde (Replay-Schutz).
 * Speichert sie im In-Memory-Store für die Dauer der QR-Gültigkeit + 60 s Puffer.
 */
function consumeNonce(nonce, ttlSeconds) {
  const key = `nonce:${nonce}`;
  if (store.get(key)) return false;          // bereits verwendet
  store.set(key, '1', ttlSeconds + 60);
  return true;
}

/** Liest die verifizierten JWT-Felder aus dem Authorization-Header. */
function extractJwtUser(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  try {
    return jwt.verify(auth.slice(7), config.jwtSecret);
  } catch {
    return null;
  }
}

// ─── Rate-Limiter ─────────────────────────────────────────────────────────────

const generateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Zu viele Anfragen. Bitte warte eine Minute.' },
});

const redeemLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Zu viele Einlöseversuche. Bitte warte eine Minute.' },
});

// ─── POST /api/points/generate-qr ─────────────────────────────────────────────
/**
 * Aufgerufen von: Employee-Dashboard oder Business-Dashboard
 * JWT-Pflicht: type === 'employee' ODER type === 'business'
 *
 * Body:  { purchase_amount: number }
 * Antwort: { qr_payload: string }   ← Base64url-kodierter, signierter JSON-String
 *
 * Der QR-Payload enthält:
 *   business_id  – UUID des Unternehmens (aus DB ermittelt)
 *   points       – floor(purchase_amount) — abgerundet
 *   issued_at    – Unix-Timestamp (Sekunden)
 *   expires_at   – issued_at + QR_TTL_SECONDS
 *   nonce        – 48-Hex-Zeichen Zufallswert (Einmalverwendung)
 *   sig          – HMAC-SHA256-Signatur
 *
 * Der Payload enthält KEINE Kunden-ID — der Kunde bleibt anonym.
 */
router.post('/points/generate-qr', generateLimiter, requireJwt, async (req, res, next) => {
  try {
    const user = req.user;  // gesetzt von requireJwt middleware

    // Nur Employees und Businesses dürfen QR-Codes erstellen
    if (user.type !== 'employee' && user.type !== 'business') {
      return res.status(403).json({ success: false, message: 'Keine Berechtigung.' });
    }

    const rawAmount = parseFloat(String(req.body.purchase_amount).replace(',', '.'));
    if (!isFinite(rawAmount) || rawAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Ungültiger Einkaufsbetrag.' });
    }

    const points = Math.floor(rawAmount);
    if (points < 1) {
      return res.status(400).json({ success: false, message: 'Betrag ergibt 0 Punkte — zu gering.' });
    }

    // Unternehmens-ID aus DB ermitteln
    let businessId;
    if (user.type === 'employee') {
      const r = await pool.query(
        'SELECT id FROM businesses WHERE email = $1',
        [user.business_email]
      );
      if (!r.rows.length) return res.status(404).json({ success: false, message: 'Unternehmen nicht gefunden.' });
      businessId = r.rows[0].id;
    } else {
      // business
      const r = await pool.query(
        'SELECT id FROM businesses WHERE email = $1',
        [user.email]
      );
      if (!r.rows.length) return res.status(404).json({ success: false, message: 'Unternehmen nicht gefunden.' });
      businessId = r.rows[0].id;
    }

    const now       = Math.floor(Date.now() / 1000);
    const expiresAt = now + config.qrTtlSeconds;
    const nonce     = generateNonce();

    const payloadData = {
      type:        'points',
      business_id: businessId,
      points,
      issued_at:   now,
      expires_at:  expiresAt,
      nonce,
    };

    const sig = signPayload(payloadData);
    const full = { ...payloadData, sig };

    // Als Base64url-String kodieren (URL-sicher für QR-Code)
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    res.json({ success: true, qr_payload: qrPayload, points, expires_in: config.qrTtlSeconds });
  } catch (err) { next(err); }
});

// ─── POST /api/points/redeem-qr ───────────────────────────────────────────────
/**
 * Aufgerufen von: Kunden-App (nach Scan des QR-Codes)
 * JWT-Pflicht: type === 'customer'
 *
 * Body:  { qr_payload: string }
 * Antwort: { success: true, points_added: number, total_points: number }
 *
 * Sicherheitsprüfungen:
 *   1. Signatur validieren
 *   2. Ablaufzeit prüfen
 *   3. Nonce-Replay-Schutz (Einmalverwendung)
 *   4. Business existiert
 *   5. Punkte atomar in DB schreiben (upsert)
 *   6. Transaktion loggen
 */
router.post('/points/redeem-qr', redeemLimiter, requireJwt, async (req, res, next) => {
  try {
    const user = req.user;

    if (user.type !== 'customer') {
      return res.status(403).json({ success: false, message: 'Nur Kunden können QR-Codes einlösen.' });
    }

    let parsed;
    try {
      const raw = Buffer.from(req.body.qr_payload, 'base64url').toString('utf8');
      parsed = JSON.parse(raw);
    } catch {
      return res.status(400).json({ success: false, message: 'Ungültiger QR-Code.' });
    }

    const { type, business_id, points, issued_at, expires_at, nonce, sig } = parsed;

    // 1. Typ prüfen
    if (type !== 'points') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    // 2. Alle Pflichtfelder vorhanden?
    if (!business_id || !points || !issued_at || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 3. Signatur validieren (verhindert Manipulation)
    const payloadWithoutSig = { type, business_id, points, issued_at, expires_at, nonce };
    if (!verifySignature(payloadWithoutSig, sig)) {
      return res.status(400).json({ success: false, message: 'Ungültige QR-Code-Signatur.' });
    }

    // 4. Ablaufzeit prüfen
    const now = Math.floor(Date.now() / 1000);
    if (now > expires_at) {
      return res.status(400).json({ success: false, message: 'QR-Code ist abgelaufen.' });
    }

    // 5. Nonce verbrauchen (Replay-Schutz — Einmalverwendung)
    const remaining = expires_at - now;
    if (!consumeNonce(nonce, remaining)) {
      return res.status(400).json({ success: false, message: 'QR-Code wurde bereits verwendet.' });
    }

    // 6. Business existiert prüfen
    const bizResult = await pool.query(
      'SELECT email FROM businesses WHERE id = $1',
      [business_id]
    );
    if (!bizResult.rows.length) {
      return res.status(400).json({ success: false, message: 'Unternehmen nicht gefunden.' });
    }
    const businessEmail = bizResult.rows[0].email;

    // 7. Punkte atomar gutschreiben (upsert)
    const upsert = await pool.query(
      `INSERT INTO user_business_points (user_email, business_id, points, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_email, business_id)
       DO UPDATE SET
         points     = user_business_points.points + EXCLUDED.points,
         updated_at = NOW()
       RETURNING points`,
      [user.email, business_id, points]
    );
    const totalPoints = upsert.rows[0].points;

    // 8. Transaktion loggen
    await pool.query(
      `INSERT INTO point_transactions
         (user_email, business_id, business_email, points, type, nonce, created_at)
       VALUES ($1, $2, $3, $4, 'earn', $5, NOW())`,
      [user.email, business_id, businessEmail, points, nonce]
    );

    res.json({
      success:      true,
      points_added: points,
      total_points: totalPoints,
      business_id,
    });
  } catch (err) { next(err); }
});

// ─── POST /api/coupon/generate-qr ─────────────────────────────────────────────
/**
 * Aufgerufen von: Kunden-App (Kunde möchte Coupon einlösen)
 * JWT-Pflicht: type === 'customer'
 *
 * Body:  { reward_id: string }
 * Antwort: { qr_payload: string }
 *
 * Der Coupon-QR enthält:
 *   type           – 'coupon'
 *   reward_id      – UUID des Rewards
 *   business_id    – UUID des Unternehmens
 *   temp_customer_id – serverseitig generierte, einmalige Pseudo-ID
 *                      (nicht die echte Kunden-E-Mail / ID)
 *   issued_at / expires_at / nonce / sig
 *
 * Die echte Kunden-E-Mail wird NICHT in den QR-Code geschrieben.
 * Sie wird serverseitig aus der temp_customer_id aufgelöst.
 */
router.post('/coupon/generate-qr', redeemLimiter, requireJwt, async (req, res, next) => {
  try {
    const user = req.user;

    if (user.type !== 'customer') {
      return res.status(403).json({ success: false, message: 'Nur Kunden können Coupon-QR-Codes erzeugen.' });
    }

    const { reward_id } = req.body;
    if (!reward_id || typeof reward_id !== 'string') {
      return res.status(400).json({ success: false, message: 'Reward-ID fehlt.' });
    }

    // Reward laden
    const rewardResult = await pool.query(
      `SELECT r.id, r.business_id, r.points_cost, r.title, r.status,
              b.email AS business_email
       FROM   business_rewards r
       JOIN   businesses b ON b.id = r.business_id
       WHERE  r.id = $1`,
      [reward_id]
    );
    if (!rewardResult.rows.length) {
      return res.status(404).json({ success: false, message: 'Coupon nicht gefunden.' });
    }
    const reward = rewardResult.rows[0];

    if (reward.status !== 'active') {
      return res.status(400).json({ success: false, message: 'Coupon ist nicht aktiv.' });
    }

    // Punkte des Kunden bei diesem Unternehmen prüfen
    const ptsResult = await pool.query(
      'SELECT points FROM user_business_points WHERE user_email = $1 AND business_id = $2',
      [user.email, reward.business_id]
    );
    const currentPoints = ptsResult.rows[0]?.points || 0;

    if (currentPoints < reward.points_cost) {
      return res.status(400).json({
        success: false,
        message: `Nicht genügend Punkte. Du hast ${currentPoints}, benötigt: ${reward.points_cost}.`,
      });
    }

    // Temporäre Kunden-ID erzeugen und in Store ablegen
    // Wichtig: Die echte E-Mail wird NICHT in den QR übertragen.
    const tempCustomerId = crypto.randomBytes(20).toString('hex');
    const now            = Math.floor(Date.now() / 1000);
    const expiresAt      = now + config.couponQrTtlSeconds;

    // Mapping: tempCustomerId → echte E-Mail + reward_id (für spätere Auflösung)
    store.set(
      `coupon_temp:${tempCustomerId}`,
      JSON.stringify({ email: user.email, reward_id }),
      config.couponQrTtlSeconds + 120
    );

    const nonce = generateNonce();
    const payloadData = {
      type:             'coupon',
      business_id:      reward.business_id,
      reward_id,
      temp_customer_id: tempCustomerId,
      issued_at:        now,
      expires_at:       expiresAt,
      nonce,
    };

    const sig     = signPayload(payloadData);
    const full    = { ...payloadData, sig };
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    res.json({
      success:     true,
      qr_payload:  qrPayload,
      reward_title: reward.title,
      points_cost:  reward.points_cost,
      expires_in:   config.couponQrTtlSeconds,
    });
  } catch (err) { next(err); }
});

// ─── POST /api/coupon/redeem-qr ───────────────────────────────────────────────
/**
 * Aufgerufen von: Employee-Dashboard oder Business-Dashboard
 * JWT-Pflicht: type === 'employee' ODER type === 'business'
 *
 * Body:  { qr_payload: string }
 * Antwort: { success: true, reward_title, points_deducted, customer_remaining }
 *
 * Sicherheitsprüfungen:
 *   1. Signatur validieren
 *   2. Ablaufzeit prüfen
 *   3. Nonce-Replay-Schutz
 *   4. temp_customer_id → echte E-Mail auflösen
 *   5. Reward gehört zum richtigen Unternehmen
 *   6. Punkte ausreichend (double-check serverseitig)
 *   7. Atomar: Punkte abziehen + Coupon als eingelöst markieren
 */
router.post('/coupon/redeem-qr', redeemLimiter, requireJwt, async (req, res, next) => {
  try {
    const user = req.user;

    if (user.type !== 'employee' && user.type !== 'business') {
      return res.status(403).json({ success: false, message: 'Keine Berechtigung.' });
    }

    let parsed;
    try {
      const raw = Buffer.from(req.body.qr_payload, 'base64url').toString('utf8');
      parsed = JSON.parse(raw);
    } catch {
      return res.status(400).json({ success: false, message: 'Ungültiger QR-Code.' });
    }

    const { type, business_id, reward_id, temp_customer_id, issued_at, expires_at, nonce, sig } = parsed;

    if (type !== 'coupon') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    if (!business_id || !reward_id || !temp_customer_id || !issued_at || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 1. Signatur
    const payloadWithoutSig = { type, business_id, reward_id, temp_customer_id, issued_at, expires_at, nonce };
    if (!verifySignature(payloadWithoutSig, sig)) {
      return res.status(400).json({ success: false, message: 'Ungültige QR-Code-Signatur.' });
    }

    // 2. Ablaufzeit
    const now = Math.floor(Date.now() / 1000);
    if (now > expires_at) {
      return res.status(400).json({ success: false, message: 'Coupon-QR-Code ist abgelaufen.' });
    }

    // 3. Replay-Schutz
    const remaining = expires_at - now;
    if (!consumeNonce(nonce, remaining)) {
      return res.status(400).json({ success: false, message: 'Coupon wurde bereits eingelöst.' });
    }

    // 4. Temp-ID → echte Kunden-E-Mail auflösen
    const tempKey = store.get(`coupon_temp:${temp_customer_id}`);
    if (!tempKey) {
      return res.status(400).json({ success: false, message: 'Coupon-Session abgelaufen oder ungültig.' });
    }
    let sessionData;
    try { sessionData = JSON.parse(tempKey); } catch {
      return res.status(400).json({ success: false, message: 'Coupon-Session ungültig.' });
    }
    const customerEmail = sessionData.email;

    // Temp-Key sofort löschen (Einmalverwendung)
    store.del(`coupon_temp:${temp_customer_id}`);

    // Reward-ID im Session-Datum muss zum QR passen
    if (sessionData.reward_id !== reward_id) {
      return res.status(400).json({ success: false, message: 'Reward-ID stimmt nicht überein.' });
    }

    // 5. Reward laden + Unternehmen verifizieren
    const rewardResult = await pool.query(
      `SELECT r.id, r.points_cost, r.title, r.business_id, b.email AS business_email
       FROM   business_rewards r
       JOIN   businesses b ON b.id = r.business_id
       WHERE  r.id = $1`,
      [reward_id]
    );
    if (!rewardResult.rows.length) {
      return res.status(404).json({ success: false, message: 'Reward nicht gefunden.' });
    }
    const reward = rewardResult.rows[0];

    // Business-ID im QR muss zur DB passen
    if (reward.business_id !== business_id) {
      return res.status(400).json({ success: false, message: 'Coupon gehört nicht zu diesem Unternehmen.' });
    }

    // Employee/Business muss zum richtigen Unternehmen gehören
    let scannerBusinessEmail;
    if (user.type === 'employee') {
      scannerBusinessEmail = user.business_email;
    } else {
      scannerBusinessEmail = user.email;
    }
    if (scannerBusinessEmail !== reward.business_email) {
      return res.status(403).json({ success: false, message: 'Du kannst diesen Coupon nicht einlösen.' });
    }

    // 6. Serverseitig Punkte prüfen (double-check)
    const ptsResult = await pool.query(
      'SELECT points FROM user_business_points WHERE user_email = $1 AND business_id = $2',
      [customerEmail, business_id]
    );
    const currentPoints = ptsResult.rows[0]?.points || 0;

    if (currentPoints < reward.points_cost) {
      return res.status(400).json({
        success: false,
        message: `Nicht genügend Punkte (hat: ${currentPoints}, benötigt: ${reward.points_cost}).`,
      });
    }

    // 7. Atomar: Punkte abziehen + Transaktion loggen (DB-Transaktion)
    const client = await pool.connect();
    let remainingPoints;
    try {
      await client.query('BEGIN');

      const updateResult = await client.query(
        `UPDATE user_business_points
         SET    points = points - $1, updated_at = NOW()
         WHERE  user_email = $2 AND business_id = $3
         RETURNING points`,
        [reward.points_cost, customerEmail, business_id]
      );
      remainingPoints = updateResult.rows[0]?.points ?? 0;

      await client.query(
        `INSERT INTO point_transactions
           (user_email, business_id, business_email, points, type, reward_id, nonce, created_at)
         VALUES ($1, $2, $3, $4, 'redeem', $5, $6, NOW())`,
        [customerEmail, business_id, reward.business_email, reward.points_cost, reward_id, nonce]
      );

      // Reward-Einlösezähler hochzählen
      await client.query(
        'UPDATE business_rewards SET redeemed = redeemed + 1 WHERE id = $1',
        [reward_id]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    res.json({
      success:            true,
      reward_title:       reward.title,
      points_deducted:    reward.points_cost,
      customer_remaining: remainingPoints,
    });
  } catch (err) { next(err); }
});

// ─── GET /api/points/balance ───────────────────────────────────────────────────
/**
 * Aufgerufen von: Kunden-App (Punktestand laden)
 * JWT-Pflicht: type === 'customer'
 *
 * Query: ?business_id=<uuid>   (optional — ohne: alle Unternehmen)
 */
router.get('/points/balance', requireJwt, async (req, res, next) => {
  try {
    const user = req.user;
    if (user.type !== 'customer') {
      return res.status(403).json({ success: false, message: 'Nur für Kunden.' });
    }

    const { business_id } = req.query;

    if (business_id) {
      const r = await pool.query(
        'SELECT points FROM user_business_points WHERE user_email = $1 AND business_id = $2',
        [user.email, business_id]
      );
      return res.json({ success: true, business_id, points: r.rows[0]?.points || 0 });
    }

    const r = await pool.query(
      `SELECT ubp.business_id, ubp.points, b.name AS business_name
       FROM   user_business_points ubp
       JOIN   businesses b ON b.id = ubp.business_id
       WHERE  ubp.user_email = $1`,
      [user.email]
    );
    return res.json({ success: true, balances: r.rows });
  } catch (err) { next(err); }
});

// ─── GET /api/points/history ───────────────────────────────────────────────────
/**
 * Aufgerufen von: Business-Dashboard oder Kunden-App (Transaktionshistorie)
 * JWT-Pflicht: customer ODER business ODER employee
 */
router.get('/points/history', requireJwt, async (req, res, next) => {
  try {
    const user = req.user;
    let rows;

    if (user.type === 'customer') {
      const r = await pool.query(
        `SELECT pt.points, pt.type, pt.created_at, b.name AS business_name
         FROM   point_transactions pt
         JOIN   businesses b ON b.id = pt.business_id
         WHERE  pt.user_email = $1
         ORDER  BY pt.created_at DESC
         LIMIT  50`,
        [user.email]
      );
      rows = r.rows;
    } else if (user.type === 'business') {
      const bizResult = await pool.query('SELECT id FROM businesses WHERE email = $1', [user.email]);
      if (!bizResult.rows.length) return res.status(404).json({ error: 'Business not found' });
      const bizId = bizResult.rows[0].id;
      const r = await pool.query(
        `SELECT pt.points, pt.type, pt.created_at, pt.user_email
         FROM   point_transactions pt
         WHERE  pt.business_id = $1
         ORDER  BY pt.created_at DESC
         LIMIT  100`,
        [bizId]
      );
      rows = r.rows;
    } else if (user.type === 'employee') {
      const bizResult = await pool.query('SELECT id FROM businesses WHERE email = $1', [user.business_email]);
      if (!bizResult.rows.length) return res.status(404).json({ error: 'Business not found' });
      const bizId = bizResult.rows[0].id;
      const r = await pool.query(
        `SELECT pt.points, pt.type, pt.created_at
         FROM   point_transactions pt
         WHERE  pt.business_id = $1
         ORDER  BY pt.created_at DESC
         LIMIT  100`,
        [bizId]
      );
      rows = r.rows;
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }

    res.json({ success: true, transactions: rows });
  } catch (err) { next(err); }
});

// ─── GET /api/rewards ─────────────────────────────────────────────────────────
/**
 * Lädt alle aktiven Rewards eines Unternehmens (für Kunden-App).
 * Öffentlich lesbar (kein JWT nötig, da keine sensitiven Daten).
 */
router.get('/rewards', async (req, res, next) => {
  try {
    const { business_id } = req.query;
    if (!business_id) return res.status(400).json({ error: 'business_id required' });

    const r = await pool.query(
      `SELECT id, title, description, points_cost, image_url
       FROM   business_rewards
       WHERE  business_id = $1 AND status = 'active'
       ORDER  BY points_cost ASC`,
      [business_id]
    );
    res.json({ success: true, rewards: r.rows });
  } catch (err) { next(err); }
});

module.exports = router;
