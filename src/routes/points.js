/**
 * POINTS & COUPON ROUTES
 *
 * Alle sicherheitskritischen Operationen für Punkte und Coupons.
 * Läuft ausschließlich serverseitig — kein Secret verlässt diesen Service.
 *
 * Schlüssel: business_email (TEXT) als Fremdschlüssel — die businesses-Tabelle
 * hat keinen UUID-Primary-Key, sondern verwendet email als eindeutigen Identifier.
 */

const express   = require('express');
const crypto    = require('crypto');
const jwt       = require('jsonwebtoken');
const router    = express.Router();
const rateLimit = require('express-rate-limit');

const config     = require('../config');
const store      = require('../services/store');
const { pool }   = require('../services/db');
const requireJwt = require('../middleware/jwt');

// ─── Hilfsfunktionen ──────────────────────────────────────────────────────────

function signPayload(payload) {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return crypto
    .createHmac('sha256', config.qrSecret)
    .update(canonical)
    .digest('base64url'); // base64url statt hex: 43 Zeichen statt 64
}

function verifySignature(payload, signature) {
  const expected = signPayload(payload);
  try {
    // Längencheck vor timingSafeEqual (verhindert Buffer-Längen-Exception)
    const a = Buffer.from(expected,  'base64url');
    const b = Buffer.from(signature, 'base64url');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function generateNonce() {
  return crypto.randomBytes(12).toString('base64url'); // 16 Zeichen statt 48
}

function consumeNonce(nonce, ttlSeconds) {
  const key = `nonce:${nonce}`;
  if (store.get(key)) return false;
  store.set(key, '1', ttlSeconds + 60);
  return true;
}

// ─── Rate-Limiter ─────────────────────────────────────────────────────────────

const generateLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Zu viele Anfragen. Bitte warte eine Minute.' },
});

const redeemLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Zu viele Einlöseversuche. Bitte warte eine Minute.' },
});

// ─── POST /api/points/generate-qr ─────────────────────────────────────────────
// Aufgerufen von: Employee-Dashboard oder Business-Dashboard
// JWT: type === 'employee' ODER type === 'business'
// Gibt einen signierten QR-Payload zurück. Enthält KEINE Kundendaten.
router.post('/points/generate-qr', generateLimiter, requireJwt, async (req, res, next) => {
  try {
    const user = req.user;

    if (user.type !== 'employee' && user.type !== 'business') {
      return res.status(403).json({ success: false, message: 'Keine Berechtigung.' });
    }

    const rawAmount = parseFloat(String(req.body.purchase_amount || '0').replace(',', '.'));
    if (!isFinite(rawAmount) || rawAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Ungültiger Einkaufsbetrag.' });
    }

    const points = Math.floor(rawAmount);
    if (points < 1) {
      return res.status(400).json({ success: false, message: 'Betrag ergibt 0 Punkte — zu gering.' });
    }

    // Business-E-Mail ermitteln (Employee kennt seine business_email aus dem JWT)
    const businessEmail = user.type === 'employee' ? user.business_email : user.email;

    // Prüfen ob das Unternehmen in der DB existiert
    const bizResult = await pool.query(
      'SELECT email FROM businesses WHERE email = $1',
      [businessEmail]
    );
    if (!bizResult.rows.length) {
      return res.status(404).json({ success: false, message: 'Unternehmen nicht gefunden.' });
    }

    const now       = Math.floor(Date.now() / 1000);
    const expiresAt = now + config.qrTtlSeconds;
    const nonce     = generateNonce();

    // Short keys to minimise payload size → smaller QR version → larger modules → reliable scan
    // t=type, b=business_email, p=points, e=expires_at, n=nonce, s=sig (truncated to 22 chars)
    const payloadData = { t: 'pts', b: businessEmail, p: points, e: expiresAt, n: nonce };
    const sig       = signPayload(payloadData).slice(0, 22);
    const full      = { ...payloadData, s: sig };
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    res.json({ success: true, qr_payload: qrPayload, points, expires_in: config.qrTtlSeconds });
  } catch (err) { next(err); }
});

// ─── POST /api/points/redeem-qr ───────────────────────────────────────────────
// Aufgerufen von: Kunden-App (nach Scan des QR-Codes)
// JWT: type === 'customer'
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

    // Support both short-key format {t,b,p,e,n,s} and legacy long-key format
    const isShort = parsed.t !== undefined;
    const type           = isShort ? (parsed.t === 'pts' ? 'points' : parsed.t) : parsed.type;
    const business_email = isShort ? parsed.b : parsed.business_email;
    const points         = isShort ? parsed.p : parsed.points;
    const expires_at     = isShort ? parsed.e : parsed.expires_at;
    const nonce          = isShort ? parsed.n : parsed.nonce;
    const sig            = isShort ? parsed.s : parsed.sig;

    if (type !== 'points') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    if (!business_email || !points || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 1. Signatur validieren
    const payloadWithoutSig = isShort
      ? { t: parsed.t, b: parsed.b, p: parsed.p, e: parsed.e, n: parsed.n }
      : { type, business_email, points, issued_at: parsed.issued_at, expires_at, nonce };
    // For short format: compare truncated sig (22 chars)
    const fullSig = signPayload(payloadWithoutSig);
    const sigValid = isShort
      ? (sig === fullSig.slice(0, 22))
      : verifySignature(payloadWithoutSig, sig);
    if (!sigValid) {
      return res.status(400).json({ success: false, message: 'Ungültige QR-Code-Signatur.' });
    }

    // 2. Ablaufzeit prüfen
    const now = Math.floor(Date.now() / 1000);
    if (now > expires_at) {
      return res.status(400).json({ success: false, message: 'QR-Code ist abgelaufen.' });
    }

    // 3. Replay-Schutz
    const remaining = expires_at - now;
    if (!consumeNonce(nonce, remaining)) {
      return res.status(400).json({ success: false, message: 'QR-Code wurde bereits verwendet.' });
    }

    // 4. Business existiert prüfen
    const bizResult = await pool.query(
      'SELECT email FROM businesses WHERE email = $1',
      [business_email]
    );
    if (!bizResult.rows.length) {
      return res.status(400).json({ success: false, message: 'Unternehmen nicht gefunden.' });
    }

    // 5. Punkte atomar gutschreiben (upsert)
    const upsert = await pool.query(
      `INSERT INTO user_business_points (user_email, business_email, points, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_email, business_email)
       DO UPDATE SET
         points     = user_business_points.points + EXCLUDED.points,
         updated_at = NOW()
       RETURNING points`,
      [user.email, business_email, points]
    );
    const totalPoints = upsert.rows[0].points;

    // 6. Transaktion loggen
    await pool.query(
      `INSERT INTO point_transactions
         (user_email, business_email, points, type, nonce, created_at)
       VALUES ($1, $2, $3, 'earn', $4, NOW())`,
      [user.email, business_email, points, nonce]
    );

    res.json({
      success:        true,
      points_added:   points,
      total_points:   totalPoints,
      business_email,
    });
  } catch (err) { next(err); }
});

// ─── POST /api/coupon/generate-qr ─────────────────────────────────────────────
// Aufgerufen von: Kunden-App
// JWT: type === 'customer'
// Gibt Coupon-QR zurück — enthält KEINE echte Kunden-E-Mail.
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
      `SELECT id, business_email, points_cost, title, status
       FROM   business_rewards
       WHERE  id = $1`,
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
      'SELECT points FROM user_business_points WHERE user_email = $1 AND business_email = $2',
      [user.email, reward.business_email]
    );
    const currentPoints = ptsResult.rows[0]?.points || 0;

    if (currentPoints < reward.points_cost) {
      return res.status(400).json({
        success: false,
        message: `Nicht genügend Punkte. Du hast ${currentPoints}, benötigt: ${reward.points_cost}.`,
      });
    }

    // Temporäre Kunden-ID erzeugen (kein Personenbezug im QR)
    const tempCustomerId = crypto.randomBytes(20).toString('hex');
    const now            = Math.floor(Date.now() / 1000);
    const expiresAt      = now + config.couponQrTtlSeconds;

    store.set(
      `coupon_temp:${tempCustomerId}`,
      JSON.stringify({ email: user.email, reward_id }),
      config.couponQrTtlSeconds + 120
    );

    const nonce = generateNonce();
    // Short keys: t=type, b=business_email, r=reward_id, c=temp_customer_id, e=expires_at, n=nonce, s=sig
    const payloadData = { t: 'cpn', b: reward.business_email, r: reward_id, c: tempCustomerId, e: expiresAt, n: nonce };
    const sig       = signPayload(payloadData).slice(0, 22);
    const full      = { ...payloadData, s: sig };
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    res.json({
      success:      true,
      qr_payload:   qrPayload,
      reward_title: reward.title,
      points_cost:  reward.points_cost,
      expires_in:   config.couponQrTtlSeconds,
    });
  } catch (err) { next(err); }
});

// ─── POST /api/coupon/redeem-qr ───────────────────────────────────────────────
// Aufgerufen von: Employee-Dashboard oder Business-Dashboard
// JWT: type === 'employee' ODER type === 'business'
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

    // Support both short-key format {t,b,r,c,e,n,s} and legacy long-key format
    const isShortC        = parsed.t !== undefined;
    const type            = isShortC ? (parsed.t === 'cpn' ? 'coupon' : parsed.t) : parsed.type;
    const business_email  = isShortC ? parsed.b : parsed.business_email;
    const reward_id       = isShortC ? parsed.r : parsed.reward_id;
    const temp_customer_id= isShortC ? parsed.c : parsed.temp_customer_id;
    const expires_at      = isShortC ? parsed.e : parsed.expires_at;
    const nonce           = isShortC ? parsed.n : parsed.nonce;
    const sig             = isShortC ? parsed.s : parsed.sig;

    if (type !== 'coupon') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    if (!business_email || !reward_id || !temp_customer_id || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 1. Signatur
    const payloadWithoutSigC = isShortC
      ? { t: parsed.t, b: parsed.b, r: parsed.r, c: parsed.c, e: parsed.e, n: parsed.n }
      : { type, business_email, reward_id, temp_customer_id, issued_at: parsed.issued_at, expires_at, nonce };
    const fullSigC = signPayload(payloadWithoutSigC);
    const sigValidC = isShortC
      ? (sig === fullSigC.slice(0, 22))
      : verifySignature(payloadWithoutSigC, sig);
    if (!sigValidC) {
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

    // Sofort löschen (Einmalverwendung)
    store.del(`coupon_temp:${temp_customer_id}`);

    if (sessionData.reward_id !== reward_id) {
      return res.status(400).json({ success: false, message: 'Reward-ID stimmt nicht überein.' });
    }

    // 5. Reward laden
    const rewardResult = await pool.query(
      'SELECT id, points_cost, title, business_email FROM business_rewards WHERE id = $1',
      [reward_id]
    );
    if (!rewardResult.rows.length) {
      return res.status(404).json({ success: false, message: 'Reward nicht gefunden.' });
    }
    const reward = rewardResult.rows[0];

    // Business-E-Mail im QR muss zur DB passen
    if (reward.business_email !== business_email) {
      return res.status(400).json({ success: false, message: 'Coupon gehört nicht zu diesem Unternehmen.' });
    }

    // Scannendes Employee/Business muss zum richtigen Unternehmen gehören
    const scannerEmail = user.type === 'employee' ? user.business_email : user.email;
    if (scannerEmail !== reward.business_email) {
      return res.status(403).json({ success: false, message: 'Du kannst diesen Coupon nicht einlösen.' });
    }

    // 6. Punkte-Check (serverseitig)
    const ptsResult = await pool.query(
      'SELECT points FROM user_business_points WHERE user_email = $1 AND business_email = $2',
      [customerEmail, business_email]
    );
    const currentPoints = ptsResult.rows[0]?.points || 0;

    if (currentPoints < reward.points_cost) {
      return res.status(400).json({
        success: false,
        message: `Nicht genügend Punkte (hat: ${currentPoints}, benötigt: ${reward.points_cost}).`,
      });
    }

    // 7. Atomar: Punkte abziehen + Transaktion loggen
    const client = await pool.connect();
    let remainingPoints;
    try {
      await client.query('BEGIN');

      const updateResult = await client.query(
        `UPDATE user_business_points
         SET    points = points - $1, updated_at = NOW()
         WHERE  user_email = $2 AND business_email = $3
         RETURNING points`,
        [reward.points_cost, customerEmail, business_email]
      );
      remainingPoints = updateResult.rows[0]?.points ?? 0;

      await client.query(
        `INSERT INTO point_transactions
           (user_email, business_email, points, type, reward_id, nonce, created_at)
         VALUES ($1, $2, $3, 'redeem', $4, $5, NOW())`,
        [customerEmail, business_email, reward.points_cost, reward_id, nonce]
      );

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
router.get('/points/balance', requireJwt, async (req, res, next) => {
  try {
    const user = req.user;
    if (user.type !== 'customer') {
      return res.status(403).json({ success: false, message: 'Nur für Kunden.' });
    }

    const { business_email } = req.query;

    if (business_email) {
      const r = await pool.query(
        'SELECT points FROM user_business_points WHERE user_email = $1 AND business_email = $2',
        [user.email, business_email]
      );
      return res.json({ success: true, business_email, points: r.rows[0]?.points || 0 });
    }

    const r = await pool.query(
      `SELECT ubp.business_email, ubp.points, b.name AS business_name
       FROM   user_business_points ubp
       LEFT   JOIN businesses b ON b.email = ubp.business_email
       WHERE  ubp.user_email = $1`,
      [user.email]
    );
    return res.json({ success: true, balances: r.rows });
  } catch (err) { next(err); }
});

// ─── GET /api/points/history ───────────────────────────────────────────────────
router.get('/points/history', requireJwt, async (req, res, next) => {
  try {
    const user = req.user;
    let rows;

    if (user.type === 'customer') {
      const r = await pool.query(
        `SELECT pt.points, pt.type, pt.created_at, b.name AS business_name
         FROM   point_transactions pt
         LEFT   JOIN businesses b ON b.email = pt.business_email
         WHERE  pt.user_email = $1
         ORDER  BY pt.created_at DESC LIMIT 50`,
        [user.email]
      );
      rows = r.rows;
    } else {
      const bizEmail = user.type === 'employee' ? user.business_email : user.email;
      const r = await pool.query(
        `SELECT points, type, created_at, user_email
         FROM   point_transactions
         WHERE  business_email = $1
         ORDER  BY created_at DESC LIMIT 100`,
        [bizEmail]
      );
      rows = r.rows;
    }

    res.json({ success: true, transactions: rows });
  } catch (err) { next(err); }
});

// ─── GET /api/rewards ─────────────────────────────────────────────────────────
router.get('/rewards', async (req, res, next) => {
  try {
    const { business_email } = req.query;
    if (!business_email) return res.status(400).json({ error: 'business_email required' });

    const r = await pool.query(
      `SELECT id, title, description, points_cost, image_url
       FROM   business_rewards
       WHERE  business_email = $1 AND status = 'active'
       ORDER  BY points_cost ASC`,
      [business_email]
    );
    res.json({ success: true, rewards: r.rows });
  } catch (err) { next(err); }
});

module.exports = router;
