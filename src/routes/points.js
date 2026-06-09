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

    const now       = Math.floor(Date.now() / 1000);
    const expiresAt = now + config.qrTtlSeconds;
    const nonce     = generateNonce();

    // Short keys to minimise payload size → smaller QR version → larger modules → reliable scan
    // t=type, b=business_email, p=points, e=expires_at, n=nonce, s=sig (truncated to 22 chars)
    const payloadData = { t: 'pts', b: businessEmail, p: points, e: expiresAt, n: nonce };
    const sig       = signPayload(payloadData).slice(0, 22);
    const full      = { ...payloadData, s: sig };
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    // Token in Supabase persistieren (Token=nonce, Betrag, Shop-ID, Ablaufzeit)
    await pool.query(
      `INSERT INTO qr_tokens (token, business_email, points, expires_at)
       VALUES ($1, $2, $3, TO_TIMESTAMP($4))
       ON CONFLICT (token) DO NOTHING`,
      [nonce, businessEmail, points, expiresAt]
    );

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

    // 3. Replay-Schutz (In-Memory)
    const remaining = expires_at - now;
    if (!consumeNonce(nonce, remaining)) {
      return res.status(400).json({ success: false, message: 'QR-Code wurde bereits verwendet.' });
    }

    // 3b. Supabase-Validierung: Token muss existieren, Betrag + Shop müssen übereinstimmen
    const tokenRow = await pool.query(
      `SELECT token, business_email, points, expires_at
       FROM   qr_tokens
       WHERE  token = $1`,
      [nonce]
    );
    if (!tokenRow.rows.length) {
      return res.status(400).json({ success: false, message: 'QR-Code ungültig oder bereits verwendet.' });
    }
    const dbToken = tokenRow.rows[0];

    // Ablaufzeit serverseitig nochmals prüfen (Supabase-Zeitstempel)
    if (new Date(dbToken.expires_at) < new Date()) {
      await pool.query('DELETE FROM qr_tokens WHERE token = $1', [nonce]);
      return res.status(400).json({ success: false, message: 'QR-Code ist abgelaufen.' });
    }

    // Betrag und Shop-ID müssen mit DB-Eintrag übereinstimmen
    if (dbToken.business_email !== business_email || dbToken.points !== points) {
      return res.status(400).json({ success: false, message: 'QR-Code wurde manipuliert.' });
    }

    // Token sofort löschen (Einmalverwendung)
    await pool.query('DELETE FROM qr_tokens WHERE token = $1', [nonce]);

    // 4. Punkte atomar gutschreiben (upsert)
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

    if (!config.supabaseUrl || !config.supabaseServiceKey) {
      return res.status(503).json({ success: false, message: 'Server-Konfiguration unvollständig (SUPABASE_URL/KEY fehlt).' });
    }

    // Reward aus Supabase laden (business_rewards liegt nur dort)
    const sbHeaders = {
      apikey: config.supabaseServiceKey,
      Authorization: `Bearer ${config.supabaseServiceKey}`,
      'Content-Type': 'application/json',
    };
    const rewardResp = await fetch(
      `${config.supabaseUrl}/rest/v1/business_rewards?id=eq.${encodeURIComponent(reward_id)}&select=id,business_email,points_cost,title,status&limit=1`,
      { headers: sbHeaders }
    );
    if (!rewardResp.ok) {
      return res.status(500).json({ success: false, message: 'Fehler beim Laden des Rewards.' });
    }
    const rewardRows = await rewardResp.json();
    if (!rewardRows.length) {
      return res.status(404).json({ success: false, message: 'Coupon nicht gefunden.' });
    }
    const reward = rewardRows[0];

    if (reward.status !== 'active') {
      return res.status(400).json({ success: false, message: 'Coupon ist nicht aktiv.' });
    }

    // Punkte des Kunden bei diesem Unternehmen prüfen (user_business_points liegt im Backend-Pool)
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

    const now       = Math.floor(Date.now() / 1000);
    const expiresAt = now + config.couponQrTtlSeconds;
    const nonce     = generateNonce();

    // Short keys: t=type, b=business_email, r=reward_id, n=nonce, e=expires_at, s=sig
    // temp_customer_id entfernt — Kunden-E-Mail wird direkt in DB gespeichert
    const payloadData = { t: 'cpn', b: reward.business_email, r: reward_id, n: nonce, e: expiresAt };
    const sig       = signPayload(payloadData).slice(0, 22);
    const full      = { ...payloadData, s: sig };
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    // Coupon-Token in DB persistieren (überlebt Server-Neustart)
    await pool.query(
      `INSERT INTO coupon_tokens
         (nonce, customer_email, business_email, reward_id, points_cost, expires_at)
       VALUES ($1, $2, $3, $4, $5, TO_TIMESTAMP($6))
       ON CONFLICT (nonce) DO NOTHING`,
      [nonce, user.email, reward.business_email, reward_id, reward.points_cost, expiresAt]
    );

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

    // Support both short-key format {t,b,r,n,e,s} and legacy format {t,b,r,c,e,n,s}
    const isShortC       = parsed.t !== undefined;
    const type           = isShortC ? (parsed.t === 'cpn' ? 'coupon' : parsed.t) : parsed.type;
    const business_email = isShortC ? parsed.b : parsed.business_email;
    const reward_id      = isShortC ? parsed.r : parsed.reward_id;
    const expires_at     = isShortC ? parsed.e : parsed.expires_at;
    const nonce          = isShortC ? parsed.n : parsed.nonce;
    const sig            = isShortC ? parsed.s : parsed.sig;

    if (type !== 'coupon') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    if (!business_email || !reward_id || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 1. Signatur prüfen (ohne temp_customer_id — neues Format)
    const payloadForSig = isShortC
      ? { t: parsed.t, b: parsed.b, r: parsed.r, n: parsed.n, e: parsed.e }
      : { type, business_email, reward_id, nonce, expires_at };
    // Legacy-Format mit c-Feld ebenfalls unterstützen
    if (isShortC && parsed.c !== undefined) payloadForSig.c = parsed.c;
    const fullSigC  = signPayload(payloadForSig);
    const sigValidC = sig === fullSigC.slice(0, 22);
    if (!sigValidC) {
      return res.status(400).json({ success: false, message: 'Ungültige QR-Code-Signatur.' });
    }

    // 2. Ablaufzeit
    const now = Math.floor(Date.now() / 1000);
    if (now > expires_at) {
      await pool.query('DELETE FROM coupon_tokens WHERE nonce = $1', [nonce]);
      return res.status(400).json({ success: false, message: 'Coupon-QR-Code ist abgelaufen.' });
    }

    // 3. DB-Token laden und Einmalverwendung sicherstellen
    const tokenRow = await pool.query(
      `SELECT customer_email, business_email, reward_id, points_cost, expires_at
       FROM coupon_tokens WHERE nonce = $1`,
      [nonce]
    );
    if (!tokenRow.rows.length) {
      return res.status(400).json({ success: false, message: 'Coupon wurde bereits eingelöst oder ist ungültig.' });
    }
    const dbToken = tokenRow.rows[0];

    if (new Date(dbToken.expires_at) < new Date()) {
      await pool.query('DELETE FROM coupon_tokens WHERE nonce = $1', [nonce]);
      return res.status(400).json({ success: false, message: 'Coupon-QR-Code ist abgelaufen.' });
    }

    if (dbToken.business_email !== business_email || dbToken.reward_id !== reward_id) {
      return res.status(400).json({ success: false, message: 'Coupon-Daten stimmen nicht überein.' });
    }

    // Sofort löschen (Einmalverwendung)
    await pool.query('DELETE FROM coupon_tokens WHERE nonce = $1', [nonce]);

    const customerEmail = dbToken.customer_email;

    // 5. Reward aus Supabase laden
    const sbHdrs = {
      apikey: config.supabaseServiceKey,
      Authorization: `Bearer ${config.supabaseServiceKey}`,
      'Content-Type': 'application/json',
    };
    const rewardResp2 = await fetch(
      `${config.supabaseUrl}/rest/v1/business_rewards?id=eq.${encodeURIComponent(reward_id)}&select=id,points_cost,title,business_email&limit=1`,
      { headers: sbHdrs }
    );
    if (!rewardResp2.ok) {
      return res.status(500).json({ success: false, message: 'Fehler beim Laden des Rewards.' });
    }
    const rewardRows2 = await rewardResp2.json();
    if (!rewardRows2.length) {
      return res.status(404).json({ success: false, message: 'Reward nicht gefunden.' });
    }
    const reward = rewardRows2[0];

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

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // redeemed-Zähler in Supabase inkrementieren (fire-and-forget)
    fetch(
      `${config.supabaseUrl}/rest/v1/rpc/increment_redeemed`,
      {
        method: 'POST',
        headers: { ...sbHdrs, 'Content-Type': 'application/json' },
        body: JSON.stringify({ reward_uuid: reward_id }),
      }
    ).catch(() => {});

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
