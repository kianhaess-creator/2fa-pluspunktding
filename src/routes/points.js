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
  return crypto.randomBytes(24).toString('base64url'); // 32 Zeichen, 192 Bit Entropie
}

async function employeeHasPerm(employeeId, perm) {
  if (!employeeId) return false;
  const r = await pool.query(
    'SELECT permissions FROM business_employees WHERE id = $1',
    [employeeId]
  );
  const perms = r.rows[0]?.permissions;
  if (!perms) return false;
  return perms[perm] === true;
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

const readLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Zu viele Anfragen. Bitte warte eine Minute.' },
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

    if (user.type === 'employee') {
      const allowed = await employeeHasPerm(user.employee_id, 'grantPoints');
      if (!allowed) return res.status(403).json({ success: false, message: 'Keine Berechtigung zum Ausstellen von Punkten.' });
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

    const payloadData = { t: 'pts', b: businessEmail, p: points, e: expiresAt, n: nonce };
    const sig       = signPayload(payloadData);
    const full      = { ...payloadData, s: sig };
    const qrPayload = Buffer.from(JSON.stringify(full)).toString('base64url');

    const employeeId = user.type === 'employee' ? (user.employee_id || null) : null;

    await pool.query(
      `INSERT INTO qr_tokens (token, business_email, points, expires_at, employee_id)
       VALUES ($1, $2, $3, TO_TIMESTAMP($4), $5)
       ON CONFLICT (token) DO NOTHING`,
      [nonce, businessEmail, points, expiresAt, employeeId]
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

    const qrPayloadRaw = req.body.qr_payload;
    if (!qrPayloadRaw || typeof qrPayloadRaw !== 'string' || qrPayloadRaw.length > 2048) {
      return res.status(400).json({ success: false, message: 'Ungültiger QR-Code.' });
    }

    let parsed;
    try {
      const raw = Buffer.from(qrPayloadRaw, 'base64url').toString('utf8');
      parsed = JSON.parse(raw);
    } catch {
      return res.status(400).json({ success: false, message: 'Ungültiger QR-Code.' });
    }

    const type           = parsed.t === 'pts' ? 'points' : parsed.t;
    const business_email = parsed.b;
    const points         = parsed.p;
    const expires_at     = parsed.e;
    const nonce          = parsed.n;
    const sig            = parsed.s;

    if (type !== 'points') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    if (!business_email || !points || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 1. Signatur validieren (volle HMAC-SHA256, timing-safe)
    const payloadWithoutSig = { t: parsed.t, b: parsed.b, p: parsed.p, e: parsed.e, n: parsed.n };
    if (!verifySignature(payloadWithoutSig, sig)) {
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

    // 3b. Token validieren — enthält auch employee_id des QR-Erstellers
    const tokenRow = await pool.query(
      `SELECT token, business_email, points, expires_at, employee_id
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

    // 6. Transaktion loggen (employee_id des QR-Erstellers aus Token)
    await pool.query(
      `INSERT INTO point_transactions
         (user_email, business_email, points, type, nonce, employee_id, created_at)
       VALUES ($1, $2, $3, 'earn', $4, $5, NOW())`,
      [user.email, business_email, points, nonce, dbToken.employee_id || null]
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
    const rewardUrl = `${config.supabaseUrl}/rest/v1/business_rewards?id=eq.${encodeURIComponent(reward_id)}&select=id,business_email,points_cost,title,status,allow_multiple&limit=1`;
    const rewardResp = await fetch(rewardUrl, { headers: sbHeaders });
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

    // Einmalige Einlösung prüfen (allow_multiple === false)
    if (reward.allow_multiple === false) {
      const alreadyRedeemed = await pool.query(
        `SELECT 1 FROM point_transactions
         WHERE user_email = $1 AND reward_id = $2 AND type = 'redeem' LIMIT 1`,
        [user.email, reward_id]
      );
      if (alreadyRedeemed.rows.length) {
        return res.status(400).json({ success: false, message: 'Du hast diesen Coupon bereits eingelöst.' });
      }
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
    const sig       = signPayload(payloadData);
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

    if (user.type === 'employee') {
      const allowed = await employeeHasPerm(user.employee_id, 'redeemCodes');
      if (!allowed) return res.status(403).json({ success: false, message: 'Keine Berechtigung zum Einlösen von Coupons.' });
    }

    const qrRaw = req.body.qr_payload;
    if (!qrRaw || typeof qrRaw !== 'string' || qrRaw.length > 2048) {
      return res.status(400).json({ success: false, message: 'Ungültiger QR-Code.' });
    }

    let parsed;
    try {
      const raw = Buffer.from(qrRaw, 'base64url').toString('utf8');
      parsed = JSON.parse(raw);
    } catch {
      return res.status(400).json({ success: false, message: 'Ungültiger QR-Code.' });
    }

    const type           = parsed.t === 'cpn' ? 'coupon' : parsed.t;
    const business_email = parsed.b;
    const reward_id      = parsed.r;
    const expires_at     = parsed.e;
    const nonce          = parsed.n;
    const sig            = parsed.s;

    if (type !== 'coupon') {
      return res.status(400).json({ success: false, message: 'Falscher QR-Code-Typ.' });
    }

    if (!business_email || !reward_id || !expires_at || !nonce || !sig) {
      return res.status(400).json({ success: false, message: 'Unvollständiger QR-Code.' });
    }

    // 1. Signatur prüfen (volle HMAC-SHA256, timing-safe)
    const payloadForSig = { t: parsed.t, b: parsed.b, r: parsed.r, n: parsed.n, e: parsed.e };
    if (!verifySignature(payloadForSig, sig)) {
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

      const redeemEmployeeId = user.type === 'employee' ? (user.employee_id || null) : null;
      await client.query(
        `INSERT INTO point_transactions
           (user_email, business_email, points, type, reward_id, nonce, employee_id, created_at)
         VALUES ($1, $2, $3, 'redeem', $4, $5, $6, NOW())`,
        [customerEmail, business_email, reward.points_cost, reward_id, nonce, redeemEmployeeId]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // redeemed-Zähler inkrementieren + ggf. status auf inactive setzen (fire-and-forget)
    (async () => {
      try {
        // 1. redeemed-Zähler via RPC inkrementieren
        await fetch(
          `${config.supabaseUrl}/rest/v1/rpc/increment_redeemed`,
          {
            method: 'POST',
            headers: { ...sbHdrs, 'Content-Type': 'application/json' },
            body: JSON.stringify({ reward_uuid: reward_id }),
          }
        );

        // 2. Aktuellen Stand laden
        const checkResp = await fetch(
          `${config.supabaseUrl}/rest/v1/business_rewards?id=eq.${encodeURIComponent(reward_id)}&select=stock,redeemed,status&limit=1`,
          { headers: sbHdrs }
        );
        if (!checkResp.ok) return;
        const [row] = await checkResp.json();
        if (!row) return;

        // 3. Wenn alle Einlösungen verbraucht → status auf inactive setzen
        if (row.status === 'active' && row.stock > 0 && row.redeemed >= row.stock) {
          await fetch(
            `${config.supabaseUrl}/rest/v1/business_rewards?id=eq.${encodeURIComponent(reward_id)}`,
            {
              method: 'PATCH',
              headers: { ...sbHdrs, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
              body: JSON.stringify({ status: 'inactive' }),
            }
          );
        }
      } catch (_) {}
    })();

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
        `SELECT pt.points, pt.type, pt.created_at, pt.reward_id, b.name AS business_name
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
        `SELECT pt.points, pt.type, pt.created_at, pt.user_email, pt.employee_id,
                be.first_name, be.last_name
         FROM   point_transactions pt
         LEFT   JOIN business_employees be ON be.id = pt.employee_id
         WHERE  pt.business_email = $1
         ORDER  BY pt.created_at DESC LIMIT 200`,
        [bizEmail]
      );
      rows = r.rows;
    }

    res.json({ success: true, transactions: rows });
  } catch (err) { next(err); }
});

// ─── GET /api/rewards ─────────────────────────────────────────────────────────
router.get('/rewards', readLimiter, async (req, res, next) => {
  try {
    const { business_email } = req.query;
    if (!business_email) return res.status(400).json({ error: 'business_email required' });

    if (!config.supabaseUrl || !config.supabaseServiceKey) {
      return res.status(503).json({ error: 'Server-Konfiguration unvollständig.' });
    }

    const sbH = {
      apikey: config.supabaseServiceKey,
      Authorization: `Bearer ${config.supabaseServiceKey}`,
    };
    const url = `${config.supabaseUrl}/rest/v1/business_rewards?business_email=eq.${encodeURIComponent(business_email)}&status=eq.active&select=id,title,description,points_cost,image_url,allow_multiple&order=points_cost.asc`;
    const resp = await fetch(url, { headers: sbH });
    if (!resp.ok) return res.status(500).json({ error: 'Fehler beim Laden der Rewards.' });
    const rows = await resp.json();
    res.json({ success: true, rewards: rows });
  } catch (err) { next(err); }
});

module.exports = router;
