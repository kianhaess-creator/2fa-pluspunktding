const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const authRoutes    = require('./routes/auth');
const businessRoutes = require('./routes/business');
const pointsRoutes  = require('./routes/points');
const { init, pool } = require('./services/db');

const app = express();

app.set('trust proxy', 1);

// ── Security Headers ───────────────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  next();
});

app.use(cors({
  origin: config.allowedOrigins.length > 0 ? config.allowedOrigins : false,
  methods: ['GET', 'POST'],
}));

app.use(express.json({ limit: '10kb' }));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
}));

app.use('/api', businessRoutes);
app.use('/api', authRoutes);
app.use('/api', pointsRoutes);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, _req, res, _next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

init()
  .then(() => {
    app.listen(config.port, () => {
      console.log(`2FA service running on port ${config.port} ✓`);
    });

    // Abgelaufene Tokens aus der DB löschen (alle 5 Minuten)
    setInterval(async () => {
      try {
        const r1 = await pool.query('DELETE FROM qr_tokens WHERE expires_at < NOW()');
        if (r1.rowCount > 0) console.log(`[QR Cleanup] ${r1.rowCount} Punkte-Token(s) gelöscht.`);
        const r2 = await pool.query('DELETE FROM coupon_tokens WHERE expires_at < NOW()');
        if (r2.rowCount > 0) console.log(`[QR Cleanup] ${r2.rowCount} Coupon-Token(s) gelöscht.`);
      } catch (err) {
        console.error('[QR Cleanup] Fehler:', err.message);
      }
    }, 5 * 60 * 1000);
  })
  .catch((err) => {
    console.error('DB init failed:', err.message);
    process.exit(1);
  });
