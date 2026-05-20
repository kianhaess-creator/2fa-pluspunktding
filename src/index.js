const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const requireApiKey = require('./middleware/apiKey');
const authRoutes = require('./routes/auth');

const app = express();

app.use(cors({
  origin: config.allowedOrigins.length > 0 ? config.allowedOrigins : false,
  methods: ['POST'],
}));

app.use(express.json({ limit: '10kb' }));

// Global rate limit: max 60 requests per minute per IP
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
}));

// All routes require a valid API key
app.use('/api', requireApiKey);
app.use('/api', authRoutes);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, _req, res, _next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(config.port, () => {
  console.log(`2FA service running on port ${config.port}`);
});
