const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const config = require('../config');
const store = require('../services/store');
const { sendVerificationEmail } = require('../services/email');

function hashCode(code) {
  return crypto
    .createHmac('sha256', config.hashPepper)
    .update(code)
    .digest('hex');
}

function storeKey(type, email) {
  return `2fa:${type}:${email.toLowerCase().trim()}`;
}

// POST /api/send-code
// Body: { email, name? }
router.post('/send-code', async (req, res, next) => {
  try {
    const { email, name } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const sendKey = storeKey('sends', email);
    const sends = store.incr(sendKey);
    if (sends === 1) store.expire(sendKey, config.code.sendWindowSeconds);

    if (sends > config.code.maxSendAttempts) {
      const remaining = store.ttl(sendKey);
      return res.status(429).json({
        error: 'Too many code requests. Please wait before requesting a new code.',
        retryAfterSeconds: remaining,
      });
    }

    const code = crypto.randomInt(100000, 1000000).toString();
    const hashed = hashCode(code);

    const codeKey = storeKey('code', email);
    const attemptsKey = storeKey('attempts', email);

    store.set(codeKey, hashed, config.code.ttlSeconds);
    store.del(attemptsKey);

    await sendVerificationEmail(email, name, code);

    res.json({ success: true, message: 'Verification code sent.' });
  } catch (err) {
    next(err);
  }
});

// POST /api/verify-code
// Body: { email, code }
router.post('/verify-code', async (req, res, next) => {
  try {
    const { email, code } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Code must be a 6-digit number' });
    }

    const codeKey = storeKey('code', email);
    const attemptsKey = storeKey('attempts', email);

    const attempts = store.incr(attemptsKey);
    if (attempts === 1) store.expire(attemptsKey, config.code.sendWindowSeconds);

    if (attempts > config.code.maxVerifyAttempts) {
      return res.status(429).json({
        error: 'Too many failed attempts. Request a new code.',
        valid: false,
      });
    }

    const stored = store.get(codeKey);

    if (!stored) {
      return res.status(404).json({ valid: false, error: 'No active code found. Please request a new one.' });
    }

    const inputHash = hashCode(code);
    const isValid = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(stored));

    if (!isValid) {
      const remaining = config.code.maxVerifyAttempts - attempts;
      return res.status(200).json({ valid: false, attemptsRemaining: remaining });
    }

    store.del(codeKey, attemptsKey);

    res.json({ valid: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
