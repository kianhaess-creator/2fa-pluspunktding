const crypto = require('crypto');
const config = require('../config');

// Constant-time comparison to prevent timing attacks
function safeCompare(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || !safeCompare(key, config.apiKey)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};
