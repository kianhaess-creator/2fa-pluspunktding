require('dotenv').config();

function required(name) {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required env variable: ${name}`);
  return val;
}

module.exports = {
  port: process.env.PORT || 3000,
  apiKey: required('API_KEY'),
  allowedOrigins: (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
  brevo: {
    apiKey: required('BREVO_API_KEY'),
    senderEmail: required('SENDER_EMAIL'),
    senderName: process.env.SENDER_NAME || 'Verification',
  },
  code: {
    ttlSeconds: 10 * 60,       // code expires after 10 minutes
    maxVerifyAttempts: 5,      // lock after 5 wrong guesses
    maxSendAttempts: 3,        // max 3 sends per email per window
    sendWindowSeconds: 15 * 60,
  },
  hashPepper: required('CODE_HASH_PEPPER'),
  jwtSecret: required('JWT_SECRET'),
  jwtExpiresIn: '30d',

  // QR-Code Signierung (Punkte & Coupons)
  qrSecret: required('QR_SECRET'),            // HMAC-Schlüssel für QR-Signaturen
  qrTtlSeconds: 15 * 60,                       // Punkte-QR läuft nach 15 Minuten ab
  couponQrTtlSeconds: 10 * 60,                 // Coupon-QR läuft nach 10 Minuten ab

  // Supabase (für business_rewards-Zugriff serverseitig)
  supabaseUrl: required('SUPABASE_URL'),
  supabaseServiceKey: required('SUPABASE_SERVICE_KEY'),
};
