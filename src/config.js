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
    smtpLogin: required('BREVO_SMTP_LOGIN'),
    smtpKey: required('BREVO_SMTP_KEY'),
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
};
