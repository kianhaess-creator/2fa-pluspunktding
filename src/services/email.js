const nodemailer = require('nodemailer');
const config = require('../config');

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: config.brevo.smtpLogin,
    pass: config.brevo.smtpKey,
  },
});

async function sendVerificationEmail(toEmail, toName, code) {
  await transporter.sendMail({
    from: `"${config.brevo.senderName}" <${config.brevo.senderEmail}>`,
    to: toName ? `"${toName}" <${toEmail}>` : toEmail,
    subject: 'Dein Verifizierungscode',
    html: buildEmailHtml(code),
  });
}

function buildEmailHtml(code) {
  return `
    <!DOCTYPE html>
    <html lang="de">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 40px 0;">
      <div style="max-width: 480px; margin: 0 auto; background: #ffffff; border-radius: 8px; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
        <h2 style="color: #1a1a1a; margin-top: 0;">Dein Verifizierungscode</h2>
        <p style="color: #555; font-size: 15px;">Bitte gib diesen Code auf der Website ein, um dich zu verifizieren:</p>
        <div style="text-align: center; margin: 32px 0;">
          <span style="font-size: 42px; font-weight: bold; letter-spacing: 10px; color: #1a1a1a; background: #f0f0f0; padding: 16px 24px; border-radius: 8px; display: inline-block;">${code}</span>
        </div>
        <p style="color: #888; font-size: 13px;">Dieser Code ist <strong>10 Minuten</strong> gültig und kann nur einmal verwendet werden.</p>
        <p style="color: #888; font-size: 13px;">Falls du diese Anfrage nicht gestellt hast, kannst du diese E-Mail ignorieren.</p>
      </div>
    </body>
    </html>
  `;
}

module.exports = { sendVerificationEmail };
