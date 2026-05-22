const config = require('../config');

async function sendVerificationEmail(toEmail, toName, code) {
  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': config.brevo.apiKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender: {
        name: config.brevo.senderName,
        email: config.brevo.senderEmail,
      },
      to: [{ email: toEmail, name: toName || toEmail }],
      subject: 'Dein Verifizierungscode',
      htmlContent: buildEmailHtml(code),
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Brevo API error ${response.status}: ${body}`);
  }
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
