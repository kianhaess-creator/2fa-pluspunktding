const express = require('express');
const router  = express.Router();
const rateLimit = require('express-rate-limit');

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Zu viele KI-Anfragen, bitte warte eine Minute.' },
});

const SYSTEM_PROMPTS = {
  admin: `Du bist ein KI-Assistent für das Pluspunkt Admin Dashboard.
Pluspunkt ist ein Bonuspunkte-Programm: Nutzer sammeln Punkte bei teilnehmenden Unternehmen und können Coupons einlösen.
Du hilfst dem Administrator bei Fragen zu Statistiken, Unternehmen, Mitarbeitern und Nutzern.
Antworte auf Deutsch, präzise und professionell. Keine langen Erklärungen — Fakten und Empfehlungen.`,

  business: `Du bist ein KI-Assistent für das Pluspunkt Business Dashboard.
Pluspunkt ist ein Bonuspunkte-Programm. Du hilfst Unternehmensinhabern bei Fragen zu ihren Statistiken,
Mitarbeitern, Rewards und der Pluspunkt-Plattform.
Antworte auf Deutsch, freundlich und hilfreich. Erkläre Funktionen klar und einfach.`,

  employee: `Du bist ein KI-Assistent für Pluspunkt-Mitarbeiter.
Pluspunkt ist ein Bonuspunkte-Programm. Du hilfst Mitarbeitern beim Scannen von QR-Codes,
Einlösen von Coupons und Fragen zu ihrer Schicht und Berechtigungen.
Antworte auf Deutsch, kurz und direkt.`,

  user: `Du bist ein KI-Assistent für die Pluspunkt App.
Pluspunkt ist ein kostenloses Bonuspunkte-Programm: Nutzer sammeln Punkte beim Einkauf
bei teilnehmenden Unternehmen und können diese gegen Coupons einlösen.
Antworte auf Deutsch, freundlich und einfach verständlich. Hilf bei Fragen zu Punkten,
Coupons, teilnehmenden Unternehmen und der App-Nutzung.`,
};

router.post('/ai-chat', aiLimiter, async (req, res) => {
  try {
    const { message, context, role } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Nachricht fehlt.' });
    }
    if (message.length > 2000) {
      return res.status(400).json({ error: 'Nachricht zu lang (max. 2000 Zeichen).' });
    }

    const systemPrompt = SYSTEM_PROMPTS[role] || SYSTEM_PROMPTS.user;

    let fullSystem = systemPrompt;
    if (context && typeof context === 'object') {
      fullSystem += '\n\nAktuelle Dashboard-Daten:\n' + JSON.stringify(context, null, 2).slice(0, 3000);
    }

    const apiKey = process.env.GEMINI_API_KEY;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const geminiRes = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: fullSystem }] },
        contents: [{ role: 'user', parts: [{ text: message }] }],
        generationConfig: { maxOutputTokens: 1024, temperature: 0.7 },
      }),
    });

    if (!geminiRes.ok) {
      const err = await geminiRes.text();
      console.error('[AI] Gemini error status:', geminiRes.status);
      console.error('[AI] Gemini error body:', err);
      return res.status(502).json({ error: 'KI-Service vorübergehend nicht verfügbar.' });
    }

    const data = await geminiRes.json();
    const reply = data.candidates?.[0]?.content?.parts?.[0]?.text || 'Keine Antwort erhalten.';

    res.json({ reply });
  } catch (err) {
    console.error('[AI] Error:', err.message);
    res.status(500).json({ error: 'Interner Fehler beim KI-Chat.' });
  }
});

module.exports = router;
