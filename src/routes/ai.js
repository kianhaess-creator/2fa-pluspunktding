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

    const messages = [{ role: 'user', content: message }];

    // Optional context from dashboard data
    let fullSystem = systemPrompt;
    if (context && typeof context === 'object') {
      fullSystem += '\n\nAktuelle Dashboard-Daten:\n' + JSON.stringify(context, null, 2).slice(0, 3000);
    }

    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: fullSystem },
          ...messages,
        ],
        max_tokens: 1024,
        temperature: 0.7,
      }),
    });

    if (!groqRes.ok) {
      const err = await groqRes.text();
      console.error('[AI] Groq error status:', groqRes.status);
      console.error('[AI] Groq error body:', err);
      console.error('[AI] API Key set:', !!process.env.GROQ_API_KEY);
      return res.status(502).json({ error: 'KI-Service vorübergehend nicht verfügbar.', status: groqRes.status, debug: err });
    }

    const data = await groqRes.json();
    const reply = data.choices?.[0]?.message?.content || 'Keine Antwort erhalten.';

    res.json({ reply });
  } catch (err) {
    console.error('[AI] Error:', err.message);
    res.status(500).json({ error: 'Interner Fehler beim KI-Chat.' });
  }
});

module.exports = router;
