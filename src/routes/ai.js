const express = require('express');
const router  = express.Router();
const rateLimit = require('express-rate-limit');

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Zu viele KI-Anfragen, bitte warte eine Minute.' },
});

const ROLE_CONTEXT = {
  user:     'Du sprichst gerade mit einem Endkunden über die Pluspunkt App. Beantworte ausschließlich Fragen zu seinen eigenen Punkten, Coupons, teilnehmenden Unternehmen und der App-Nutzung. Antworte freundlich und einfach verständlich. Gib keine Auskunft über interne Unternehmens- oder Mitarbeiterdaten.',
  business: 'Du sprichst gerade mit einem Unternehmensinhaber im Business Dashboard. Beantworte ausschließlich Fragen zu seinen eigenen Statistiken, Mitarbeitern, Rewards und der Verwaltung seines Unternehmens auf der Pluspunkt-Plattform. Antworte freundlich und klar. Gib keine Auskunft über andere Unternehmen, Kundendaten oder Admin-Funktionen.',
  employee: 'Du sprichst gerade mit einem Mitarbeiter im Employee Dashboard. Beantworte ausschließlich Fragen zum Scannen von QR-Codes, Einlösen von Coupons und operativen Abläufen im Tagesgeschäft. Antworte kurz und direkt. Gib keine Auskunft über Unternehmensstatistiken, andere Mitarbeiter oder Admin-Funktionen.',
  admin:    'Du sprichst gerade mit einem Pluspunkt-Administrator im Admin Dashboard. Du darfst Fragen zu allen Bereichen der Plattform beantworten: Statistiken, Unternehmen, Mitarbeiter, Nutzer und technische Abläufe. Antworte präzise und professionell, ohne unnötige Erklärungen.',
};

const BASE_PROMPT = `Du bist der offizielle KI-Assistent von Pluspunkt — einem lokalen Bonuspunkte-Programm, bei dem Kunden beim Einkauf bei teilnehmenden Unternehmen Punkte sammeln und diese gegen Coupons einlösen können.

Du kennst die gesamte Plattform: die Kunden-App, das Business Dashboard für Unternehmensinhaber, das Employee Dashboard für Mitarbeiter und das Admin Dashboard.

Wichtige Regeln:
- Antworte immer auf Deutsch.
- Beantworte nur Fragen, die für die aktuelle Rolle relevant sind — was erlaubt ist, steht im Rollenkontext unten.
- Erfinde keine Daten. Wenn du etwas nicht weißt, sage es ehrlich.
- Halte Antworten präzise — kein unnötiges Füllmaterial.
- Beantworte keine Fragen zu anderen Unternehmen, Wettbewerbern oder Themen außerhalb von Pluspunkt.

Rollenkontext: {{ROLE_CONTEXT}}`;

function buildPrompt(role, context) {
  const roleCtx = ROLE_CONTEXT[role] || ROLE_CONTEXT.user;
  let prompt = BASE_PROMPT.replace('{{ROLE_CONTEXT}}', roleCtx);
  if (context && typeof context === 'object') {
    prompt += '\n\nAktuelle Dashboard-Daten:\n' + JSON.stringify(context, null, 2).slice(0, 3000);
  }
  return prompt;
}

router.post('/ai-chat', aiLimiter, async (req, res) => {
  try {
    const { message, context, role } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Nachricht fehlt.' });
    }
    if (message.length > 2000) {
      return res.status(400).json({ error: 'Nachricht zu lang (max. 2000 Zeichen).' });
    }

    const fullSystem = buildPrompt(role, context);

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
