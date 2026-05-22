# 2FA Integration Guide

## Übersicht

Dieser Service schickt dem User nach dem Login einen 6-stelligen Code per E-Mail.
Der User muss den Code eingeben, bevor er auf die Website kommt.
Google- und Apple-Login überspringen die 2FA komplett.

---

## Voraussetzungen

Der 2FA-Service muss deployed und erreichbar sein. Trage die URL und den API Key hier ein:

- **Service URL:** `https://twofa-pluspunktding.onrender.com`
- **API Key:** `c12f48f7b74becf2bac9ee8b62a7bc131b295fb0f06490f052a61678c969015e`

---

## Ablauf

```
User gibt E-Mail + Passwort ein
        ↓
Login erfolgreich
        ↓
2FA-Seite wird angezeigt (Code wird automatisch gesendet)
        ↓
User gibt 6-stelligen Code ein
        ↓
Code korrekt → User kommt auf die Website
Code falsch  → Fehlermeldung (max. 5 Versuche)
Code abgelaufen → neuen Code anfordern (10 Min. Gültigkeit)

--- AUSNAHME ---
Google Login  → direkt auf die Website, KEIN 2FA
Apple Login   → direkt auf die Website, KEIN 2FA
```

---

## Schritt 1 — Nach dem Login zur 2FA-Seite weiterleiten

Füge nach einem **erfolgreichen E-Mail/Passwort-Login** diesen Code ein.
**Nicht** nach Google- oder Apple-Login ausführen.

```javascript
// Nach erfolgreichem Login mit E-Mail/Passwort:
function onEmailLoginSuccess(userEmail, userName) {
  // E-Mail und Name in sessionStorage speichern
  sessionStorage.setItem('2fa_email', userEmail);
  sessionStorage.setItem('2fa_name', userName || '');

  // Zur 2FA-Seite weiterleiten
  window.location.href = '/verify.html';
}

// Nach Google- oder Apple-Login: diese Funktion NICHT aufrufen
// Stattdessen direkt zur Website weiterleiten
function onSocialLoginSuccess() {
  window.location.href = '/dashboard.html'; // oder deine Zielseite
}
```

---

## Schritt 2 — Die 2FA-Seite (verify.html) erstellen

Erstelle eine neue Datei `verify.html` in deinem Website-Ordner mit folgendem Inhalt.
Passe `SERVICE_URL` und `API_KEY` an.

```html
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifizierung – Pluspunkt</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }

    .card {
      background: #fff;
      border-radius: 12px;
      padding: 40px;
      max-width: 420px;
      width: 100%;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
      text-align: center;
    }

    h1 {
      font-size: 22px;
      color: #1a1a1a;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #666;
      font-size: 14px;
      margin-bottom: 32px;
      line-height: 1.5;
    }

    .email-display {
      color: #1a1a1a;
      font-weight: bold;
    }

    .code-input {
      width: 100%;
      font-size: 32px;
      font-weight: bold;
      letter-spacing: 12px;
      text-align: center;
      border: 2px solid #ddd;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
      outline: none;
      transition: border-color 0.2s;
    }

    .code-input:focus { border-color: #1a1a1a; }
    .code-input.error { border-color: #e53e3e; }

    .btn {
      width: 100%;
      padding: 14px;
      font-size: 15px;
      font-weight: bold;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s, opacity 0.2s;
    }

    .btn-primary {
      background: #1a1a1a;
      color: #fff;
      margin-bottom: 12px;
    }

    .btn-primary:hover { background: #333; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

    .btn-secondary {
      background: transparent;
      color: #666;
      font-size: 14px;
      padding: 8px;
    }

    .btn-secondary:hover { color: #1a1a1a; }
    .btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

    .message {
      font-size: 14px;
      margin-bottom: 16px;
      min-height: 20px;
    }

    .message.error { color: #e53e3e; }
    .message.success { color: #38a169; }

    .timer {
      font-size: 13px;
      color: #999;
      margin-top: 8px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Bestätigungscode</h1>
    <p class="subtitle">
      Wir haben einen Code an<br>
      <span class="email-display" id="emailDisplay"></span><br>
      gesendet.
    </p>

    <input
      type="text"
      class="code-input"
      id="codeInput"
      placeholder="000000"
      maxlength="6"
      inputmode="numeric"
      pattern="\d{6}"
      autocomplete="one-time-code"
    >

    <div class="message" id="message"></div>

    <button class="btn btn-primary" id="verifyBtn" onclick="verifyCode()">
      Bestätigen
    </button>

    <button class="btn btn-secondary" id="resendBtn" onclick="resendCode()">
      Neuen Code senden
    </button>

    <div class="timer" id="timer"></div>
  </div>

  <script>
    const SERVICE_URL = 'https://twofa-pluspunktding.onrender.com';
    const API_KEY = 'c12f48f7b74becf2bac9ee8b62a7bc131b295fb0f06490f052a61678c969015e';
    const REDIRECT_URL = '/dashboard.html'; // ← hier deine Zielseite nach erfolgreichem Login

    const email = sessionStorage.getItem('2fa_email');
    const name = sessionStorage.getItem('2fa_name');

    let timerInterval = null;

    // Wenn keine E-Mail vorhanden → zurück zum Login
    if (!email) {
      window.location.href = '/login.html';
    }

    document.getElementById('emailDisplay').textContent = email;

    // Code automatisch beim Laden senden
    sendCode();

    // Nur Zahlen erlauben und bei 6 Ziffern automatisch prüfen
    document.getElementById('codeInput').addEventListener('input', function () {
      this.value = this.value.replace(/\D/g, '').slice(0, 6);
      if (this.value.length === 6) verifyCode();
    });

    async function sendCode() {
      setMessage('', '');
      setResendDisabled(true);

      try {
        const res = await fetch(`${SERVICE_URL}/api/send-code`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': API_KEY,
          },
          body: JSON.stringify({ email, name }),
        });

        const data = await res.json();

        if (res.status === 429) {
          setMessage(`Bitte warte ${data.retryAfterSeconds || 60} Sekunden bevor du einen neuen Code anforderst.`, 'error');
          startTimer(data.retryAfterSeconds || 60);
          return;
        }

        if (!res.ok) {
          setMessage('Fehler beim Senden des Codes. Bitte versuche es erneut.', 'error');
          setResendDisabled(false);
          return;
        }

        startTimer(60);
      } catch (e) {
        setMessage('Verbindung zum Server fehlgeschlagen.', 'error');
        setResendDisabled(false);
      }
    }

    async function resendCode() {
      document.getElementById('codeInput').value = '';
      document.getElementById('codeInput').classList.remove('error');
      await sendCode();
    }

    async function verifyCode() {
      const code = document.getElementById('codeInput').value;

      if (code.length !== 6) {
        setMessage('Bitte gib den vollständigen 6-stelligen Code ein.', 'error');
        return;
      }

      setVerifyDisabled(true);
      setMessage('', '');

      try {
        const res = await fetch(`${SERVICE_URL}/api/verify-code`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': API_KEY,
          },
          body: JSON.stringify({ email, code }),
        });

        const data = await res.json();

        if (data.valid) {
          sessionStorage.removeItem('2fa_email');
          sessionStorage.removeItem('2fa_name');
          window.location.href = REDIRECT_URL;
          return;
        }

        if (res.status === 429) {
          setMessage('Zu viele Fehlversuche. Bitte fordere einen neuen Code an.', 'error');
          document.getElementById('codeInput').classList.add('error');
          setVerifyDisabled(true);
          return;
        }

        if (res.status === 404) {
          setMessage('Code abgelaufen. Bitte fordere einen neuen Code an.', 'error');
          document.getElementById('codeInput').classList.add('error');
          setVerifyDisabled(false);
          return;
        }

        const remaining = data.attemptsRemaining ?? '';
        setMessage(
          `Falscher Code.${remaining !== '' ? ` Noch ${remaining} Versuch${remaining === 1 ? '' : 'e'}.` : ''}`,
          'error'
        );
        document.getElementById('codeInput').classList.add('error');
        document.getElementById('codeInput').value = '';
      } catch (e) {
        setMessage('Verbindung zum Server fehlgeschlagen.', 'error');
      }

      setVerifyDisabled(false);
    }

    function startTimer(seconds) {
      clearInterval(timerInterval);
      let remaining = seconds;
      updateTimerDisplay(remaining);

      timerInterval = setInterval(() => {
        remaining--;
        updateTimerDisplay(remaining);
        if (remaining <= 0) {
          clearInterval(timerInterval);
          document.getElementById('timer').textContent = '';
          setResendDisabled(false);
        }
      }, 1000);
    }

    function updateTimerDisplay(seconds) {
      document.getElementById('timer').textContent =
        `Neuen Code in ${seconds}s anfordern`;
    }

    function setMessage(text, type) {
      const el = document.getElementById('message');
      el.textContent = text;
      el.className = `message ${type}`;
    }

    function setVerifyDisabled(disabled) {
      document.getElementById('verifyBtn').disabled = disabled;
    }

    function setResendDisabled(disabled) {
      document.getElementById('resendBtn').disabled = disabled;
    }
  </script>
</body>
</html>
```

---

## Schritt 3 — Anpassungen in verify.html

Ersetze die folgenden zwei Zeilen im `<script>` Block:

| Variable | Was eintragen |
|---|---|
| `SERVICE_URL` | Die URL deines deployed 2FA-Service, z.B. `https://2fa.pluspunkt.online` |
| `REDIRECT_URL` | Die Seite nach erfolgreichem Login, z.B. `/dashboard.html` |

---

## Schritt 4 — Login-Seite anpassen

In deiner bestehenden Login-Seite, nach erfolgreichem E-Mail/Passwort-Login:

```javascript
// VORHER (direkt weiterleiten):
window.location.href = '/dashboard.html';

// NACHHER (erst 2FA):
sessionStorage.setItem('2fa_email', userEmail);   // E-Mail des Users
sessionStorage.setItem('2fa_name', userName || ''); // Name optional
window.location.href = '/verify.html';
```

**Google/Apple Login bleibt unverändert** — diese leiten weiterhin direkt zur Zielseite weiter.

---

## API Referenz

Beide Endpunkte erwarten den Header `x-api-key` und `Content-Type: application/json`.

### POST /api/send-code
```json
{ "email": "user@example.com", "name": "Max" }
```
Antwort: `{ "success": true, "message": "Verification code sent." }`

### POST /api/verify-code
```json
{ "email": "user@example.com", "code": "123456" }
```
Antwort bei Erfolg: `{ "valid": true }`  
Antwort bei Fehler: `{ "valid": false, "attemptsRemaining": 4 }`

---

## Sicherheitshinweise

- Der **API Key** ist im Frontend-JS sichtbar. Das ist durch CORS (nur `https://pluspunkt.online` erlaubt) und Rate-Limiting abgesichert.
- Codes sind **einmalig verwendbar** und werden nach Eingabe sofort gelöscht.
- Nach **5 Fehlversuchen** wird der Code gesperrt — der User muss einen neuen anfordern.
- Codes laufen nach **10 Minuten** automatisch ab und werden aus dem Speicher gelöscht.
