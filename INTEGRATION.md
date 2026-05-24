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

    /* Toast Popup oben links */
    .toast {
      position: fixed;
      top: 20px;
      left: 20px;
      background: #fff;
      border-radius: 12px;
      padding: 14px 16px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.12);
      display: flex;
      align-items: center;
      gap: 12px;
      max-width: 300px;
      z-index: 1000;
      transform: translateX(-120%);
      transition: transform 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
    }
    .toast.show { transform: translateX(0); }
    .toast-icon { font-size: 22px; flex-shrink: 0; }
    .toast-text { font-size: 13px; color: #333; line-height: 1.4; }
    .toast-text strong { display: block; margin-bottom: 2px; }
    .toast-close {
      position: absolute;
      top: 8px;
      right: 10px;
      background: none;
      border: none;
      font-size: 16px;
      color: #999;
      cursor: pointer;
      line-height: 1;
    }
    .toast-close:hover { color: #333; }

    /* Karte */
    .card {
      background: #fff;
      border-radius: 12px;
      padding: 40px;
      max-width: 420px;
      width: 100%;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
      text-align: center;
    }

    /* Animierte Taube */
    .dove-container {
      height: 90px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 16px;
    }
    .dove-wrapper {
      animation: float 3s ease-in-out infinite;
    }
    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50%       { transform: translateY(-10px); }
    }
    .dove-svg .wing-top {
      transform-origin: 52px 38px;
      animation: flapTop 0.6s ease-in-out infinite alternate;
    }
    .dove-svg .wing-bottom {
      transform-origin: 52px 44px;
      animation: flapBottom 0.6s ease-in-out infinite alternate;
    }
    @keyframes flapTop {
      from { transform: rotate(0deg); }
      to   { transform: rotate(-22deg); }
    }
    @keyframes flapBottom {
      from { transform: rotate(0deg); }
      to   { transform: rotate(12deg); }
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
    .email-display { color: #1a1a1a; font-weight: bold; }

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
    .btn-primary { background: #1a1a1a; color: #fff; margin-bottom: 12px; }
    .btn-primary:hover { background: #333; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-secondary { background: transparent; color: #666; font-size: 14px; padding: 8px; }
    .btn-secondary:hover { color: #1a1a1a; }
    .btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

    .message { font-size: 14px; margin-bottom: 16px; min-height: 20px; }
    .message.error { color: #e53e3e; }
    .message.success { color: #38a169; }

    .timer { font-size: 13px; color: #999; margin-top: 8px; }
  </style>
</head>
<body>

  <!-- Toast Popup -->
  <div class="toast" id="toast">
    <span class="toast-icon" id="toastIcon"></span>
    <div class="toast-text">
      <strong id="toastTitle"></strong>
      <span id="toastBody"></span>
    </div>
    <button class="toast-close" onclick="closeToast()">×</button>
  </div>

  <div class="card">

    <!-- Animierte Taube -->
    <div class="dove-container">
      <div class="dove-wrapper">
        <svg class="dove-svg" width="110" height="80" viewBox="0 0 110 80" fill="none" xmlns="http://www.w3.org/2000/svg">
          <!-- Körper -->
          <ellipse cx="52" cy="46" rx="22" ry="13" fill="#f0f0f0" stroke="#ccc" stroke-width="1"/>
          <!-- Kopf -->
          <circle cx="76" cy="38" r="10" fill="#f0f0f0" stroke="#ccc" stroke-width="1"/>
          <!-- Schnabel mit Brief -->
          <polygon points="86,37 96,35 86,39" fill="#f4a62a"/>
          <!-- Kleiner Brief im Schnabel -->
          <rect x="88" y="31" width="14" height="10" rx="1.5" fill="#fff" stroke="#aaa" stroke-width="1"/>
          <line x1="88" y1="35" x2="102" y2="35" stroke="#aaa" stroke-width="0.8"/>
          <line x1="88" y1="31" x2="95" y2="36" stroke="#aaa" stroke-width="0.8"/>
          <line x1="102" y1="31" x2="95" y2="36" stroke="#aaa" stroke-width="0.8"/>
          <!-- Auge -->
          <circle cx="78" cy="36" r="2" fill="#555"/>
          <circle cx="78.7" cy="35.3" r="0.6" fill="#fff"/>
          <!-- Oberer Flügel -->
          <path class="wing-top" d="M50 38 Q30 18 12 22 Q28 32 50 42 Z" fill="#e0e0e0" stroke="#ccc" stroke-width="1"/>
          <!-- Unterer Flügel -->
          <path class="wing-bottom" d="M50 44 Q32 54 14 52 Q30 46 50 44 Z" fill="#d4d4d4" stroke="#ccc" stroke-width="1"/>
          <!-- Schwanz -->
          <path d="M30 46 Q18 52 10 58 Q20 52 30 50 Z" fill="#e0e0e0" stroke="#ccc" stroke-width="1"/>
          <path d="M30 46 Q16 56 8 65 Q19 56 30 50 Z" fill="#d8d8d8" stroke="#ccc" stroke-width="1"/>
        </svg>
      </div>
    </div>

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
    const name  = sessionStorage.getItem('2fa_name');

    let timerInterval = null;

    if (!email) { window.location.href = '/login.html'; }

    document.getElementById('emailDisplay').textContent = email;

    // Toast: Empfehlung für Gmail- oder iCloud-Nutzer
    function showSocialHint() {
      const domain = email.split('@')[1]?.toLowerCase();
      let icon, title, body;

      if (domain === 'gmail.com' || domain === 'googlemail.com') {
        icon  = '🔵';
        title = 'Tipp: Mit Google anmelden';
        body  = 'Du nutzt Gmail — du kannst dich auch direkt über Google einloggen, ohne Code.';
      } else if (['icloud.com','me.com','mac.com'].includes(domain)) {
        icon  = '🍎';
        title = 'Tipp: Mit Apple anmelden';
        body  = 'Du nutzt iCloud — du kannst dich auch direkt über Apple einloggen, ohne Code.';
      } else {
        return;
      }

      document.getElementById('toastIcon').textContent  = icon;
      document.getElementById('toastTitle').textContent = title;
      document.getElementById('toastBody').textContent  = body;

      setTimeout(() => document.getElementById('toast').classList.add('show'), 800);
      setTimeout(() => closeToast(), 8000);
    }

    function closeToast() {
      document.getElementById('toast').classList.remove('show');
    }

    showSocialHint();
    sendCode();

    document.getElementById('codeInput').addEventListener('input', function () {
      this.value = this.value.replace(/\D/g, '').slice(0, 6);
      if (this.value.length === 6) verifyCode();
    });

    async function sendCode() {
      setMessage('', '');
      setResendDisabled(true);
      try {
        const res  = await fetch(`${SERVICE_URL}/api/send-code`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
          body: JSON.stringify({ email, name }),
        });
        const data = await res.json();
        if (res.status === 429) {
          setMessage(`Bitte warte ${data.retryAfterSeconds || 60} Sekunden.`, 'error');
          startTimer(data.retryAfterSeconds || 60);
          return;
        }
        if (!res.ok) {
          setMessage('Fehler beim Senden. Bitte erneut versuchen.', 'error');
          setResendDisabled(false);
          return;
        }
        startTimer(60);
      } catch (e) {
        setMessage('Verbindung fehlgeschlagen.', 'error');
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
      if (code.length !== 6) { setMessage('Bitte gib den vollständigen 6-stelligen Code ein.', 'error'); return; }
      setVerifyDisabled(true);
      setMessage('', '');
      try {
        const res  = await fetch(`${SERVICE_URL}/api/verify-code`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
          body: JSON.stringify({ email, code }),
        });
        const data = await res.json();
        if (data.valid) {
          sessionStorage.setItem('auth_token', data.token);
          sessionStorage.setItem('auth_email', email);
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
        setMessage(`Falscher Code.${remaining !== '' ? ` Noch ${remaining} Versuch${remaining === 1 ? '' : 'e'}.` : ''}`, 'error');
        document.getElementById('codeInput').classList.add('error');
        document.getElementById('codeInput').value = '';
      } catch (e) {
        setMessage('Verbindung fehlgeschlagen.', 'error');
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

    function updateTimerDisplay(s) {
      document.getElementById('timer').textContent = `Neuen Code in ${s}s anfordern`;
    }
    function setMessage(text, type) {
      const el = document.getElementById('message');
      el.textContent = text;
      el.className = `message ${type}`;
    }
    function setVerifyDisabled(d)  { document.getElementById('verifyBtn').disabled  = d; }
    function setResendDisabled(d)  { document.getElementById('resendBtn').disabled  = d; }
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
Antwort bei Erfolg: `{ "valid": true, "token": "eyJ..." }` ← JWT Token  
Antwort bei Fehler: `{ "valid": false, "attemptsRemaining": 4 }`

---

## Sicherheitshinweise

- Der **API Key** ist im Frontend-JS sichtbar. Das ist durch CORS (nur `https://pluspunkt.online` erlaubt) und Rate-Limiting abgesichert.
- Codes sind **einmalig verwendbar** und werden nach Eingabe sofort gelöscht.
- Nach **5 Fehlversuchen** wird der Code gesperrt — der User muss einen neuen anfordern.
- Codes laufen nach **10 Minuten** automatisch ab und werden aus dem Speicher gelöscht.
