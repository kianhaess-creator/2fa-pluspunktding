# Frontend Integration Prompt für Claude

Bitte integriere ein vollständiges Authentifizierungssystem in meine bestehende HTML/CSS/JS Website.
Der Backend-Server läuft bereits unter `https://twofa-pluspunktding.onrender.com`.

---

## Konstanten (überall gleich verwenden)

```javascript
const SERVICE_URL = 'https://twofa-pluspunktding.onrender.com';
const API_KEY     = 'c12f48f7b74becf2bac9ee8b62a7bc131b295fb0f06490f052a61678c969015e';
```

---

## Ablauf (genau so umsetzen)

```
REGISTRIERUNG:
Formular (E-Mail, Passwort, Name, PLZ, Stadt, Geburtsdatum)
→ POST /api/auth/register
→ POST /api/send-code  (2FA Code senden)
→ verify.html          (Code eingeben)
→ verify-code gibt { valid: true, token: "JWT..." } zurück
→ token in sessionStorage speichern
→ Weiterleitung zur Website

LOGIN:
Formular (E-Mail, Passwort)
→ POST /api/auth/login
→ bei { success: true }: POST /api/send-code (2FA Code senden)
→ verify.html (Code eingeben)
→ verify-code gibt { valid: true, token: "JWT..." } zurück
→ token in sessionStorage speichern
→ Weiterleitung zur Website

GOOGLE / APPLE LOGIN:
→ Kein 2FA, kein Token vom Server nötig
→ Supabase gibt eigenen Token → direkt zur Website

AUSLOGGEN:
→ sessionStorage.removeItem('auth_token')
→ sessionStorage.removeItem('auth_email')
→ Weiterleitung zu login.html

SEITEN SCHÜTZEN (auf jeder geschützten Seite am Anfang prüfen):
→ token = sessionStorage.getItem('auth_token')
→ Falls kein token → window.location.href = '/login.html'
```

---

## API Endpunkte

Alle Endpunkte außer Profil brauchen den Header: `x-api-key: <API_KEY>`
Profil-Endpunkte brauchen stattdessen: `Authorization: Bearer <token>`

### POST /api/auth/register
```json
Body:    { "email", "password", "name"?, "postalCode"?, "city"?, "birthDate"? }
Erfolg:  { "success": true }
Fehler:  { "error": "email_taken" }  → E-Mail bereits registriert
Fehler:  { "error": "invalid_data" } → Pflichtfelder fehlen oder Passwort < 6 Zeichen
```

### POST /api/auth/login
```json
Body:    { "email", "password" }
Erfolg:  { "success": true }
Fehler:  { "success": false } → falsches Passwort oder E-Mail nicht gefunden
```

### POST /api/send-code
```json
Body:    { "email", "name"? }
Erfolg:  { "success": true, "message": "Verification code sent." }
```

### POST /api/verify-code
```json
Body:    { "email", "code" }
Erfolg:  { "valid": true, "token": "eyJ..." }   ← JWT Token!
Fehler:  { "valid": false, "attemptsRemaining": 4 }
```

### POST /api/auth/profile  (Authorization: Bearer <token>)
```json
Body:    { "name"?, "postalCode"?, "city"?, "birthDate"?, "loginCount"?, "lastLoginAt"?, "loginMethod"? }
Erfolg:  { "success": true }
```

### GET /api/auth/profile  (Authorization: Bearer <token>)
```json
Erfolg:  { "name", "postalCode", "city", "birthDate", "loginCount", "lastLoginAt", "loginMethod" }
Fehler:  { "error": "not_found" }
```

### POST /api/auth/reset-password
```json
Body:    { "email", "newPassword" }
Erfolg:  { "success": true }
Fehler:  { "error": "not_found" }
```

---

## Token speichern & verwenden

```javascript
// Nach verify-code:
sessionStorage.setItem('auth_token', data.token);
sessionStorage.setItem('auth_email', email);

// Für Profil-Anfragen:
const token = sessionStorage.getItem('auth_token');
fetch(`${SERVICE_URL}/api/auth/profile`, {
  headers: {
    'x-api-key': API_KEY,
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  }
});

// Seite schützen:
if (!sessionStorage.getItem('auth_token')) {
  window.location.href = '/login.html';
}
```

---

## verify.html (fertig — nicht neu erstellen, nur REDIRECT_URL anpassen)

Die `verify.html` existiert bereits. Sie muss nach erfolgreichem Code:
1. `data.token` in `sessionStorage.setItem('auth_token', data.token)` speichern
2. `sessionStorage.removeItem('2fa_email')` und `sessionStorage.removeItem('2fa_name')` löschen
3. Zur Zielseite weiterleiten

Passe in `verify.html` die `verifyCode()` Funktion so an:

```javascript
if (data.valid) {
  sessionStorage.setItem('auth_token', data.token);   // ← NEU
  sessionStorage.removeItem('2fa_email');
  sessionStorage.removeItem('2fa_name');
  window.location.href = REDIRECT_URL;
  return;
}
```

---

## Wichtige Hinweise

- **Google/Apple Login** → kein `auth_token` vom Server setzen — Supabase handhabt die Session selbst
- **Passwort-Reset-Flow**: erst 2FA abschließen, dann `/api/auth/reset-password` aufrufen
- **Token läuft nach 24h ab** → beim nächsten Login wird ein neuer ausgestellt
- Token enthält die E-Mail des Users (kann mit `JSON.parse(atob(token.split('.')[1])).email` gelesen werden)
