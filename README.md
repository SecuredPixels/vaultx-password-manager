# 🔐 VaultX — Password Manager

A beginner cybersecurity project: a fully client-side, encrypted password manager built with vanilla HTML, CSS, and JavaScript.

## Features

- **AES-256-GCM encryption** via the browser's native Web Crypto API
- **PBKDF2 key derivation** with 310,000 iterations (OWASP 2023 standard)
- **Zero-knowledge design** — passwords never leave your device
- **Master password hashing** — the raw password is never stored
- **Auto-lock** after 15 minutes of inactivity
- **Password strength meter** on all password fields
- **Random password generator** (configurable length, character sets)
- **Category filtering** and search
- **Copy to clipboard** with one click
- **Weak & reused password detection**

## Project Structure

```
password-manager/
├── index.html   — App shell, all screens and modals
├── style.css    — Dark terminal aesthetic, responsive layout
├── crypto.js    — Encryption engine (Web Crypto API)
├── app.js       — Application state, UI logic, storage
└── README.md    — This file
```

## How It Works

### Encryption Flow

```
Master Password
      │
      ▼
  PBKDF2 (SHA-256, 310,000 iterations, random 16-byte salt)
      │
      ▼
  AES-256-GCM key
      │
      ▼
  Encrypt(JSON entries, random 12-byte IV)
      │
      ▼
  localStorage ← { salt, iv, ciphertext } (Base64 JSON)
```

### Master Password Verification

The master password is **never stored**. Instead:
1. A random salt is generated at setup
2. A PBKDF2 hash of the password + salt is stored in `localStorage`
3. On unlock, the entered password is re-hashed and compared

### Key Derivation

```javascript
PBKDF2(password, salt, iterations=310_000, hash='SHA-256') → AES-256-GCM key
```

## Security Concepts Learned

| Concept | Implementation |
|---|---|
| Symmetric encryption | AES-256-GCM |
| Authenticated encryption | GCM tag prevents tampering |
| Key derivation | PBKDF2 slows brute force |
| Salt | Prevents rainbow table attacks |
| IV / Nonce | Unique per encryption, prevents ciphertext reuse |
| Zero-knowledge | No server, no transmission |

## How to Run

1. Clone the repository
2. Open `index.html` in any modern browser
3. Set a master password to create your vault

> **No build step, no dependencies, no server required.**

## Browser Compatibility

Works in any browser that supports the **Web Crypto API** (all modern browsers):
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 12+

## ⚠️ Educational Disclaimer

This project is for **learning cybersecurity concepts**. For production use, consider:
- Server-side encrypted backups
- Secure memory wiping
- A dedicated security audit

---

Built as part of a cybersecurity learning curriculum. Demonstrates real-world cryptography without external libraries.
