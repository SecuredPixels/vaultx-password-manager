/**
 * crypto.js — VaultX Encryption Engine
 *
 * Uses the browser's native Web Crypto API (SubtleCrypto).
 * Algorithm: AES-256-GCM  (authenticated encryption)
 * Key derivation: PBKDF2 with SHA-256, 310,000 iterations
 *
 * Everything stays in-browser — no passwords ever leave your device.
 */

'use strict';

const Crypto = (() => {

  const PBKDF2_ITERATIONS = 310_000;   // OWASP 2023 recommendation
  const KEY_BITS          = 256;
  const SALT_BYTES        = 16;
  const IV_BYTES          = 12;        // AES-GCM standard nonce size

  // ── Helpers ────────────────────────────────────────────────────────

  /** Convert ArrayBuffer → Base64 string */
  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  /** Convert Base64 string → Uint8Array */
  function b64ToBuf(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }

  /** Encode string → Uint8Array */
  const encode = (str) => new TextEncoder().encode(str);

  /** Decode Uint8Array → string */
  const decode = (buf) => new TextDecoder().decode(buf);

  // ── Key derivation ────────────────────────────────────────────────

  /**
   * Derive an AES-256-GCM key from a master password + salt.
   * @param {string}     password
   * @param {Uint8Array} salt
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(password, salt) {
    const rawKey = await crypto.subtle.importKey(
      'raw',
      encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name:       'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash:       'SHA-256',
      },
      rawKey,
      { name: 'AES-GCM', length: KEY_BITS },
      false,             // not extractable
      ['encrypt', 'decrypt']
    );
  }

  // ── Public API ─────────────────────────────────────────────────────

  /**
   * Encrypt a plaintext string with a master password.
   * Returns a JSON string: { salt, iv, ciphertext } all Base64-encoded.
   *
   * @param {string} plaintext
   * @param {string} password
   * @returns {Promise<string>} encrypted payload (JSON)
   */
  async function encrypt(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv   = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const key  = await deriveKey(password, salt);

    const cipherBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encode(plaintext)
    );

    return JSON.stringify({
      salt:       bufToB64(salt),
      iv:         bufToB64(iv),
      ciphertext: bufToB64(cipherBuf),
    });
  }

  /**
   * Decrypt a payload produced by `encrypt()`.
   * Throws DOMException if password is wrong or data is tampered.
   *
   * @param {string} payload  — the JSON string from `encrypt()`
   * @param {string} password
   * @returns {Promise<string>} plaintext
   */
  async function decrypt(payload, password) {
    const { salt, iv, ciphertext } = JSON.parse(payload);
    const key = await deriveKey(password, b64ToBuf(salt));

    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(iv) },
      key,
      b64ToBuf(ciphertext)
    );

    return decode(plainBuf);
  }

  /**
   * Hash the master password (for vault existence check).
   * We store a salted PBKDF2 hash — never the raw password.
   *
   * @param {string}     password
   * @param {Uint8Array} salt
   * @returns {Promise<string>} Base64 hash
   */
  async function hashPassword(password, salt) {
    const rawKey = await crypto.subtle.importKey(
      'raw', encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      rawKey, KEY_BITS
    );
    return bufToB64(bits);
  }

  /**
   * Generate a random salt.
   * @returns {string} Base64-encoded 16-byte salt
   */
  function generateSalt() {
    return bufToB64(crypto.getRandomValues(new Uint8Array(SALT_BYTES)));
  }

  /**
   * Verify a password against a stored hash + salt.
   * @param {string} password
   * @param {string} storedHash  Base64
   * @param {string} storedSalt  Base64
   * @returns {Promise<boolean>}
   */
  async function verifyPassword(password, storedHash, storedSalt) {
    const salt = b64ToBuf(storedSalt);
    const hash = await hashPassword(password, salt);
    return hash === storedHash;
  }

  return { encrypt, decrypt, hashPassword, verifyPassword, generateSalt, b64ToBuf };
})();
