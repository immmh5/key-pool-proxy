'use strict';
/**
 * Optional at-rest encryption for stored API keys.
 *
 * If KEY_ENC_SECRET is set, keys are encrypted with AES-256-GCM before
 * hitting SQLite. If it is NOT set, keys are stored in plain text (still
 * safer than committing them to source control — the DB file lives on a
 * private disk / local file).
 *
 * Format of an encrypted value:  "enc:v1:<ivB64>:<authTagB64>:<cipherB64>"
 */
const crypto = require('crypto');

const SECRET = process.env.KEY_ENC_SECRET || '';
const ENABLED = SECRET.length >= 16; // need at least a 128-bit secret to bother

function deriveKey() {
  // A fixed salt is fine here: the secret itself is the secret.
  return crypto.pbkdf2Sync(SECRET, 'key-pool-proxy-v1', 100_000, 32, 'sha256');
}

function encrypt(plain) {
  if (!ENABLED) return plain;
  if (!plain) return plain;
  const key = deriveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'enc:v1:' + iv.toString('base64') + ':' + tag.toString('base64') + ':' + enc.toString('base64');
}

function decrypt(stored) {
  if (!ENABLED) return stored;
  if (!stored) return stored;
  if (typeof stored !== 'string' || !stored.startsWith('enc:v1:')) return stored; // legacy plaintext
  const parts = stored.split(':');
  if (parts.length < 5) return stored;
  const ivB64 = parts[2];
  const tagB64 = parts[3];
  const dataB64 = parts.slice(4).join(':'); // base64 may itself contain nothing but safe chars; join to be safe
  if (!ivB64 || !tagB64 || !dataB64) return stored;
  const key = deriveKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const dec = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]);
  return dec.toString('utf8');
}

function enabled() {
  return ENABLED;
}

module.exports = { encrypt, decrypt, enabled };
