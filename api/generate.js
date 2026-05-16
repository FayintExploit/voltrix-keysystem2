// api/generate.js
// Key format: VOLTRIX-{base64(ip|expire)}.{hmac}
// Stateless — gak butuh database atau memory

import crypto from 'crypto';

export const config = { api: { bodyParser: true } };

const SECRET  = process.env.VOLTRIX_SECRET || 'fayintz-voltrix-k9x2mz84';
const KEY_TTL = 24 * 60 * 60 * 1000; // 24 jam
const SESSION_MAX = 15 * 60 * 1000;  // session valid 15 menit

function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || 'unknown';
}

function verifySessionToken(sessionToken) {
  try {
    const dotIdx  = sessionToken.lastIndexOf('.');
    if (dotIdx === -1) return false;
    const b64     = sessionToken.substring(0, dotIdx);
    const sig     = sessionToken.substring(dotIdx + 1);
    const payload = Buffer.from(b64, 'base64').toString('utf8');
    const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    if (sig !== expected) return false;
    const createdAt = parseInt(payload.split('|')[1]);
    if (isNaN(createdAt)) return false;
    if (Date.now() - createdAt > SESSION_MAX) return false;
    return true;
  } catch(e) { return false; }
}

function buildKey(expire) {
  // Payload: expire timestamp
  const payload = `${expire}`;
  const sig     = crypto.createHmac('sha256', SECRET).update(payload).digest('hex').substring(0, 16).toUpperCase();
  // Format: VOLTRIX-XXXX-XXXX-{sig bagian 1}-{sig bagian 2}
  const p1 = sig.substring(0, 4);
  const p2 = sig.substring(4, 8);
  const p3 = sig.substring(8, 12);
  const p4 = sig.substring(12, 16);
  // Encode expire ke dalam key
  const expB64 = Buffer.from(payload).toString('base64').replace(/=/g,'').substring(0,8).toUpperCase();
  return `VOLTRIX-${p1}${p2}-${p3}${p4}-${expB64}`;
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  const { sessionToken } = req.body || {};

  if (!sessionToken) {
    return res.status(403).json({ success:false, message:'No session token. Complete all checkpoints first.' });
  }

  if (!verifySessionToken(sessionToken)) {
    return res.status(403).json({ success:false, message:'Invalid or expired session. Please restart.' });
  }

  const expire = Date.now() + KEY_TTL;
  const key    = buildKey(expire);

  return res.status(200).json({ success:true, key, expire });
}
