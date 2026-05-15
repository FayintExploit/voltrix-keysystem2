// api/generate.js
import crypto from 'crypto';

export const config = { api: { bodyParser: true } };

const SECRET  = process.env.VOLTRIX_SECRET || 'fayintz-voltrix-k9x2mz84';
const KEY_TTL = 24 * 60 * 60 * 1000;
const SESSION_MAX = 15 * 60 * 1000; // session valid max 15 menit

if (!global.keyStore)   global.keyStore   = {};
if (!global.usedTokens) global.usedTokens = {};

function cleanUp() {
  const now = Date.now();
  for (const k in global.keyStore)   { if (global.keyStore[k].expire < now) delete global.keyStore[k]; }
  for (const k in global.usedTokens) { if (global.usedTokens[k] < now)      delete global.usedTokens[k]; }
}

function verifySessionToken(sessionToken) {
  try {
    const dotIdx = sessionToken.lastIndexOf('.');
    if (dotIdx === -1) return null;
    const b64    = sessionToken.substring(0, dotIdx);
    const sig    = sessionToken.substring(dotIdx + 1);
    const payload = Buffer.from(b64, 'base64').toString('utf8');
    const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    if (sig !== expectedSig) return null;
    const parts     = payload.split('|');
    const createdAt = parseInt(parts[1]);
    if (isNaN(createdAt)) return null;
    if (Date.now() - createdAt > SESSION_MAX) return { valid:false, expired:true };
    return { valid:true, createdAt };
  } catch(e) { return null; }
}

function genKey() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const s = () => Array.from({length:4}, () => c[Math.floor(Math.random()*c.length)]).join('');
  return `VOLTRIX-${s()}-${s()}`;
}

function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || 'unknown';
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  cleanUp();

  const ip = getIP(req);
  const { sessionToken } = req.body || {};

  if (!sessionToken) return res.status(403).json({ success:false, message:'No session token.' });

  const result = verifySessionToken(sessionToken);
  if (!result)         return res.status(403).json({ success:false, message:'Invalid session. Complete all checkpoints first.' });
  if (result.expired)  return res.status(403).json({ success:false, message:'Session expired. Please restart.' });
  if (!result.valid)   return res.status(403).json({ success:false, message:'Invalid session.' });

  // Cek token sudah dipakai (one-time use)
  if (global.usedTokens[sessionToken]) {
    // Return key yang sudah ada kalau masih aktif
    const existing = Object.values(global.keyStore).find(v => v.ip === ip && v.expire > Date.now());
    if (existing) return res.status(200).json({ success:true, key:existing.key, expire:existing.expire, cached:true });
  }

  // Mark token sebagai used
  global.usedTokens[sessionToken] = Date.now() + SESSION_MAX;

  // Cek IP sudah punya key aktif
  const existingKey = Object.values(global.keyStore).find(v => v.ip === ip && v.expire > Date.now());
  if (existingKey) return res.status(200).json({ success:true, key:existingKey.key, expire:existingKey.expire, cached:true });

  // Generate key baru
  const key    = genKey();
  const expire = Date.now() + KEY_TTL;
  global.keyStore[key] = { key, ip, expire };

  return res.status(200).json({ success:true, key, expire, cached:false });
}
