// api/start.js
// POST /api/start → kasih signed timerToken ke client
// Token berisi timestamp start + IP, di-sign pakai HMAC SHA256
// Gak butuh in-memory storage → aman dari cold start

import crypto from 'crypto';

export const config = { api: { bodyParser: true } };

const SECRET = process.env.VOLTRIX_SECRET || 'fayintz-voltrix-k9x2mz84';

function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  const ip        = getIP(req);
  const startedAt = Date.now();

  // Buat payload: ip|startedAt
  const payload = `${ip}|${startedAt}`;

  // Sign pakai HMAC
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');

  // Token = base64(payload) + '.' + sig
  const timerToken = Buffer.from(payload).toString('base64') + '.' + sig;

  return res.status(200).json({ success:true, timerToken });
}
