// api/token.js
// POST /api/token → verifikasi timerToken, kasih sessionToken
// Body: { timerToken: string }

import crypto from 'crypto';

const SECRET    = process.env.VOLTRIX_SECRET || 'fayintz-voltrix-k9x2mz84';
const TIMER_MIN = 14000; // 14 detik minimum
const TOKEN_TTL = 10 * 60 * 1000; // sessionToken valid 10 menit

function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

function verifyTimerToken(timerToken, ip) {
  try {
    const [b64, sig] = timerToken.split('.');
    if (!b64 || !sig) return null;

    const payload    = Buffer.from(b64, 'base64').toString('utf8');
    const [tokenIP, startedAtStr] = payload.split('|');
    const startedAt  = parseInt(startedAtStr);

    // Verifikasi signature
    const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return null;

    // Verifikasi IP
    if (tokenIP !== ip) return null;

    // Verifikasi waktu minimum
    const elapsed = Date.now() - startedAt;
    if (elapsed < TIMER_MIN) return { valid:false, wait: Math.ceil((TIMER_MIN - elapsed) / 1000) };

    // Token expired kalau lebih dari 10 menit
    if (elapsed > 10 * 60 * 1000) return { valid:false, expired:true };

    return { valid:true, startedAt };
  } catch(e) {
    return null;
  }
}

function randStr(n) {
  const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({length:n}, () => c[Math.floor(Math.random()*c.length)]).join('');
}

// Session token store — tetap in-memory tapi cuma 10 menit
if (!global.sessionStore) global.sessionStore = {};

function cleanSessions() {
  const now = Date.now();
  for (const k in global.sessionStore) {
    if (global.sessionStore[k].expire < now) delete global.sessionStore[k];
  }
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  const ip = getIP(req);
  const { timerToken } = req.body || {};

  if (!timerToken) {
    return res.status(400).json({ success:false, message:'No timer token provided.' });
  }

  const result = verifyTimerToken(timerToken, ip);

  if (!result) {
    return res.status(403).json({ success:false, message:'Invalid token. Do not tamper with the request.' });
  }

  if (result.expired) {
    return res.status(403).json({ success:false, message:'Session expired. Please restart.' });
  }

  if (!result.valid) {
    return res.status(403).json({ success:false, message:`Timer not complete. Wait ${result.wait}s more.` });
  }

  cleanSessions();

  // Buat session token (valid 10 menit)
  const sessionToken = randStr(40);
  global.sessionStore[sessionToken] = { ip, expire: Date.now() + TOKEN_TTL };

  return res.status(200).json({ success:true, sessionToken });
}
