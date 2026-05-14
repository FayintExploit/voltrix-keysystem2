// api/generate.js
// POST /api/generate
// Body: { sessionToken: string }

if (!global.keyStore)   global.keyStore   = {};
if (!global.tokenStore) global.tokenStore = {};
if (!global.ipCooldown) global.ipCooldown = {};

const KEY_TTL   = 24 * 60 * 60 * 1000; // 24 jam
const TOKEN_TTL =  5 * 60 * 1000;      // token valid 5 menit

function cleanUp() {
  const now = Date.now();
  for (const k in global.keyStore)   { if (global.keyStore[k].expire   < now) delete global.keyStore[k]; }
  for (const k in global.tokenStore) { if (global.tokenStore[k].expire < now) delete global.tokenStore[k]; }
  for (const k in global.ipCooldown) { if (global.ipCooldown[k]        < now) delete global.ipCooldown[k]; }
}

function genKey() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const s = () => Array.from({length:4}, () => c[Math.floor(Math.random()*c.length)]).join('');
  return `VOLTRIX-${s()}-${s()}`;
}

function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false, message:'Method not allowed' });

  cleanUp();

  const ip = getIP(req);
  const { sessionToken } = req.body || {};

  // 1. Cek token ada
  if (!sessionToken || !global.tokenStore[sessionToken]) {
    return res.status(403).json({ success:false, message:'Invalid session token. Complete all checkpoints first.' });
  }

  const tok = global.tokenStore[sessionToken];

  // 2. Token expired?
  if (tok.expire < Date.now()) {
    delete global.tokenStore[sessionToken];
    return res.status(403).json({ success:false, message:'Session expired. Please restart.' });
  }

  // 3. IP harus sama (anti share token)
  if (tok.ip !== ip) {
    return res.status(403).json({ success:false, message:'Session mismatch detected.' });
  }

  // 4. Cek IP cooldown — kalau masih ada key aktif, return key lama
  if (global.ipCooldown[ip] && global.ipCooldown[ip] > Date.now()) {
    const existing = Object.values(global.keyStore).find(v => v.ip === ip && v.expire > Date.now());
    if (existing) {
      delete global.tokenStore[sessionToken];
      return res.status(200).json({ success:true, key:existing.key, expire:existing.expire, cached:true });
    }
  }

  // 5. Generate key baru
  const key    = genKey();
  const expire = Date.now() + KEY_TTL;

  global.keyStore[key]  = { key, ip, expire };
  global.ipCooldown[ip] = expire;

  // Token one-time use — hapus setelah dipakai
  delete global.tokenStore[sessionToken];

  return res.status(200).json({ success:true, key, expire, cached:false });
}
