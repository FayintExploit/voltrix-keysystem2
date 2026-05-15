// api/generate.js
export const config = { api: { bodyParser: true } };

if (!global.sessionStore) global.sessionStore = {};
if (!global.keyStore)     global.keyStore     = {};
if (!global.ipCooldown)   global.ipCooldown   = {};

const KEY_TTL = 24 * 60 * 60 * 1000;

function cleanUp() {
  const now = Date.now();
  for (const k in global.sessionStore) { if (global.sessionStore[k].expire < now) delete global.sessionStore[k]; }
  for (const k in global.keyStore)     { if (global.keyStore[k].expire     < now) delete global.keyStore[k]; }
  for (const k in global.ipCooldown)   { if (global.ipCooldown[k]          < now) delete global.ipCooldown[k]; }
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
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  cleanUp();

  const ip = getIP(req);
  const { sessionToken } = req.body || {};

  // Cek session token
  if (!sessionToken || !global.sessionStore[sessionToken]) {
    return res.status(403).json({ success:false, message:'Invalid session. Complete all checkpoints first.' });
  }

  const sess = global.sessionStore[sessionToken];

  if (sess.expire < Date.now()) {
    delete global.sessionStore[sessionToken];
    return res.status(403).json({ success:false, message:'Session expired. Please restart.' });
  }

  if (sess.ip !== ip) {
    return res.status(403).json({ success:false, message:'Session mismatch detected.' });
  }

  // Cek IP cooldown — return key lama kalau masih aktif
  if (global.ipCooldown[ip] && global.ipCooldown[ip] > Date.now()) {
    const existing = Object.values(global.keyStore).find(v => v.ip === ip && v.expire > Date.now());
    if (existing) {
      delete global.sessionStore[sessionToken];
      return res.status(200).json({ success:true, key:existing.key, expire:existing.expire, cached:true });
    }
  }

  // Generate key baru
  const key    = genKey();
  const expire = Date.now() + KEY_TTL;

  global.keyStore[key]  = { key, ip, expire };
  global.ipCooldown[ip] = expire;
  delete global.sessionStore[sessionToken];

  return res.status(200).json({ success:true, key, expire, cached:false });
}
