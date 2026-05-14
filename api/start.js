// api/start.js
// POST /api/start — dipanggil saat user klik "Start Verification"
// Returns timerKey yang akan dipakai untuk claim session token

if (!global.timerStore) global.timerStore = {};

function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

function randStr(n) {
  const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({length:n}, () => c[Math.floor(Math.random()*c.length)]).join('');
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  const ip       = getIP(req);
  const timerKey = randStr(40);

  // Simpan waktu mulai + IP
  global.timerStore[timerKey] = {
    ip,
    startedAt: Date.now(),
    expire:    Date.now() + 10 * 60 * 1000, // 10 menit max
  };

  // Cleanup expired
  const now = Date.now();
  for (const k in global.timerStore) {
    if (global.timerStore[k].expire < now) delete global.timerStore[k];
  }

  return res.status(200).json({ success:true, timerKey });
}
