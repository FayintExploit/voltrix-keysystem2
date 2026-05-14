// api/token.js
// POST /api/token — issued setelah timer selesai di frontend
// Body: { timerKey: string } — timerKey adalah challenge key yang di-generate saat CP1

if (!global.tokenStore)   global.tokenStore   = {};
if (!global.timerStore)   global.timerStore   = {};

const TOKEN_TTL = 5 * 60 * 1000;  // token valid 5 menit
const TIMER_MIN = 14 * 1000;      // minimum timer harus 14 detik (toleransi 1 detik)

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

  const ip = getIP(req);
  const { timerKey } = req.body || {};

  if (!timerKey || !global.timerStore[timerKey]) {
    return res.status(403).json({ success:false, message:'Invalid timer key.' });
  }

  const timerData = global.timerStore[timerKey];

  // Pastikan IP sama
  if (timerData.ip !== ip) {
    return res.status(403).json({ success:false, message:'IP mismatch.' });
  }

  // Pastikan sudah cukup waktu berlalu (anti skip)
  const elapsed = Date.now() - timerData.startedAt;
  if (elapsed < TIMER_MIN) {
    return res.status(403).json({ success:false, message:`Timer not complete. Wait ${Math.ceil((TIMER_MIN - elapsed)/1000)}s more.` });
  }

  // Hapus timerKey (one-time)
  delete global.timerStore[timerKey];

  // Buat session token
  const sessionToken = randStr(32);
  global.tokenStore[sessionToken] = { ip, expire: Date.now() + TOKEN_TTL };

  return res.status(200).json({ success:true, sessionToken });
}
