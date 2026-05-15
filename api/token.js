// api/token.js
import crypto from 'crypto';

export const config = { api: { bodyParser: true } };

const SECRET    = process.env.VOLTRIX_SECRET || 'fayintz-voltrix-k9x2mz84';
const TIMER_MIN = 14000; // 14 detik minimum

function verifyTimerToken(timerToken) {
  try {
    const dotIdx = timerToken.lastIndexOf('.');
    if (dotIdx === -1) return null;
    const b64 = timerToken.substring(0, dotIdx);
    const sig  = timerToken.substring(dotIdx + 1);
    const payload   = Buffer.from(b64, 'base64').toString('utf8');
    const parts     = payload.split('|');
    const startedAt = parseInt(parts[1]);
    if (isNaN(startedAt)) return null;
    const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    if (sig !== expectedSig) return null;
    const elapsed = Date.now() - startedAt;
    if (elapsed < TIMER_MIN) return { valid:false, wait: Math.ceil((TIMER_MIN - elapsed) / 1000) };
    if (elapsed > 10 * 60 * 1000) return { valid:false, expired:true };
    return { valid:true };
  } catch(e) { return null; }
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ success:false });

  const { timerToken } = req.body || {};
  if (!timerToken) return res.status(400).json({ success:false, message:'No timer token.' });

  const result = verifyTimerToken(timerToken);
  if (!result)          return res.status(403).json({ success:false, message:'Invalid token.' });
  if (result.expired)   return res.status(403).json({ success:false, message:'Session expired. Please restart.' });
  if (!result.valid)    return res.status(403).json({ success:false, message:`Wait ${result.wait}s more.` });

  // Buat sessionToken HMAC signed — stateless, gak butuh memory
  const sessionPayload = `session|${Date.now()}`;
  const sessionSig     = crypto.createHmac('sha256', SECRET).update(sessionPayload).digest('hex');
  const sessionToken   = Buffer.from(sessionPayload).toString('base64') + '.' + sessionSig;

  return res.status(200).json({ success:true, sessionToken });
}
