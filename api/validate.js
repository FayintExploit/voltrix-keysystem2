// api/validate.js
// GET /api/validate?key=VOLTRIX-XXXXXXXX-XXXXXXXX-XXXXXXXX
// Stateless — verifikasi HMAC dari key itu sendiri

import crypto from 'crypto';

const SECRET = process.env.VOLTRIX_SECRET || 'fayintz-voltrix-k9x2mz84';

function verifyKey(key) {
  try {
    // Format: VOLTRIX-{p1p2}-{p3p4}-{expB64}
    const parts = key.split('-');
    if (parts.length !== 4 || parts[0] !== 'VOLTRIX') return null;

    const sig8  = (parts[1] + parts[2]).toUpperCase(); // 8 char sig
    const expB64 = parts[3];

    // Decode expire
    // Pad base64
    const padded  = expB64 + '=='.substring(0, (4 - expB64.length % 4) % 4);
    const payload = Buffer.from(padded, 'base64').toString('utf8');
    const expire  = parseInt(payload);
    if (isNaN(expire)) return null;

    // Verifikasi HMAC
    const expectedSig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex').substring(0, 16).toUpperCase();
    const expectedP1P2 = expectedSig.substring(0, 8);
    const expectedP3P4 = expectedSig.substring(8, 16);
    const expectedFull = expectedP1P2 + expectedP3P4;

    if (sig8 !== expectedFull) return null;

    // Cek expire
    if (Date.now() > expire) return { valid:false, expired:true };

    return {
      valid:    true,
      expire,
      timeLeft: Math.floor((expire - Date.now()) / 1000),
    };
  } catch(e) { return null; }
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { key } = req.query;
  if (!key) return res.status(400).json({ valid:false, message:'No key provided.' });

  const result = verifyKey(key);

  if (!result)          return res.status(200).json({ valid:false, message:'Key not found or invalid.' });
  if (result.expired)   return res.status(200).json({ valid:false, message:'Key expired.' });

  return res.status(200).json({
    valid:    true,
    key,
    expire:   result.expire,
    timeLeft: result.timeLeft,
    message:  'Key valid.',
  });
}
