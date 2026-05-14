// api/validate.js
// GET /api/validate?key=VOLTRIX-XXXX-XXXX → validasi key dari Lua

if (!global.keyStore) global.keyStore = {};

export default function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { key } = req.query;

  if (!key) {
    return res.status(400).json({ valid: false, message: 'No key provided' });
  }

  const data = global.keyStore[key];

  if (!data) {
    return res.status(200).json({ valid: false, message: 'Key tidak ditemukan' });
  }

  if (data.expire < Date.now()) {
    delete global.keyStore[key];
    return res.status(200).json({ valid: false, message: 'Key sudah expired' });
  }

  const timeLeft = Math.floor((data.expire - Date.now()) / 1000); // detik

  return res.status(200).json({
    valid: true,
    key,
    expire: data.expire,
    timeLeft, // detik
    message: 'Key valid',
  });
}
