const express = require('express');
const crypto = require('crypto');

const app = express();

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Signature');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Wir brauchen den RAW body für HMAC -> express.raw
app.use('/mc-pay', express.raw({ type: 'application/json' }));

const SECRET = process.env.MC_WEBHOOK_SECRET || 'dev-secret-change-me';

// In-Memory Speicherung (zum Testen). Bei Neustart weg.
const payments = [];

// Healthcheck
app.get('/', (req, res) => res.json({ ok: true }));

// Webhook: POST /mc-pay
app.post('/mc-pay', (req, res) => {
  try {
    const sig = (req.header('X-Signature') || '').trim();
    const rawBody = req.body; // Buffer

    if (!sig) return res.status(401).json({ ok: false, error: 'Missing X-Signature' });

    const expected = crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');

    // timing safe compare
    if (sig.length !== expected.length) {
      return res.status(401).json({ ok: false, error: 'Bad signature' });
    }
    const equal = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    if (!equal) return res.status(401).json({ ok: false, error: 'Bad signature' });

    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return res.status(400).json({ ok: false, error: 'Invalid JSON' });
    }

    // Validation
    if (payload?.type !== 'pay_received') return res.status(400).json({ ok: false, error: 'type must be pay_received' });
    if (typeof payload.payer !== 'string' || !payload.payer) return res.status(400).json({ ok: false, error: 'payer must be string' });
    if (typeof payload.amount !== 'number' || Number.isNaN(payload.amount)) return res.status(400).json({ ok: false, error: 'amount must be number' });
    if (typeof payload.ts !== 'string' || !payload.ts) return res.status(400).json({ ok: false, error: 'ts must be string' });

    const entry = {
      id: crypto.randomUUID(),
      payer: payload.payer,
      amount: payload.amount,
      raw: payload.raw || '',
      ts: payload.ts,
      receivedAt: new Date().toISOString(),
    };

    payments.unshift(entry);           // newest first
    payments.splice(200);              // cap size

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// GET /balance?user=Steve
app.get('/balance', (req, res) => {
  const user = String(req.query.user || '').trim();
  if (!user) return res.status(400).json({ ok: false, error: 'Missing user' });

  const balance = payments
    .filter(p => (p.payer || '').toLowerCase() === user.toLowerCase())
    .reduce((sum, p) => sum + Number(p.amount || 0), 0);

  res.json({ ok: true, user, balance });
});



const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Listening on', port));
