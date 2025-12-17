import express from 'express';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { randomUUID } from 'crypto';
import { createClient } from 'redis';
import cors from 'cors';

dotenv.config({ path: path.resolve(process.cwd(), '.env.local') });

// Access token disponível em process.env.MP_ACCESS_TOKEN
const allowedOrigin = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// sessão de tokens temporários para o front-end (esconde a MP_SERVER_KEY)
// Use Redis quando REDIS_URL estiver definido; caso contrário, fallback para memória.
let redisClient = null;
const useRedis = !!process.env.REDIS_URL;
if (useRedis) {
  redisClient = createClient({ url: process.env.REDIS_URL });
  redisClient.on('error', (err) => console.error('Redis error', err));
  // connect async but don't block startup
  redisClient.connect().then(() => console.log('Connected to Redis')).catch((e) => console.error('Redis connect failed', e));
}

// sessionTokens: token -> { email, expiresAt }
const sessionTokens = new Map(); // usado quando não há Redis
const users = new Map(); // email -> { passwordHash }
// limpa tokens expirados a cada minuto (apenas para fallback em memória)
setInterval(() => {
  if (useRedis) return;
  const now = Date.now();
  for (const [t, v] of sessionTokens) {
    if (!v || v.expiresAt < now) sessionTokens.delete(t);
  }
}, 60 * 1000);

const app = express();
app.use(express.json());
app.use(cors({ origin: allowedOrigin }));
app.use(express.static(process.cwd()));

app.get('/config', (req, res) => {
  const cfgPath = path.resolve(process.cwd(), 'public-config.json');
  if (fs.existsSync(cfgPath)) {
    const data = fs.readFileSync(cfgPath, 'utf8');
    return res.type('application/json').send(data);
  }
  return res.status(404).json({ error: 'config not found' });
});

// Gera um token de sessão de curta duração para o front-end (origin deve ser allowedOrigin)
// Session tokens disabled: frontend must send x-api-key (server key) with requests.

// Middleware de autenticação condicional:
// - Requests da origem `allowedOrigin` são permitidas sem chave
// - Outras origens precisam enviar `x-api-key` com MP_SERVER_KEY
function requireAuth(req, res, next) {
  // Permite autenticação via session token Bearer ou via x-api-key (server key)
  const auth = req.get('authorization');
  if (auth && auth.toLowerCase().startsWith('bearer ')) {
    const token = auth.slice(7).trim();
    if (useRedis) {
      // Redis-backed sessions not implemented in this demo path
    } else {
      const rec = sessionTokens.get(token);
      if (rec && rec.expiresAt > Date.now()) {
        req.user = { email: rec.email };
        return next();
      }
    }
  }

  // fallback: accept server key for API clients
  const key = req.get('x-api-key') || req.query.api_key;
  if (key && key === process.env.MP_SERVER_KEY) return next();

  return res.status(401).json({ error: 'Unauthorized: missing or invalid credentials' });
}

app.post('/create-payment', requireAuth, async (req, res) => {
  try {
    let items = [];
    if (Array.isArray(req.body.items) && req.body.items.length > 0) {
      items = req.body.items.map((it) => ({
        title: it.title,
        quantity: Number(it.quantity) || 1,
        currency_id: it.currency_id || 'BRL',
        unit_price: Number(it.unit_price) || Number(it.price) || 0
      }));
    } else if (req.body.title) {
      items = [
        {
          title: req.body.title,
          quantity: Number(req.body.quantity) || 1,
          currency_id: req.body.currency_id || 'BRL',
          unit_price: Number(req.body.unit_price) || Number(req.body.price) || 0
        }
      ];
    } else {
      items = [{ title: 'Livro Digital', quantity: 1, currency_id: 'BRL', unit_price: 5.0 }];
    }

    // Se o front pedir especificamente PIX, criaremos um Payment (PIX) diretamente
    const method = (req.body.method || '').toLowerCase();

    if (method === 'pix') {
      // calcula o valor total
      const total = items.reduce((s, it) => s + (Number(it.unit_price || 0) * Number(it.quantity || 1)), 0);
      const payer = req.body.payer || { email: req.body.email || 'payer@example.com' };

      const paymentBody = {
        transaction_amount: Number(total),
        description: items.map(i => i.title).join(', '),
        payment_method_id: 'pix',
        payer
      };

      const payRes = await fetch('https://api.mercadopago.com/v1/payments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` },
        body: JSON.stringify(paymentBody)
      });

      const payJson = await payRes.json();
      if (!payRes.ok) return res.status(payRes.status).json({ error: payJson });

      // Retorna informações úteis do PIX ao frontend (qr_code, qr_code_base64, transaction_data)
      const poi = payJson.point_of_interaction || {};
      return res.status(200).json({ payment: payJson, pix: poi.transaction_data || poi });
    }

    // Comportamento padrão: criar preferência (Checkout) — permite múltiplos métodos
    const preference = { items, back_urls: { success: 'https://SEU_SITE.vercel.app/sucesso', failure: 'https://SEU_SITE.vercel.app/erro', pending: 'https://SEU_SITE.vercel.app/pendente' }, auto_return: 'approved' };

    const apiRes = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` },
      body: JSON.stringify(preference)
    });

    const json = await apiRes.json();
    if (!apiRes.ok) return res.status(apiRes.status).json({ error: json });
    return res.status(200).json({ init_point: json.init_point });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

  // Registro simples de usuário (demo). Retorna token de sessão.
  app.post('/register', (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const key = email.toLowerCase();
    if (users.has(key)) return res.status(409).json({ error: 'user exists' });
    const hash = require('crypto').createHash('sha256').update(password).digest('hex');
    users.set(key, { passwordHash: hash });
    const token = randomUUID();
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24h
    sessionTokens.set(token, { email: key, expiresAt });
    return res.status(201).json({ token, expiresAt });
  });

  app.post('/login', (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const key = email.toLowerCase();
    const rec = users.get(key);
    if (!rec) return res.status(401).json({ error: 'invalid credentials' });
    const hash = require('crypto').createHash('sha256').update(password).digest('hex');
    if (hash !== rec.passwordHash) return res.status(401).json({ error: 'invalid credentials' });
    const token = randomUUID();
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    sessionTokens.set(token, { email: key, expiresAt });
    return res.json({ token, expiresAt });
  });

  app.get('/me', (req, res) => {
    // retorna informação do usuário autenticado
    const auth = req.get('authorization');
    if (!auth || !auth.toLowerCase().startsWith('bearer ')) return res.status(401).json({ error: 'not authenticated' });
    const token = auth.slice(7).trim();
    const rec = sessionTokens.get(token);
    if (!rec || rec.expiresAt < Date.now()) return res.status(401).json({ error: 'not authenticated' });
    return res.json({ email: rec.email });
  });

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Servidor rodando em http://localhost:${port}`));
