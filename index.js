// index.js
require('dotenv').config(); // en Railway no hace falta .env; local sí

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();

// ---- Config básica ----
app.use(express.json({ limit: '256kb' }));
app.use(helmet());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// CORS: permite origen desde ENV; por defecto permite todo (útil para pruebas)
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*';
app.use(
  cors({
    origin: ALLOW_ORIGIN === '*' ? true : ALLOW_ORIGIN.split(',').map(s => s.trim()),
    credentials: false,
  })
);

// ---- Postgres ----
if (!process.env.DATABASE_URL) {
  console.error('❌ Falta DATABASE_URL en variables de entorno');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.PGSSL_DISABLE === '1'
      ? false
      : { rejectUnauthorized: false }, // Railway suele requerir SSL
});

// ---- Auth por API Token (Bearer) ----
const API_TOKEN = process.env.API_TOKEN; // PON ESTO EN RAILWAY
if (!API_TOKEN) {
  console.warn('⚠️ No hay API_TOKEN definido. Las peticiones protegidas fallarán con 401.');
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!API_TOKEN || token !== API_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// (Opcional) Lista blanca de IPs para /ingest (separadas por coma en ALLOW_IPS)
function ipAllowed(req) {
  const list = (process.env.ALLOW_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (list.length === 0) return true; // sin restricción
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  return list.includes(ip);
}

// ---- Rutas ----

// Healthcheck sencillo (sin auth)
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'db_unreachable' });
  }
});

// Página raíz (sin auth)
app.get('/', (req, res) => {
  res.send('API de seguridad Roblox corriendo 🚀');
});

// Ingesta (con auth + opcional IP allowlist)
app.post('/ingest', auth, async (req, res) => {
  if (!ipAllowed(req)) return res.status(403).json({ error: 'forbidden_ip' });

  const { userId, username, displayName, message } = req.body || {};
  if (!userId || !username || !message) {
    return res.status(400).json({ error: 'missing fields', required: ['userId', 'username', 'message'] });
  }

  try {
    await pool.query('BEGIN');

    await pool.query(
      `INSERT INTO users (id, username, display_name)
       VALUES ($1, $2, $3)
       ON CONFLICT (id)
       DO UPDATE SET username = EXCLUDED.username, display_name = EXCLUDED.display_name`,
      [userId, username, displayName || null]
    );

    await pool.query(
      `INSERT INTO messages (user_id, message, ts)
       VALUES ($1, $2, NOW())`,
      [userId, message]
    );

    await pool.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await pool.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// 404
app.use((req, res) => res.status(404).json({ error: 'not_found' }));

// ---- Arranque ----
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`✅ Servidor corriendo en puerto ${port}`);
});
