import './instrument.js';
import express from 'express';
import * as Sentry from '@sentry/node';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import pinoHttp from 'pino-http';
import { logger } from './logger.js';
import { requireAuth } from './auth.js';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
app.use(helmet());
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use(rateLimit({ windowMs: 60_000, limit: 100 }));
app.use(express.json());
app.use(pinoHttp({ logger }));

const Query = z.object({ name: z.string().max(64) });

app.get('/users', async (req, res) => {
  const { name } = Query.parse(req.query);
  const { rows } = await pool.query('SELECT id, name FROM users WHERE name = $1', [name]);
  res.json(rows);
});

app.post('/login', async (req, res) => {
  const ok = await argon2.verify(req.user.hash, req.body.password);
  const token = jwt.sign({ sub: req.user.id }, process.env.JWT_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '15m' });
  res.json({ ok, token });
});

app.post('/orders', requireAuth, async (req, res) => {
  const Order = z.object({ sku: z.string(), qty: z.number().int().positive() }).strict();
  const input = Order.parse(req.body);
  try {
    const { rows } = await pool.query('INSERT INTO orders (sku, qty, user_id) VALUES ($1, $2, $3) RETURNING id', [input.sku, input.qty, req.user.id]);
    res.status(201).json(rows[0]);
  } catch (err) {
    req.log.error({ err }, 'order insert failed');
    res.status(500).json({ message: 'Internal error', requestId: req.id });
  }
});

app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

app.get('/readyz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ready' });
  } catch (err) {
    req.log.warn({ err }, 'readiness failed');
    res.status(503).json({ status: 'unavailable' });
  }
});

Sentry.setupExpressErrorHandler(app);

app.use((err, req, res, next) => {
  req.log?.error(err);
  res.status(500).json({ message: 'Internal error', requestId: req.id });
});

app.listen(3000);
