import './instrument.js';
import express from 'express';
import 'express-async-errors';
import { initialize as initFlags } from 'unleash-client';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yaml';
import fs from 'node:fs';
import { config } from './config.js';
import * as Sentry from '@sentry/node';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import Redis from 'ioredis';
import compression from 'compression';
import { z, ZodError } from 'zod';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import pinoHttp from 'pino-http';
import { logger } from './logger.js';
import { requireAuth } from './auth.js';
import { recordAudit } from './audit.js';
import { problem } from './problem.js';

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX ?? 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  statement_timeout: 5_000,
  ssl: { rejectUnauthorized: true, ca: process.env.DB_CA_CERT },
});
const redis = new Redis(config.REDIS_URL);
const flags = initFlags({ url: config.UNLEASH_URL, appName: 'secure-api', customHeaders: { Authorization: config.UNLEASH_TOKEN } });
const openapi = YAML.parse(fs.readFileSync(new URL('../openapi.yaml', import.meta.url), 'utf8'));

export const app = express();
app.set('trust proxy', 1);
app.use(compression());
app.use(helmet());
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use(rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false, store: new RedisStore({ sendCommand: (...args) => redis.call(...args) }) }));
app.use(express.json());
app.use(pinoHttp({ logger }));
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapi));

const UsersQuery = z.object({
  name: z.string().max(64),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

app.get('/v1/users', async (req, res) => {
  const { name, limit } = UsersQuery.parse(req.query);
  const cacheKey = `users:${name}:${limit}`;
  const cached = await redis.get(cacheKey);
  if (cached) return res.json(JSON.parse(cached));
  const { rows } = await pool.query('SELECT id, name FROM users WHERE name = $1 ORDER BY id LIMIT $2', [name, limit]);
  await redis.set(cacheKey, JSON.stringify({ data: rows }), 'EX', 60);
  res.json({ data: rows });
});

app.post('/v1/login', async (req, res) => {
  const ok = await argon2.verify(req.user.hash, req.body.password);
  await recordAudit(pool, req, { action: ok ? 'auth.login.success' : 'auth.login.failure', targetType: 'user', targetId: req.user.id });
  if (!ok) return problem(res, 401, 'Invalid credentials');
  const token = jwt.sign({ sub: req.user.id }, process.env.JWT_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '15m' });
  res.json({ token });
});

app.post('/v1/orders', requireAuth, async (req, res) => {
  if (!flags.isEnabled('orders-enabled')) return problem(res, 503, 'Ordering temporarily disabled', { retryAfter: 60 });
  const key = req.get('Idempotency-Key');
  if (!key) return problem(res, 400, 'Idempotency-Key header required');
  const previous = await redis.get(`idem:${req.user.id}:${key}`);
  if (previous) return res.status(201).json(JSON.parse(previous));
  const Order = z.object({ sku: z.string(), qty: z.number().int().positive() }).strict();
  const input = Order.parse(req.body);
  try {
    const { rows } = await pool.query('INSERT INTO orders (sku, qty, user_id, created_by) VALUES ($1, $2, $3, $3) RETURNING id', [input.sku, input.qty, req.user.id]);
    await recordAudit(pool, req, { action: 'order.create', targetType: 'order', targetId: rows[0].id });
    await redis.set(`idem:${req.user.id}:${key}`, JSON.stringify(rows[0]), 'EX', 86_400);
    res.status(201).json(rows[0]);
  } catch (err) {
    req.log.error({ err }, 'order insert failed');
    problem(res, 500, 'Internal error', { requestId: req.id });
  }
});

app.get('/healthz', (req, res) => res.json({ status: 'ok' }));

app.get('/readyz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ready' });
  } catch (err) {
    req.log.warn({ err }, 'readiness failed');
    problem(res, 503, 'Not ready');
  }
});

Sentry.setupExpressErrorHandler(app);

app.use((err, req, res, next) => {
  // Invalid input is the client's mistake: 400 with the issues, not a 500.
  if (err instanceof ZodError) return problem(res, 400, 'Invalid request', { issues: err.issues });
  req.log?.error(err);
  problem(res, 500, 'Internal error', { requestId: req.id });
});

const server = app.listen(3000);
// Load balancer idle timeout is 60 s: keep sockets open longer than that.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;
server.requestTimeout = 30_000;

process.on('SIGTERM', () => {
  server.close(async () => {
    await pool.end();
    await redis.quit();
    process.exit(0);
  });
});
