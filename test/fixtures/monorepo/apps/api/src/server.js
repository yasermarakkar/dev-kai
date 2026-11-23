import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import pino from 'pino';
import pinoHttp from 'pino-http';

const logger = pino({ level: process.env.LOG_LEVEL ?? 'info', base: { service: 'api' }, redact: ['req.headers.authorization'] });
const app = express();
app.use(helmet());
app.use(cors({ origin: ['https://shop.example.com'] }));
app.use(rateLimit({ windowMs: 60_000, limit: 100 }));
app.use(pinoHttp({ logger }));

const Query = z.object({ q: z.string().max(100) });
app.get('/v1/products', (req, res) => {
  const { q } = Query.parse(req.query);
  res.json({ data: [], q });
});

app.listen(3000);
