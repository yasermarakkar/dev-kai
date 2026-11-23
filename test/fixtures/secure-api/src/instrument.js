import * as Sentry from '@sentry/node';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import http from 'node:http';
import client from 'prom-client';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.APP_ENV,
  release: process.env.GIT_SHA,
  tracesSampleRate: Number(process.env.TRACES_SAMPLE_RATE ?? 0.1),
});

new NodeSDK({ instrumentations: [getNodeAutoInstrumentations()] }).start();

// Metrics on an internal-only port, scraped by Prometheus.
client.collectDefaultMetrics();
http
  .createServer(async (req, res) => {
    res.setHeader('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
  })
  .listen(Number(process.env.METRICS_PORT ?? 9464));
