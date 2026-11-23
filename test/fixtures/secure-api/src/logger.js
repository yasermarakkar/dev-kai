import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  base: { service: 'secure-api', env: process.env.NODE_ENV },
  redact: ['req.headers.authorization', 'req.headers.cookie', '*.password', '*.token'],
  transport: process.env.NODE_ENV === 'development' ? { target: 'pino-pretty' } : undefined,
});

process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'uncaught exception');
  process.exit(1);
});
process.on('unhandledRejection', (err) => {
  logger.fatal({ err }, 'unhandled rejection');
  process.exit(1);
});
