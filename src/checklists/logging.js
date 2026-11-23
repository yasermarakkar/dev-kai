import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { blocksAfter, lineIndex } from '../core/lexer.js';

const LOGGERS = [
  'pino', 'winston', 'bunyan', 'log4js', 'tslog', '@logtape/logtape', 'roarr', 'loglevel', 'signale',
  'nestjs-pino', '@nestjs/common', 'consola', '@aws-lambda-powertools/logger', 'electron-log', 'react-native-logs',
];
const SERVER_LOGGERS = LOGGERS.filter((l) => !['loglevel', 'consola', 'signale', 'react-native-logs'].includes(l));

const HTTP_LOGGERS = ['pino-http', 'morgan', 'express-winston', 'nestjs-pino', 'koa-logger', 'koa-pino-logger', 'hono-pino', '@hono/logger', 'express-pino-logger'];

const SHIPPERS = [
  'pino-loki', 'pino-elasticsearch', 'pino-datadog-transport', 'pino-cloudwatch', '@logtail/pino', '@logtail/node', '@logtail/winston',
  'winston-cloudwatch', 'winston-elasticsearch', 'winston-loki', '@google-cloud/logging', '@google-cloud/logging-winston',
  '@google-cloud/pino-logging-gcp-config', 'datadog-winston', '@datadog/browser-logs', '@axiomhq/pino', '@axiomhq/winston',
  'pino-socket', 'winston-syslog', '@opentelemetry/sdk-logs', '@opentelemetry/winston-transport', 'pino-opentelemetry-transport',
  'newrelic', 'dd-trace', '@sentry/node',
];

const SENSITIVE = '(password|passwd|pwd|secret|token|accessToken|refreshToken|apiKey|api_key|authorization|cookie|ssn|creditCard|cardNumber|cvv|pin)';
const LOG_CALL = '\\b(console|logger|log|this\\.logger|req\\.log|ctx\\.log|request\\.log|fastify\\.log|app\\.log)\\.(log|info|debug|warn|error|trace|fatal)\\s*\\(';

// Files that are allowed to print: CLIs, scripts, build config, seeds.
const PRINT_OK = /(^|\/)(scripts?|bin|cli|tools|seeds?|migrations?|\.storybook)\/|(^|\/)[\w.-]*\.(config|conf)\.[cm]?[jt]s$|(^|\/)(cli|seed)\.[cm]?[jt]s$/;

const structuredLogger = defineCheck({
  id: 'LOG-001',
  title: 'A structured logger is used (not bare console)',
  severity: 'high',
  tags: ['logger'],
  why: 'console output has no levels, no JSON, no context — logs cannot be filtered, searched or correlated across apps.',
  fix: 'Use pino (fastest, JSON by default) or winston on the server; NestJS: nestjs-pino. Create one shared logger module and import it everywhere.',
  docs: ['https://getpino.io/', 'https://github.com/winstonjs/winston'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected (frontend logging is covered by LOG-002).');
    const found = SERVER_LOGGERS.filter((l) => ctx.hasDep(l) && (l !== '@nestjs/common' || ctx.contains(/new\s+Logger\s*\(|Logger\.(log|error|warn)/)));
    if (ctx.hasDep('fastify') && ctx.contains(/fastify\s*\(\s*\{[^}]*logger\s*:/)) found.push('fastify built-in (pino)');
    return found.length ? pass(`Using ${found.join(', ')}.`) : fail('No logging library found; logging relies on console.*.');
  },
});

const noConsole = defineCheck({
  id: 'LOG-002',
  title: 'No stray console.log in application code',
  severity: 'medium',
  tags: ['logger', 'hygiene'],
  why: 'console.log bypasses levels and redaction, leaks data into browser consoles and floods production logs.',
  fix: 'Replace with the shared logger (server) or remove (frontend). Enforce with ESLint `no-console` and strip in builds (e.g. `compiler.removeConsole` in Next.js).',
  run(ctx) {
    const files = ctx.appCodeFiles.filter((f) => !PRINT_OK.test(f));
    const hits = ctx.grep(/\bconsole\.(log|debug|info|trace|dir|table)\s*\(/, { files });
    if (!hits.length) return pass('No console.log/debug/info in application code.');
    const eslintEnforced = ctx.findFiles(/(^|\/)(\.eslintrc(\.\w+)?|eslint\.config\.[cm]?[jt]s|package\.json)$/)
      .some((f) => /no-console['"]?\s*[:,]\s*\[?\s*['"]?(error|warn|2|1)/.test(ctx.read(f) ?? ''));
    const msg = `${hits.length} console call(s) in ${new Set(hits.map((h) => h.file)).size} file(s)${eslintEnforced ? ' (ESLint no-console is on)' : ''}.`;
    return hits.length > 5 && !eslintEnforced ? fail(msg, hits) : warn(msg, hits);
  },
});

const levelFromEnv = defineCheck({
  id: 'LOG-003',
  title: 'Log level is configurable per environment',
  severity: 'low',
  tags: ['logger', 'config'],
  why: 'You need debug logs in an incident without a redeploy, and quiet logs (and bills) the rest of the time.',
  fix: 'Read the level from env: `pino({ level: process.env.LOG_LEVEL ?? \'info\' })`.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    if (ctx.contains(/LOG_LEVEL|level\s*:\s*(process\.env|config\.|env\.)|logLevel\s*:\s*(process\.env|config\.)/)) return pass('Log level read from environment/config.');
    if (ctx.contains(/level\s*:\s*['"`](debug|trace|info|warn|error)['"`]/)) return fail('Log level is hardcoded.', ctx.grep(/level\s*:\s*['"`](debug|trace|info|warn|error)['"`]/));
    return fail('No configurable log level found.');
  },
});

const httpLogging = defineCheck({
  id: 'LOG-004',
  title: 'HTTP requests are logged (method, path, status, duration)',
  severity: 'medium',
  tags: ['http'],
  why: 'Access logs are the first thing you need to answer "what happened at 14:02?" or "which client is hammering us?".',
  fix: 'Add pino-http / nestjs-pino (or morgan with JSON format). Fastify: `fastify({ logger: true })`.',
  run(ctx) {
    if (!ctx.stack.server.length) return skip('No HTTP server framework detected (Next.js/Vercel logs requests at the platform).');
    const found = HTTP_LOGGERS.filter((l) => ctx.hasDep(l));
    if (ctx.hasDep('fastify') && ctx.contains(/logger\s*:\s*(true|\{)/)) found.push('fastify logger');
    return found.length ? pass(`Using ${found.join(', ')}.`) : fail('No request logging middleware found.');
  },
});

const correlationId = defineCheck({
  id: 'LOG-005',
  title: 'Requests carry a correlation / request id across services',
  severity: 'high',
  tags: ['tracing', 'multi-app'],
  why: 'With several apps talking to each other, you cannot follow one user action through the logs without a shared id.',
  fix: 'Accept or generate `x-request-id` at the edge, store it in AsyncLocalStorage, add it to every log line, and forward it on outbound calls. OpenTelemetry trace ids do this for you.',
  docs: ['https://nodejs.org/api/async_context.html', 'https://opentelemetry.io/docs/languages/js/'],
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const libs = ['cls-rtracer', 'express-request-id', 'nestjs-cls', 'express-http-context', 'cls-hooked', '@opentelemetry/api', '@opentelemetry/sdk-node', 'dd-trace', 'correlation-id'];
    const found = libs.filter((l) => ctx.hasDep(l));
    const patterns = ctx.contains(/x-request-id|x-correlation-id|correlationId|requestId|genReqId|AsyncLocalStorage|traceparent/i);
    if (found.length) return pass(`Using ${found.join(', ')}.`);
    if (patterns) return warn('Request id handling found in code — confirm it is added to every log line and forwarded to downstream calls.');
    return fail('No request/correlation id propagation found.');
  },
});

const redaction = defineCheck({
  id: 'LOG-006',
  title: 'Sensitive fields are redacted from logs',
  severity: 'high',
  tags: ['privacy', 'security'],
  why: 'Passwords, tokens and personal data in logs end up in third-party log tools with weaker access control — a breach and a GDPR issue.',
  fix: 'Configure redaction centrally: pino `redact: [\'req.headers.authorization\', \'*.password\', \'*.token\']`, or a winston format that masks keys. Never log raw request bodies.',
  docs: ['https://getpino.io/#/docs/redaction', 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'],
  run(ctx) {
    const leaks = ctx.grep(new RegExp(`${LOG_CALL}[^)]*\\b${SENSITIVE}\\b`, 'i'));
    if (leaks.length) return fail(`${leaks.length} log call(s) include sensitive-looking fields.`, leaks);
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const hasRedact = ctx.contains(/\bredact(Paths)?\s*:|fast-redact|redactKeys|maskSensitive|sanitize(Log|r)/i) || ctx.hasDep('fast-redact', '@pinojs/redact', 'pino-noir');
    return hasRedact ? pass('Redaction configured; no sensitive fields in log calls.') : warn('No sensitive fields logged directly, but no redaction config either — one future log of a request object will leak.');
  },
});

const swallowedErrors = defineCheck({
  id: 'LOG-007',
  title: 'Errors are not silently swallowed',
  severity: 'medium',
  tags: ['errors'],
  why: 'Empty catch blocks hide failures: the bug exists, but there is no log line to find it.',
  fix: 'Log with the error object (`logger.error({ err }, \'charge failed\')`) and rethrow or handle. If ignoring is intentional, leave a comment explaining why.',
  run(ctx) {
    // Review mode uses comment-stripped text and matches across lines, so `catch (e) {\n}` is caught too
    // while a catch containing only an explanatory comment is still flagged (comment ≠ handling).
    const findings = unique([
      ...ctx.grep(/catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}/),
      ...ctx.grep(/\.catch\s*\(\s*(\(\s*\w*\s*\)|\w+)\s*=>\s*(\{\s*\}|null|undefined|void 0)\s*\)/),
      ...ctx.grep(/\.catch\s*\(\s*(function\s*\(\s*\w*\s*\)\s*\{\s*\}|noop|\(\)\s*=>\s*\{\s*\})\s*\)/),
    ]);
    return findings.length ? fail(`${findings.length} empty catch handler(s).`, findings) : pass('No empty catch blocks found.');
  },
});

const processHandlers = defineCheck({
  id: 'LOG-008',
  title: 'Uncaught exceptions and unhandled rejections are logged',
  severity: 'medium',
  tags: ['errors', 'process'],
  why: 'Without handlers, a crash leaves no structured log line — just a dead process.',
  fix: 'Add `process.on(\'uncaughtException\')` and `process.on(\'unhandledRejection\')` that log with the logger (fatal level), flush, then exit(1) so the orchestrator restarts you.',
  docs: ['https://nodejs.org/api/process.html#event-uncaughtexception'],
  run(ctx) {
    if (!ctx.stack.server.length) return skip('No long-running Node server detected.');
    if (ctx.hasDep('@sentry/node', 'dd-trace', 'newrelic', '@bugsnag/js', 'rollbar', '@honeybadger-io/js', 'elastic-apm-node')) {
      return pass('Error tracking SDK installed (captures uncaught errors).');
    }
    const uncaught = ctx.contains(/process\.on\s*\(\s*['"`]uncaughtException/);
    const rejection = ctx.contains(/process\.on\s*\(\s*['"`]unhandledRejection/);
    if (uncaught && rejection) return pass('Both handlers registered.');
    if (uncaught || rejection) return warn(`Only ${uncaught ? 'uncaughtException' : 'unhandledRejection'} is handled.`);
    return fail('No process-level error handlers.');
  },
});

const logDestination = defineCheck({
  id: 'LOG-009',
  title: 'Logs go to stdout or a log platform (files are rotated)',
  severity: 'medium',
  tags: ['shipping'],
  why: 'Log files inside a container vanish on restart; unrotated files fill the disk and take the app down.',
  fix: 'Log JSON to stdout and let the platform ship it (Docker/K8s/ECS → Loki, Datadog, CloudWatch, ELK). If you must write files, use winston-daily-rotate-file / pino-roll or logrotate.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const fileLogs = [
      ...ctx.grep(/transports\.File\s*\(|new\s+File\s*\(\s*\{[^}]*filename/),
      ...ctx.grep(/pino\.destination\s*\(\s*['"`][^'"`]+\.log/),
      ...ctx.grep(/(appendFile|appendFileSync|createWriteStream)\s*\([^)]*\.log['"`]/),
    ];
    const rotated = ctx.hasDep('winston-daily-rotate-file', 'pino-roll', 'rotating-file-stream', 'file-stream-rotator', 'logrotate-stream');
    const shippers = SHIPPERS.filter((s) => ctx.hasDep(s));
    if (fileLogs.length && !rotated) return fail('Logs written to files without rotation.', fileLogs);
    if (shippers.length) return pass(`Shipping via ${shippers.join(', ')}.`);
    return pass(fileLogs.length ? 'File logs are rotated.' : 'Logs go to stdout (ensure your platform collects them).');
  },
});

const prettyInProd = defineCheck({
  id: 'LOG-010',
  title: 'Pretty-printing is dev-only',
  severity: 'low',
  tags: ['performance'],
  why: 'pino-pretty / colorized output in production is slow and breaks JSON parsing in your log platform.',
  fix: 'Move pino-pretty to devDependencies and enable it only when NODE_ENV !== \'production\' (or pipe: `node app | pino-pretty` locally).',
  run(ctx) {
    if (!ctx.hasDep('pino-pretty') && !ctx.contains(/format\.(colorize|prettyPrint|simple)\s*\(/)) return skip('No pretty-printer in use.');
    const inProdDeps = ctx.prodDeps.has('pino-pretty');
    const unguarded = ctx.grep(/target\s*:\s*['"`]pino-pretty['"`]|prettyPrint\s*:\s*true|format\.colorize\s*\(/)
      .filter((h) => !/NODE_ENV|isDev|isProd|development|production/.test((ctx.read(h.file) ?? '')));
    if (unguarded.length) return fail('Pretty output enabled without an environment guard.', unguarded);
    if (inProdDeps) return warn('pino-pretty is in dependencies (ships to prod) — move to devDependencies.');
    return pass('Pretty output is environment-guarded.');
  },
});

const serviceContext = defineCheck({
  id: 'LOG-011',
  title: 'Every log line names its service and environment',
  severity: 'low',
  tags: ['multi-app'],
  why: 'In a central log store with many apps, a line without `service` and `env` is noise you cannot filter.',
  fix: 'Set base fields once: pino `base: { service: \'orders-api\', env: process.env.NODE_ENV }` / winston `defaultMeta`, or use OpenTelemetry resource attributes.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    if (!SERVER_LOGGERS.some((l) => ctx.hasDep(l))) return skip('No logger library (see LOG-001).');
    const has = ctx.contains(/\bbase\s*:\s*\{|defaultMeta\s*:|\.child\s*\(\s*\{[^}]*(service|app|module)|service(Name)?\s*:\s*['"`\w]|OTEL_SERVICE_NAME|SemanticResourceAttributes|ATTR_SERVICE_NAME/);
    return has ? pass('Logger sets base/service context.') : fail('Logger has no service/env base fields.');
  },
});

// ---------- in-depth (--review) ----------

const loggedRequestObjects = defineCheck({
  id: 'LOG-R01',
  review: true,
  title: 'Whole request bodies, headers or user records are not logged',
  severity: 'high',
  tags: ['privacy', 'security'],
  why: 'Logging `req.body`, `req.headers` or a full user object dumps passwords, tokens and PII — even when field names look harmless.',
  fix: 'Log ids and a small allow-listed set of fields. Rely on the logger\'s request serializer (which redacts) instead of passing raw objects.',
  run(ctx) {
    const findings = ctx.grep(new RegExp(`${LOG_CALL}[^;]*\\b(req|request|ctx\\.request)\\.(body|headers|cookies)\\b(?!\\.)|${LOG_CALL}\\s*(user|account|customer|profile|payload|body|headers|credentials)\\s*[,)]`, 'i'));
    return findings.length ? fail('Raw request/user objects passed to logs.', findings) : pass('No raw request bodies/headers/user objects logged.');
  },
});

const errorLevels = defineCheck({
  id: 'LOG-R02',
  review: true,
  title: 'Errors in catch blocks are logged at error/warn level with the error object',
  severity: 'medium',
  tags: ['errors', 'levels'],
  why: 'Failures logged at info/debug never fire alerts, and logging only `err.message` throws away the stack trace and cause.',
  fix: 'Inside catch: `logger.error({ err }, \'what failed\')` (pino) or `logger.error(\'what failed\', { error })` (winston). Reserve info for normal flow.',
  run(ctx) {
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !/catch/.test(code)) continue;
      const lineOf = lineIndex(code);
      for (const b of blocksAfter(code, /\bcatch\s*(\(\s*(\w+)\s*\))?\s*\{/)) {
        const errName = (code.slice(b.start, b.open).match(/\(\s*(\w+)\s*\)/) ?? [])[1];
        const body = b.body;
        const lowLevel = body.match(/\b(logger|log|this\.logger|req\.log)\.(info|debug|trace|log)\s*\(/);
        const consoleLow = body.match(/\bconsole\.(log|info|debug)\s*\(/);
        const messageOnly = errName && new RegExp(`\\.(error|warn)\\s*\\([^)]*\\b${errName}\\.message\\b`).test(body) && !new RegExp(`\\b${errName}\\b(?!\\.message)`).test(body.replace(new RegExp(`${errName}\\.message`, 'g'), ''));
        const hit = lowLevel ?? consoleLow;
        if (hit) findings.push(ctx.at(f, lineOf(b.open + 1 + hit.index), `error logged at "${hit[2] ?? hit[1]}" level`));
        else if (messageOnly) findings.push(ctx.at(f, lineOf(b.open), `only ${errName}.message logged — stack lost`));
      }
    }
    return findings.length ? fail(`${findings.length} catch block(s) log errors at the wrong level or without the error object.`, findings) : pass('Catch blocks log at error/warn with the error object.');
  },
});

const manual = [
  {
    id: 'LOG-M01', title: 'Logs from all apps land in one searchable place', severity: 'high',
    why: 'Debugging a multi-app system by SSH-ing into boxes or opening five dashboards does not scale.',
    fix: 'Pick one platform (Loki/Grafana, Datadog, ELK/OpenSearch, CloudWatch, Axiom) and ship every app and website there.',
  },
  {
    id: 'LOG-M02', title: 'Retention period is defined per log type and meets legal needs', severity: 'medium',
    why: 'Keeping logs forever costs money and violates data minimization; keeping them too short breaks investigations.',
    fix: 'e.g. app logs 30 days, security/audit logs 1 year+; document it; configure lifecycle rules.',
  },
  {
    id: 'LOG-M03', title: 'Access to logs is restricted and itself logged', severity: 'medium',
    why: 'Logs contain user data; everyone with access is a potential leak.',
    fix: 'SSO + role-based access on the log platform; audit who queries production logs.',
  },
  {
    id: 'LOG-M04', title: 'Log volume and cost are budgeted (sampling for noisy paths)', severity: 'low',
    why: 'A debug log in a hot loop can cost more than the servers.',
    fix: 'Set per-service ingest alerts; sample health checks and high-volume info logs.',
  },
  {
    id: 'LOG-M05', title: 'Team can trace one request across all apps from the logs', severity: 'medium',
    why: 'The point of logging is answering questions fast during an incident.',
    fix: 'Write a short runbook: "given a request id / user id, here is the query"; practice it once.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'logging',
  title: 'Logging',
  description: 'Structured, leveled, correlated and privacy-safe logs that let you answer "what happened?" across every app.',
  checks: [
    structuredLogger, noConsole, levelFromEnv, httpLogging, correlationId, redaction,
    swallowedErrors, processHandlers, logDestination, prettyInProd, serviceContext,
    loggedRequestObjects, errorLevels,
    ...manual,
  ],
});
