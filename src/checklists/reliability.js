import { defineCheck, defineChecklist, pass, fail, warn, skip, unique } from '../core/check.js';
import { blocksAfter, extractArgs, lineIndex } from '../core/lexer.js';

// ---------- shared ----------

const HTTP_CLIENT_CALL = /(^|[^.\w])fetch\s*\(|\baxios(\.(get|post|put|patch|delete|request|head))?\s*\(|\bgot(\.(get|post|put|patch|delete))?\s*\(|\bky(\.(get|post|put|patch|delete))?\s*\(|\bundici\.request\s*\(|\bsuperagent\.(get|post|put|delete)\s*\(|\bhttps?\.(get|request)\s*\(/;
const RETRY_LIBS = ['axios-retry', 'p-retry', 'async-retry', 'retry', 'cockatiel', 'exponential-backoff', '@lifeomic/attempt', 'fetch-retry', 'retry-axios', 'ts-retry-promise', 'promise-retry', 'got', 'ky'];
const BREAKER_LIBS = ['opossum', 'cockatiel', 'brakes', 'mollitia', 'circuit-breaker-js', '@nestjs-circuit-breaker/core', 'resilience4js'];
const PAYMENT_LIBS = ['stripe', '@stripe/stripe-js', 'braintree', '@paypal/checkout-server-sdk', '@paypal/paypal-server-sdk', '@adyen/api-library', 'square', 'razorpay', 'mollie-api-node', '@mollie/api-client', '@lemonsqueezy/lemonsqueezy.js', 'paddle-sdk', '@paddle/paddle-node-sdk'];
const FLAG_LIBS = ['launchdarkly-node-server-sdk', '@launchdarkly/node-server-sdk', 'launchdarkly-js-client-sdk', 'unleash-client', '@unleash/proxy-client-react', 'flagsmith', 'flagsmith-nodejs', '@growthbook/growthbook', '@growthbook/growthbook-react', '@vercel/flags', 'flags', 'configcat-node', 'configcat-js', '@openfeature/server-sdk', '@openfeature/web-sdk', 'posthog-node', '@statsig/js-client', 'statsig-node', '@harnessio/ff-nodejs-server-sdk'];

function expressMajor(ctx) {
  for (const { pkg } of ctx.apps) {
    const v = pkg.dependencies?.express ?? pkg.devDependencies?.express;
    if (v) {
      const m = String(v).match(/(\d+)/);
      if (m) return Number(m[1]);
    }
  }
  return null;
}

const asyncWrapped = (ctx) => ctx.hasDep('express-async-errors', 'express-async-handler', 'express-promise-router', '@awaitjs/express', 'express-async-router')
  || ctx.contains(/\b(asyncHandler|catchAsync|wrapAsync|asyncWrap|tryCatch)\s*\(\s*async/);

/** Async Express-style handlers in a file: [{ line, body }]. */
function asyncHandlers(code) {
  const lineOf = lineIndex(code);
  const out = [];
  const re = /\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all|use)\s*\(/g;
  let m;
  while ((m = re.exec(code))) {
    if (/^(axios|http|https|got|ky|client|api|this|map|cache|redis|db|prisma|headers|searchParams|params)$/i.test(m[1])) continue;
    const open = m.index + m[0].length - 1;
    const { args } = extractArgs(code, open);
    const last = args.at(-1) ?? '';
    if (/^async\b/.test(last)) out.push({ line: lineOf(m.index), body: last, name: m[2] });
  }
  return out;
}

// ---------- quick checks ----------

const retries = defineCheck({
  id: 'REL-001',
  title: 'Transient failures are retried with backoff',
  severity: 'medium',
  tags: ['resilience'],
  why: 'Networks drop packets and services restart: a single retry with jitter turns most "random" errors into nothing.',
  fix: 'Retry idempotent calls with exponential backoff + jitter and a small cap (axios-retry, p-retry, cockatiel, got/ky built-in retry). Never retry non-idempotent calls without an idempotency key.',
  run(ctx) {
    if (!ctx.contains(HTTP_CLIENT_CALL, { codeOnly: true }) && !ctx.hasDep('@aws-sdk/client-s3', 'stripe', 'twilio', '@sendgrid/mail')) return skip('No outbound calls found.');
    const libs = RETRY_LIBS.filter((l) => ctx.hasDep(l));
    if (libs.length) return pass(`Retry support via ${libs.join(', ')}.`);
    if (ctx.contains(/\b(retry|withRetry|retryWithBackoff|backoff)\s*\(|maxRetries\s*:|retries\s*:\s*\d/)) return pass('Custom retry logic found.');
    return fail('Outbound calls without any retry/backoff mechanism.', ctx.grep(HTTP_CLIENT_CALL, { limit: 5, codeOnly: true }));
  },
});

const circuitBreaker = defineCheck({
  id: 'REL-002',
  title: 'Circuit breakers protect calls to other services',
  severity: 'medium',
  tags: ['resilience', 'multi-app'],
  why: 'When a downstream app is down, retrying every request piles up load on both sides; a breaker fails fast and lets it recover.',
  fix: 'Wrap calls to other apps/third parties with opossum or cockatiel (breaker + timeout + fallback). Return a degraded response instead of an error where possible.',
  run(ctx) {
    if (!ctx.contains(HTTP_CLIENT_CALL, { codeOnly: true })) return skip('No outbound HTTP calls found.');
    const libs = BREAKER_LIBS.filter((l) => ctx.hasDep(l));
    if (libs.length) return pass(`Circuit breaking via ${libs.join(', ')}.`);
    if (ctx.contains(/CircuitBreaker|circuitBreaker|breaker\.(fire|execute)/)) return pass('Custom circuit breaker found.');
    return warn('Outbound calls without circuit breaking — fine for one dependency, risky across several apps.');
  },
});

const idempotency = defineCheck({
  id: 'REL-003',
  title: 'Payments and order creation are idempotent',
  severity: 'high',
  tags: ['integrity', 'payments'],
  why: 'Clients retry on timeouts and users double-click: without idempotency keys that means double charges and duplicate orders.',
  fix: 'Accept an `Idempotency-Key` header on POST endpoints that create money/orders, store the key + response (Redis/DB unique constraint) and replay the stored response. Pass `idempotencyKey` to Stripe and other PSPs.',
  docs: ['https://docs.stripe.com/api/idempotent_requests'],
  run(ctx) {
    const payments = PAYMENT_LIBS.filter((l) => ctx.hasDep(l));
    const routes = ctx.grep(/\.(post|put)\s*\(\s*['"`][^'"`]*(order|checkout|payment|pay|charge|refund|subscription|invoice|transfer|payout)s?\b[^'"`]*['"`]/i);
    if (!payments.length && !routes.length) return skip('No payment or order-creation code found.');
    if (ctx.contains(/idempotency[-_]?key|Idempotency-Key|idempotencyKey|x-idempotency|requestKey\s*:/i)) return pass('Idempotency keys handled.');
    return fail(`${payments.length ? `Uses ${payments.join(', ')}` : 'Order/payment endpoints'} without idempotency keys.`, routes);
  },
});

const webhooks = defineCheck({
  id: 'REL-004',
  title: 'Incoming webhooks are verified and processed once',
  severity: 'high',
  tags: ['integrity', 'security'],
  why: 'Providers retry webhooks and deliver them out of order; anyone can POST a fake one. Unverified, non-deduplicated handlers mark orders paid twice — or for free.',
  fix: 'Verify the signature on the raw body (`stripe.webhooks.constructEvent`, svix, HMAC + `timingSafeEqual`), store processed event ids with a unique constraint, return 2xx fast and do the work in a queue.',
  run(ctx) {
    const hooks = ctx.grep(/\.(post|all)\s*\(\s*['"`][^'"`]*webhook[^'"`]*['"`]|(^|\/)webhooks?\b/i, { filter: (f) => /webhook/i.test(f) || /webhook/i.test(ctx.read(f) ?? '') })
      .filter((h) => /webhook/i.test(h.text) || /webhook/i.test(h.file));
    const files = [...new Set(hooks.map((h) => h.file))];
    if (!files.length) return skip('No webhook handlers found.');
    const text = files.map((f) => ctx.read(f) ?? '').join('\n');
    const verified = /constructEvent|verifySignature|verifyWebhook|webhooks\.verify|validateWebhook|timingSafeEqual|svix|Webhook\s*\(\s*[\w.]+\s*\)\.verify|x-hub-signature|stripe-signature/i.test(text);
    const deduped = /event\.id|eventId|event_id|processed_?events|webhook_?events|ON CONFLICT|unique|already processed|isDuplicate|idempot/i.test(text);
    if (!verified) return fail('Webhook handler without signature verification.', hooks);
    if (!deduped) return warn('Webhooks verified but not deduplicated by event id.', hooks);
    return pass('Webhooks verified and deduplicated.');
  },
});

const errorHandler = defineCheck({
  id: 'REL-005',
  title: 'A central error handler returns consistent errors',
  severity: 'medium',
  tags: ['errors'],
  why: 'Without one place that maps errors to responses, some failures crash the process, some hang, and clients get a different error shape from every route.',
  fix: 'Express: final `app.use((err, req, res, next) => …)`. Fastify: `setErrorHandler`. NestJS: a global ExceptionFilter. Next.js: `error.tsx` / `global-error.tsx` and route handler try/catch. Log, report, return `{ error, requestId }`.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const found = ctx.contains(/\.use\s*\(\s*(async\s*)?(function\s*\w*\s*)?\(\s*(err|error|e)\s*,\s*req\s*,\s*res\s*,\s*next\s*\)|setErrorHandler\s*\(|@Catch\s*\(|implements\s+ExceptionFilter|useGlobalFilters\s*\(|app\.on\s*\(\s*['"`]error|\.onError\s*\(/)
      || ctx.findFiles(/(^|\/)app\/(.*\/)?(global-)?error\.[jt]sx?$/).length > 0;
    return found ? pass('Central error handler found.') : fail('No central error handler.');
  },
});

const asyncErrors = defineCheck({
  id: 'REL-006',
  title: 'Async route errors reach the error handler (Express 4)',
  severity: 'high',
  tags: ['errors'],
  why: 'Express 4 ignores rejected promises from async handlers: the request hangs until timeout and an unhandledRejection may crash the process.',
  fix: 'Upgrade to Express 5 (handles promises), add `import \'express-async-errors\'` once at startup, or wrap each handler with an asyncHandler.',
  run(ctx) {
    const major = expressMajor(ctx);
    if (major === null) return skip('Express not used.');
    if (major >= 5) return pass(`Express ${major} forwards async errors.`);
    const files = ctx.appCodeFiles.filter((f) => asyncHandlers(ctx.code(f) ?? '').length > 0);
    if (!files.length) return pass('No async handlers.');
    if (asyncWrapped(ctx)) return pass('Async errors forwarded (express-async-errors / asyncHandler).');
    return fail(`Express ${major} with async handlers in ${files.length} file(s) and no async error forwarding.`, files.map((f) => ({ file: f })));
  },
});

const errorBoundaries = defineCheck({
  id: 'REL-007',
  title: 'Frontends catch rendering errors (error boundaries)',
  severity: 'medium',
  tags: ['frontend', 'errors'],
  why: 'One exception in one React component unmounts the whole page — the user sees a blank screen.',
  fix: 'React: wrap routes/widgets in `react-error-boundary` or `Sentry.ErrorBoundary`. Next.js: `error.tsx` per segment + `global-error.tsx`. Vue: `app.config.errorHandler` / `onErrorCaptured`.',
  run(ctx) {
    const fe = [...ctx.stack.frontend, ...ctx.stack.fullstack];
    if (!fe.length) return skip('No frontend detected.');
    const nextErr = ctx.findFiles(/(^|\/)app\/(.*\/)?(global-)?error\.[jt]sx?$/).length > 0;
    const react = ctx.hasDep('react-error-boundary') || ctx.contains(/componentDidCatch|getDerivedStateFromError|ErrorBoundary/);
    const vue = ctx.contains(/config\.errorHandler\s*=|onErrorCaptured\s*\(|errorCaptured\s*\(/);
    const angular = ctx.contains(/implements\s+ErrorHandler|provide\s*:\s*ErrorHandler/);
    const svelte = ctx.findFiles(/\+error\.svelte$/).length > 0;
    return nextErr || react || vue || angular || svelte ? pass('Error boundary / handler in place.') : fail(`${fe.join(', ')} app without error boundaries.`);
  },
});

const pinnedRuntime = defineCheck({
  id: 'REL-008',
  title: 'Runtime and base images are pinned',
  severity: 'low',
  tags: ['builds'],
  why: '`FROM node:latest` or an unpinned Node version means a rebuild of the same commit can behave differently — or break — on any day.',
  fix: 'Pin the major (or digest) in Dockerfiles (`FROM node:22.11-slim`), set `engines.node` and `.nvmrc`/`.node-version`, use the same version in CI.',
  run(ctx) {
    const dockerfiles = ctx.findFiles(/(^|\/)Dockerfile[^/]*$/);
    const floating = [];
    for (const f of dockerfiles) {
      const stages = new Set(); // names from `FROM x AS name` — later `FROM name` is not an image
      (ctx.read(f) ?? '').split('\n').forEach((text, i) => {
        const m = text.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
        if (!m) return;
        const image = m[1];
        if (m[2]) stages.add(m[2].toLowerCase());
        if (stages.has(image.toLowerCase()) || image === 'scratch' || image.startsWith('$') || image.includes('@sha256:')) return;
        const tag = image.lastIndexOf(':') > image.lastIndexOf('/') ? image.slice(image.lastIndexOf(':') + 1) : '';
        if (!tag || /^(latest|current|lts|stable|alpine|slim|bookworm|bullseye)$/i.test(tag)) floating.push({ file: f, line: i + 1, text });
      });
    }
    if (floating.length) return fail('Docker base images use a floating tag.', floating);
    const engines = ctx.apps.some((a) => a.pkg.engines?.node) || ctx.findFiles(/(^|\/)(\.nvmrc|\.node-version|\.tool-versions|volta\.json)$/).length > 0 || ctx.apps.some((a) => a.pkg.volta?.node);
    if (!ctx.apps.length) return skip('No Node project.');
    return engines || dockerfiles.length ? pass('Runtime version pinned.') : warn('No engines.node / .nvmrc — local, CI and production may run different Node versions.');
  },
});

const featureFlags = defineCheck({
  id: 'REL-009',
  title: 'Risky changes can be switched off without a deploy (feature flags)',
  severity: 'low',
  tags: ['releases'],
  why: 'A kill switch turns a 40-minute rollback into a 10-second toggle, and lets you release to 1% first.',
  fix: 'Adopt a flag service (OpenFeature + Unleash/Flagsmith/GrowthBook/LaunchDarkly/PostHog) for new features and expensive paths; remove flags once rolled out.',
  run(ctx) {
    if (!ctx.stack.hasBackend && !ctx.stack.frontend.length) return skip('No app detected.');
    const libs = FLAG_LIBS.filter((l) => ctx.hasDep(l));
    if (libs.length) return pass(`Feature flags via ${libs.join(', ')}.`);
    if (ctx.contains(/FEATURE_[A-Z_]+|isFeatureEnabled|featureFlags?\.|flags\.(isEnabled|get)\s*\(/)) return pass('Env/config-based feature flags in use.');
    return warn('No feature flag mechanism found.');
  },
});

const queueRetries = defineCheck({
  id: 'REL-010',
  title: 'Queue consumers retry with backoff and dead-letter poison messages',
  severity: 'medium',
  tags: ['jobs', 'resilience'],
  why: 'A message that always fails either blocks the queue forever or disappears silently; neither is acceptable for orders or emails.',
  fix: 'BullMQ: `attempts` + `backoff`, handle `failed` events. SQS: RedrivePolicy → DLQ. RabbitMQ: `x-dead-letter-exchange`. pg-boss: `retryLimit`/`retryBackoff`. Alert on DLQ depth.',
  run(ctx) {
    const queues = ['bullmq', 'bull', 'bee-queue', 'agenda', 'pg-boss', 'graphile-worker', '@aws-sdk/client-sqs', 'sqs-consumer', 'amqplib', 'amqp-connection-manager', 'kafkajs', '@google-cloud/pubsub', '@azure/service-bus', '@nestjs/bull', '@nestjs/bullmq'].filter((q) => ctx.hasDep(q));
    if (!queues.length) return skip('No message queue in use.');
    const pool = ctx.files.filter((f) => ctx.codeFiles.includes(f) || /\.(tf|ya?ml|json)$/.test(f));
    const retry = ctx.contains(/\battempts\s*:|backoff\s*:|retryLimit|retryBackoff|maxReceiveCount|maxDeliveryAttempts|retry\s*:\s*\{|retries\s*:/, { files: pool });
    const dlq = ctx.contains(/dead.?letter|deadLetter|RedrivePolicy|redrive_policy|x-dead-letter|\bDLQ\b|\.on\s*\(\s*['"`]failed['"`]/i, { files: pool });
    if (retry && dlq) return pass('Retries and dead-lettering configured.');
    if (retry || dlq) return warn(`Only ${retry ? 'retries' : 'dead-lettering'} configured.`);
    return fail(`Using ${queues.join(', ')} with default retry/failure handling.`);
  },
});

const configValidation = defineCheck({
  id: 'REL-011',
  title: 'Configuration is validated at startup (fail fast)',
  severity: 'medium',
  tags: ['config'],
  why: 'A missing env var should stop the deploy at boot — not surface as `undefined` in a payment call three hours later.',
  fix: 'Parse `process.env` once with a schema (zod, envalid, @t3-oss/env-core, env-schema, @nestjs/config validationSchema) and export a typed config object.',
  run(ctx) {
    const envUses = ctx.grep(/process\.env\.[A-Z_]+/, { codeOnly: true });
    if (envUses.length < 3) return skip('Little or no environment configuration.');
    if (ctx.hasDep('envalid', '@t3-oss/env-core', '@t3-oss/env-nextjs', 'env-schema', 'convict', 'znv', '@julr/vite-plugin-validate-env', 'env-var')) return pass('Env validation library in use.');
    if (ctx.contains(/\.(parse|safeParse|validate|assert)\s*\(\s*process\.env\s*\)|validationSchema\s*:|cleanEnv\s*\(|createEnv\s*\(/)) return pass('process.env validated with a schema.');
    const vars = new Set(envUses.map((h) => h.match.replace('process.env.', '')));
    return fail(`${vars.size} env var(s) read directly with no startup validation.`, envUses.slice(0, 10));
  },
});

// ---------- in-depth (--review) ----------

const unhandledAsync = defineCheck({
  id: 'REL-R01',
  review: true,
  title: 'Each async handler handles its own errors (when nothing else does)',
  severity: 'high',
  tags: ['errors'],
  why: 'Lists the exact handlers that will hang or crash on the first rejected promise.',
  fix: 'Add express-async-errors once (simplest), or try/catch → next(err) in each listed handler.',
  run(ctx) {
    const major = expressMajor(ctx);
    if (major === null) return skip('Express not used.');
    if (major >= 5 || asyncWrapped(ctx)) return pass('Async errors are forwarded globally.');
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code) continue;
      for (const h of asyncHandlers(code)) {
        if (!/\btry\s*\{/.test(h.body) && /\bawait\b/.test(h.body)) findings.push(ctx.at(f, h.line, `async ${h.name.toUpperCase()} handler without try/catch`));
      }
    }
    return findings.length ? fail(`${findings.length} async handler(s) can leave requests hanging.`, findings) : pass('Every async handler catches its errors.');
  },
});

const floatingPromises = defineCheck({
  id: 'REL-R02',
  review: true,
  title: 'No floating promise chains (`.then()` without `.catch()`)',
  severity: 'medium',
  tags: ['errors'],
  why: 'A rejected promise nobody awaits or catches becomes an unhandledRejection — which crashes Node ≥ 15 by default.',
  fix: 'await it inside try/catch, return it to the caller, or end the chain with `.catch(err => logger.error({ err }, …))`. Enable `@typescript-eslint/no-floating-promises`.',
  run(ctx) {
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.codeOnly(f);
      if (!code || !/\.then\s*\(/.test(code)) continue;
      const lineOf = lineIndex(code);
      const re = /\.then\s*\(/g;
      let m;
      while ((m = re.exec(code))) {
        const lineStart = code.lastIndexOf('\n', m.index) + 1;
        const head = code.slice(lineStart, m.index);
        if (/\b(return|await|yield)\b|=\s*[^=>]|\(\s*$|,\s*$|:\s*$|=>\s*$/.test(head)) continue; // used, not floating
        // walk to the end of the chain; .then(onOk, onError) already handles rejection
        const first = extractArgs(code, m.index + m[0].length - 1);
        if (first.args.length >= 2) continue;
        let end = first.end;
        let chain = '';
        for (let guard = 0; guard < 6; guard++) {
          const next = code.slice(end).match(/^\s*\.\s*(then|catch|finally)\s*\(/);
          if (!next) break;
          chain += next[1];
          end = extractArgs(code, end + next[0].length - 1).end;
        }
        if (!/catch/.test(chain)) findings.push(ctx.at(f, lineOf(m.index), '.then() chain without .catch()'));
      }
    }
    return findings.length ? fail(`${findings.length} floating promise chain(s).`, unique(findings)) : pass('All promise chains are awaited, returned or caught.');
  },
});

const swallowedSuccess = defineCheck({
  id: 'REL-R03',
  review: true,
  title: 'Failures are not reported to clients as success',
  severity: 'medium',
  tags: ['errors', 'integrity'],
  why: 'A catch block that answers `{ ok: true }` (or a plain 200) tells the client — or the calling app — that the order/payment worked when it did not.',
  fix: 'In catch blocks, respond with the right 4xx/5xx (or rethrow / next(err)); never a success body.',
  run(ctx) {
    if (!ctx.stack.hasBackend) return skip('No backend detected.');
    const findings = [];
    for (const f of ctx.appCodeFiles) {
      const code = ctx.code(f);
      if (!code || !/catch/.test(code)) continue;
      const lineOf = lineIndex(code);
      for (const b of blocksAfter(code, /\bcatch\s*(\([^)]*\))?\s*\{/)) {
        const responds = b.body.match(/\b(res|reply|ctx|response)\s*\.\s*(json|send|end)\s*\(|ctx\.body\s*=|return\s+(Response|NextResponse)\.json\s*\(/);
        if (!responds) continue;
        const errorStatus = /\.(status|code|sendStatus)\s*\(\s*[45]\d\d|status\s*:\s*[45]\d\d|ctx\.status\s*=\s*[45]\d\d|\bthrow\b|next\s*\(\s*\w+\s*\)|Exception\s*\(/.test(b.body);
        if (!errorStatus) findings.push(ctx.at(f, lineOf(b.open + 1 + responds.index), 'catch block responds without an error status'));
      }
    }
    return findings.length ? fail(`${findings.length} catch block(s) answer with success.`, findings) : pass('Catch blocks respond with error statuses.');
  },
});

// ---------- manual ----------

const manual = [
  {
    id: 'REL-M01', title: 'Failure modes per dependency are known and tested (game day / chaos test)', severity: 'high',
    why: 'You learn what "Redis is down" does to your apps either in a drill or in production.',
    fix: 'For each dependency (DB, cache, queue, each other app, each third party) write the expected behaviour, then break it in staging once a quarter.',
  },
  {
    id: 'REL-M02', title: 'Rollback is one command and was tested recently', severity: 'high',
    why: 'Fast rollback is the cheapest reliability feature: most incidents are caused by a change.',
    fix: 'Keep the previous image/build deployable; practice rollback (and DB-compatible migrations) as part of the release process.',
  },
  {
    id: 'REL-M03', title: 'Incidents follow a process with blameless post-mortems and tracked action items', severity: 'medium',
    why: 'Without follow-through, the same outage happens again next month.',
    fix: 'Severity levels, incident commander role, timeline, post-mortem template, action items in the backlog with owners.',
  },
  {
    id: 'REL-M04', title: 'Disaster recovery plan with RTO/RPO, tested end to end', severity: 'high',
    why: 'Region outages, account compromise or accidental deletion need a rebuild path that does not depend on heroics.',
    fix: 'Document RTO/RPO per app, keep IaC to rebuild everything, cross-region backups, run a DR exercise yearly.',
  },
  {
    id: 'REL-M05', title: 'Every third-party dependency has a known SLA and a degraded mode', severity: 'medium',
    why: 'When the email, maps or payment provider is down, the rest of the product should keep working.',
    fix: 'List providers with SLA and status page; define fallback (queue and retry later, cached data, hide the feature).',
  },
  {
    id: 'REL-M06', title: 'Cross-app events use the outbox pattern (no dual writes)', severity: 'medium',
    why: '"Save to DB, then publish to the queue" loses events whenever the process dies between the two steps — apps drift apart.',
    fix: 'Write the event to an outbox table in the same transaction, relay it to the broker; consumers are idempotent.',
  },
  {
    id: 'REL-M07', title: 'Timeout budgets shrink along the call chain', severity: 'medium',
    why: 'If the gateway gives up after 10 s but the service waits 30 s on its downstream, work continues for responses nobody will read.',
    fix: 'Document per hop: client > gateway > service > downstream > DB, each strictly shorter; propagate deadlines where possible.',
  },
].map((m) => defineCheck({ ...m, manual: true, tags: ['process'] }));

export default defineChecklist({
  id: 'reliability',
  title: 'Reliability',
  description: 'Retries, circuit breakers, idempotency, error handling and safe releases — so one failing piece does not take down the rest of your apps.',
  checks: [
    retries, circuitBreaker, idempotency, webhooks, errorHandler, asyncErrors, errorBoundaries,
    pinnedRuntime, featureFlags, queueRetries, configValidation,
    unhandledAsync, floatingPromises, swallowedSuccess,
    ...manual,
  ],
});
